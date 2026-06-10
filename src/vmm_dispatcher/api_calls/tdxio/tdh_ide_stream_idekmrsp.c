// Copyright (C) 2023 Intel Corporation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
// OR OTHER DEALINGS IN THE SOFTWARE.
//
// SPDX-License-Identifier: MIT
/**
 * @file tdh_ide_stream_idekmrsp.c
 * @brief TDHIDESTREAMIDEKMRSP API handler
 */
#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/ide_stream.h"

#include "helpers/helpers.h"
#include "tdxio/iommu.h"
#include "tdxio/kcbar.h"
#include "tdxio/spdm.h"
#include "tdxio/aead.h"
#include "tdxio/seam_sai.h"
#include "tdxio/rp_cfg_page.h"

_STATIC_INLINE_ api_error_type enable_ide_stream(
    iommu_id_reg_t iommu_id_reg,
    stream_info_t *stream_info_ptr,
    ide_km_param_t ide_km_param)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    enable_seam_sai_generation();

    socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
    hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

    kcbar_t *kcbar_ptr = map_kcbar(
        socket_io_info_ptr,
        hiop_info_ptr);

    stream_config_reg_block_t *stream_config_reg_block = get_stream_cfg_reg_block(
        kcbar_ptr,
        stream_info_ptr->key_id);

    stream_config_reg_block->control.en = 1;
    vol_write_reg32(&stream_config_reg_block->control, stream_config_reg_block->control.raw);

    // TODO
    // stream_info_ptr->ide_stream_ctrl.enabled = 1;

    lnk_ide_stream_reg_block_t *lnk_ide_stream_reg_block = NULL;
    sel_ide_stream_reg_block_t *sel_ide_stream_reg_block = NULL;

    rp_cfg_page_t *rp_cfg_page_ptr = map_rp_mmcfg(
        hiop_info_ptr,
        stream_info_ptr->rp_df_num);

    void *ide_reg_block_ptr = get_ide_reg_block(
        socket_io_info_ptr,
        rp_cfg_page_ptr,
        stream_info_ptr->ide_id,
        stream_info_ptr->stream_sts.stream_type);
    if (ide_reg_block_ptr == NULL)
    {
        TDX_ERROR("Failed to get ide_reg_block\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_NOT_SUPPORTED, OPERAND_ID_R8);
        goto EXIT;
    }

    if (stream_info_ptr->stream_sts.stream_type == IDE_STREAM_SEL_IDE)
    {
        sel_ide_stream_reg_block = (sel_ide_stream_reg_block_t *)ide_reg_block_ptr;
        sel_ide_stream_reg_block->control.enabled = 1;
        vol_write_reg32(&sel_ide_stream_reg_block->control, sel_ide_stream_reg_block->control.raw);
    }
    else
    {
        lnk_ide_stream_reg_block = (lnk_ide_stream_reg_block_t *)ide_reg_block_ptr;
        lnk_ide_stream_reg_block->control.en = 1;
        vol_write_reg32(&lnk_ide_stream_reg_block->control, lnk_ide_stream_reg_block->control.raw);
    }

    // HW indicates the key is ready for use in [Rx/Tx]_Ready_Key_Set_[0/1] register
    bool_t is_key_ready = is_ide_ks_ready(
        kcbar_ptr,
        stream_info_ptr->key_id,
        ide_km_param.key_set);
    if (!is_key_ready)
    {
        TDX_ERROR("Failed to enable IDE stream KS is not ready yet\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_IDEKM_KEYS_NOT_READY, OPERAND_ID_RDX);
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:

    if (rp_cfg_page_ptr != NULL)
    {
        free_la(rp_cfg_page_ptr);
    }

    free_la(kcbar_ptr);

    // Disable SEAM SAI generation using the MSR_ENABLE_SEAM_SAI
    disable_seam_sai_generation();

    return return_val;
}

api_error_type tdh_ide_stream_idekmrsp(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id_reg,
    pa_t message_pa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    stream_info_t *stream_info_ptr = NULL;
    stream_info_t *stream_info_base_ptr = NULL;
    spdmdir_entry_t *spdmdir_entry_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;
    stream_exinfo_t *stream_exinfo_ptr = NULL;
    void *message_ptr = NULL;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;
    bool_t is_message_decrypted = false;

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        iommu_id_reg.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify Stream ID
    if (stream_id_reg.raw >= MAX_IDE_STREAM_ID)
    {
        TDX_ERROR("Invalid stream id (=0x%llx)\n", stream_id_reg.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    pa_t stream_info_pa = stream_id_reg.stream_id.page_selector == 1 ? iommu_config_ptr->stinfopa_1 : iommu_config_ptr->stinfopa_0;
    stream_info_base_ptr = (stream_info_t *)map_pa_with_global_hkid(
        stream_info_pa.raw_void,
        TDX_RANGE_RO);
    stream_info_ptr = &stream_info_base_ptr[stream_id_reg.stream_id.index];

    // IDE-Stream must be configured
    if (stream_info_ptr->stream_sts.config_lock == 0)
    {
        TDX_ERROR("IDE-stream is not configured\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_NOT_CONFIGURED, OPERAND_ID_RDX);
        goto EXIT;
    }

    // IDE-Stream must not be blocked
    if (stream_info_ptr->stream_sts.stream_block)
    {
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_BLOCKED, OPERAND_ID_RDX);
        goto EXIT;
    }

    // stream_exinfo.outstanding_req_object_id must not be IDE_OBJECT_INVALID, or else there are outstanding request pending response
    stream_exinfo_ptr = (stream_exinfo_t *)map_pa_with_global_hkid(
        stream_info_ptr->stream_exinfo_pa.raw_void,
        TDX_RANGE_RW);

    if (stream_exinfo_ptr->outstanding_req_object_id == IDE_OBJECT_INVALID)
    {
        TDX_ERROR("There aren't any outstanding request pending response\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_IDEKM_INVALID_RESPONSE, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Lock check and map SPDM info
    return_val = lock_check_and_map_spdm_metadata(
        stream_exinfo_ptr->spdm_id,
        OPERAND_ID_RDX,
        iommu_config_ptr,
        SPDM_STATE_BOUND,
        &spdm_info_ptr,
        &spdmdir_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify MESSAGE_PA
    if (shared_hpa_check_with_pwr_2_alignment(message_pa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS)
    {
        TDX_ERROR("Invalid message PA (=0x%llx)\n", message_pa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Use pa own shared keyid
    message_ptr = (uint64_t *)map_pa(
        message_pa.raw_void,
        TDX_RANGE_RO);

    uint64_t message_len = ((idekm_msg_t *)message_ptr)->spdm_doe_headers.doe_header.doe_length.raw * DOE_LENGTH_GRANULARITY;

    // Decrypt, authenticate and copy into internal buffer
    return_val = tdx_io_aead_decrypt(
        spdm_info_ptr,
        message_ptr,
        message_len,
        (void *)stream_exinfo_ptr->idekm_msg_buffer,
        SIZE_OF_IDE_KM_MSG_BUFFER_IN_BYTES);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
        goto EXIT;
    }
    is_message_decrypted = true;

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    const uint32_t* const msg_in_dwords = (uint32_t *)stream_exinfo_ptr->idekm_msg_buffer;
    uint32_t msg_length = ((idekm_msg_t *)stream_exinfo_ptr->idekm_msg_buffer)->spdm_doe_headers.doe_header.doe_length.length;
    TDX_LOG("Printing decrypted IDEKM response message:\n");

    for(uint32_t idx = 0; idx < msg_length; idx++)
    {
        TDX_LOG("0x%lx\n", msg_in_dwords[idx]);
    }
#endif // DEBUGFEATURE_TDX_DBG_TRACE

    bool_t bool_ret = verify_idekm_message_content(
        stream_exinfo_ptr,
        stream_id_reg.stream_id,
        spdm_info_ptr);
    if (!bool_ret)
    {
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_IDEKM_INVALID_RESPONSE, OPERAND_ID_R8);
        goto EXIT;
    }

    // Update Key_GO tracker to mark no outstanding KEY_GO pending
    // If ack received for K_SET_GO from device for receive direction then switch the keyset for the rootport transmit direction
    if (stream_exinfo_ptr->outstanding_req_object_id == IDE_OBJECT_ID_K_SET_GO)
    {
        ide_km_param_t ide_km_param = stream_exinfo_ptr->outstanding_req_km_param;
        stream_exinfo_ptr->key_go[ide_km_param.direction][ide_km_param.key_set] &= (uint8_t)~BIT(ide_km_param.sub_stream_id);
        if (ide_km_param.direction == DEV_RX &&
            stream_exinfo_ptr->key_go[ide_km_param.direction][ide_km_param.key_set] == 0)
        {
            // Enable SEAM SAI generation using the MSR_ENABLE_SEAM_SAI
            enable_seam_sai_generation();

            socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
            hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

            kcbar_t *kcbar_ptr = map_kcbar(
                socket_io_info_ptr,
                hiop_info_ptr);

            set_rc_tx_ide_key_set(
                kcbar_ptr,
                stream_info_ptr->key_id,
                ide_km_param.key_set);

            free_la(kcbar_ptr);
            // Disable SEAM SAI generation using the MSR_ENABLE_SEAM_SAI
            disable_seam_sai_generation();
        }
    }

    // Enable the stream after configuring all TX keys
    idekm_msg_t *idekm_msg_ptr = (idekm_msg_t *)stream_exinfo_ptr->idekm_msg_buffer;
    k_gostop_ack_obj_t *k_gostop_ack_obj_ptr = (k_gostop_ack_obj_t *)&idekm_msg_ptr->payload;

    if (stream_exinfo_ptr->primed_tx_key_counter == MAX_TX_PRIMED_KEYS &&
        k_gostop_ack_obj_ptr->object_id == IDE_OBJECT_ID_K_GOSTOP_ACK)
    {
        return_val = enable_ide_stream(iommu_id_reg, stream_info_ptr, stream_exinfo_ptr->outstanding_req_km_param);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to enable ide stream\n");
            goto EXIT;
        }
        stream_exinfo_ptr->primed_tx_key_counter = 0;
    }

    // RCX = Copy first 8 bytes from MSG_BUF starting at MSG_BUF.PROTOCOL_ID
    get_local_data()->vmm_regs.rcx = *((uint64_t *)&idekm_msg_ptr->payload);
    stream_exinfo_ptr->outstanding_req_object_id = IDE_OBJECT_INVALID;
    return_val = TDX_SUCCESS;

EXIT:
    if (is_message_decrypted)
    {
        basic_memset_to_zero((void *)stream_exinfo_ptr->idekm_msg_buffer, SIZE_OF_IDE_KM_MSG_BUFFER_IN_BYTES);
    }

    if (message_ptr != NULL)
    {
        free_la(message_ptr);
    }

    if (spdm_info_ptr != NULL)
    {
        free_la(spdm_info_ptr);
    }

    if (spdmdir_entry_ptr != NULL)
    {
        unlock_spdmdir_entry(spdmdir_entry_ptr, stream_exinfo_ptr->spdm_id);
        free_la(spdmdir_entry_ptr);
    }

    if (stream_exinfo_ptr != NULL)
    {
        free_la(stream_exinfo_ptr);
    }

    if (stream_info_base_ptr != NULL)
    {
        free_la(stream_info_base_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
