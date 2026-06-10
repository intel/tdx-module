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
 * @file tdh_ide_stream_idekmreq.c
 * @brief TDHIDESTREAMIDEKMREQ API handler
 */
#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/ide_stream.h"

#include "crypto/hmac_sha.h"
#include "helpers/helpers.h"
#include "tdxio/iommu.h"
#include "tdxio/kcbar.h"
#include "tdxio/spdm.h"
#include "tdxio/seam_sai.h"

_STATIC_INLINE_ bool_t is_object_id_valid(const ide_object_id_t object_id)
{
    return (object_id == IDE_OBJECT_ID_KEY_PROG ||
            object_id == IDE_OBJECT_ID_K_SET_GO ||
            object_id == IDE_OBJECT_ID_K_SET_STOP);
}

_STATIC_INLINE_ bool_t is_km_param_valid(const ide_km_param_reg_t ide_km_param_reg)
{
    return ide_km_param_reg.rsvd == 0 &&
           ide_km_param_reg.ide_km_param.rsvd == 0 &&
           (ide_km_param_reg.ide_km_param.sub_stream_id == SUBSTREAM_PR ||
            ide_km_param_reg.ide_km_param.sub_stream_id == SUBSTREAM_NPR ||
            ide_km_param_reg.ide_km_param.sub_stream_id == SUBSTREAM_CPL);
}

api_error_type tdh_ide_stream_idekmreq(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id_reg,
    ide_object_id_t object_id,
    ide_km_param_reg_t ide_km_param_reg,
    uint64_t slot_id,
    pa_t message_pa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    stream_info_t *stream_info_ptr = NULL;
    stream_info_t *stream_info_base_ptr = NULL;
    stream_exinfo_t *stream_exinfo_ptr = NULL;

    spdmdir_entry_t *spdmdir_entry_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;
    kcbar_t *kcbar_ptr = NULL;

    idekm_msg_t *message_ptr = NULL;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    // Only used in case of KEY_PROG
    key_slot_t substream_key = {0};
    bool_t is_substream_key_generated = false;

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
        TDX_ERROR("IDE-stream is not blocked\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_BLOCKED, OPERAND_ID_RDX);
        goto EXIT;
    }

    // stream_exinfo.outstanding_req_object_id must be IDE_OBJECT_INVALID, or else there are outstanding request pending response
    stream_exinfo_ptr = (stream_exinfo_t *)map_pa_with_global_hkid(
        stream_info_ptr->stream_exinfo_pa.raw_void,
        TDX_RANGE_RW);

    if (stream_exinfo_ptr->outstanding_req_object_id != IDE_OBJECT_INVALID)
    {
        TDX_ERROR("There are outstanding request pending response\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_IDEKM_OUTREQ, OPERAND_ID_RDX);
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

    // Verify OBJECT_ID value is valid
    if (!is_object_id_valid(object_id))
    {
        TDX_ERROR("Invalid object id (=%u)\n", object_id);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // If OBJECT_ID is K_SET_STOP, verify there are no active device interfaces bound to the stream
    if (object_id == IDE_OBJECT_ID_K_SET_STOP &&
        stream_exinfo_ptr->tdi_ref_cnt != 0)
    {
        TDX_ERROR("OBJECT_ID is K_SET_STOP, and there are active device interfaces bound to the stream\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_HAS_DEVICE_INTERFACES, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Verify IDE_KM_PARAM is valid
    if (!is_km_param_valid(ide_km_param_reg))
    {
        TDX_ERROR("Invalid ide_km_param (=0x%llx)\n", ide_km_param_reg.raw)
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }

    ide_km_param_t ide_km_param = ide_km_param_reg.ide_km_param;

    socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
    hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

    kcbar_ptr = map_kcbar(
        socket_io_info_ptr,
        hiop_info_ptr);
    // If OBJECT_ID is K_SET_GO, check that all keys for this key set and direction key set have been configured (and primed) in Key Config BAR
    if (object_id == IDE_OBJECT_ID_K_SET_GO)
    {
        uint64_t key_go = stream_exinfo_ptr->key_go[ide_km_param.direction][ide_km_param.key_set];
        if ((key_go & BIT(ide_km_param.sub_stream_id)) == 0)
        {
            TDX_ERROR("OBJECT_ID is K_SET_GO, and not all keys for this key set and direction key set have been configured in Key Config BAR\n");
            return_val = api_error_with_operand_id(TDX_IDE_STREAM_IDEKM_KEYS_NOT_READY, OPERAND_ID_RDX);
            goto EXIT;
        }

        if (ide_km_param.direction == DEV_TX)
        {
            stream_exinfo_ptr->primed_tx_key_counter++;
            tdx_sanity_check((stream_exinfo_ptr->primed_tx_key_counter <= MAX_TX_PRIMED_KEYS), FATAL_ERROR_ID_305, 1);
        }
    }

    // If OBJECT_ID is KEY_PROG, SLOT_ID must be valid index in KCBAR
    if (object_id == IDE_OBJECT_ID_KEY_PROG)
    {
        uint32_t num_of_key_slots = ide_km_param.direction == DEV_TX ? kcbar_ptr->capabilities.num_rx_key_slots : kcbar_ptr->capabilities.num_tx_key_slots;
        if (slot_id > num_of_key_slots)
        {
            TDX_ERROR("OBJECT_ID is KEY_PROG, and SLOT_ID (=0x%llx) is not a valid index in KCBAR\n", slot_id);
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
            goto EXIT;
        }
    }
    else if (slot_id) // Otherwise it must be 0
    {
        TDX_ERROR("OBJECT_ID is not KEY_PROG, and SLOT_ID (=0x%llx) is not zero\n", slot_id);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    // Verify MESSAGE_PA
    if (shared_hpa_check_with_pwr_2_alignment(message_pa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS)
    {
        TDX_ERROR("Invalid message PA (=0x%llx)\n", message_pa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R11);
        goto EXIT;
    }

    // Use PA own shared keyID
    message_ptr = map_pa(
        message_pa.raw_void,
        TDX_RANGE_RW);

    if (object_id == IDE_OBJECT_ID_KEY_PROG)
    {
        key_slot_t key_derivation_key = {0};

        if (!generate_256bit_random(&key_derivation_key))
        {
            return_val = TDX_RND_NO_ENTROPY;
            goto EXIT;
        }

        // replace the PRF to HMAC-SHA256
        ide_kdf_hmac_sha256(key_derivation_key.bytes, stream_id_reg.stream_id.raw, ide_km_param.raw, substream_key.bytes);

        // Scrub key_Derivation_key
        basic_memset_to_zero(key_derivation_key.bytes, sizeof(key_derivation_key));

        // Set flag to scrub the substream_key at the end of the flow
        is_substream_key_generated = true;

        // Enable SEAM SAI generation using the MSR_ENABLE_SEAM_SAI
        enable_seam_sai_generation();

        // Configure generated key in KCBAR
        cfg_rc_ide_keys(
            kcbar_ptr,
            stream_info_ptr->key_id,
            ide_km_param.direction,
            ide_km_param.key_set,
            ide_km_param.sub_stream_id,
            (uint8_t)slot_id,
            &substream_key);

        // Mark key is valid for the specified dierction, key set and substream
        stream_exinfo_ptr->key_valid[ide_km_param.direction][ide_km_param.key_set] |= (uint8_t)BIT(ide_km_param.sub_stream_id);

        // If all keys were programmed for this dierction and key set then trigger the root
        // port to prime the keys and make them valid and mark that we are ready to hand out GO message
        if (stream_exinfo_ptr->key_valid[ide_km_param.direction][ide_km_param.key_set] == ALL_IDE_KEYS_VALID_MASK)
        {
            prime_rc_ide_keys(
                kcbar_ptr,
                stream_info_ptr->key_id,
                ide_km_param.direction,
                ide_km_param.key_set);

            stream_exinfo_ptr->key_go[ide_km_param.direction][ide_km_param.key_set] = ALL_IDE_KEYS_VALID_MASK;
            stream_exinfo_ptr->key_valid[ide_km_param.direction][ide_km_param.key_set] = 0;
        }

        // Disable SEAM SAI generation using the MSR_ENABLE_SEAM_SAI
        disable_seam_sai_generation();
    }

    return_val = generate_ide_km_req_msg(
        stream_exinfo_ptr,
        stream_id_reg.stream_id,
        spdm_info_ptr,
        object_id,
        ide_km_param,
        &substream_key,
        message_ptr);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        TDX_ERROR("Failed to generate ide_km request message\n")
        goto EXIT;
    }

    // Update IDEKM state variables
    stream_exinfo_ptr->outstanding_req_object_id = object_id;
    stream_exinfo_ptr->outstanding_req_km_param.raw = ide_km_param.raw;

    return_val = TDX_SUCCESS;
EXIT:

    if (message_ptr != NULL)
    {
        free_la(message_ptr);
    }

    if(is_substream_key_generated)
    {
        basic_memset_to_zero(substream_key.bytes, sizeof(substream_key));
    }

    if (kcbar_ptr != NULL)
    {
        free_la(kcbar_ptr);
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
