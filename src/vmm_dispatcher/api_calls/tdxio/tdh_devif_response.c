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
 * @file tdh_devif_response.c
 * @brief TDHDEVIFRESPONSE API handler
 */

#include "tdxio/aead.h"
#include "tdxio/spdm.h"
#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/devif.h"
#include "tdxio/tdisp.h"
#include "tdxio/iommu.h"
#include "tdxio/devifmt.h"

api_error_type tdh_devif_response(
    function_id_reg_t function_id_reg,
    devif_rsp_in_t devif_rsp_in,
    pa_t vmm_msg_buff_output_pa,
    uint64_t unused_r9)
{
    // DEVIFCS related variables
    devif_verify_param_t devif_verify_param = {0};
    devif_rsp_out_t devif_rsp_out = {0};

    // TDISP related variables
    spdmdir_entry_t *spdmdir_entry_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;
    tdisp_msg_t *tdisp_msg_ptr = NULL;
    void *msg_in_ptr = NULL;
    bool_t is_message_decrypted = false;

    if (devif_rsp_in.reserved1 != 0 ||
        devif_rsp_in.reserved2 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (unused_r9 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }

    pa_t res_pa = {.raw = 0};
    res_pa.page_4k_num = devif_rsp_in.pa;
    if (shared_hpa_check_with_pwr_2_alignment(res_pa, _4KB) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Lock, map and check devifcs
    return_val = tdh_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_RCX,
        &devif_verify_param);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify there is an outstanding message request
    if (!devif_verify_param.devifcs_ptr->out_tdisp_req)
    {
        TDX_ERROR("No outstanding message request\n");
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_OUT_REQ, OPERAND_ID_RCX);
        goto EXIT;
    }

    // 1st quick td_flag validity check. If td_tdisp_req_sts indicates the TD request was generated (meaning VMM sent last the TD reguest),
    // the td_flag is expected from VMM. We'll do more td_flag validity after decrypting the message
    bool_t td_flag_expected = devif_verify_param.devifcs_ptr->td_tdisp_req_sts == TDISP_REQ_GENERATED;
    if (td_flag_expected &&
        devif_rsp_in.td_flag == 0)
    {
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_REQ_STS, OPERAND_ID_RDX);
        goto EXIT;
    }

    pa_t dest_response_pa = {.raw = 0};
    if (devif_rsp_in.td_flag)
    {
        // For TD response the ouput PA must be zero
        if (vmm_msg_buff_output_pa.raw != NULL_PA)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }

        dest_response_pa = devif_verify_param.devifcs_ptr->td_tdisp_msg_buff_pa;
    }
    else
    {
        // For a VMM reponse the output PA must be valid (if provided)
        if (vmm_msg_buff_output_pa.raw != NULL_PA &&
            shared_hpa_check_with_pwr_2_alignment(vmm_msg_buff_output_pa, _4KB) != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }
        dest_response_pa = devif_verify_param.devifcs_ptr->vmm_tdisp_msg_buff_pa;
    }

    // implicitly get the IOMMU config
    iommu_config_t *iommu_config_ptr = &get_global_data()->iommu_configs[devif_verify_param.devifcs_ptr->devif_id.iommu_id.raw];
    return_val = lock_check_and_map_spdm_metadata(
        devif_verify_param.devifcs_ptr->spdm_id,
        OPERAND_ID_RCX,
        iommu_config_ptr,
        SPDM_STATE_BOUND,
        &spdm_info_ptr,
        &spdmdir_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Copy the message to the appropriate VMM/TD buffer
    msg_in_ptr = map_pa(res_pa.raw_void, TDX_RANGE_RO);

    // ***TODO:*** Check the DOE header and all available plain (unencrypted) data before the decrypt

    // Map destination message buffer
    tdisp_msg_ptr = map_pa_with_global_hkid(dest_response_pa.raw_void, TDX_RANGE_RW);
    uint64_t source_msg_len = ((doe_header_t *)msg_in_ptr)->doe_length.length * DOE_LENGTH_GRANULARITY;


    return_val = tdx_io_aead_decrypt(
        spdm_info_ptr,
        msg_in_ptr,
        source_msg_len,
        (void *)tdisp_msg_ptr,
        DOE_MSG_BUFF_SIZE);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }
    is_message_decrypted = true;


#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    const uint32_t *const msg_in_dwords = (uint32_t *)tdisp_msg_ptr;
    uint32_t msg_length = tdisp_msg_ptr->spdm_doe_headers.doe_header.doe_length.length;
    TDX_LOG("Printing decrypted DEVIF response message:\n");

    for (uint32_t idx = 0; idx < msg_length; idx++)
    {
        TDX_LOG("0x%lx\n", msg_in_dwords[idx]);
    }
#endif // DEBUGFEATURE_TDX_DBG_TRACE

    // Verify Headers
    bool_t bool_ret = verify_tdisp_message_content(
        tdisp_msg_ptr,
        spdm_info_ptr);
    if (!bool_ret)
    {
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_MESSAGE, OPERAND_ID_RDX);
        goto EXIT;
    }

    uint16_t payload_length = tdisp_msg_ptr->spdm_doe_headers.spdm_vendor_defined_msg_header.payload_len - TDISP_PROTOCOL_ID_SIZE;
    // Check the TDISP message length validity
    if (payload_length < TDISP_PAYLOAD_MIN_SIZE ||
        payload_length > TDISP_PAYLOAD_MAX_SIZE)
    {
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_MESSAGE, OPERAND_ID_RDX);
        goto EXIT;
    }

    tdisp_header_t *response_header_ptr = &tdisp_msg_ptr->tdisp_payload.header;
    const tdisp_msg_type_t tdisp_msg_type = response_header_ptr->msg_type;

    // At this point we have TDISP message decrypted and valid (protocol-wise).
    // For the VMM response (td_flag == 0) we continue with the checks and processing.
    // For the TD response (td_flag == 1) all further checks and  message processing will
    // be done in TDG.DEVIF.RESPONSE
    if (devif_rsp_in.td_flag)
    {
        // For the TD response, set the TD response state and save the response length
        devif_verify_param.devifcs_ptr->td_tdisp_req_sts = TDISP_REQ_PROCESSED;
        devif_verify_param.devifcs_ptr->td_tdisp_payload_length = payload_length;
    }
    else
    {
        // For VMM response
        // Check the TDISP header (version and rid)
        if (!is_valid_tdisp_header(devif_verify_param.devifcs_ptr, response_header_ptr))
        {
            return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_MESSAGE, OPERAND_ID_RDX);
            goto EXIT;
        }

        // Check that VMM isn't asking for a TD-only response (by not setting TD flag)
        if (tdisp_msg_type == DEVICE_INTERFACE_REPORT_RESPONSE ||
            tdisp_msg_type == START_INTERFACE_RESPONSE) // VMM didn't set TD flag for TD-only request
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            goto EXIT;
        }

        // Process response to TD TDISP request
        return_val = tdisp_process_response(
            response_header_ptr,
            &devif_rsp_out,
            &devif_verify_param);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
            goto EXIT;
        }

        // Copy the response to the caller if requested
        if (vmm_msg_buff_output_pa.raw != NULL_PA)
        {
            void *out_ptr = map_pa(vmm_msg_buff_output_pa.raw_void, TDX_RANGE_RW);
            tdx_memcpy(
                out_ptr, TDX_PAGE_SIZE_IN_BYTES,
                response_header_ptr, payload_length);

            devif_rsp_out.output_len = payload_length;
            free_la(out_ptr);
        }
    }
    // Clear outstanding request flag and set return values
    devif_verify_param.devifcs_ptr->out_tdisp_req = false;
    devif_rsp_out.resp_code = tdisp_msg_type;
    get_local_data()->vmm_regs.rcx = devif_rsp_out.raw;

    return_val = TDX_SUCCESS;

EXIT:
    // Wipe the decyrpted buffer in case it's a host message
    // Guest messages are handled in TDG.DEVIF.RESPOSE
    if (is_message_decrypted &&
        (return_val != TDX_SUCCESS || !devif_rsp_in.td_flag))
    {
        basic_memset_to_zero(
            (void *)tdisp_msg_ptr,
            source_msg_len);
    }

    if (tdisp_msg_ptr != NULL)
    {
        free_la(tdisp_msg_ptr);
    }

    if (msg_in_ptr != NULL)
    {
        free_la(msg_in_ptr);
    }

    if (spdm_info_ptr != NULL)
    {
        free_la(spdm_info_ptr);
    }

    if (spdmdir_entry_ptr != NULL)
    {
        unlock_spdmdir_entry(spdmdir_entry_ptr, devif_verify_param.devifcs_ptr->spdm_id);
        free_la(spdmdir_entry_ptr);
    }

    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
