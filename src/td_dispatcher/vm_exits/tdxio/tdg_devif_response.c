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
 * @file tdg_devif_response.c
 * @brief TDGDEVIFREQUEST API handler
 */

#include "tdxio/tdxio_td_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/devif.h"
#include "tdxio/tdisp.h"
#include "tdxio/devifmt.h"

api_error_type tdg_devif_response(
    function_id_reg_t function_id_reg,
    pa_t target_gpa,
    uint64_t unused_r9)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    devif_verify_param_t devif_verify_param = {0};
    tdx_module_local_t *local_data = get_local_data();

    devif_rsp_out_t devif_rsp_out = {0};

    tdisp_msg_t *tdisp_msg_ptr = NULL;
    void *dest_page_ptr = NULL;

    if (unused_r9 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }

    // Verify the target GPA
    if (target_gpa.raw != NULL_PA)
    {
        if (!is_addr_aligned_any(target_gpa.raw, TDX_PAGE_SIZE_IN_BYTES))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            goto EXIT;
        }

        return_val = check_walk_and_map_guest_side_gpa(
            local_data->vp_ctx.tdcs,
            local_data->vp_ctx.tdvps,
            target_gpa,
            local_data->vp_ctx.tdr->key_management_fields.hkid,
            TDX_RANGE_RW,
            true,
            &dest_page_ptr);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to walk and map destination page (destination pa = 0x%llx)\n", target_gpa.raw);
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
            goto EXIT;
        }
    }

    // Lock, map and check devifcs
    return_val = tdg_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_RCX,
        true,
        &devif_verify_param,
        local_data);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify the response for the TD was processed
    if (devif_verify_param.devifcs_ptr->td_tdisp_req_sts != TDISP_REQ_PROCESSED)
    {
        TDX_ERROR("TD TDISP request status (=%u) is not TDISP_REQ_PROCESSED\n",
                  devif_verify_param.devifcs_ptr->td_tdisp_req_sts);
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_REQ_STS, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Map the TD message buffer PA using TDX global HKID
    tdisp_msg_ptr = (tdisp_msg_t *)map_pa_with_global_hkid(
        devif_verify_param.devifcs_ptr->td_tdisp_msg_buff_pa.raw_void,
        TDX_RANGE_RW);

    // Check message is valid
    if (!is_valid_tdisp_header(devif_verify_param.devifcs_ptr, &tdisp_msg_ptr->tdisp_payload.header))
    {
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_MESSAGE, OPERAND_ID_RCX);
        goto EXIT;
    }

    tdisp_header_t *response_header_ptr = &tdisp_msg_ptr->tdisp_payload.header;
    const tdisp_msg_type_t tdisp_msg_type = response_header_ptr->msg_type;

    // Check that the response doesn't belong to VMM-only response
    if (tdisp_msg_type == LOCK_INTERFACE_RESPONSE ||
        tdisp_msg_type == STOP_INTERFACE_RESPONSE) // VMM has set td_flag for VMM-only response
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Process response to TD TDISP request
    return_val = tdisp_process_response(
        response_header_ptr,
        &devif_rsp_out,
        &devif_verify_param);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Copy the response to the caller if requested
    // Map the destination page and copy the response payload
    if (target_gpa.raw != NULL_PA)
    {
        tdx_memcpy(
            dest_page_ptr,
            TDISP_PAYLOAD_MAX_SIZE,
            &tdisp_msg_ptr->tdisp_payload,
            devif_verify_param.devifcs_ptr->td_tdisp_payload_length);
        devif_rsp_out.output_len = devif_verify_param.devifcs_ptr->td_tdisp_payload_length;
    }

    uint32_t tdisp_msg_length = tdisp_msg_ptr->spdm_doe_headers.doe_header.doe_length.length * DOE_LENGTH_GRANULARITY;
    // Wipe the decyrpted buffer
    basic_memset_to_zero(
        tdisp_msg_ptr,
        tdisp_msg_length);

    devif_verify_param.devifcs_ptr->td_tdisp_req_sts = TDISP_REQ_AVAILABLE;
    devif_rsp_out.resp_code = tdisp_msg_type;
    local_data->vp_ctx.tdvps->guest_state.gpr_state.rcx = devif_rsp_out.raw;

    return_val = TDX_SUCCESS;

EXIT:
    if (tdisp_msg_ptr != NULL)
    {
        free_la(tdisp_msg_ptr);
    }
    if (dest_page_ptr != NULL)
    {
        free_la(dest_page_ptr);
    }

    // Release all acquired locks and free keyhole mappings
    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
