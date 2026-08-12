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
 * @file tdisp.c
 * @brief
 */

#include "tdisp.h"
#include "devif.h"

bool_t is_valid_tdisp_header(
    const devifcs_t *const devifcs_ptr,
    const tdisp_header_t *const header)
{
    // TDISP header version check
    if (header->tdisp_version != devifcs_ptr->tdisp_version)
    {
        TDX_ERROR("Invalid TDISP header version\n");
        return false;
    }

    if (header->reserved != 0)
    {
        TDX_ERROR("Invalid TDISP reserved\n");
        return false;
    }

    // INTERFACE_ID in the TDISP header should match the DEVIFCS rid
    if (header->interface_id.function_id.rid.raw != devifcs_ptr->devif_id.function_id.rid.raw)
    {
        TDX_ERROR("Invalid TDISP header RID\n");
        return false;
    }
    return true;
}

bool_t is_valid_tdisp_req_msg_type(
    const tdisp_msg_type_t msg_type,
    const uint8_t td_flag)
{
    if (td_flag) // TD initiated request message
    {
        return msg_type == DEVICE_INTERFACE_REPORT_REQUEST ||
               msg_type == DEVICE_INTERFACE_STATE_REQUEST ||
               msg_type == START_INTERFACE_REQUEST;
    }
    else // VMM initiated request message
    {
        return msg_type == LOCK_INTERFACE_REQUEST ||
               msg_type == DEVICE_INTERFACE_STATE_REQUEST ||
               msg_type == STOP_INTERFACE_REQUEST;
    }
}

bool_t assign_tdisp_header(
    tdisp_msg_t *const tdisp_msg_ptr,
    const devif_req_in_t devif_req_in,
    const devif_verify_param_t *const devif_verify_param_ptr,
    uint16_t *const ret_payload_length_ptr)
{
    tdisp_header_t *const tdisp_header_ptr = &tdisp_msg_ptr->tdisp_payload.header;

    tdisp_header_ptr->msg_type = devif_req_in.req_code;
    tdisp_header_ptr->interface_id.function_id = devif_verify_param_ptr->devifcs_ptr->devif_id.function_id;
    tdisp_header_ptr->reserved = 0;
    tdisp_header_ptr->tdisp_version = devif_verify_param_ptr->devifcs_ptr->tdisp_version;

    // Build TDISP 1.0 payload for the given request code
    switch (devif_req_in.req_code)
    {
    case LOCK_INTERFACE_REQUEST:
    {
        tdisp_lock_interface_request_t *lock_req_ptr = (tdisp_lock_interface_request_t *)tdisp_header_ptr;

        lock_req_ptr->flags = devif_req_in.no_fw_update;
        lock_req_ptr->stream_id = devif_verify_param_ptr->devifcs_ptr->devif_id.stream_id;
        lock_req_ptr->mmio_reporting_offset = devif_verify_param_ptr->devifcs_ptr->mmio_reporting_offset;
        lock_req_ptr->bind_p2p_address_mask = 0;
        lock_req_ptr->reserved = 0;
        *ret_payload_length_ptr = sizeof(tdisp_lock_interface_request_t);
        break;
    }
    case DEVICE_INTERFACE_STATE_REQUEST:
    case STOP_INTERFACE_REQUEST:
    {
        // Nothing to build except the header
        *ret_payload_length_ptr = sizeof(tdisp_header_t);
        break;
    }
    case START_INTERFACE_REQUEST:
    {
        tdisp_start_interface_request_t *start_req_ptr = (tdisp_start_interface_request_t *)tdisp_header_ptr;
        tdx_memcpy(
            start_req_ptr->start_interface_nonce,
            sizeof(start_req_ptr->start_interface_nonce),
            devif_verify_param_ptr->devifcs_ptr->start_interface_nonce,
            sizeof(devif_verify_param_ptr->devifcs_ptr->start_interface_nonce));
        *ret_payload_length_ptr = sizeof(tdisp_start_interface_request_t);
        break;
    }
    case DEVICE_INTERFACE_REPORT_REQUEST:
    {
        tdisp_device_interface_report_request_t *report_req_ptr = (tdisp_device_interface_report_request_t *)tdisp_header_ptr;

        // There is no more report portion to read. Return error
        if (devif_verify_param_ptr->devifcs_ptr->dev_report_len == 0)
        {
            return false;
        }
        report_req_ptr->length = devif_verify_param_ptr->devifcs_ptr->dev_report_len;
        report_req_ptr->offset = devif_verify_param_ptr->devifcs_ptr->dev_report_offset;
        *ret_payload_length_ptr = sizeof(tdisp_device_interface_report_request_t);
        break;
    }
    default:
    {
        fatal_error(FATAL_ERROR_ID_91, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
    }

    return true;
}

/**
 * @brief Check the device report interface_info flags are supported by TDX Connect.
 *
 * @note Future: Compare with TDX_CONNECT_FEATURES bitmask to make the checks generic
 *
 * @param interface_info
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t check_report_interface_info(const device_report_interface_info_t interface_info)
{
    return interface_info.wo_pasid == 1 && // TDX Connect supports DMA requests without PASID
           interface_info.w_pasid == 0 &&  // TDX Connect doesn't supports DMA requests with PASID
           interface_info.ats == 0 &&      // TDX Connect doesn't support ATS and ATS is not enabled
           interface_info.prs == 0;        // TDX Connect doesn't support PRS
}

/**
 * @brief Check the device report controls
 *
 * @param rep1_ptr
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t check_report_control(const tdisp_device_interface_1st_report_layout_t *const rep1_ptr)
{
    return rep1_ptr->msi_x_message_control == 0 && // TDX Module prevented it on LOCK_INTERFACE
           rep1_ptr->lnr_control == 0 &&           // Not supported on GNR
           rep1_ptr->tph_control == 0;             // TDX Module prevented it on LOCK_INTERFACE
}

api_error_type tdisp_process_response(
    const tdisp_header_t *const response_header_ptr,
    devif_rsp_out_t *const devif_rsp_out_ptr,
    devif_verify_param_t *const devif_verify_param_ptr)
{
    switch (response_header_ptr->msg_type)
    {
    case TDISP_ERROR:
        devif_rsp_out_ptr->rsp_error.tdisp_error_code = ((tdisp_error_response_t *)response_header_ptr)->error_code;
        break;

    case START_INTERFACE_RESPONSE:
        // Update the actual TDISP state
        devif_verify_param_ptr->devifcs_ptr->tdisp_sts = TDISP_STATE_RUN;
        break;

    case STOP_INTERFACE_RESPONSE:
        // We only update the actual TDISP state here
        devif_verify_param_ptr->devifcs_ptr->tdisp_sts = TDISP_STATE_CONFIG_UNLOCKED;
        devif_verify_param_ptr->devifcs_ptr->valid = 0;
        // Wipe the start nonce according to TDISP requirement
        basic_memset_to_zero(
            devif_verify_param_ptr->devifcs_ptr->start_interface_nonce,
            sizeof(devif_verify_param_ptr->devifcs_ptr->start_interface_nonce));
        break;

    case LOCK_INTERFACE_RESPONSE:
        tdx_memcpy(
            devif_verify_param_ptr->devifcs_ptr->start_interface_nonce,
            sizeof(devif_verify_param_ptr->devifcs_ptr->start_interface_nonce),
            ((tdisp_lock_interface_response_t *)response_header_ptr)->start_interface_nonce,
            sizeof(((tdisp_lock_interface_response_t *)response_header_ptr)->start_interface_nonce));

        // Update the actual TDISP state
        devif_verify_param_ptr->devifcs_ptr->tdisp_sts = TDISP_STATE_CONFIG_LOCKED;
        // Reset the device report tracking variables
        devif_verify_param_ptr->devifcs_ptr->dev_report_offset = 0;
        devif_verify_param_ptr->devifcs_ptr->dev_report_len = TDISP_PAYLOAD_MAX_SIZE;
        break;

    case DEVICE_INTERFACE_STATE_RESPONSE:
        devif_verify_param_ptr->devifcs_ptr->tdisp_sts = ((tdisp_device_interface_state_response_t *)response_header_ptr)->tdi_state;
        if (devif_verify_param_ptr->devifcs_ptr->tdisp_sts == TDISP_STATE_ERROR)
        {
            // DEVIFCS is no longer valid
            devif_verify_param_ptr->devifcs_ptr->valid = 0;
            // Wipe the start nonce according to TDISP requirement
            basic_memset_to_zero(
                devif_verify_param_ptr->devifcs_ptr->start_interface_nonce,
                sizeof(devif_verify_param_ptr->devifcs_ptr->start_interface_nonce));
        }
        devif_rsp_out_ptr->rsp_state.tdi_state = devif_verify_param_ptr->devifcs_ptr->tdisp_sts;
        break;

    case DEVICE_INTERFACE_REPORT_RESPONSE:
    {
        tdisp_device_interface_report_response_t *const report_response_ptr = (tdisp_device_interface_report_response_t *)response_header_ptr;

        if (devif_verify_param_ptr->devifcs_ptr->dev_report_offset == 0)
        {
            // 1st page of the report offset (with INTERFACE_INFO flags and control registers)
            if (report_response_ptr->portion_length < sizeof(tdisp_device_interface_1st_report_layout_t))
            {
                return TDX_DEVIF_TDISP_INVALID_MESSAGE;
            }

            // rep1_ptr starts directly after report_response_ptr
            tdisp_device_interface_1st_report_layout_t *rep1_ptr = (tdisp_device_interface_1st_report_layout_t *)(report_response_ptr + 1);

            // Enforce the report checks
            // Check interface info flags
            if (!check_report_interface_info(rep1_ptr->interface_info) ||
                !check_report_control(rep1_ptr))
            {
                // Render the DEVIFCS invalid
                devif_verify_param_ptr->devifcs_ptr->valid = 0;
                return TDX_DEVIF_INVALID_TDI_CONFIGURATION;
            }
        }

        // Update the device report offset/length tracking vars
        // TBD: should we reset the vars offset and len to allow more than one cycle of the report reading?
        devif_verify_param_ptr->devifcs_ptr->dev_report_offset += report_response_ptr->portion_length; // Next portion offset
        if (report_response_ptr->remainder_length < devif_verify_param_ptr->devifcs_ptr->dev_report_len)
        {
            devif_verify_param_ptr->devifcs_ptr->dev_report_len = report_response_ptr->remainder_length; // Next portion length
        }

        // Set the output portion/remainder values
        devif_rsp_out_ptr->rsp_report.portion_len = report_response_ptr->portion_length;
        devif_rsp_out_ptr->rsp_report.remainder_len = report_response_ptr->remainder_length;
        break;
    }
    default:
        return TDX_DEVIF_TDISP_INVALID_MESSAGE;
    }
    return TDX_SUCCESS;
}
