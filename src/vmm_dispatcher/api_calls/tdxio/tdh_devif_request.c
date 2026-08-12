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
 * @file tdh_devif_request.c
 * @brief TDHDEVIFREQUEST API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/devif.h"
#include "tdxio/devifmt.h"

_STATIC_INLINE_ bool_t is_valid_tdh_devif_req_in(const devif_req_in_t devif_req_in)
{
    return (devif_req_in.reserved == 0 &&
            (devif_req_in.td_flag != 1 || devif_req_in.req_code == 0) &&
            // no_fw_update is valid only for the LOCK_INTERFACE_REQUEST
            (devif_req_in.req_code == LOCK_INTERFACE_REQUEST || devif_req_in.no_fw_update != 1));
}

api_error_type tdh_devif_request(
    function_id_reg_t function_id_reg,
    devif_req_in_t devif_req_in,
    pa_t tdisp_req_out_pa,
    uint64_t unused_r9)
{
    // DEVIFCS related variables
    devif_verify_param_t devif_verify_param = {0};

    tdisp_msg_t *doe_spdm_buff_ptr = NULL;
    uint16_t tdisp_payload_length = 0;

    devif_req_out_t devif_req_out = {.raw = 0};
    api_error_type return_val = UNINITIALIZE_ERROR;


    if (!is_valid_tdh_devif_req_in(devif_req_in))
    {
        TDX_ERROR("There is an outstanding TDISP request awaiting a repsonse\n")
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (unused_r9 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
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

    // Check if we are in TDISP error state,
    // where only GET_DEVICE_INTERFACE_STATE and STOP_INTERFACE_REQUEST are allowed
    if (devif_verify_param.devifcs_ptr->tdisp_sts == TDISP_STATE_ERROR)
    {
        if (!(devif_req_in.req_code == DEVICE_INTERFACE_STATE_REQUEST ||
              devif_req_in.req_code == STOP_INTERFACE_REQUEST))
        {
            TDX_ERROR("TDISP in error state. Only DEVICE_INTERFACE_STATE_REQUEST and \
                        STOP_INTERFACE_REQUEST are allowd (request code = %u)\n",
                      devif_req_in.req_code);
            return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_ERROR_STATE, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // There must be no outstanding TDISP request awaiting a repsonse
    if (devif_verify_param.devifcs_ptr->out_tdisp_req)
    {
        TDX_ERROR("There is an outstanding TDISP request awaiting a repsonse\n")
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_OUT_REQ, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify request states
    if (devif_req_in.td_flag) // a TD-generated request
    {
        // A TD generated request must be requested by TDG.DEVIF.REQUEST (td_tdisp_req_sts is REQUESTE
        if (devif_verify_param.devifcs_ptr->td_tdisp_req_sts != TDISP_REQ_REQUESTED)
        {
            TDX_ERROR("TD-generated request - TD tdisp request status is not TDISP_REQ_REQUESTED\n");
            return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_REQ_STS, OPERAND_ID_RCX);
            goto EXIT;
        }

        doe_spdm_buff_ptr = map_pa_with_global_hkid(devif_verify_param.devifcs_ptr->td_tdisp_msg_buff_pa.raw_void, TDX_RANGE_RW);
        tdisp_payload_length = devif_verify_param.devifcs_ptr->td_tdisp_payload_length;
    }
    else // a VMM-generated request
    {
        // Check the VMM is a valid initiator for the message
        if (!is_valid_tdisp_req_msg_type(devif_req_in.req_code, devif_req_in.td_flag))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            goto EXIT;
        }

        doe_spdm_buff_ptr = map_pa_with_global_hkid(devif_verify_param.devifcs_ptr->vmm_tdisp_msg_buff_pa.raw_void, TDX_RANGE_RW);

        // Build TDISP 1.0 header for the given request code
        (void)assign_tdisp_header(doe_spdm_buff_ptr, devif_req_in, &devif_verify_param, &tdisp_payload_length);
    }

    devif_req_out.message_code = doe_spdm_buff_ptr->tdisp_payload.header.msg_type;

    // Verify tdisp_req_out_pa is 4KB aligned && TDX reserved HKID bits are not set
    if (shared_hpa_check_with_pwr_2_alignment(tdisp_req_out_pa, _4KB) != TDX_SUCCESS)
    {
        TDX_ERROR("Target page address (=0x%llx) is not 4KB aligned && TDX reserved HKID bits are set\n", tdisp_req_out_pa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Generate and output TDISP request message
    return_val = generate_tdisp_req_msg(
        devif_verify_param.devifcs_ptr,
        doe_spdm_buff_ptr,
        tdisp_payload_length,
        OPERAND_ID_RCX,
        tdisp_req_out_pa);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Update DEVIFCS TDISP request state
    devif_verify_param.devifcs_ptr->out_tdisp_req = true;

    if (devif_req_in.td_flag)
    {
        devif_verify_param.devifcs_ptr->td_tdisp_req_sts = TDISP_REQ_GENERATED;
        devif_verify_param.devifcs_ptr->td_tdisp_payload_length = 0;
    }

    devif_req_out.target_length = (uint16_t)doe_spdm_buff_ptr->spdm_doe_headers.doe_header.doe_length.length * DOE_LENGTH_GRANULARITY;

    get_local_data()->vmm_regs.rcx = devif_req_out.raw;

    return_val = TDX_SUCCESS;

EXIT:

    if (doe_spdm_buff_ptr != NULL)
    {
        free_la(doe_spdm_buff_ptr);
    }

    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
