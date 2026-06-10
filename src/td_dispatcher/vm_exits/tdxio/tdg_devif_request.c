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
 * @file tdg_devif_request.c
 * @brief TDGDEVIFREQUEST API handler
 */

#include "tdxio/tdxio_td_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/devif.h"
#include "tdxio/tdisp.h"
#include "tdxio/devifmt.h"

api_error_type tdg_devif_request(
    function_id_reg_t function_id_reg,
    devif_req_in_t devif_req_in,
    uint64_t unused_r9)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    devif_verify_param_t devif_verify_param = {0};
    tdisp_msg_t *dest_tdisp_msg_ptr = NULL;

    if (devif_req_in.reserved != 0 ||
        devif_req_in.td_flag == 1 ||
        devif_req_in.no_fw_update == 1) // for a TD request only the message code is expected in tdisp_req_in
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (unused_r9 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }

    // Check a TD is a valid initiator for the message
    if (!is_valid_tdisp_req_msg_type(devif_req_in.req_code, true))
    {
        TDX_ERROR("Invalid REQ CODE\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Lock, map and check devifcs
    return_val = tdg_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_RCX,
        true,
        &devif_verify_param,
        NULL);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Check if we aren't in a TDISP error state, where only GET_DEVICE_INTERFACE_STATE is allowed for TD
    if (devif_verify_param.devifcs_ptr->tdisp_sts == TDISP_STATE_ERROR &&
        devif_req_in.req_code != DEVICE_INTERFACE_STATE_REQUEST)
    {
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_ERROR_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify the TD request state is avaliable
    if (devif_verify_param.devifcs_ptr->td_tdisp_req_sts != TDISP_REQ_AVAILABLE)
    {
        TDX_ERROR("TDISP request status is not TDISP_REQ_AVAILABLE\n");
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_REQ_STS, OPERAND_ID_RCX);
        goto EXIT;
    }

    dest_tdisp_msg_ptr = map_pa_with_global_hkid(devif_verify_param.devifcs_ptr->td_tdisp_msg_buff_pa.raw_void, TDX_RANGE_RW);

    uint16_t tdisp_payload_length = 0;
    if (!assign_tdisp_header(
            dest_tdisp_msg_ptr,
            devif_req_in,
            &devif_verify_param,
            &tdisp_payload_length))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Record request in DEVIFCS
    devif_verify_param.devifcs_ptr->td_tdisp_payload_length = tdisp_payload_length;
    devif_verify_param.devifcs_ptr->td_tdisp_req_sts = TDISP_REQ_REQUESTED;
    return_val = TDX_SUCCESS;

EXIT:
    if (dest_tdisp_msg_ptr != NULL)
    {
        free_la(dest_tdisp_msg_ptr);
    }

    // Release all acquired locks and free keyhole mappings
    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
