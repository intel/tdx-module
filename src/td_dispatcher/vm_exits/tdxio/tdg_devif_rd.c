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
 * @file tdg_devif_rd.c
 * @brief TDGDEVIFRD API handler
 */

#include "tdxio/tdxio_td_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/iommu_common.h"
#include "tdxio/devif.h"
#include "tdxio/devifmt.h"

api_error_type tdg_devif_rd(
    function_id_reg_t function_id_reg,
    devif_rd_input_t devif_rd_input,
    uint64_t unused_r9)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    devif_verify_param_t devif_verify_param = {0};
    tdx_module_local_t *local_data = get_local_data();

    if (unused_r9 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }

    if (devif_rd_input.reserved != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (!is_valid_field_code(devif_rd_input.devif_field_code))
    {
        TDX_ERROR("Invalid field code = %u\n", devif_rd_input.devif_field_code);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Lock, map and check devifcs
    return_val = tdg_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RO,
        OPERAND_ID_RCX,
        true,
        &devif_verify_param,
        local_data);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    uint64_t result = 0;
    switch (devif_rd_input.devif_field_code)
    {
    case TDISP_VER_FIELD_CODE:
        result = devif_verify_param.devifcs_ptr->tdisp_version;
        break;
    default:
        fatal_error(FATAL_ERROR_ID_102, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        goto EXIT;
    }

    local_data->vp_ctx.tdvps->guest_state.gpr_state.rcx = result;
    return_val = TDX_SUCCESS;
EXIT:

    // Release all acquired locks and free keyhole mappings
    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
