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
 * @file tdh_devif_mt_rd.c
 * @brief TDHDEVIFMTRD API handler
 */

#include "tdxio/devifmt.h"
#include "tdxio/tdxio_vmm_api_handlers.h"

api_error_type tdh_devif_mt_rd(devifmt_idx_t devifmt_idx)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    devifmt_walk_res_t devifmt_walk_result = {0};
    bool_t is_devifmt_walked = false;

    if (!is_valid_devifmt_idx(devifmt_idx, true))
    {
        TDX_ERROR("Invalid DEVIFMT index (0x%llx)\n", devifmt_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // walk to parent level
    return_val = devifmt_walk(devifmt_idx, false, DEVIFMT_HP_LOCK_MODE, false, &is_devifmt_walked, &devifmt_walk_result);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    tdx_module_local_t *local_data_ptr = get_local_data();
    local_data_ptr->vmm_regs.rcx = devifmt_walk_result.devifmt_path_arr[devifmt_idx.level]->raw;

EXIT:
    if (is_devifmt_walked)
    {
        devifmt_unwalk(&devifmt_walk_result);
    }

    return return_val;
}