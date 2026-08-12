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
 * @file tdh_mmio_mt_rd.c
 * @brief TDHMMIOMTRD API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/mmiomt.h"

api_error_type tdh_mmio_mt_rd(mmiomt_idx_t mmiomt_idx)
{
    // mmiomt_walk variables
    mmiomt_walk_res_t mmiomt_walk_res = {0};
    bool_t is_mmiomt_walked = false;
    mmiomt_entry_t *mmiomt_entry_ptr = NULL;
    tdx_module_local_t *local_data_ptr = get_local_data();

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Verify MMIOMT_IDX
    if (!is_valid_mmiomt_idx(mmiomt_idx, MMIOMT_L0))
    {
        TDX_ERROR("Invalid mmiomt_idx =0x%llx\n", mmiomt_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    return_val = mmiomt_walk(
        mmiomt_idx,
        false,
        TDX_RANGE_RO,
        &is_mmiomt_walked,
        &mmiomt_walk_res);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("MMIOMT walk failed\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    mmiomt_entry_ptr = mmiomt_walk_res.mmiomt_path_arr[mmiomt_idx.level];

    // Write MMIOMT entry in output registers
    local_data_ptr->vmm_regs.rcx = mmiomt_entry_ptr->raw.qwords[0];
    local_data_ptr->vmm_regs.rdx = mmiomt_entry_ptr->raw.qwords[1];
    local_data_ptr->vmm_regs.r8 = mmiomt_entry_ptr->raw.qwords[2];
    local_data_ptr->vmm_regs.r9 = mmiomt_entry_ptr->raw.qwords[3];

    return_val = TDX_SUCCESS;
EXIT:
    if (is_mmiomt_walked)
    {
        mmiomt_unwalk(&mmiomt_walk_res);
    }

    return return_val;
}
