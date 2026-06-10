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
 * @file tdh_devif_mt_add.c
 * @brief TDHDEVIFMTADD API handler
 */

#include "tdxio/devifmt.h"
#include "tdxio/tdxio_vmm_api_handlers.h"

api_error_type tdh_devif_mt_add(
    devifmt_idx_t devifmt_idx,
    pa_t devifmt_pa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    // PAMT related variables
    void *devifmt_entry_ptr = NULL;
    pamt_walk_result_t devif_pamt_walk_result;
    bool_t is_devifmt_pamt_locked = false;

    // devifmt_walk parameters
    devifmt_walk_res_t devifmt_walk_result = {0};
    bool_t is_devifmt_walked = false;
    devifmt_entry_t *devifmt_parent_ptr = NULL;

    // check devifmt_idx parameter
    if (!is_valid_devifmt_idx(devifmt_idx, false))
    {
        TDX_ERROR("Invalid DEVIFMT index (0x%llx)\n", devifmt_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check and lock DEVIFMT_PA in PAMT
    return_val = check_and_lock_explicit_4k_private_hpa(
        devifmt_pa,
        OPERAND_ID_RDX,
        TDX_LOCK_EXCLUSIVE,
        PT_NDA,
        &devif_pamt_walk_result,
        &is_devifmt_pamt_locked);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock DEVIFMT pamt\n");
        goto EXIT;
    }

    return_val = devifmt_walk(devifmt_idx, true, DEVIFMT_HP_LOCK_MODE, false, &is_devifmt_walked, &devifmt_walk_result);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Get the parent level entry, and make it point to the new page
    devifmt_parent_ptr = devifmt_walk_result.devifmt_path_arr[devifmt_idx.level];

    // check that the present bit is zero
    if (devifmt_parent_ptr->p != 0)
    {
        TDX_ERROR("DEVIFMT entry is present\n");
        return_val = api_error_with_operand_id(TDX_DEVIFMT_ALREADY_PRESENT, OPERAND_ID_RCX);
        goto EXIT;
    }

    devifmt_parent_ptr->p = 1;
    devifmt_parent_ptr->pa = devifmt_pa.page_4k_num;

    // Initialize the new DEVIFMT page to zero
    devifmt_entry_ptr = map_pa_with_global_hkid(
        devifmt_pa.raw_void,
        TDX_RANGE_RW);

    zero_area_cacheline(devifmt_entry_ptr, TDX_PAGE_SIZE_IN_BYTES);

    // Update the new MMIOMT page PAMT entry
    devif_pamt_walk_result.pamt_entry_p->pt = PT_DEVIF_MT;

EXIT:
    if (devifmt_entry_ptr != NULL)
    {
        free_la(devifmt_entry_ptr);
    }

    if (is_devifmt_walked)
    {
        devifmt_unwalk(&devifmt_walk_result);
    }

    if (is_devifmt_pamt_locked)
    {
        pamt_unwalk(&devif_pamt_walk_result);
    }
    return return_val;
}
