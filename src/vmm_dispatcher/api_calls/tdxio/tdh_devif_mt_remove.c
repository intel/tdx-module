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
 * @file tdh_devif_mt_remove.c
 * @brief TDHDEVIFMTREMOVE API handler
 */

#include "tdxio/devifmt.h"
#include "tdxio/tdxio_vmm_api_handlers.h"

api_error_type tdh_devif_mt_remove(devifmt_idx_t devifmt_idx)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    devifmt_walk_res_t devifmt_walk_result = {0};
    bool_t is_devifmt_walked = false;

    // PAMT related variables
    devifmt_entry_t *devifmt_parent_ptr = NULL;
    devifmt_entry_t *devifmt_entry_ptr = NULL;
    pamt_entry_t *devifmt_pamt_entry_ptr = NULL;

    if (!is_valid_devifmt_idx(devifmt_idx, false))
    {
        TDX_ERROR("Invalid DEVIFMT index (0x%llx)\n", devifmt_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // walk to parent level
    return_val = devifmt_walk(devifmt_idx, true, DEVIFMT_HP_LOCK_MODE, false, &is_devifmt_walked, &devifmt_walk_result);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    devifmt_parent_ptr = devifmt_walk_result.devifmt_path_arr[devifmt_idx.level];
    if (!devifmt_parent_ptr->p)
    {
        TDX_ERROR("DEVIFMT entry not present\n");
        return_val = api_error_with_operand_id(TDX_DEVIFMT_NOT_PRESENT, OPERAND_ID_RCX);
        goto EXIT;
    }

    pa_t remove_pa = {.raw = 0};
    remove_pa.page_4k_num = devifmt_parent_ptr->pa;

    // Check and lock DEVIFMT_PA in PAMT
    devifmt_entry_ptr = map_pa_with_global_hkid(
        remove_pa.raw_void,
        TDX_RANGE_RO);

    // Update the remove_pa in PAMT to free
    return_val = pamt_implicit_get_and_lock(
        remove_pa,
        PT_4KB,
        TDX_LOCK_EXCLUSIVE,
        &devifmt_pamt_entry_ptr,
        false);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock DEVIFMT PAMT entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify that all of the entries are not present
    for (uint64_t entry_idx = 0; entry_idx < DEVIFMT_COUNT_PER_PAGE; entry_idx++)
    {
        if (devifmt_entry_ptr[entry_idx].p != 0)
        {
            TDX_ERROR("DEVIFMT page is not empty (found entry in present status on page)\n");
            return_val = api_error_with_operand_id(TDX_DEVIF_INVALID_METADATA, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Unmap the parent DEVIFMT_ENTRY
    devifmt_entry_t devifmt_parent_ptr_copy = {.raw = devifmt_parent_ptr->raw};
    devifmt_parent_ptr_copy.p = 0;
    atomic_mem_write_64b(&devifmt_parent_ptr->raw, devifmt_parent_ptr_copy.raw);
    // Free PAMT child entry
    devifmt_pamt_entry_ptr->pt = PT_NDA;

    tdx_module_local_t *local_data_ptr = get_local_data();
    local_data_ptr->vmm_regs.rcx = remove_hkid_from_pa(remove_pa).raw;

    return_val = TDX_SUCCESS;

EXIT:
    if (devifmt_pamt_entry_ptr != NULL)
    {
        pamt_implicit_release_lock(devifmt_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE);
    }

    if (is_devifmt_walked)
    {
        devifmt_unwalk(&devifmt_walk_result);
    }

    if (devifmt_entry_ptr != NULL)
    {
        free_la(devifmt_entry_ptr);
    }

    return return_val;
}