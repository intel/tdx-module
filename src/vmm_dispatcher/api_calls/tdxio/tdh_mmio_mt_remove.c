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
 * @file tdh_mmio_mt_add.c
 * @brief TDHMMIOMTADD API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/mmiomt.h"

api_error_type tdh_mmio_mt_remove(mmiomt_idx_t mmiomt_idx)
{
    // mmiomt_walk variables
    mmiomt_walk_res_t mmiomt_walk_res = {0};
    bool_t is_mmiomt_walked = false;

    mmiomt_node_t *mmiomt_parent_ptr = NULL;
    mmiomt_entry_t *mmiomt_entry_ptr = NULL;
    pamt_entry_t *mmiomt_pamt_entry_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Verify MMIOMT_IDX
    if (!is_valid_mmiomt_idx(mmiomt_idx, MMIOMT_L1))
    {
        TDX_ERROR("Invalid MMIOMT index (=0x%llx), or MMIOMT index (=%u) equals zero\n", mmiomt_idx.raw, mmiomt_idx.level);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    return_val = mmiomt_walk(
        mmiomt_idx,
        true,
        TDX_RANGE_RW,
        &is_mmiomt_walked,
        &mmiomt_walk_res);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to perform mmiomt walk\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify entry type is QNODE and corresponding NODE entry present bit is set
    if (mmiomt_walk_res.mmiomt_path_arr[mmiomt_idx.level]->type != MMIOMT_QNODE)
    {
        TDX_ERROR("MMIOMT entry type is not QNODE\n");
        return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_RCX);
        goto EXIT;
    }

    mmiomt_parent_ptr = mmiomt_get_node_from_q_node(&mmiomt_walk_res);

    if (!mmiomt_parent_ptr->p)
    {
        TDX_ERROR("MMIOMT parent entry present bit is not set\n");
        return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_RCX);
        goto EXIT;
    }

    pa_t remove_pa = {.raw = 0};
    remove_pa.page_4k_num = mmiomt_parent_ptr->pa;

    mmiomt_entry_ptr = map_pa_with_global_hkid(
        remove_pa.raw_void,
        TDX_RANGE_RO);

    // Update the remove_pa in PAMT to free
    return_val = pamt_implicit_get_and_lock(
        remove_pa,
        PT_4KB,
        TDX_LOCK_EXCLUSIVE,
        &mmiomt_pamt_entry_ptr,
        false);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to get or lock MMIOMT pamt entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify the MMIOMT page to remove is empty
    for (uint8_t i = 0; i < MMIOMT_QNODE_TBL_SIZE; i++)
    {
        mmiomt_entry_t *curr_entry = mmiomt_entry_ptr + i;
        if (curr_entry->type != MMIOMT_QNODE ||
            curr_entry->qnode[0].p ||
            curr_entry->qnode[1].p ||
            curr_entry->qnode[2].p ||
            curr_entry->qnode[3].p)
        {
            TDX_ERROR("MMIOMT page to remove is not empty, or entry type (=%u) is not MMIOMT_QNODE\n", curr_entry->type);
            return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Unmap the parent MMIOMT_ENTRY
    mmiomt_parent_ptr->p = 0;
    mmiomt_pamt_entry_ptr->pt = PT_NDA;

    get_local_data()->vmm_regs.rcx = remove_hkid_from_pa(remove_pa).page_4k_num;

    return_val = TDX_SUCCESS;

EXIT:
    if (mmiomt_pamt_entry_ptr != NULL)
    {
        pamt_implicit_release_lock(mmiomt_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE);
    }

    if (mmiomt_entry_ptr != NULL)
    {
        free_la(mmiomt_entry_ptr);
    }

    if (is_mmiomt_walked)
    {
        mmiomt_unwalk(&mmiomt_walk_res);
    }

    return return_val;
}
