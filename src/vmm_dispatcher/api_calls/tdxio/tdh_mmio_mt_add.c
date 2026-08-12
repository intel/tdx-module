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

api_error_type tdh_mmio_mt_add(
    mmiomt_idx_t mmiomt_idx,
    pa_t mmiomt_pa)
{
    // PAMT related variables
    void *mmiomt_ptr = NULL;
    pamt_walk_result_t mmiomt_pamt_walk_result;
    bool_t is_mmiomt_pamt_locked = false;

    // mmiomt_walk variables
    mmiomt_walk_res_t mmiomt_walk_res = {0};
    bool_t is_mmiomt_walked = false;
    mmiomt_node_t *mmiomt_parent_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Verify MMIOMT_IDX
    if (!is_valid_mmiomt_idx(mmiomt_idx, MMIOMT_L1))
    {
        TDX_ERROR("Invalid mmiomt_idx =0x%llx\n", mmiomt_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check and lock MMIOMT_PA in PAMT
    return_val = check_and_lock_explicit_4k_private_hpa(
        mmiomt_pa,
        OPERAND_ID_RDX,
        TDX_LOCK_EXCLUSIVE,
        PT_NDA,
        &mmiomt_pamt_walk_result,
        &is_mmiomt_pamt_locked);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check and lock mmiomt_pamt_entry_ptr\n");
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
        TDX_ERROR("MMIOMT walk failed\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify MMIOMT parent entry is not already mapped
    if (mmiomt_walk_res.mmiomt_path_arr[mmiomt_idx.level]->type != MMIOMT_QNODE)
    {
        TDX_ERROR("MMIOMT entry type (=%u) is not MMIOMT_QNODE\n",
                    mmiomt_walk_res.mmiomt_path_arr[mmiomt_idx.level]->type);
        return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_RCX);
        goto EXIT;
    }

    mmiomt_parent_ptr = mmiomt_get_node_from_q_node(&mmiomt_walk_res);

    if (mmiomt_parent_ptr->p)
    {
        TDX_ERROR("MMIOMT parent entry is already mapped\n");
        return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Initialize the new MMIOMT page to zero
    mmiomt_ptr = map_pa_with_global_hkid(
        mmiomt_pa.raw_void,
        TDX_RANGE_RW);

    zero_area_cacheline(mmiomt_ptr, TDX_PAGE_SIZE_IN_BYTES);

    // Map the MMIOMT parent entry to point the new MMIOMT page
    mmiomt_parent_ptr->p = 1;
    mmiomt_parent_ptr->pa = mmiomt_pa.page_4k_num;

    // Update the new MMIOMT page PAMT entry
    mmiomt_pamt_walk_result.pamt_entry_p->pt = PT_MMIO_MT;

EXIT:
    if (mmiomt_ptr != NULL)
    {
        free_la(mmiomt_ptr);
    }

    if (is_mmiomt_walked)
    {
        mmiomt_unwalk(&mmiomt_walk_res);
    }

    if (is_mmiomt_pamt_locked)
    {
        pamt_unwalk(&mmiomt_pamt_walk_result);
    }
    return return_val;
}
