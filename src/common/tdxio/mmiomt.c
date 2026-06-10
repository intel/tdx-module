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

#include "tdxio/mmiomt.h"
#include "helpers/helpers.h"
#include "helpers/mt_walk_helpers.h"

api_error_code_e mmiomt_walk(
    const mmiomt_idx_t mmiomt_idx,
    const bool_t lock_entry,
    const mapping_type_t leaf_mapping_type,
    bool_t *const is_mmiomt_walked_ptr,
    mmiomt_walk_res_t *const mmiomt_walk_res)
{
    api_error_code_e return_val = UNINITIALIZE_ERROR;
    mapping_type_t mapping_type = TDX_RANGE_RO;
    pa_t tbl_pa = {.raw = 0};
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();

    // Init as invalid
    mmiomt_walk_res->mmiomt_idx.raw = mmiomt_idx.raw;

    // Set root
    mmiomt_walk_res->mmiomt_path_arr[MMIOMT_L_ROOT] = (mmiomt_entry_t *)&tdx_global_data_ptr->mmiomt_root_node;

    // Set current level reached
    mmiomt_walk_res->mmiomt_idx.level = MMIOMT_L_ROOT;

    // If desired level reached exit
    if (mmiomt_idx.level == mmiomt_walk_res->mmiomt_idx.level)
    {
        goto EXIT_LOCK;
    }

    // Check root present bit
    if (!mmiomt_walk_res->mmiomt_path_arr[MMIOMT_L_ROOT]->qnode[0].p)
    {
        TDX_ERROR("MMIOMT root not present\n");
        return_val = TDX_MMIOMT_NOT_PRESENT;
        goto EXIT;
    }

    tbl_pa.page_4k_num = mmiomt_walk_res->mmiomt_path_arr[MMIOMT_L_ROOT]->qnode[0].pa;

    // Array containing all relevant Qnode indices
    uint8_t qnode_idx_arr[] = {mmiomt_idx.l0_idx, mmiomt_idx.l1_idx, mmiomt_idx.l2_idx, mmiomt_idx.l3_idx, mmiomt_idx.l4_idx};
    // Array containing all relevant inner node indices within each Qnode
    uint8_t entry_idx_arr[] = {mmiomt_idx.l1_q_idx, mmiomt_idx.l2_q_idx, mmiomt_idx.l3_q_idx, mmiomt_idx.l4_q_idx};

    for (int8_t i = MMIOMT_L4; i >= MMIOMT_L0; i--)
    {
        // RW access to leaf level only
        mapping_type = mmiomt_idx.level == (mmiomt_lvl_t)i ? leaf_mapping_type : TDX_RANGE_RO;

        return_val = mt_lock_pamt_and_map_la(
            tbl_pa,
            qnode_idx_arr[i],
            sizeof(mmiomt_entry_t),
            false,
            &mmiomt_walk_res->pamt_walk_result_arr[i],
            PT_MMIO_MT,
            mapping_type,
            (void **)&mmiomt_walk_res->mmiomt_path_arr[i]);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to lock or map mmiomt entry at level %u\n", i);
            goto EXIT;
        }

        // Set current level reached
        mmiomt_walk_res->mmiomt_idx.level = (mmiomt_lvl_t)i;

        // If desired level reached exit
        if (mmiomt_idx.level == mmiomt_walk_res->mmiomt_idx.level)
        {
            goto EXIT_LOCK;
        }

        /**
         * @note this won't be rached when i == 0, since mmiomt_idx is required to be a valid input
         */
        // Verify a data node wasn't reached and check the present bit
        if (mmiomt_walk_res->mmiomt_path_arr[i]->type == MMIOMT_DATA ||
            !mmiomt_walk_res->mmiomt_path_arr[i]->qnode[entry_idx_arr[i - 1]].p)
        {
            TDX_ERROR("Node present bit is zero at level %u\n", i - 1);
            return_val = TDX_MMIOMT_NOT_PRESENT;
            goto EXIT;
        }

        // Set next pa
        tbl_pa.page_4k_num = mmiomt_walk_res->mmiomt_path_arr[i]->qnode[entry_idx_arr[i - 1]].pa;
    }

EXIT_LOCK:
    // Acquire lock on last entry only
    if (lock_entry)
    {
        if (!mmiomt_lock_node(mmiomt_walk_res))
        {
            TDX_ERROR("Failed to lock mmiomt node\n");
            return_val = TDX_OPERAND_BUSY;
            goto EXIT;
        }
    }
    mmiomt_walk_res->entry_locked = lock_entry;
    return_val = TDX_SUCCESS;

EXIT:
    if (return_val != TDX_SUCCESS)
    {
        mmiomt_unwalk(mmiomt_walk_res);
    }

    *is_mmiomt_walked_ptr = return_val == TDX_SUCCESS;

    return return_val;
}

void mmiomt_unwalk(mmiomt_walk_res_t *const mmiomt_walk_res)
{
    tdx_sanity_check(mmiomt_walk_res != NULL, FATAL_ERROR_ID_246, 2);

    // MMIOMT_L0 does NOT contain any inner nodes to unlock
    if (mmiomt_walk_res->entry_locked)
    {
        mmiomt_release_node(mmiomt_walk_res);
    }

    const mmiomt_idx_t mmiomt_idx = mmiomt_walk_res->mmiomt_idx;
    // Array containing all relevant inner node indices within each Qnode
    /**
     * @note Each entry in the array below refers to the qnode index within the parent entry.
     *       The root level doesn't have any Qnodes. Therefore, a hardcoded zero is used to index tha parent of L4.
     */
    const uint8_t entry_idx_arr[] = {mmiomt_idx.l1_q_idx, mmiomt_idx.l2_q_idx, mmiomt_idx.l3_q_idx, mmiomt_idx.l4_q_idx, 0};

    // @note MMIOMT_L_ROOT won't get inside this for loop
    for (uint8_t level_idx = mmiomt_walk_res->mmiomt_idx.level; level_idx <= MMIOMT_L4; level_idx++)
    {
        pa_t mmiomt_pa = {.raw = 0};
        // The current level PA is extracted from the parent node
        mmiomt_pa.page_4k_num = mmiomt_walk_res->mmiomt_path_arr[level_idx + 1]->qnode[entry_idx_arr[level_idx]].pa;

        pamt_unwalk(&mmiomt_walk_res->pamt_walk_result_arr[level_idx]);
        free_la(mmiomt_walk_res->mmiomt_path_arr[level_idx]);
    }
}

mmiomt_data_t *mmiomt_implicit_get(
    const pa_t mmio_pa,
    const mmiomt_lvl_t mmiomt_lvl)
{
    mmiomt_idx_t mmiomt_idx = {.raw = remove_hkid_from_pa(mmio_pa).raw};
    mmiomt_idx.level = mmiomt_lvl;
    mmiomt_entry_t *curr_entry = NULL;

    // Any other higher level doesn't contain any data nodes
    if (mmiomt_idx.level > MMIOMT_L2)
    {
        fatal_error(FATAL_ERROR_ID_86, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    pa_t tbl_pa = {.raw = 0};
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    mapping_type_t mapping_type = TDX_RANGE_RO;
    mmiomt_entry_t root_mmiomt_entry = {.raw = tdx_global_data_ptr->mmiomt_root_node};

    // Check root present bit
    if (!root_mmiomt_entry.qnode[0].p)
    {
        fatal_error(FATAL_ERROR_ID_87, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    // Get pa from root
    tbl_pa.page_4k_num = root_mmiomt_entry.qnode[0].pa;

    // Array containing all relevant Qnode indices
    uint8_t qnode_idx_arr[] = {mmiomt_idx.l0_idx, mmiomt_idx.l1_idx, mmiomt_idx.l2_idx, mmiomt_idx.l3_idx, mmiomt_idx.l4_idx};
    // Array containing all relevant inner node indices within each Qnode
    uint8_t entry_idx_arr[] = {mmiomt_idx.l1_q_idx, mmiomt_idx.l2_q_idx, mmiomt_idx.l3_q_idx, mmiomt_idx.l4_q_idx};

    for (int8_t i = MMIOMT_L4; i >= MMIOMT_L0; i--)
    {
        // RW access to leaf level only
        mapping_type = mmiomt_idx.level == (mmiomt_lvl_t)i ? TDX_RANGE_RW : TDX_RANGE_RO;

        // Jump to relevant offset
        tbl_pa.raw += (uint64_t)(qnode_idx_arr[i] * sizeof(mmiomt_qnode_t));

        curr_entry = (mmiomt_entry_t *)map_pa_with_global_hkid(
            tbl_pa.raw_void,
            mapping_type);

        // If data entry reached, return found entry without freeing it
        if (curr_entry->type == MMIOMT_DATA)
        {
            tdx_sanity_check(i == mmiomt_lvl, FATAL_ERROR_ID_247, 1);
            goto EXIT;
        }

        // Check qnode present bit
        if (!curr_entry->qnode[entry_idx_arr[i - 1]].p)
        {
            fatal_error(FATAL_ERROR_ID_88, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        // Set next pa
        tbl_pa.raw = 0;
        tbl_pa.page_4k_num = curr_entry->qnode[entry_idx_arr[i - 1]].pa;

        free_la(curr_entry);
    }

EXIT:
    return (mmiomt_data_t *)curr_entry;
}
