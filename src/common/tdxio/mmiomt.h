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
 * @file mmiomt.h
 */

#ifndef MMIOMT_H_
#define MMIOMT_H_

#include "helpers/helpers.h"
#include "data_structures/tdxio/mmiomt_defs.h"

_STATIC_INLINE_ bool_t is_valid_mmiomt_idx(
    const mmiomt_idx_t mmiomt_idx,
    const mmiomt_lvl_e min_allowed_level)
{
    pa_t tmp_pa = {.raw = 0};
    tmp_pa.page_4k_num = mmiomt_idx.pa;

    return (!mmiomt_idx.rsvd1) &&
           (!mmiomt_idx.rsvd2) &&
           mmiomt_idx.level >= min_allowed_level &&
           mmiomt_idx.level <= MMIOMT_L_ROOT &&
           (hpa_check_with_pwr_2_alignment(tmp_pa, _4KB) == TDX_SUCCESS);
}

/**
 * @brief Get relevant node from Q node using the coresponding mmiomt_idx bits
 *
 * @param mmiomt_walk_res
 *
 * @return mmiomt_qnode_q_t *
 */
_STATIC_INLINE_ mmiomt_node_t *mmiomt_get_node_from_q_node(const mmiomt_walk_res_t *const mmiomt_walk_res)
{
    mmiomt_idx_t mmiomt_idx = mmiomt_walk_res->mmiomt_idx;
    switch (mmiomt_idx.level)
    {
    case MMIOMT_L_ROOT:
        return &mmiomt_walk_res->mmiomt_path_arr[MMIOMT_L_ROOT]->qnode[0];
    case MMIOMT_L4:
        return &mmiomt_walk_res->mmiomt_path_arr[mmiomt_idx.level]->qnode[mmiomt_idx.l4_q_idx];
    case MMIOMT_L3:
        return &mmiomt_walk_res->mmiomt_path_arr[mmiomt_idx.level]->qnode[mmiomt_idx.l3_q_idx];
    case MMIOMT_L2:
        return &mmiomt_walk_res->mmiomt_path_arr[mmiomt_idx.level]->qnode[mmiomt_idx.l2_q_idx];
    case MMIOMT_L1:
        return &mmiomt_walk_res->mmiomt_path_arr[mmiomt_idx.level]->qnode[mmiomt_idx.l1_q_idx];
    default:
        fatal_error(FATAL_ERROR_ID_89, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
    return NULL;
}

_STATIC_INLINE_ bool_t mmiomt_lock_node(mmiomt_walk_res_t *const mmiomt_walk_res)
{
    void *node = NULL;
    if (mmiomt_walk_res->mmiomt_idx.level == MMIOMT_L0)
    {
        // L0 only contains DATA entries
        node = &mmiomt_walk_res->mmiomt_path_arr[mmiomt_walk_res->mmiomt_idx.level]->data;
    }
    else
    {
        // Get relevant node from Q node
        node = &mmiomt_walk_res->mmiomt_path_arr[mmiomt_walk_res->mmiomt_idx.level]->qnode;
    }
    return acquire_bit_lock((uint32_t *)node, MMIOMT_ENTRY_XLOCK_BIT) == TDX_SUCCESS;
}

_STATIC_INLINE_ void mmiomt_release_node(mmiomt_walk_res_t *const mmiomt_walk_res)
{
    void *node = NULL;
    if (mmiomt_walk_res->mmiomt_idx.level == MMIOMT_L0)
    {
        node = &mmiomt_walk_res->mmiomt_path_arr[mmiomt_walk_res->mmiomt_idx.level]->data;
    }
    else
    {
        node = &mmiomt_walk_res->mmiomt_path_arr[mmiomt_walk_res->mmiomt_idx.level]->qnode;
    }

    release_bit_lock((uint32_t *)node, MMIOMT_ENTRY_XLOCK_BIT);
}

/**
 * @brief Given mmiomt_idx_t input, the functions return a mmiomt_walk_res_t structure which includes all the MMIOMMT entry
 *        and PAMT entry pointer on the path from the MMIOMT root to the reached level entry.
 *
 *        The function acquires shared locks on each visited MMIOMT page (in PAMT) and if the XLOCK flag was set, it also
 *        acquires the exclusive lock MMIOMT entry lock.
 *
 *        The walk result is successful (and returned status is TDX_SUCCESS ) if all the entries except the entry indicated by the
 *        level input  were present and all the required locks were acquired successfully.
 *
 * @note mmiomt_idx must be valid and verified by the caller of this function
 *
 * @param mmiomt_idx
 * @param lock_entry
 * @param is_mmiomt_walked_ptr - Reminds the user to unwalk the MMIOMT tree
 * @param mmiomt_walk_res
 *
 * @return Success or Error type
 */
api_error_code_e mmiomt_walk(
    const mmiomt_idx_t mmiomt_idx,
    const bool_t lock_entry,
    const mapping_type_t leaf_mapping_type,
    bool_t *const  is_mmiomt_walked_ptr,
    mmiomt_walk_res_t *const mmiomt_walk_res);

/**
 * @brief Given mmiomt_walk_res_t structure returned by a MMIOMT_WALK function call,
 *        un-map and unlock the path of PASIDMT entries and pages.
 *
 * @param mmiomt_walk_res
 */
void mmiomt_unwalk(mmiomt_walk_res_t *const mmiomt_walk_res);

/**
 * @brief Given MMIO address, the functions return a pointer to a present MMIOMT_DATA entry without taking any locks in MMIOMT
 *        The HKID is removed inside the function
 *
 * @note The caller of the function is responsible to ensure that the MMIOMT entry is present and may not be removed by a concurrent thread
 *       (e.g. by acquiring returned MMIOMT entry lock to ensure that)
 *
 * @param mmio_pa
 * @param mmiomt_lvl - used to map the leaf entry as RW
 * @return mmiomt_data_t*
 */
mmiomt_data_t *mmiomt_implicit_get(
    const pa_t mmio_pa,
    const mmiomt_lvl_t mmiomt_lvl);

#endif /* MMIOMT_H_ */
