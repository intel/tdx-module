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
 * @file helpers.h
 * @brief Helper functions for meta-data page table walks
 */

#ifndef SRC_MT_WALK_HELPERS_HELPERS_H_
#define SRC_MT_WALK_HELPERS_HELPERS_H_

#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "tdx_basic_types.h"
#include TDX_ERROR_CODES_DEFS_HEADER

/**
 * @brief Helper function for mt_walk (used for MMIOMT and DEVIFMT)
 *        Locks PAMT as TDX_LOCK_SHARED and maps the linear address after calculating its index and offset
 *
 * @param entry_page_pa
 * @param entry_idx
 * @param entry_size
 * @param is_guest
 * @param pamt_block_ptr
 * @param pamt_entry
 * @param expected_pt
 * @param mapping_type
 * @param entry_la
 * @return api_error_code_e
 */
api_error_code_e mt_lock_pamt_and_map_la(
    pa_t entry_page_pa,
    const uint64_t entry_idx,
    const uint64_t entry_size,
    const bool_t is_guest,
    pamt_walk_result_t* pamt_walk_result,
    const page_type_t expected_pt,
    const mapping_type_t mapping_type,
    void **entry_la);

//Suggestion for future stepping
// typedef struct
// {
//     uint64_t idx;                                // Index includes lowest reached level
//     bool_t entry_locked;                         // Flag indicating whether entry at LEVEL was exclusively locked (using the entry lock).
//     void *mt_path_arr[MMIOMT_L_ROOT + 1];        // Array of L0 … L4 QNODE/DATA entry pointers (only valid where index >= LEVEL).
//     pamt_entry_t *pamt_path_arr[MMIOMT_L_ROOT];  // Array PAMT entry pointers for MMIOMT L0 … L4 pages, QNODE/DATA page (only valid where index >= LEVEL)
// } mt_walk_res_t;

#endif // SRC_MT_WALK_HELPERS_HELPERS_H_
