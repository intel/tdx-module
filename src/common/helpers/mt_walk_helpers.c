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
 * @file mt_walk_helpers.c
 * @brief
 */

#include "mt_walk_helpers.h"
#include "helpers.h"

api_error_code_e mt_lock_pamt_and_map_la(
    pa_t entry_page_pa,
    const uint64_t entry_idx,
    const uint64_t entry_size,
    const bool_t is_guest,
    pamt_walk_result_t* pamt_walk_result,
    const page_type_t expected_pt,
    const mapping_type_t mapping_type,
    void **entry_la)
{
    // Set correct offset
    entry_page_pa.raw += entry_idx * entry_size;

    pamt_block_t pamt_block;

    api_error_code_e return_val = non_shared_hpa_metadata_check_and_lock(
        entry_page_pa,
        TDX_LOCK_SHARED,
        expected_pt,
        PT_4KB,
        true,
        is_guest,
        &pamt_block,
        pamt_walk_result);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on pamt entry\n");
        goto EXIT;
    }

    *entry_la = map_pa_with_global_hkid(
        entry_page_pa.raw_void,
        mapping_type);

    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}
