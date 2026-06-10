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
 * @file tdh_phymem_pamt_remove
 * @brief TDHPHYMEMPAMTREMOVE API handler
 */


#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"

api_error_type tdh_phymem_pamt_remove(page_size_api_input_t page_info)
{
    // TDX Local data
    tdx_module_local_t  * local_data_ptr = get_local_data();

    pa_t                  page_pa = { .raw = page_info.raw & ~0xFFFULL };

    pamt_walk_result_t    pamt_walk_result = { .valid = false };

    api_error_type        return_val = UNINITIALIZE_ERROR;

    if (!get_global_data()->dynamic_pamt_enabled)
    {
        TDX_ERROR("Dynamic PAMT not enabled!\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    // Do some checks
    if ((page_info.level != PT_2MB) || page_info.reserved1 || (get_hkid_from_pa(page_pa) != 0) ||
         page_info.reserved2 || !is_addr_aligned_pwr_of_2(page_pa.raw, _2MB))
    {
        TDX_ERROR("Error in page_info input! 0x%llx\n", page_info.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    pamt_block_t pamt_block;

    if (!pamt_get_block(page_pa, &pamt_block))
    {
        TDX_ERROR("Couldn't find relevant PAMT for 0x%llx\n", page_info.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_ADDR_RANGE_ERROR, OPERAND_ID_RCX);
        goto EXIT;
    }

    return_val = pamt_walk(page_pa, pamt_block, TDX_LOCK_EXCLUSIVE, PT_2MB, true, false, &pamt_walk_result);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("PAMT walk failure for 0x%llx!\n", page_info.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    pamt_non_leaf_entry_t* pamt_node_p = (pamt_non_leaf_entry_t*)pamt_walk_result.pamt_entry_p;

    if ((pamt_walk_result.level_reached != PT_2MB) || (pamt_node_p->pt != PT_PAMT))
    {
        TDX_ERROR("PAMT is not a node 0x%llx!\n", pamt_node_p->pt);
        return_val = api_error_with_operand_id(TDX_NO_PAMT_PAGE_PAIR, OPERAND_ID_RCX);
        goto EXIT;
    }

    pa_t pamt_pages[2];
    pamt_pages[0] = get_pamt_node_page0(pamt_node_p);
    pamt_pages[1] = get_pamt_node_page1(pamt_node_p);

    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);

    for (uint32_t i = 0; i < 2; i++)
    {
        pamt_entry_t* pamt_entries_la = map_pa_with_global_hkid(pamt_pages[i].raw_void, TDX_RANGE_RO);

        for (uint32_t j = 0; j < pamt_entries_in_page; j++)
        {
            if (pamt_entries_la[j].pt != PT_NDA)
            {
                free_la(pamt_entries_la);
                TDX_ERROR("PAMT entry doesn't have PT_NDA type %d\n", pamt_entries_la[i].pt);
                return_val = api_error_with_operand_id(TDX_PAMT_PAGE_NOT_EMPTY, i);
                goto EXIT;
            }
        }

        free_la(pamt_entries_la);
    }

    tdx_sanity_check(pamt_node_p->page_count == 0, FATAL_ERROR_ID_343, 0);

    pamt_block_t pamt0_block, pamt1_block;

    if (!pamt_get_block(pamt_pages[0], &pamt0_block) || !pamt_get_block(pamt_pages[1], &pamt1_block))
    {
        TDX_ERROR("Couldn't find covering TDMR for removed PAMT pages - not expected\n");
        fatal_error(FATAL_ERROR_ID_338, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    dynamic_pamt_4k_bitmap_clear(&pamt0_block, pamt_pages[0].raw);
    dynamic_pamt_4k_bitmap_clear(&pamt1_block, pamt_pages[1].raw);

    local_data_ptr->vmm_regs.rdx = pamt_pages[0].raw;
    local_data_ptr->vmm_regs.r8  = pamt_pages[1].raw;

    pamt_node_p->pt = PT_NDA;

EXIT:

    if (pamt_walk_result.valid)
    {
        pamt_unwalk(&pamt_walk_result);
    }

    return return_val;
}

