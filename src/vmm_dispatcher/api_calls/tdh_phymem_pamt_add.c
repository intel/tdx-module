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
 * @file tdh_phymem_pamt_add
 * @brief TDHPHYMEMPAMTADD API handler
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

api_error_type tdh_phymem_pamt_add(page_size_api_input_t page_info,
                                   uint64_t hpa0,
                                   uint64_t hpa1)
{
    pa_t                  page_pa = { .raw = page_info.raw & ~0xFFFULL };

    pa_t                  pamt_hpa0 = { .raw = hpa0 };
    pa_t                  pamt_hpa1 = { .raw = hpa1 };

    pamt_walk_result_t    pamt_walk_result = { .valid = false };

    pamt_block_t          pamt0_block;
    pamt_block_t          pamt1_block;

    pamt_walk_result_t    pamt0_walk_result = { .valid = false };
    pamt_walk_result_t    pamt1_walk_result = { .valid = false };

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

    if ((get_hkid_from_pa(pamt_hpa0) != 0) || !is_addr_aligned_pwr_of_2(pamt_hpa0.raw, TDX_PAGE_SIZE_IN_BYTES) ||
        !is_pa_smaller_than_max_pa(pamt_hpa0.raw))
    {
        TDX_ERROR("Error in HPA0 0x%llx\n", pamt_hpa0);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (!pamt_get_block(pamt_hpa0, &pamt0_block))
    {
        TDX_ERROR("Error in HPA0 PAMT 0x%llx\n", pamt_hpa0);
        return_val = api_error_with_operand_id(TDX_OPERAND_ADDR_RANGE_ERROR, OPERAND_ID_RDX);
        goto EXIT;
    }

    if ((get_hkid_from_pa(pamt_hpa1) != 0) || !is_addr_aligned_pwr_of_2(pamt_hpa1.raw, TDX_PAGE_SIZE_IN_BYTES) ||
        !is_pa_smaller_than_max_pa(pamt_hpa1.raw))
    {
        TDX_ERROR("Error in HPA1 0x%llx\n", pamt_hpa1);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    if (!pamt_get_block(pamt_hpa1, &pamt1_block))
    {
        TDX_ERROR("Error in HPA1 PAMT 0x%llx\n", pamt_hpa1);
        return_val = api_error_with_operand_id(TDX_OPERAND_ADDR_RANGE_ERROR, OPERAND_ID_R8);
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

    if ((pamt_walk_result.level_reached != PT_2MB) || (pamt_node_p->pt != PT_NDA))
    {
        TDX_ERROR("PAMT already in use 0x%llx!\n", pamt_node_p->pt);
        return_val = api_error_with_operand_id(TDX_HPA_RANGE_NOT_FREE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // PAMT-walk the two new pages and check their type
    if (pamt_hpa0.page_2m_num != page_pa.page_2m_num)
    {
        return_val = pamt_walk(pamt_hpa0, pamt0_block, TDX_LOCK_SHARED, PT_4KB, true, false, &pamt0_walk_result);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
            goto EXIT;
        }

        if (pamt0_walk_result.pamt_entry_p->pt != PT_NDA)
        {
            TDX_ERROR("New PAMT HPA0 - 0x%llx is not free!\n", pamt_hpa0);
            return_val = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_RDX);
            goto EXIT;
        }
    }

    if (pamt_hpa1.page_2m_num != page_pa.page_2m_num)
    {
        return_val = pamt_walk(pamt_hpa1, pamt1_block, TDX_LOCK_SHARED, PT_4KB, true, false, &pamt1_walk_result);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
            goto EXIT;
        }

        if (pamt1_walk_result.pamt_entry_p->pt != PT_NDA)
        {
            TDX_ERROR("New PAMT HPA1 - 0x%llx is not free!\n", pamt_hpa1);
            return_val = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_R8);
            goto EXIT;
        }
    }

    // For each of the two new PAMT pages, atomically test & set its respective PAMT_PAGE_BITMAP bit.
    if (!dynamic_pamt_4k_bitmap_set(&pamt0_block, pamt_hpa0.raw))
    {
        TDX_ERROR("New PAMT HPA0 - 0x%llx already used as PAMT page\n", pamt_hpa0);
        return_val = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (!dynamic_pamt_4k_bitmap_set(&pamt1_block, pamt_hpa1.raw))
    {
        dynamic_pamt_4k_bitmap_clear(&pamt0_block, pamt_hpa0.raw);

        TDX_ERROR("New PAMT HPA1 - 0x%llx already used as PAMT page\n", pamt_hpa1);
        return_val = api_error_with_operand_id(TDX_PAGE_NOT_FREE, OPERAND_ID_R8);
        goto EXIT;
    }

    pamt_entry_t* pamt_page_la[2];

    pamt_page_la[0] = map_pa_with_global_hkid(pamt_hpa0.raw_void, TDX_RANGE_RW);
    pamt_page_la[1] = map_pa_with_global_hkid(pamt_hpa1.raw_void, TDX_RANGE_RW);

    zero_area_cacheline(pamt_page_la[0], TDX_PAGE_SIZE_IN_BYTES);
    zero_area_cacheline(pamt_page_la[1], TDX_PAGE_SIZE_IN_BYTES);

    pamt_node_p->pt = PT_PAMT;
    pamt_node_p->second_quadword = 0;
    pamt_node_p->page_hpa0 = ((pa_t)pamt_hpa0).page_4k_num;
    pamt_node_p->page_hpa1 = ((pa_t)pamt_hpa1).page_4k_num;

    free_la(pamt_page_la[0]);
    free_la(pamt_page_la[1]);

EXIT:

    if (pamt1_walk_result.valid)
    {
        pamt_unwalk(&pamt1_walk_result);
    }

    if (pamt0_walk_result.valid)
    {
        pamt_unwalk(&pamt0_walk_result);
    }

    if (pamt_walk_result.valid)
    {
        pamt_unwalk(&pamt_walk_result);
    }

    return return_val;
}

