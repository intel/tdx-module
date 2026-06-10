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
 * @file tdh_phymem_page_rdmd
 * @brief TDHPHYMEMPAGERDMD API handler
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


api_error_type tdh_phymem_page_rdmd(uint64_t target_page_pa)
{
    // TDX Local data
    tdx_module_local_t  * local_data_ptr = get_local_data();

    // Target page related variables
    page_size_api_input_t page_pa_and_size = { .raw = target_page_pa };
    pa_t                  page_pa;
    pamt_block_t          page_pamt_block;
    pamt_walk_result_t    page_pamt_walk_result = { .valid = false };
    bool_t                page_locked_flag = false;

    page_size_t           page_min_size = page_pa_and_size.level;
    page_size_t           page_actual_size;
    pamt_entry_t          pamt_entry;

    phymem_page_rdmd_pt_ret_t pt_ret;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Initialize output registers to default values
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;
    local_data_ptr->vmm_regs.r8  = 0ULL;
    local_data_ptr->vmm_regs.r9  = 0ULL;
    local_data_ptr->vmm_regs.r10 = 0ULL;
    local_data_ptr->vmm_regs.r11 = 0ULL;

    // Check reserved and other fields
    if (page_pa_and_size.reserved1 || page_pa_and_size.reserved2 || (page_min_size > PT_1GB) ||
        (!get_global_data()->dynamic_pamt_enabled && (page_min_size > PT_4KB)))
    {
        TDX_ERROR("Wrong page size or reserved bits 0x%llx\n", page_pa_and_size.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_actual_size = page_min_size;
    page_pa.raw = page_pa_and_size.hpa << 12;

    // Check that page address is page-aligned and that its HKID is zero
    if (!is_addr_aligned_pwr_of_2(page_pa.raw, TDX_PAGE_SIZE_IN_BYTES << (page_min_size * 9)) ||
        !is_pa_smaller_than_max_pa(page_pa.raw) ||
        (get_hkid_from_pa(page_pa) != 0))
    {
        TDX_ERROR("Page is not aligned or does not have zero-ed HKID bits\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    if (!pamt_get_block(page_pa, &page_pamt_block))
    {
        TDX_ERROR("Page PA does not comply with PAMT range rules\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_ADDR_RANGE_ERROR, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Walk and locate the leaf PAMT entry
    if ((return_val = pamt_walk(page_pa, page_pamt_block, TDX_LOCK_SHARED,
                                page_actual_size, true, false, &page_pamt_walk_result)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to PAMT walk to entry - PAMT is locked\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    page_locked_flag = true;

    page_actual_size = page_pamt_walk_result.level_reached;
    pamt_entry = *(page_pamt_walk_result.pamt_entry_p);

    pt_ret.raw = 0;
    if (get_global_data()->dynamic_pamt_enabled)
    {
        if ((page_min_size == PT_4KB) && (pamt_entry.pt == PT_NDA) &&
            dynamic_pamt_4k_bitmap_get(&page_pamt_block, page_pa.raw))
        {
            // A 4KB page was requested, but we got to a PT_NDA entry (which may be a 2MB or 4KB entry).
            // In this case, the PAMT_PAGE_BITMAP indicates if this is a PAMT page.
            // We return the information of the PAMT page.
            pt_ret.pt = PT_PAMT;
            local_data_ptr->vmm_regs.r8 = PT_4KB;
        }
        else
        {
            pt_ret.pt = pamt_entry.pt;
            if (pamt_entry.pt == PT_PAMT)
            {
                pt_ret.non_leaf = 1;

                pamt_non_leaf_entry_t* pamt_node = (pamt_non_leaf_entry_t*)&pamt_entry;
                local_data_ptr->vmm_regs.r10 = get_pamt_node_page0(pamt_node).raw;
                local_data_ptr->vmm_regs.r11 = get_pamt_node_page1(pamt_node).raw;
            }
            local_data_ptr->vmm_regs.r8  = (uint64_t)page_actual_size;
        }
    }
    else
    {
        pt_ret.pt = pamt_entry.pt;
        local_data_ptr->vmm_regs.r8  = (uint64_t)page_actual_size;
    }

    local_data_ptr->vmm_regs.rcx = pt_ret.raw;

    if (pamt_entry.pt == PT_IOMMU_MT)
    {
        local_data_ptr->vmm_regs.rdx = pamt_entry.owner; //IOMMU ID
    }
    else
    if (pt_ret.pt != PT_PAMT) // Don't return OWNER for PAMT pages or PT_PAMT non-leaf entries
    {
        // HKID should be zero at this point
        local_data_ptr->vmm_regs.rdx = get_pamt_entry_owner(&pamt_entry).raw; // Shift to get TDR HPA
    }

    if ((pamt_entry.pt == PT_REG) || (pamt_entry.pt == PT_EPT)
        || (pamt_entry.pt == PT_IOMMU_MT)
        )
    {
        local_data_ptr->vmm_regs.r9 = pamt_entry.bepoch.raw;
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks
    if (page_locked_flag)
    {
        pamt_unwalk(&page_pamt_walk_result);
    }

    return return_val;
}
