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
#include "auto_gen/tdx_error_codes_defs.h"
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
    pa_t                  page_pa = {.raw = target_page_pa};
    pamt_block_t          page_pamt_block;
    pamt_entry_t        * page_pamt_entry_ptr;
    bool_t                page_locked_flag = false;

    page_size_t           page_leaf_size;
    pamt_entry_t          pamt_entry;

    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Initialize output registers to default values
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;
    local_data_ptr->vmm_regs.r8  = 0ULL;
    local_data_ptr->vmm_regs.r9  = 0ULL;
    local_data_ptr->vmm_regs.r10 = 0ULL;
    local_data_ptr->vmm_regs.r11 = 0ULL;

    // Check that page address is page-aligned and that its HKID is zero
    if (!is_addr_aligned_pwr_of_2(page_pa.raw, TDX_PAGE_SIZE_IN_BYTES) ||
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
                                &page_leaf_size, false, false, &page_pamt_entry_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to PAMT walk to entry - PAMT is locked\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    page_locked_flag = true;

    pamt_entry = *page_pamt_entry_ptr;

    local_data_ptr->vmm_regs.rcx = (uint64_t)pamt_entry.pt;
    pa_t owner_pa = get_pamt_entry_owner(&pamt_entry);
    local_data_ptr->vmm_regs.rdx = owner_pa.raw;
    local_data_ptr->vmm_regs.r8  = (uint64_t)page_leaf_size;

    if ((pamt_entry.pt == PT_REG) || (pamt_entry.pt == PT_EPT))
    {
        local_data_ptr->vmm_regs.r9 = pamt_entry.bepoch.raw;
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks
    if (page_locked_flag)
    {
        pamt_unwalk(page_pa, page_pamt_block, page_pamt_entry_ptr, TDX_LOCK_SHARED, page_leaf_size);
    }

    return return_val;
}
