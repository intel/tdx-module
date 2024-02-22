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
 * @file tdh_mem_page_aug
 * @brief TDHMEMPAGEAUG API handler
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


api_error_type tdh_mem_page_aug(page_info_api_input_t gpa_page_info,
                           uint64_t target_tdr_pa,
                           uint64_t target_page_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA and SEPT related variables
    pa_t                  page_gpa = {.raw = 0};        // Target page GPA
    page_info_api_input_t gpa_mappings = gpa_page_info; // GPA and level
    ia32e_sept_t        * page_sept_entry_ptr = NULL;   // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;          // Cached SEPT entry of the page
    ept_level_t           page_level_entry = gpa_mappings.level;    // SEPT entry level of the page
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;    // Indicate SEPT entry is locked

    // New TD private page variables
    pa_t                  td_page_pa;                // Physical address of the new TD page
    pamt_block_t          td_page_pamt_block;        // New TD page PAMT block
    pamt_entry_t        * td_page_pamt_entry_ptr;    // Pointer to the TD PAMT entry
    bool_t                td_page_locked_flag = false;   // Indicate TD page is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    td_page_pa.raw = target_page_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page (Shared lock!)
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_MEM_PAGE_AUG_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PT, LVL_PD))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &page_sept_entry_ptr,
                                                      &page_level_entry,
                                                      &page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry in memory
    return_val = sept_lock_acquire_host(page_sept_entry_ptr);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry (again after locking)
    page_sept_entry_copy = *page_sept_entry_ptr;

    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_PAGE_AUG_LEAF, page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        TDX_ERROR("TDH_MEM_PAGE_AUG is not allowed in current SEPT entry state - 0x%llx\n", page_sept_entry_copy.raw);
        goto EXIT;
    }

    // Check, lock and map the new SEPT EPT page
    return_val = check_and_lock_free_range_hpa(td_page_pa,
                                               OPERAND_ID_R8,
                                               TDX_LOCK_EXCLUSIVE,
                                               (page_size_t)page_level_entry,
                                               &td_page_pamt_block,
                                               &td_page_pamt_entry_ptr,
                                               &td_page_locked_flag);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map the new TD private page - error = %llx\n", return_val);
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Update the parent EPT entry with the new TD page HPA and SEPT_PENDING state
    sept_set_leaf_and_release_locks(page_sept_entry_ptr, SEPT_PERMISSIONS_NONE, td_page_pa, SEPT_STATE_PEND_MASK);
    septe_locked_flag = false;

    // Increment TDR child count, use an atomic operation since we have SHARED lock on TDR
    (void)_lock_xadd_64b(&(tdr_ptr->management_fields.chldcnt), 1 << (9 * page_level_entry));

    // Update the new Secure EPT page’s PAMT entry
    td_page_pamt_entry_ptr->pt = PT_REG;
    set_pamt_entry_owner(td_page_pamt_entry_ptr, tdr_pa);
    td_page_pamt_entry_ptr->bepoch.raw = 0;   // Setting BEPOCH to 0 is required to avoid confusion during page export

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (td_page_locked_flag)
    {
        pamt_unwalk(td_page_pa, td_page_pamt_block, td_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, (page_size_t)page_level_entry);
    }
    if (septe_locked_flag)
    {
        sept_lock_release(page_sept_entry_ptr);
    }
    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (page_sept_entry_ptr != NULL)
        {
            free_la(page_sept_entry_ptr);
        }
    }
    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }
    return return_val;
}
