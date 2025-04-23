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
 * @file tdh_mem_page_remove
 * @brief TDHMEMPAGEREMOVE API handler
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


api_error_type tdh_mem_page_remove(page_info_api_input_t target_page_info, uint64_t target_tdr_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa = {.raw = target_tdr_pa};  // TDR physical address
    tdr_t               * tdr_ptr;                          // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;                   // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;               // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;          // Indicate TDR is locked
    tdcs_t              * tdcs_ptr = NULL;                  // Pointer to the TDCS structure (Multi-page)

    // GPA and level related variables
    pa_t                  page_gpa = {.raw = 0};                  // Target page GPA
    page_info_api_input_t gpa_mappings = target_page_info;        // GPA and level
    ia32e_sept_t        * page_sept_entry_ptr = NULL;             // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;                   // Cached SEPT entry of the page
    ept_level_t           page_level_entry = gpa_mappings.level;  // EPT level of the page parent
    bool_t                sept_locked_flag = false;               // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;

    // Removed page variables
    pa_t                  removed_page_pa = {.raw = 0};      // Physical address of the page to-be-removed
    pamt_entry_t        * removed_page_pamt_entry_ptr = NULL;  // Pointer to the to-be-removed page PAMT entry
    bool_t                removed_page_locked_flag = false;  // Indicate PAMT of to-be-removed page is locked

    ia32e_sept_t        * l2_sept_entry_ptr = NULL;

    api_error_type        return_val = UNINITIALIZE_ERROR;

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
                                               false, TDH_MEM_PAGE_REMOVE_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PT, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // Check GPA, lock SEPT and walk to located entry of to-be-removed page
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

    // Verify the located entry points is a leaf entry and relocate is allowed
    if (!is_secure_ept_leaf_entry(&page_sept_entry_copy) ||
        !sept_state_is_seamcall_leaf_allowed(TDH_MEM_PAGE_REMOVE_LEAF, page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
        TDX_ERROR("Is leaf entry, or not allowed in current SEPT entry - 0x%llx!\n", page_sept_entry_copy.raw);
        goto EXIT;
    }

    // Cleanup leftover ACCEPT_COUNTER bits
    sept_cleanup_if_pending(&page_sept_entry_copy, page_level_entry);

    // Get removed page HPA PAMT entry
    removed_page_pa.raw = leaf_ept_entry_to_hpa(page_sept_entry_copy, page_gpa.raw, page_level_entry);

    if ((return_val = pamt_implicit_get_and_lock(removed_page_pa, (page_size_t)page_level_entry,
                      TDX_LOCK_EXCLUSIVE, &removed_page_pamt_entry_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Can't acquire lock on removed page pamt entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    removed_page_locked_flag = true;

    if (sept_state_is_tlb_tracking_required(page_sept_entry_copy) &&
        op_state_is_tlb_tracking_required(tdcs_ptr->management_fields.op_state))
    {
        // The TD may be running and this page must be blocked and tracked before it's removed.

        // Verify the entry is *BLOCKED (originally MAPPED or PENDING)
        if (!sept_state_is_any_blocked(page_sept_entry_copy))
        {
            return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
            TDX_ERROR("Promoted SEPT entry is not blocked - 0x%llx\n", page_sept_entry_copy.raw);
            goto EXIT;
        }

        // Check TLB tracking
        if (!is_tlb_tracked(tdcs_ptr, removed_page_pamt_entry_ptr->bepoch))
        {
            TDX_ERROR("Target splitted page TLB tracking not done\n");
            return_val = api_error_with_operand_id(TDX_TLB_TRACKING_NOT_DONE, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if (!sept_state_is_aliased(page_sept_entry_copy, vm_id))
        {
            continue;
        }

        return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, page_gpa, &page_level_entry, &l2_sept_entry_ptr);
        if (return_val != TDX_SUCCESS)
        {
            FATAL_ERROR(); // Should not happen - no need to free the L2 SEPT PTR's
        }

        atomic_mem_write_64b(&l2_sept_entry_ptr->raw, SEPTE_L2_INIT_VALUE);

        free_la(l2_sept_entry_ptr);
    }

    // Atomically set the removed page Secure-EPT entry to SEPT_FREE or REMOVED (if import is in progress)
    septe_set_free_or_removed_and_release_locks(&page_sept_entry_copy, tdcs_ptr);
    atomic_mem_write_64b(&page_sept_entry_ptr->raw, page_sept_entry_copy.raw);
    septe_locked_flag = false;

    // Atomically decrement TDR child count by the amount of removed 4KB pages
    (void)_lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, -(1 << (9 * page_level_entry)));

    // Update the removed page PAMT entry to FREE
    removed_page_pamt_entry_ptr->pt = PT_NDA;

    // Update RCX with the removed page HPA
    local_data_ptr->vmm_regs.rcx = removed_page_pa.raw;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (removed_page_locked_flag)
    {
        pamt_implicit_release_lock(removed_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE);
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
