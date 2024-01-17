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
 * @file tdh_mem_range_unblock
 * @brief TDHMEMRANGEUNBLOCK API handler
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


api_error_type tdh_mem_range_unblock(page_info_api_input_t gpa_page_info, uint64_t target_tdr_pa)
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
    ia32e_sept_t        * sept_entry_ptr = NULL;        // SEPT entry of the page
    ia32e_sept_t          sept_entry_copy;              // Cached SEPT entry of the page
    ept_level_t           sept_level_entry = gpa_mappings.level; // SEPT entry level of the page
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;    // Indicate SEPT entry is locked

    // Blocked TD private page variables
    pa_t                  unblocked_page_pa = {.raw = 0};      // Physical address of the page to-be-removed
    pamt_entry_t        * unblocked_page_pamt_entry_ptr = NULL;  // Pointer to the to-be-removed page PAMT entry


    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
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
                                               false, TDH_MEM_RANGE_UNBLOCK_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PT, tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl))
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
                                                      TDX_LOCK_EXCLUSIVE,
                                                      &sept_entry_ptr,
                                                      &sept_level_entry,
                                                      &sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry
    return_val = sept_lock_acquire_host(sept_entry_ptr);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry after being locked
    sept_entry_copy.raw = sept_entry_ptr->raw;


    // Verify if BLOCKW is allowed for the SEPT entry state.
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_RANGE_UNBLOCK_LEAF, sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, gpa_mappings.level, local_data_ptr);
        TDX_ERROR("TDH_MEM_RANGE_UNBLOCK_LEAF is not allowed in current SEPT entry state - 0x%llx\n", sept_entry_copy.raw);
        goto EXIT;
    }
    // No need to cleanup ACCEPT_COUNTER bit, the page can't be PENDING
    tdx_debug_assert((sept_entry_ptr->raw & SEPT_STATE_ENCODING_MASK) != SEPT_STATE_PEND_MASK);

    if (sept_state_is_tlb_tracking_required(sept_entry_copy) &&
        op_state_is_tlb_tracking_required(tdcs_ptr->management_fields.op_state))
    {
        // Get the PAMT entry of the unblocked page
        if (is_secure_ept_leaf_entry(&sept_entry_copy))
        {
            // Get unblocked page HPA PAMT entry
            unblocked_page_pa.raw = leaf_ept_entry_to_hpa(sept_entry_copy, page_gpa.raw, sept_level_entry);
            // Leaf points to a PT_REG page, get its PAMT entry
            unblocked_page_pamt_entry_ptr = pamt_implicit_get(unblocked_page_pa, (page_size_t)sept_level_entry);
        }
        else
        {
            // Get unblocked page HPA PAMT entry
            unblocked_page_pa.raw = 0;
            unblocked_page_pa.page_4k_num = sept_entry_copy.base;
            // Non-leaf points to a PT_SEPT page, get its PAMT entry
            unblocked_page_pamt_entry_ptr = pamt_implicit_get(unblocked_page_pa, PT_4KB);
        }

        // The TD may be running and this page must be blocked and tracked before it's removed.

        // Verify the TLB tacking of the blocked Secure-EPT page has been completed
        if (!is_tlb_tracked(tdcs_ptr, unblocked_page_pamt_entry_ptr->bepoch))
        {
            TDX_ERROR("Blocked SEPT page TLB tracking is not complete\n");
            return_val = api_error_with_operand_id(TDX_TLB_TRACKING_NOT_DONE, OPERAND_ID_SEPT_TREE);
            goto EXIT;
        }
    }

    //---------------------------------------------------------------
    //  ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    //---------------------------------------------------------------

    // Unblock any L2 aliases
    // This is done before unblocking the L1 SEPT entry.  This way, if there's an EPT violation in an
    // L2 VM before we blocked the L2 SEPT entries, the VM exit handler will understand that the
    // range has been blocked and will TD exit to the host VMM.
    if (!sept_state_is_any_pending(sept_entry_copy))
    {
        for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
        {
            if (!sept_state_is_aliased(sept_entry_copy, vm_id))
            {
                continue;
            }

            ia32e_sept_t* l2_sept_entry_ptr = NULL;

            return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, page_gpa, &sept_level_entry, &l2_sept_entry_ptr);
            if (return_val != TDX_SUCCESS)
            {
                FATAL_ERROR(); // Should not happen - no need to free the L2 SEPT PTR's
            }

            sept_l2_unblock(l2_sept_entry_ptr);

            free_la(l2_sept_entry_ptr);
        }
    }

    // Unblock and unlock the SEPT entry's local copy
    ia32e_sept_t epte_val;
    epte_val.raw = sept_entry_copy.raw;

    sept_unblock(&epte_val);
    sept_lock_release_local(&epte_val);

    // Write the whole 64-bit EPT entry in a single operation
    atomic_mem_write_64b(&sept_entry_ptr->raw, epte_val.raw);
    septe_locked_flag = false;

EXIT:

    if (unblocked_page_pamt_entry_ptr)
    {
        free_la(unblocked_page_pamt_entry_ptr);
    }

    if (septe_locked_flag)
    {
        sept_lock_release(sept_entry_ptr);
    }

    // Release all acquired locks and free keyhole mappings
    if (sept_locked_flag)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (sept_entry_ptr != NULL)
        {
            free_la(sept_entry_ptr);
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
