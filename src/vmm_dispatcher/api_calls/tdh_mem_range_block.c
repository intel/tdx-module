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
 * @file tdh_mem_range_block
 * @brief TDHMEMRANGEBLOCK API handler
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

static void block_sept_entry(ia32e_sept_t* sept_entry, ept_level_t level)
{
    sept_cleanup_if_pending(sept_entry, level);
    switch (sept_entry->raw & SEPT_STATE_ENCODING_MASK)
    {
        case SEPT_STATE_NL_MAPPED_MASK:
            // No need to save the permission bits
            sept_update_state(sept_entry, SEPT_STATE_NL_BLOCKED_MASK);
            // Clean up the permissions to mark as not-present
            // No need to save the permissions bits as the unlock will set it back defaults
            sept_entry->raw &= ~SEPT_PERMISSIONS_MASK;
            break;
        case SEPT_STATE_MAPPED_MASK:
        case SEPT_STATE_BLOCKEDW_MASK:
            // No need to save the L1 permission bits; their values are implicit
            sept_entry->raw &= ~SEPT_PERMISSIONS_MASK;    // set permissions to NONE
            sept_update_state(sept_entry, SEPT_STATE_BLOCKED_MASK);
            break;
        case SEPT_STATE_PEND_MASK:
        case SEPT_STATE_PEND_BLOCKEDW_MASK:
            // No need to save the permission bits
            sept_update_state(sept_entry, SEPT_STATE_PEND_BLOCKED_MASK);
            break;
        default:
            FATAL_ERROR();
    }
}

static void block_l2_sept_entry(ia32e_sept_t* l2_sept_entry_ptr, bool_t is_l1_blockedw)
{
    ia32e_sept_t tmp_ept_entry = { .raw = l2_sept_entry_ptr->raw };

    // Block the L2 Secure EPT entry
    // If leaf:
    //      If is_blockedw, save the RXsXu bits to TDR, TDXS and TDXU
    //      Else, save the RWXsXu bits to TDR, TDW, TDXS and TDXU
    // Clear RXsXu bits to 0
    // Set the state to L2_BLOCKED (if leaf) or L2_NL_BLOCKED (if non-leaf)

    if (is_secure_ept_leaf_entry(&tmp_ept_entry))
    {
        if (!is_l1_blockedw)
        {
            tmp_ept_entry.l2_encoding.tdwr = tmp_ept_entry.l2_encoding.w;
        }

        tmp_ept_entry.l2_encoding.mt0_tdrd = tmp_ept_entry.l2_encoding.r;
        tmp_ept_entry.l2_encoding.mt1_tdxs = tmp_ept_entry.l2_encoding.x;
        tmp_ept_entry.l2_encoding.mt2_tdxu = tmp_ept_entry.l2_encoding.xu;

        sept_l2_update_state(&tmp_ept_entry, SEPT_STATE_L2_BLOCKED_MASK);
    }
    else
    {
        sept_l2_update_state(&tmp_ept_entry, SEPT_STATE_L2_NL_BLOCKED_MASK);
    }

    tmp_ept_entry.l2_encoding.r  = 0;
    tmp_ept_entry.l2_encoding.w  = 0;
    tmp_ept_entry.l2_encoding.x  = 0;
    tmp_ept_entry.l2_encoding.xu = 0;

    atomic_mem_write_64b(&l2_sept_entry_ptr->raw, tmp_ept_entry.raw);
}

api_error_type tdh_mem_range_block(page_info_api_input_t sept_level_and_gpa,
                        uint64_t target_tdr_pa)
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
    pa_t                  page_gpa;                  // Target page GPA
    ia32e_sept_t        * page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           page_level_entry = sept_level_and_gpa.level; // SEPT entry level of the page
    bool_t                sept_locked_flag = false;  // Indicate SEPT is locked
    bool_t                septe_locked_flag = false; // Indicate SEPT entry is locked

    // Blocked TD private page variables
    pa_t                  td_page_pa;                    // Physical address of the blocked TD page
    pamt_entry_t        * td_page_pamt_entry_ptr = NULL; // Pointer to the TD PAMT entry

    ia32e_sept_t        * l2_sept_entry_ptr = NULL;

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page (Shared lock!)
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
                                               false, TDH_MEM_RANGE_BLOCK_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(sept_level_and_gpa, LVL_PT, tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", sept_level_and_gpa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(sept_level_and_gpa);

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_EXCLUSIVE,
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

    // Lock the SEPT entry
    return_val = sept_lock_acquire_host(page_sept_entry_ptr);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry after being locked
    page_sept_entry_copy.raw = page_sept_entry_ptr->raw;

    // Verify the Secure-EPT entry to block
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_RANGE_BLOCK_LEAF, page_sept_entry_copy))
    {
        if (sept_state_is_any_blocked(page_sept_entry_copy))
        {
            return_val = api_error_with_operand_id(TDX_GPA_RANGE_ALREADY_BLOCKED, OPERAND_ID_RCX);
        }
        else
        {
            return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        }

        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, sept_level_and_gpa.level, local_data_ptr);
        TDX_ERROR("MEM.RANGE.BLOCK not allowed in current SEPT entry - 0x%llx!\n", page_sept_entry_copy.raw);
        goto EXIT;
    }

    // Prepare the EPT entry value with TDB set, RWX cleared and suppress VE set
    ia32e_sept_t new_septe_val;
    new_septe_val.raw = page_sept_entry_copy.raw;

    block_sept_entry(&new_septe_val, sept_level_and_gpa.level);

    // Update the SEPT entry in memory
    atomic_mem_write_64b(&page_sept_entry_ptr->raw, new_septe_val.raw);

    // Block any L2 aliases
    // This is done after blocking the L1 SEPT entry.  This way, if there's an EPT violation in an
    // L2 VM before we blocked the L2 SEPT entries, the VM exit handler will understand that the
    // range has been blocked and will TD exit to the host VMM.
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

        block_l2_sept_entry(l2_sept_entry_ptr, sept_state_is_any_blockedw(page_sept_entry_copy));

        free_la(l2_sept_entry_ptr);
    }

    /*---------------------------------------------------------------
        ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    ---------------------------------------------------------------*/

    // Atomically update the PAMT.BEPOCH for the blocked page
    // Read the TD’s epoch (TDCS.TD_EPOCH) and write it to the PAMT entry of the
    // blocked Secure EPT page or TD private page (PAMT.BEPOCH)
    td_page_pa.raw = 0;
    td_page_pa.page_4k_num = page_sept_entry_copy.base;

    if (is_secure_ept_leaf_entry(&page_sept_entry_copy))
    {
        td_page_pamt_entry_ptr = pamt_implicit_get(td_page_pa, (page_size_t)page_level_entry);
    }
    else
    {
        td_page_pamt_entry_ptr = pamt_implicit_get(td_page_pa, PT_4KB);
    }

    td_page_pamt_entry_ptr->bepoch.raw = tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch;

EXIT:

    // Release all acquired locks
    if (td_page_pamt_entry_ptr != NULL)
    {
        free_la(td_page_pamt_entry_ptr);
    }

    if (septe_locked_flag)
    {
        sept_lock_release(page_sept_entry_ptr);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
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
