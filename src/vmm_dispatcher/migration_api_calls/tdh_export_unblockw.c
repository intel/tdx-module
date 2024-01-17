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
 * @file tdh_export_unblockw
 * @brief TDHEXPORTUNBLOCKW API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/op_state_lookup.h"
#include "auto_gen/sept_state_lookup.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"
#include "metadata_handlers/metadata_generic.h"
#include "memory_handlers/sept_manager.h"

api_error_type tdh_export_unblockw(uint64_t page_pa, uint64_t target_tdr_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();

    // TDR and TDCS
    tdr_t                  *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t                    tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t            tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t           *tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    tdcs_t                 *tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t                  tdr_locked_flag = false; // Indicate TDR is locked

    bool_t                  op_state_locked_flag = false; // Indicate OP is locked

    // GPA and Secure-EPT
    page_info_api_input_t   gpa_and_level;              // GPA and level
    bool_t                  sept_locked_flag = false;   // Indicate SEPT is locked
    ia32e_sept_t           *page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t            page_sept_entry_copy;       // Cached SEPT entry of the page
    bool_t                  septe_locked_flag = false;  // Indicate SEPTE is locked

    uint64_t old_value;

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    gpa_and_level.raw = page_pa;

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
                                                 &tdr_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_SHARED, false,
                                                TDH_EXPORT_UNBLOCKW_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Verify that level input is 4KB

    // Verify that GPA mapping input reserved fields equal zero
    if (!is_reserved_zero_in_mappings(gpa_and_level))
    {
        TDX_ERROR("Reserved fields in GPA mappings are not zero\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify mapping level input is valid (only 4KB is supported)
    if (gpa_and_level.level != LVL_PT)
    {
        TDX_ERROR("Input GPA level (=%u) is not valid\n", gpa_and_level.level);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify GPA is aligned
    if (!is_gpa_aligned(gpa_and_level))
    {
        TDX_ERROR("Page to accept GPA (=%llx) is not aligned.\n", gpa_and_level.gpa);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Walk the Secure EPT to locate the leaf entry of the page
    pa_t          page_gpa = page_info_to_pa(gpa_and_level);
    ept_level_t   page_level_entry = gpa_and_level.level; // SEPT entry level of the page

    return_val = lock_sept_check_and_walk_private_gpa(tdcs_p,
                                                  OPERAND_ID_RCX,
                                                  page_gpa,
                                                  tdr_p->key_management_fields.hkid,
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

        TDX_ERROR("Secure EPT lock and walk failed. Error code 0x%llx\n", return_val);
        goto EXIT;
    }

    // Lock SEPT host side
    return_val = sept_lock_acquire_host(page_sept_entry_ptr);
    if (TDX_SUCCESS != return_val)
    {
        TDX_ERROR("Secure EPT lock host size failed.\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry (again after locking)
    page_sept_entry_copy = *page_sept_entry_ptr;

    // Verify the entry is a leaf entry, and the SEAMCALL allowed
    if (!sept_state_is_seamcall_leaf_allowed(TDH_EXPORT_UNBLOCKW_LEAF, page_sept_entry_copy))
    {
        TDX_ERROR("SEAMCALL not allowed in this state (page_sept_entry_copy.raw0x%llx)\n", page_sept_entry_copy.raw);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, (ept_level_t)gpa_and_level.level, local_data_ptr);
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        goto EXIT;
    }

    /*
     * Prepare the EPT entry value:
     *  - Update the state bits
     *  - Clear SVE if restored to PENDING
     *  - Release the TDHL lock
     */
    ia32e_sept_t new_septe;
    new_septe.raw = page_sept_entry_copy.raw;

    // Update the local copy of the state:  see the SEPT entry state diagram in the TD Migration FAS
    switch (page_sept_entry_copy.raw & SEPT_STATE_ENCODING_MASK)
    {
        case SEPT_STATE_BLOCKEDW_MASK:
            sept_update_state(&new_septe, SEPT_STATE_MAPPED_MASK);
            new_septe.w = 1;
            break;
        case SEPT_STATE_EXP_BLOCKEDW_MASK:
        case SEPT_STATE_EXP_DIRTY_BLOCKEDW_MASK:
            sept_update_state(&new_septe, SEPT_STATE_EXP_DIRTY_MASK);
            new_septe.w = 1;
            break;
        case SEPT_STATE_PEND_BLOCKEDW_MASK:
            sept_update_state(&new_septe, SEPT_STATE_PEND_MASK);
            break;
        case SEPT_STATE_PEND_EXP_BLOCKEDW_MASK:
        case SEPT_STATE_PEND_EXP_DIRTY_BLOCKEDW_MASK:
            sept_update_state(&new_septe, SEPT_STATE_PEND_EXP_DIRTY_MASK);
            break;
        default:
            FATAL_ERROR();
    }

    atomic_mem_write_64b(&page_sept_entry_ptr->raw, new_septe.raw);

    /*---------------------------------------------------------------
       ALL_CHECKS_PASSED:  The function is guaranteed to succeed
   ---------------------------------------------------------------*/

   if (sept_state_is_any_exported_and_non_dirty(page_sept_entry_copy))
   {
       // The page has been exported, mark it as dirty
       old_value = _lock_xadd_64b(&(tdcs_p->migration_fields.dirty_count), 1);
       tdx_debug_assert(old_value < (1ULL << 63));
   }

EXIT:
    // Release all acquired locks
    if (septe_locked_flag)
    {
        sept_lock_release(page_sept_entry_ptr);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_p->executions_ctl_fields.secure_ept_lock);
        if (page_sept_entry_ptr != NULL)
        {
            free_la(page_sept_entry_ptr);
        }
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp(&(tdcs_p->management_fields.op_state_lock), TDX_LOCK_SHARED);
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_p);
    }

    return return_val;
}

