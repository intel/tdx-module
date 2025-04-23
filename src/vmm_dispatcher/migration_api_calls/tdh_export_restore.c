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
 * @file tdh_export_restore
 * @brief TDHEXPORTRESTORE API handler
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

api_error_type tdh_export_restore(gpa_list_info_t gpa_list_info, uint64_t target_tdr_pa)
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

    // GPA list
    pa_t                    gpa;
    gpa_list_entry_t       *gpa_list_p = NULL;
    gpa_list_entry_t        gpa_list_entry;
    uint64_t                entry_num = gpa_list_info.first_entry;
    uint64_t                problem_ops_count = 0;

    // Secure-EPT
    bool_t                  sept_locked_flag = false;   // Indicate SEPT is locked
    ia32e_sept_t           *sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t            sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t             sept_entry_level = LVL_PT;
    bool_t                  septe_locked_flag = false;  // Indicate SEPTE is locked

    api_error_type          return_val = TDX_OPERAND_INVALID;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
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
                                               TDH_EXPORT_RESTORE_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Acquire Secure-EPT lock as shared
    if (acquire_sharex_lock(&tdcs_p->executions_ctl_fields.secure_ept_lock, TDX_LOCK_SHARED) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT_TREE);
        TDX_ERROR("Failed to acquire SEPT tree lock");
        goto EXIT;
    }
    sept_locked_flag = true;

    if (gpa_list_info.format != GPA_LIST_FORMAT_GPA_ONLY)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("GPA list info format is invalid = 0x%llx\n", gpa_list_info.format);
        goto EXIT;
    }

    return_val = check_and_map_gpa_list(gpa_list_info, &gpa_list_p);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        TDX_ERROR("GPA list info is incorrect = 0x%llx\n", gpa_list_info.raw);
        goto EXIT;
    }

    // Loop over the GPA list
    for (entry_num = gpa_list_info.first_entry; entry_num <= gpa_list_info.last_entry; entry_num++)
    {
        gpa_list_entry_status_t err_status = GPA_ENTRY_STATUS_SUCCESS;
        gpa_list_entry = gpa_list_p[entry_num];

        do
        {
            if (is_gpa_list_entry_op_cancel_or_nop(gpa_list_entry))
            {
                if (!gpa_list_entry_is_valid(gpa_list_entry))
                {
                    gpa_list_entry.operation = GPA_ENTRY_OP_NOP;
                    gpa_list_entry.status = GPA_ENTRY_STATUS_GPA_LIST_ENTRY_INVALID;
                    gpa_list_p[entry_num] = gpa_list_entry;
                    return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_GPA_LIST_ENTRY);
                    TDX_ERROR("Invalid GPA entry in the list - 0x%llx\n", gpa_list_entry.raw);
                    goto EXIT;
                }

                err_status = GPA_ENTRY_STATUS_SKIPPED; break;
            }

            if (!check_and_get_gpa_from_entry(gpa_list_entry, tdcs_p->executions_ctl_fields.gpaw, &gpa, tdcs_p->executions_ctl_fields.virt_maxpa))
            {
                gpa_list_entry.operation = GPA_ENTRY_OP_NOP;
                gpa_list_entry.status = GPA_ENTRY_STATUS_GPA_LIST_ENTRY_INVALID;
                gpa_list_p[entry_num] = gpa_list_entry;
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_GPA_LIST_ENTRY);
                TDX_ERROR("Invalid GPA entry in the list - 0x%llx\n", gpa_list_entry.raw);
                goto EXIT;
            }

            sept_entry_level = LVL_PT;
            // Walk the Secure-EPT to locate the parent entry for the new TD page
            return_val = walk_private_gpa(tdcs_p, gpa, tdr_p->key_management_fields.hkid,
                                          &sept_entry_ptr, &sept_entry_level, &sept_entry_copy);

            if (return_val != TDX_SUCCESS)
            {
                err_status = GPA_ENTRY_STATUS_SEPT_WALK_FAILED; break;
            }

            // Lock the SEPT entry in memory
            return_val = sept_lock_acquire_host(sept_entry_ptr);
            if (TDX_SUCCESS != return_val)
            {
                err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_BUSY_HOST_PRIORITY; break;
            }
            septe_locked_flag = true;

            // Read the SEPT entry value again after it has been locked
            sept_entry_copy = *sept_entry_ptr;

            // Verify the Secure-EPT entry is *EXPORTED_*
            if (!sept_state_is_seamcall_leaf_allowed(TDH_EXPORT_RESTORE_LEAF, sept_entry_copy))
            {
                err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT; break;
            }

            // Atomically decrement MIG_COUNT
            uint64_t old_value = _lock_xadd_64b(&tdcs_p->migration_fields.mig_count, (uint64_t)-1);
            tdx_sanity_check(old_value != 0, SCEC_SEAMCALL_SOURCE(TDH_EXPORT_RESTORE_LEAF), 0);

            // Prepare the EPT entry value:
            //   - If the SEPT state is one of the PENDING_* states, update it to PENDING.
            //     Else, update it to MAPPED
            //   - Restore W
            //   - Clear TDBW and TDEX
            //   - Set SVE to ~P
            //   - Release the entry lock
            ia32e_sept_t new_sept_entry = sept_entry_copy;
            if (sept_state_is_any_pending(new_sept_entry))
            {
                sept_update_state(&new_sept_entry, SEPT_STATE_PEND_MASK);
            }
            else
            {
                sept_update_state(&new_sept_entry, SEPT_STATE_MAPPED_MASK);
                new_sept_entry.w = 1;
            }

            // Write the new SEPT entry value to memory in a single 64b write.
            //  The new SEPT entry value is written as unlocked.
            atomic_mem_write_64b(&sept_entry_ptr->raw, new_sept_entry.raw);
            sept_lock_release(sept_entry_ptr);
            septe_locked_flag = false;

            gpa_list_entry.status = GPA_ENTRY_STATUS_SUCCESS;

        } while(0);

        IF_RARE (err_status != GPA_ENTRY_STATUS_SUCCESS)
        {
            gpa_list_entry.operation = GPA_ENTRY_OP_NOP;
            gpa_list_entry.status = err_status;
            if (err_status != GPA_ENTRY_STATUS_SKIPPED)
            {
                problem_ops_count++;
            }
        }

        // Write back the updated GPA list entry to memory
        gpa_list_p[entry_num] = gpa_list_entry;

        if (septe_locked_flag)
        {
            sept_lock_release(sept_entry_ptr);
            septe_locked_flag = false;
        }

        if (sept_entry_ptr != NULL)
        {
            free_la(sept_entry_ptr);
            sept_entry_ptr = NULL;
        }

        if (entry_num < gpa_list_info.last_entry)
        {
            // If we are not on the last entry, then check pending interrupts
            if (is_interrupt_pending_host_side())
            {
                // increment the entry_num to the index of NEXT entry before
                // breaking the loop and returning to the VMM
                entry_num++;

                // Updated GPA_LIST_INFO is returned in RCX.
                return_val = TDX_INTERRUPTED_RESUMABLE;
                break;
            }
        }
        else // Loop is finished
        {
            // If the last entry was 511, entry_num will become 512, and on later assignment to first_entry
            // will become 0, as expected by the definition
            return_val = api_error_with_operand_id(TDX_SUCCESS, problem_ops_count);
        }
    }

EXIT:

    gpa_list_info.first_entry = entry_num;

    local_data_ptr->vmm_regs.rcx = gpa_list_info.raw;

    if (gpa_list_p != NULL)
    {
        free_la(gpa_list_p);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_p->executions_ctl_fields.secure_ept_lock);
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
