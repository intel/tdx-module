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
 * @file tdh_export_mem
 * @brief TDH_EXPORT_MEM API handler
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
#include "memory_handlers/keyhole_manager.h"

typedef   uint8_t mac_list_entry_t[MAC256_LEN];

static api_error_type handle_new_command(gpa_list_info_t gpa_list_info, tdcs_t* tdcs_p,
                                         migsc_t* migsc_p, uint16_t migs_i, mbmd_t* mbmd,
                                         mbmd_t* mbmd_p, mac_list_entry_t** mac_list_p)
{
    /*----------------------------------------------
       This is a new invocation, not a resumption.
    ----------------------------------------------*/
    // On a new invocation, the GPA list must start from entry 0
    if (gpa_list_info.first_entry != 0)
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
    }

    // Initialize the MIGSC if needed
    if (!tdcs_p->f_migsc_links[migs_i].initialized)
    {
        tdcs_p->f_migsc_links[migs_i].initialized = true;
        migsc_init(migsc_p, &tdcs_p->migration_fields.mig_enc_working_key);
    }

    // Mark this flow as non-interrupted
    migsc_p->interrupted_state.valid = false;

    // Set the initial migration buffers counter:  GPA list and up to 2 Page MAC buffers
    migsc_p->interrupted_state.num_processed = 1;
    if (mac_list_p[0] != NULL)
    {
        migsc_p->interrupted_state.num_processed++;
    }
    if (mac_list_p[1] != NULL)
    {
        migsc_p->interrupted_state.num_processed++;
    }

    // Increment the IV counter so we don't reuse a previous IV even if aborted
    migsc_p->iv_counter++;

    // Build the MBMD
    mbmd->header.mig_version = (uint16_t)tdcs_p->migration_fields.mig_working_version; // Current MBMD version
    mbmd->header.size = sizeof(mbmd_t);
    mbmd->header.migs_index = 0;   // Real value is written later, after MAC calculation
    mbmd->header.mb_type = MB_TYPE_MEM;
    mbmd->header.reserved_1 = 0;
    mbmd->header.mb_counter = migsc_p->next_mb_counter;
    mbmd->header.mig_epoch = tdcs_p->migration_fields.mig_epoch;
    mbmd->header.iv_counter = 0;   // Real value is written later, after MAC calculation

    mbmd->mem.num_gpas = gpa_list_info.last_entry + 1;
    mbmd->mem.reserved = 0;

    reset_to_next_iv(migsc_p, migsc_p->iv_counter, migs_i);
    if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (const uint8_t*)&mbmd->mem,
                            MBMD_SIZE_NO_MAC(mbmd->mem)) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }
    if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mbmd->mem.mac) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }

    // Update the MBMD with values not included in the MAC calculation
    mbmd->header.migs_index = migs_i;
    mbmd->header.iv_counter = migsc_p->iv_counter;

    // Write out the MBMD
    copy_mbmd(mbmd_p, mbmd);

    return TDX_SUCCESS;
}

static api_error_type handle_resumed_command(gpa_list_info_t gpa_list_info, tdcs_t* tdcs_p,
                                             migsc_t* migsc_p, uint16_t migs_i,
                                             pa_t mig_buff_list_pa, pa_t* mac_list_pa)
{
    tdx_module_local_t* local_data_ptr = get_local_data();

    /*---------------------------------------------------------------
       This is a resumption of a previously-interrupted invocation
    ---------------------------------------------------------------*/

    // Check that the migration stream is enabled
    if (!tdcs_p->f_migsc_links[migs_i].initialized)
    {
        return TDX_MIGRATION_STREAM_STATE_INCORRECT;
    }

    // Check the interrupted flag, then clear it
    if (!migsc_p->interrupted_state.valid)
    {
        return TDX_INVALID_RESUMPTION;
    }

    migsc_p->interrupted_state.valid = false;

    // Check proper resume conditions
    if ((migsc_p->interrupted_state.func.raw != local_data_ptr->vmm_regs.rax) ||
        (migsc_p->interrupted_state.gpa_list_info.raw != gpa_list_info.raw) ||
        (migsc_p->interrupted_state.mig_buff_list_pa.raw != mig_buff_list_pa.raw) ||
        (migsc_p->interrupted_state.mac_list_pa[0].raw != mac_list_pa[0].raw) ||
        (migsc_p->interrupted_state.mac_list_pa[1].raw != mac_list_pa[1].raw) ||
        (migsc_p->mbmd.mem.header.mig_epoch != tdcs_p->migration_fields.mig_epoch))
    {
        return TDX_INVALID_RESUMPTION;
    }

    return TDX_SUCCESS;
}

static api_error_type check_mbmd(migs_index_and_cmd_t migs_i_and_cmd, gpa_list_info_t gpa_list_info,
                                 tdcs_t* tdcs_p, uint16_t migs_i, migsc_t* migsc_p, mac_list_entry_t** mac_list_p,
                                 mbmd_t* mbmd, mbmd_t* mbmd_p, pa_t mig_buff_list_pa, pa_t* mac_list_pa)
{
    api_error_type return_val = TDX_SUCCESS;

    if (migs_i_and_cmd.command == MIGS_INDEX_COMMAND_NEW)
    {
        return_val = handle_new_command(gpa_list_info, tdcs_p, migsc_p, migs_i, mbmd, mbmd_p, mac_list_p);
    }
    else // migs_i_and_cmd.command == MIGS_INDEX_COMMAND_RESUME
    {
        return_val = handle_resumed_command(gpa_list_info, tdcs_p, migsc_p, migs_i, mig_buff_list_pa, mac_list_pa);
    }

    return return_val;
}

static gpa_list_entry_status_t handle_export_in_order(tdcs_t* tdcs_p, gpa_list_entry_t* gpa_list_entry, ia32e_sept_t sept_entry_copy)
{
    // Export is in the in-order phase
    if (gpa_list_entry->operation == GPA_ENTRY_OP_CANCEL)
    {
        // Check that the operation is allowed during in-order export, per the SEPT entry state
        if (!sept_state_is_export_cancel_allowed(sept_entry_copy))
        {
            return GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT;
        }
    }
    else
    {
        // Operation is either MIGRATE or REMIGRATE: on input they both mean MIGRATE.

        // During in-order-export, if the SEPT entry state indicates that this is a first-time export,
        // mark the operation as MIGRATE. Else, mark as REMIGRATE.
        if (sept_state_is_first_time_export_allowed(sept_entry_copy))
        {
            gpa_list_entry->operation = GPA_ENTRY_OP_MIGRATE;
        }
        else if (sept_state_is_any_exported_and_dirty(sept_entry_copy))
        {
            gpa_list_entry->operation = GPA_ENTRY_OP_REMIGRATE;
        }
        else
        {
            return GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT;
        }

        // Checks for live export
        if (tdcs_p->management_fields.op_state == OP_STATE_LIVE_EXPORT)
        {
            // A live export was requested; check that it's allowed
            if (!sept_state_is_live_export_allowed(sept_entry_copy))
            {
                return GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT;
            }

            // The TD may still run.  If SEPT entry state indicates that TLB tracking for
            // this page needs to be checked, check TLB tracking.  Checking is done vs.
            // TDCS.BW_EPOCH that has been updated by TDH.EXPORT.BLOCKW.
            if (sept_state_is_tlb_tracking_required(sept_entry_copy) &&
                (!is_tlb_tracked(tdcs_p, tdcs_p->migration_fields.bw_epoch)))
            {
                return GPA_ENTRY_STATUS_TLB_TRACKING_NOT_DONE;
            }
        }
    }

    return GPA_ENTRY_STATUS_SUCCESS;
}

static gpa_list_entry_status_t handle_export_out_of_order(gpa_list_entry_t* gpa_list_entry, ia32e_sept_t sept_entry_copy)
{
    // Export is in the out-of-order phase
    if (gpa_list_entry->operation == GPA_ENTRY_OP_CANCEL)
    {
        // CANCEL can only be done during in-order export
        return GPA_ENTRY_STATUS_OP_STATE_INCORRECT;
    }
    else
    {
        // Operation is either MIGRATE or REMIGRATE: on input they both mean MIGRATE.
        // During out-of-order export, the operation is always MIGRATE.
        if (sept_state_is_paused_export_allowed(sept_entry_copy))
        {
            gpa_list_entry->operation = GPA_ENTRY_OP_MIGRATE;
        }
        else
        {
            return GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT;
        }
    }

    return GPA_ENTRY_STATUS_SUCCESS;
}

static gpa_list_entry_status_t handle_export_by_order(tdcs_t* tdcs_p, gpa_list_entry_t* gpa_list_entry, ia32e_sept_t sept_entry_copy)
{
    if (op_state_is_export_in_order(tdcs_p->management_fields.op_state))
    {
        return handle_export_in_order(tdcs_p, gpa_list_entry, sept_entry_copy);
    } // if export_in_order
    else
    {
        return handle_export_out_of_order(gpa_list_entry, sept_entry_copy);
    }
}

static gpa_list_entry_status_t handle_operation(gpa_list_entry_t gpa_list_entry, uint64_t* mig_count_increment,
                                                ia32e_sept_t* sept_entry_copy, uint64_t* dirty_count_increment,
                                                page_list_entry_t* mig_buff_list_entry)
{
    if (gpa_list_entry.operation == GPA_ENTRY_OP_CANCEL)
    {
        *mig_count_increment = (uint64_t)-1;   // MIG_COUNT is updated later, after all error checking
        if (sept_state_is_any_exported_and_dirty(*sept_entry_copy))
        {
            *dirty_count_increment = (uint64_t)-1;   // DIRTY_COUNT is updated later, after all error checking
        }

        // No migration buffer is used
        mig_buff_list_entry->invalid = 1;
        if (gpa_list_entry.pending)
        {
            sept_update_state(sept_entry_copy, SEPT_STATE_PEND_MASK);
        }
        else
        {
            sept_update_state(sept_entry_copy, SEPT_STATE_MAPPED_MASK);
            sept_entry_copy->w = 1;
        }
    }
    else
    {
        // This is either MIGRATE or REMIGRATE

        if (!sept_state_is_any_exported(*sept_entry_copy))
        {
            // The page has not been exported before, increment MIG_COUNT
            *mig_count_increment = 1;   // MIG_COUNT is updated later, after all error checking
        }
        else if (sept_state_is_any_exported_and_dirty(*sept_entry_copy))
        {
            // The page has been exported an is dirty, decrement DIRTY_COUNT
            *dirty_count_increment = (uint64_t)-1;   // DIRTY_COUNT is updated later, after all error checking
        }

        if (gpa_list_entry.pending)
        {
            // No migration buffer is used
            mig_buff_list_entry->invalid = 1;
            sept_update_state(sept_entry_copy, SEPT_STATE_PEND_EXP_BLOCKEDW_MASK);
        }
        else
        {
            // Migration buffer is going to be used
            if (mig_buff_list_entry->invalid != 0)
            {
                //throw GPA_LIST_STATUS(GPA_LIST_ENTRY_t::MIG_BUFFER_NOT_AVAILABLE);
                return GPA_ENTRY_STATUS_MIG_BUFFER_NOT_AVAILABLE;
            }
            sept_update_state(sept_entry_copy, SEPT_STATE_EXP_BLOCKEDW_MASK);
        }
    }

    return GPA_ENTRY_STATUS_SUCCESS;
}

static api_error_type finish_entry_processing(uint64_t* entry_num, gpa_list_info_t gpa_list_info,
                                              migsc_t* migsc_p, pa_t mig_buff_list_pa, pa_t* mac_list_pa,
                                              tdcs_t* tdcs_p, uint32_t problem_ops_count)
{
    api_error_type return_val = TDX_SUCCESS;

    if (*entry_num < gpa_list_info.last_entry)
    {
        // If we are not on the last entry, then check pending interrupts
        if (is_interrupt_pending_host_side())
        {
            // increment the entry_num to the index of NEXT entry before
            // breaking the loop and returning to the VMM
            (*entry_num)++;

            // There is a pending interrupt.  Save the state for the next invocation.
            migsc_p->interrupted_state.valid = true;
            tdx_module_local_t* local_data_ptr = get_local_data();
            migsc_p->interrupted_state.func.raw = local_data_ptr->vmm_regs.rax;
            migsc_p->interrupted_state.gpa_list_info.raw = gpa_list_info.raw;
            migsc_p->interrupted_state.gpa_list_info.first_entry = *entry_num;
            migsc_p->interrupted_state.mig_buff_list_pa.raw = mig_buff_list_pa.raw;
            migsc_p->interrupted_state.mac_list_pa[0] = mac_list_pa[0];
            migsc_p->interrupted_state.mac_list_pa[1] = mac_list_pa[1];
            migsc_p->mbmd.mem.header.mig_epoch = tdcs_p->migration_fields.mig_epoch;

            // Updated GPA_LIST_INFO is returned in RCX.
            return_val = TDX_INTERRUPTED_RESUMABLE;
        }
    }
    else
    {
        // This was the last GPA list entry.  Update the migration counters and mark as non-interrupted.
        // If the last entry was 511, entry_num will become 512, and on later assignment to first_entry
        // will become 0, as expected by the definition
        (void)_lock_xadd_64b(&tdcs_p->migration_fields.total_mb_count, 1);
        migsc_p->next_mb_counter++;

        // Indicate the number of pages processed, an overall success and
        // the number of problematic GPA list entries.
        get_local_data()->vmm_regs.rdx = migsc_p->interrupted_state.num_processed;
        return_val = api_error_with_operand_id(TDX_SUCCESS, problem_ops_count);
    }

    return return_val;
}

api_error_type tdh_export_mem(gpa_list_info_t gpa_list_info, uint64_t target_tdr_pa,
                              uint64_t hpa_and_size_pa, uint64_t mig_buff_list_pa_val,
                              uint64_t migs_i_and_cmd_val, uint64_t  mac_list_0_pa, uint64_t  mac_list_1_pa)
{   
    // Local data for return values
    tdx_module_local_t* local_data_ptr = get_local_data();

    // TDR and TDCS
    tdr_t* tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t                    tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t            tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t* tdr_pamt_entry_ptr;
    tdcs_t* tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t                  tdr_locked_flag = false;
    bool_t                  op_state_locked_flag = false;

    // GPA list
    gpa_list_entry_t* gpa_list_p = NULL;
    gpa_list_entry_t        gpa_list_entry;
    uint64_t                entry_num = gpa_list_info.first_entry;
    uint32_t                problem_ops_count = 0;

    // GPA and Secure-EPT
    pa_t                    page_gpa;
    bool_t                  sept_tree_locked_flag = false;
    ia32e_sept_t* sept_entry_ptr = NULL;
    ia32e_sept_t            sept_entry_copy;
    ia32e_sept_t            sept_entry_old;
    bool_t                  septe_locked_flag = false;
    ept_level_t             sept_entry_level = LVL_PT;

    // TD Private Page
    pa_t                    td_page_pa;
    void* td_page_p = NULL;

    // MBMD
    mbmd_t* mbmd_p = NULL;
    mbmd_t                  mbmd;
    hpa_and_size_t          mbmd_hpa_and_size;

    // Migration Buffers
    pa_t                    mig_buff_list_pa;
    page_list_entry_t* mig_buff_list_p = NULL;
    page_list_entry_t       mig_buff_list_entry;
    void* mig_buff_p = NULL;

    // MAC list
    pa_t                    mac_list_pa[2];
    mac_list_entry_t* mac_list_p[2] = { NULL, NULL };

    // Migration Stream
    migs_index_and_cmd_t    migs_i_and_cmd;
    uint16_t                migs_i;
    migsc_t* migsc_p = NULL;
    pa_t                    migsc_pa;
    bool_t                  migsc_locked_flag = false;

    uint64_t                old_value;
    bool_t                  mig_locked_flag = false;
    uint64_t                mig_count_increment;   // Value to increment MIG_COUNT after success is guaranteed
    uint64_t                dirty_count_increment; // Value to increment DIRTY_COUNT after success is guaranteed
    api_error_type          return_val = TDX_OPERAND_INVALID;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    mig_buff_list_pa.raw = mig_buff_list_pa_val;
    mac_list_pa[0].raw = mac_list_0_pa;
    mac_list_pa[1].raw = mac_list_1_pa;
    migs_i_and_cmd.raw = migs_i_and_cmd_val;

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
                                               TDH_EXPORT_MEM_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Lock the whole migration context to prevent concurrent TDH.EXPORT.TRACK
    if (acquire_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_SHARED) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIG);
        TDX_ERROR("Failed to lock TDCS mig lock - error = %llx\n", return_val);
        goto EXIT;
    }
    mig_locked_flag = true;

    //--------------------------------
    // Process the Migration Stream
    //--------------------------------
    if ((migs_i_and_cmd.reserved_31_16 != 0) ||
        (migs_i_and_cmd.reserved_62_32 != 0))
    {
        TDX_ERROR("Invalid migs_i_and_cmd (0x%llx)\n", migs_i_and_cmd.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    migs_i = migs_i_and_cmd.migs_index;

    /*
     * Check that the export session is in the correct state and that
     * the migration stream index is correct for that state.
    */
    if ((uint32_t)migs_i >= tdcs_p->migration_fields.num_migs - 1)  // Allow for one backward mig. stream
    {
        TDX_ERROR("Migs index (%u) is higher than num_migs (%u)\n", migs_i,
            tdcs_p->migration_fields.num_migs);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    lfence();
    // Lock the MIGSC link
    if (!(migsc_lock(&tdcs_p->f_migsc_links[migs_i])))
    {
        TDX_ERROR("Failed to lock tdcs_p->f_migsc_links[%u]\n", migs_i);
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
        goto EXIT;
    }
    migsc_locked_flag = true;

    // Map the MIGSC
    migsc_pa.raw = 0;
    migsc_pa.page_4k_num = tdcs_p->f_migsc_links[migs_i].migsc_hpa;

    migsc_p = (migsc_t*)map_pa_with_hkid(migsc_pa.raw_void, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    if (acquire_sharex_lock(&tdcs_p->executions_ctl_fields.secure_ept_lock, TDX_LOCK_SHARED) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT_TREE);
        TDX_ERROR("Failed to acquire SEPT tree lock");
        goto EXIT;
    }
    sept_tree_locked_flag = true;

    return_val = check_and_map_gpa_list(gpa_list_info, &gpa_list_p);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        TDX_ERROR("GPA list info is incorrect = 0x%llx\n", gpa_list_info.raw);
        goto EXIT;
    }

    /* Check that the migration buffers list physical address is canonical, shared,
       and aligned to 4KB, and map it. */
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(mig_buff_list_pa, TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R9);
        goto EXIT;
    }

    mig_buff_list_p = (page_list_entry_t*)map_pa(mig_buff_list_pa.raw_void, TDX_RANGE_RW);

    /* Check that the MAC lists physical addresses are canonical, shared,
       and aligned to 4KB, and map it. Only the relevant MAC list HPAs are checked and mapped. */
    if (gpa_list_info.first_entry < MAC_LIST_ENTRIES_IN_PAGE)
    {
        if ((return_val = shared_hpa_check_with_pwr_2_alignment(mac_list_pa[0], TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
        {
            TDX_ERROR("Check on shared mac_list[0] hpa (0x%llx) failed with error 0x%llx\n", mac_list_pa[0].raw, return_val);
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_R11);
            goto EXIT;
        }
        mac_list_p[0] = (mac_list_entry_t*)map_pa(mac_list_pa[0].raw_void, TDX_RANGE_RW);
    }

    if (gpa_list_info.last_entry >= MAC_LIST_ENTRIES_IN_PAGE)
    {
        if ((return_val = shared_hpa_check_with_pwr_2_alignment(mac_list_pa[1], TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
        {
            TDX_ERROR("Check on shared mac_list[1] hpa (0x%llx) failed with error 0x%llx\n", mac_list_pa[1].raw, return_val);
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_R12);
            goto EXIT;
        }
        mac_list_p[1] = (mac_list_entry_t*)map_pa(mac_list_pa[1].raw_void, TDX_RANGE_RW);
    }

    /*--------------------------------------------------
       Check and map the MBMD buffer in shared memory
    --------------------------------------------------*/
    if (mbmd_hpa_and_size.size < sizeof(mbmd_t))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    /* Verify the MBMD physical address is canonical, shared, and aligned to 128B
       and map it. */
    mbmd_hpa_and_size.size = 0;
    pa_t mbmd_hpa_and_size_pa = { .raw = mbmd_hpa_and_size.raw };
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa_and_size_pa, MBMD_ALIGN)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", mbmd_hpa_and_size_pa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
        goto EXIT;
    }

    mbmd_p = (mbmd_t*)map_pa(mbmd_hpa_and_size_pa.raw_void, TDX_RANGE_RW);

    if (TDX_SUCCESS != (return_val = check_mbmd(migs_i_and_cmd, gpa_list_info, tdcs_p, migs_i, migsc_p,
        mac_list_p, &mbmd, mbmd_p, mig_buff_list_pa, mac_list_pa)))
    {
        goto EXIT;
    }

    /*---------------------------------------------------------
                   Loop over the GPA list
    ---------------------------------------------------------*/
    for (entry_num = gpa_list_info.first_entry; entry_num <= gpa_list_info.last_entry; entry_num++)
    {
        gpa_list_entry_status_t err_status = GPA_ENTRY_STATUS_SUCCESS;
        gpa_list_entry = gpa_list_p[entry_num];
        mig_buff_list_entry = mig_buff_list_p[entry_num];

        // Default values for this loop iteration
        mig_count_increment = 0;
        dirty_count_increment = 0;
        septe_locked_flag = false;

        do
        {
            if (gpa_list_entry.operation == GPA_ENTRY_OP_NOP)
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

            if (!check_and_get_gpa_from_entry(gpa_list_entry, tdcs_p->executions_ctl_fields.gpaw, &page_gpa))
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
            return_val = walk_private_gpa(tdcs_p, page_gpa, tdr_p->key_management_fields.hkid,
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
            sept_entry_old = sept_entry_copy;   // Will be used for CMPXCHG when updating in memory

            // Verify if BLOCKW is allowed for the SEPT entry state.
            if (!sept_state_is_seamcall_leaf_allowed(TDH_EXPORT_MEM_LEAF, sept_entry_copy))
            {
                err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT; break;
            }

            if (GPA_ENTRY_STATUS_SUCCESS != (err_status = handle_export_by_order(tdcs_p, &gpa_list_entry, sept_entry_copy)))
            {
                break;
            }

            gpa_list_entry.pending = sept_state_is_any_pending(sept_entry_copy);
            gpa_list_entry.l2_map = 0;

            if (GPA_ENTRY_STATUS_SUCCESS != (err_status = handle_operation(gpa_list_entry, &mig_count_increment, &sept_entry_copy,
                                                                           &dirty_count_increment, &mig_buff_list_entry)))
            {
                break;
            }

            // Update the SEPT entry in memory, but keep it locked since we still access the page later.
            atomic_mem_write_64b(&sept_entry_ptr->raw, sept_entry_copy.raw);

            // Update MIG_COUNT and DIRTY_COUNT by the increment calculated above
            old_value = _lock_xadd_64b(&tdcs_p->migration_fields.mig_count, mig_count_increment);
            tdx_debug_assert(old_value < (1ULL << 63));
            old_value = _lock_xadd_64b(&tdcs_p->migration_fields.dirty_count, dirty_count_increment);
            tdx_debug_assert(old_value < (1ULL << 63));

            /*---------------------------------------------------------------------------
               Export, re-export or cancellation of this page is guaranteed to succeed
            ---------------------------------------------------------------------------*/
        } while (0);

        IF_RARE(err_status != GPA_ENTRY_STATUS_SUCCESS)
        {
            gpa_list_entry.operation = GPA_ENTRY_OP_NOP;
            gpa_list_entry.status = err_status;
            mig_buff_list_entry.invalid = 1;
            if (err_status != GPA_ENTRY_STATUS_SKIPPED)
            {
                problem_ops_count++;
            }
        }

        /*--------------------------------------------------------------
           Page encryption (if required) and page MAC calculation
        --------------------------------------------------------------*/

        // Increment the IV counter for use with this GPA list entry
        migsc_p->iv_counter++;

        // Calculate a MAC over the GPA list entry
        reset_to_next_iv(migsc_p, migsc_p->iv_counter, migs_i);

        if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (const uint8_t*)&gpa_list_entry,
            sizeof(gpa_list_entry)) != AES_GCM_NO_ERROR)
        {
            FATAL_ERROR();
        }

        if (mig_buff_list_entry.invalid == 0)
        {
            /* We're about to export a page that was not PENDING* when we checked the SEPT entry
             * above.
             * Concurrency Notes:
             * - There is no case where the guest could concurrently change a non-PENDING page to a PENDING page.
             * - The host-side SEPT entry lock is still acquired by the current flow.
             */
            tdx_debug_assert((gpa_list_entry.operation == GPA_ENTRY_OP_MIGRATE) ||
                             (gpa_list_entry.operation == GPA_ENTRY_OP_REMIGRATE));

            // Map the 4KB TD private page
            td_page_pa.raw = 0;
            td_page_pa.page_4k_num = sept_entry_copy.base;
            if (td_page_p)
            {
                free_la(td_page_p);
                td_page_p = NULL;
            }
            td_page_p = map_pa_with_hkid(td_page_pa.raw_void, tdr_p->key_management_fields.hkid, TDX_RANGE_RO);

            // Check the migration buffer HPA and map it
            pa_t mig_buff_list_entry_pa = { .raw = 0 };
            mig_buff_list_entry_pa.page_4k_num = mig_buff_list_entry.hpa;
            if ((return_val = shared_hpa_check_with_pwr_2_alignment(mig_buff_list_entry_pa, TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
            {
                return_val = api_error_with_operand_id(return_val, OPERAND_ID_MIG_BUFF_LIST_ENTRY);
                goto EXIT;
            }

            mig_buff_p = map_pa(mig_buff_list_entry_pa.raw_void, TDX_RANGE_RW);

            // Encrypt the TD 4KB page or chuck into the output page
            if (aes_gcm_encrypt(&migsc_p->aes_gcm_context, (uint8_t*)td_page_p,
                                (uint8_t*)mig_buff_p, _4KB) != AES_GCM_NO_ERROR)
            {
                FATAL_ERROR();
            }
            free_la(mig_buff_p);

            migsc_p->interrupted_state.num_processed++;
        }

        /* Calculate the MAC and write to the proper MAC list page.  There are 256 entries
           per page.
        */
        if (aes_gcm_finalize(&migsc_p->aes_gcm_context,
            mac_list_p[(entry_num >> 8) & 1][entry_num & 0xFF]) != AES_GCM_NO_ERROR)
        {
            FATAL_ERROR();
        }

        // Write back the updated migration buffer list and GPA list entries to memory
        mig_buff_list_p[entry_num] = mig_buff_list_entry;
        gpa_list_p[entry_num] = gpa_list_entry;

        // Now that we're done processing the page, unlock the SEPT entry
        if (septe_locked_flag)
        {
            sept_lock_release(sept_entry_ptr);
            septe_locked_flag = false;
        }
        if (sept_entry_ptr)
        {
            free_la(sept_entry_ptr);
            sept_entry_ptr = NULL;
        }

        /*--------------------------------------
           Done processing one GPA list entry
        --------------------------------------*/
        if (TDX_INTERRUPTED_RESUMABLE == (return_val = finish_entry_processing(&entry_num, gpa_list_info, migsc_p,
                                                                               mig_buff_list_pa, mac_list_pa,
                                                                               tdcs_p, problem_ops_count)))
        {
            break;
        }
    } // for

EXIT:

    gpa_list_info.first_entry = entry_num;

    // In all cases, including error cases, RCX returns the updated GPA_LIST_INFO
    local_data_ptr->vmm_regs.rcx = gpa_list_info.raw;

    // Release all acquired locks

    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    if (td_page_p)
    {
        free_la(td_page_p);
    }

    if (migsc_p != NULL)
    {
        free_la(migsc_p);
    }

    if (mac_list_p[0])
    {
        free_la(mac_list_p[0]);
    }

    if (mac_list_p[1])
    {
        free_la(mac_list_p[1]);
    }

    if (mig_buff_list_p)
    {
        free_la(mig_buff_list_p);
    }

    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->f_migsc_links[migs_i]);
    }

    if (septe_locked_flag)
    {
        sept_lock_release(sept_entry_ptr);
    }

    if (sept_entry_ptr)
    {
        free_la(sept_entry_ptr);
    }

    if (gpa_list_p != NULL)
    {
        free_la(gpa_list_p);
    }

    if (sept_tree_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_p->executions_ctl_fields.secure_ept_lock);
    }

    if (mig_locked_flag)
    {
        release_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_SHARED);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp_sh(&(tdcs_p->management_fields.op_state_lock));
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
