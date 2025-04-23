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
 * @file tdh_import_mem
 * @brief TDH_IMPORT_MEM API handler
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

typedef enum gpa_list_error_type_e
{
    GPA_LIST_ERROR_TYPE_SUCCESS = 0,
    GPA_LIST_ERROR_TYPE_LIST_SKIP,
    GPA_LIST_ERROR_TYPE_LIST_ABORT,
    GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER
} gpa_list_error_type_t;

static api_error_type handle_new_command(gpa_list_info_t gpa_list_info, tdcs_t* tdcs_p,
                                         migsc_t* migsc_p, uint16_t migs_i,
                                         mbmd_t* mbmd, uint8_t* mac, uint8_t mac_size)
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
        migsc_init(migsc_p, &tdcs_p->migration_fields.mig_dec_working_key);
    }

    // Mark this flow as non-interrupted
    migsc_p->interrupted_state.valid = false;

    // Check the MBMD
    if ((mbmd->header.mig_version != (uint16_t)tdcs_p->migration_fields.mig_working_version) ||
        (mbmd->header.size != sizeof(mbmd_mem_t)) ||
        (mbmd->header.migs_index != migs_i) ||
        (mbmd->header.mb_type != MB_TYPE_MEM) ||
        (mbmd->header.reserved_1 != 0) ||
        (mbmd->header.mig_epoch != tdcs_p->migration_fields.mig_epoch) ||
        (mbmd->mem.num_gpas != gpa_list_info.last_entry + 1) ||
        (mbmd->mem.reserved != 0))
    {
        TDX_ERROR("mbmd check failed\n");
        return TDX_INVALID_MBMD;
    }

    // Order is only checked during the in-order import phase
    if (op_state_is_import_in_order(tdcs_p->management_fields.op_state))
    {
        if (mbmd->header.mb_counter != migsc_p->expected_mb_counter)
        {
            TDX_ERROR("mbmd mb_counter (%u) is different than expected (%u)\n", mbmd->header.mb_counter, migsc_p->expected_mb_counter);
            return TDX_INVALID_MBMD;
        }
    }
    else
    {
        /* During the out-of-order import phase, check that the imported page was not exported
           in the in-order phase.
           This check is redundant, consider changing it to an assert.
        */
        if (mbmd->header.mig_epoch != MIG_EPOCH_OUT_OF_ORDER)
        {
            TDX_ERROR("mbmd mig_epch (0x%lx) is not equal to MIG_EPOCH_OUT_OF_ORDER (0x%lx)\n", mbmd->header.mig_epoch, MIG_EPOCH_OUT_OF_ORDER);
            return TDX_INVALID_MBMD;
        }
    }

    // Save the IV counter in the MIGSC, so it survives interruption
    migsc_p->iv_counter = mbmd->header.iv_counter;

    /* Calculate a MAC over the MBMD
       Clear the fields that are not part of the MAC calculation.
       No need for a safe compare of the MAC: it is not a secret.
    */
    mbmd->header.migs_index = 0;
    mbmd->header.iv_counter = 0;

    // Accumulate a MAC over the MAC’ed fields of the MBMD
    reset_to_next_iv(migsc_p, migsc_p->iv_counter, migs_i);
    if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (const uint8_t*)&(mbmd->mem), MBMD_SIZE_NO_MAC(mbmd->mem)) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }
    if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }

    if (!tdx_memcmp_safe(mac, mbmd->mem.mac, mac_size))
    {
        return TDX_INCORRECT_MBMD_MAC;
    }

    /* Advance the migration stream's EXPECTED_MB_COUNTER to avoid a replay.
       From this point on, every error aborts the import session. */
    migsc_p->expected_mb_counter++;

    return TDX_SUCCESS;
}

static api_error_type handle_resumed_command(gpa_list_info_t gpa_list_info, tdcs_t* tdcs_p, migsc_t* migsc_p, uint16_t migs_i,
                                             pa_t mig_buff_list_pa, pa_t* mac_list_pa, pa_t new_page_list_pa)
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

    // Check that the same function is resumed with the same parameters
    if ((migsc_p->interrupted_state.func.raw != local_data_ptr->vmm_regs.rax) ||
        (migsc_p->interrupted_state.gpa_list_info.raw != gpa_list_info.raw) ||
        (migsc_p->interrupted_state.mig_buff_list_pa.raw != mig_buff_list_pa.raw) ||
        (migsc_p->interrupted_state.mac_list_pa[0].raw != mac_list_pa[0].raw) ||
        (migsc_p->interrupted_state.mac_list_pa[1].raw != mac_list_pa[1].raw) ||
        (migsc_p->interrupted_state.new_page_list_pa.raw != new_page_list_pa.raw) ||
        (migsc_p->mbmd.mem.header.mig_epoch != tdcs_p->migration_fields.mig_epoch))   // This condition is a defense-in-depth, shouldn't happen
    {
        TDX_ERROR("Bad resumption \n");
        return TDX_INVALID_RESUMPTION;
    }

    return TDX_SUCCESS;
}

static api_error_type check_mbmd(migs_index_and_cmd_t migs_i_and_cmd, gpa_list_info_t gpa_list_info, tdcs_t* tdcs_p,
                                 migsc_t* migsc_p, uint16_t migs_i, mbmd_t* mbmd, uint8_t* mac, uint8_t mac_size,
                                 pa_t mig_buff_list_pa, pa_t* mac_list_pa, pa_t new_page_list_pa)
{
    api_error_type return_val = TDX_SUCCESS;

    if (migs_i_and_cmd.command == MIGS_INDEX_COMMAND_NEW)
    {
        return_val = handle_new_command(gpa_list_info, tdcs_p, migsc_p, migs_i, mbmd, mac, mac_size);
    }
    else // migs_i_and_cmd.command == MIGS_INDEX_COMMAND_RESUME
    {
        return_val = handle_resumed_command(gpa_list_info, tdcs_p, migsc_p, migs_i,
            mig_buff_list_pa, mac_list_pa, new_page_list_pa);
    }

    return return_val;
}

static api_error_type compare_macs_and_update_error_statuses(uint8_t* mac, uint8_t mac_size, uint8_t* page_mac,
                                                             gpa_list_error_type_t* gpa_list_error_type,
                                                             api_error_type* return_val, gpa_list_entry_status_t* err_status)
{
    if (!tdx_memcmp_safe(mac, page_mac, mac_size))
    {
        *gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
        *return_val = api_error_with_operand_id(TDX_INVALID_PAGE_MAC, OPERAND_ID_GPA_LIST_ENTRY);
        *err_status = GPA_ENTRY_STATUS_INVALID_PAGE_MAC;
        return *return_val;
    }

    return TDX_SUCCESS;
}

static api_error_type handle_expected_mig_buf(gpa_list_entry_t* gpa_list_entry, page_list_entry_t mig_buff_list_entry,
                                              gpa_list_error_type_t* gpa_list_error_type, gpa_list_entry_status_t* err_status,
                                              void** mig_buff_p, bool_t* mig_buff_mapped)
{
    api_error_type return_val = TDX_SUCCESS;

    if ((gpa_list_entry->operation != GPA_ENTRY_OP_CANCEL) && !gpa_list_entry->pending)
    {
        // Migration buffer is required
        if (mig_buff_list_entry.invalid != 0)
        {
            *gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
            *err_status = GPA_ENTRY_STATUS_MIG_BUFFER_NOT_AVAILABLE;
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_MIG_BUFF_LIST_ENTRY);
        }
        /* Check the migration buffer HPA and map it.  At this point the list entry
           contains only the HPA.  Note that an error breaks the execution
           of the flow. */
        pa_t mig_buff_list_entry_pa = { .raw = 0 };
        mig_buff_list_entry_pa.page_4k_num = mig_buff_list_entry.hpa;

        if (TDX_SUCCESS != (return_val = shared_hpa_check_with_pwr_2_alignment(mig_buff_list_entry_pa, TDX_PAGE_SIZE_IN_BYTES)))
        {
            *gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
            *err_status = GPA_ENTRY_STATUS_MIG_BUFFER_NOT_AVAILABLE;
            return api_error_with_operand_id(return_val, OPERAND_ID_MIG_BUFF_LIST_ENTRY);
        }

        *mig_buff_p = map_pa(mig_buff_list_entry_pa.raw_void, TDX_RANGE_RO);
        *mig_buff_mapped = true;
    }

    return TDX_SUCCESS;
}

static api_error_type handle_import(page_list_entry_t* new_page_list_p, page_list_entry_t new_page_list_entry,
                                    page_list_entry_t mig_buff_list_entry, gpa_list_error_type_t* gpa_list_error_type,
                                    gpa_list_entry_status_t* err_status, gpa_list_entry_t gpa_list_entry,
                                    bool_t* mig_buff_mapped, uint8_t** buff_4k, void** mig_buff_p, pa_t* td_page_pa)
{
    api_error_type return_val = TDX_SUCCESS;

    if ((new_page_list_p == NULL) || (new_page_list_entry.invalid == 1))
    {
        /* This is an in-place import.
         * The migration buffer must be valid - it will become the new TD page.
         * If not PENDING, copy the migration buffer to a temporary buffer and use that as
         * the source.
         * Note:  The host VMM is responsible to ensure that no cache lines of the migration
         *        buffer is in a MODIFIED state.  Since a shared HKID has been used until now,
         *        these cache lines will not get overwritten when the page is re-initialized as
         *        a private page.
         */
        if (mig_buff_list_entry.invalid == 1)
        {
            *gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
            *err_status = GPA_ENTRY_STATUS_MIG_BUFFER_NOT_AVAILABLE;
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_MIG_BUFF_LIST_ENTRY);
        }

        if (!gpa_list_entry.pending)
        {
            tdx_debug_assert(*mig_buff_mapped);
            // Copy the migration buffer to a temporary buffer
            tdx_memcpy(*buff_4k, _4KB, *mig_buff_p, _4KB);

            free_la(*mig_buff_p);
            *mig_buff_mapped = false;

            // Further on, use the temporary buffer as the source
            *mig_buff_p = *buff_4k;
        }

        *td_page_pa = set_hkid_to_pa((pa_t)mig_buff_list_entry.raw, 0);
    }
    else
    {
        /* This is not an in-place import.
           The new TD page is provided separately. HKID bits must be 0.
        */
        td_page_pa->raw = new_page_list_entry.raw;

        if (!is_addr_aligned_pwr_of_2(td_page_pa->raw, TDX_PAGE_SIZE_IN_BYTES) ||
            !is_pa_smaller_than_max_pa(td_page_pa->raw) ||
            (get_hkid_from_pa(*td_page_pa) != 0))
        {
            TDX_ERROR("Failed on new page list shared HPA 0x%llx check\n", td_page_pa->raw);
            *gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
            *err_status = GPA_ENTRY_STATUS_NEW_PAGE_NOT_AVAILABLE;
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_NEW_PAGE_LIST_ENTRY);
        }
    }

    return return_val;
}

static api_error_type handle_rare_errors(gpa_list_entry_status_t err_status, gpa_list_entry_t* gpa_list_entry,
                                         gpa_list_error_type_t gpa_list_error_type, uint32_t* problem_ops_count,
                                         gpa_list_entry_t* gpa_list_p, uint64_t entry_num,
                                         page_list_entry_t* new_page_list_p, tdcs_t* tdcs_p,
                                         page_list_entry_t* new_page_list_entry, api_error_type* return_val)
{
    IF_RARE(err_status != GPA_ENTRY_STATUS_SUCCESS)
    {
        gpa_list_entry->operation = GPA_ENTRY_OP_NOP;
        gpa_list_entry->status = err_status;

        if (gpa_list_error_type == GPA_LIST_ERROR_TYPE_LIST_SKIP)
        {
            new_page_list_entry->invalid = 1;
            if (err_status != GPA_ENTRY_STATUS_SKIPPED)
            {
                (*problem_ops_count)++;
            }
        }
        else if ((gpa_list_error_type == GPA_LIST_ERROR_TYPE_LIST_ABORT) ||
                 (gpa_list_error_type == GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER))
        {
            gpa_list_p[entry_num] = *gpa_list_entry;
            if (gpa_list_error_type == GPA_LIST_ERROR_TYPE_LIST_ABORT)
            {
                if (new_page_list_p)
                {
                    new_page_list_p[entry_num].invalid = 1;
                }
                *return_val = abort_import_session(tdcs_p, *return_val, 0);
                return *return_val;
            }
            else // GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER
            {
                if (op_state_is_import_in_order(tdcs_p->management_fields.op_state))
                {
                    if (new_page_list_p)
                    {
                        new_page_list_p[entry_num].invalid = 1;
                    }
                    tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
                    *return_val = api_error_fatal(*return_val);
                    return *return_val;
                }

                new_page_list_entry->invalid = 1;
                (*problem_ops_count)++;
            }
        }
    }

    return TDX_SUCCESS;
}

static api_error_type finish_entry_processing(uint64_t* entry_num, gpa_list_info_t gpa_list_info,
                                              migsc_t* migsc_p, pa_t mig_buff_list_pa, pa_t* mac_list_pa,
                                              pa_t new_page_list_pa, tdcs_t* tdcs_p, uint32_t problem_ops_count)
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
            migsc_p->interrupted_state.mac_list_pa[0].raw = mac_list_pa[0].raw;
            migsc_p->interrupted_state.mac_list_pa[1].raw = mac_list_pa[1].raw;
            migsc_p->interrupted_state.new_page_list_pa.raw = new_page_list_pa.raw;
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

        /* Indicate an overall success and the
           number of problematic GPA list entries. */
        return_val = api_error_with_operand_id(TDX_SUCCESS, problem_ops_count);
    }

    return return_val;
}

api_error_type tdh_import_mem(gpa_list_info_t gpa_list_info, uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                              uint64_t mig_buff_list_pa_val, uint64_t migs_i_and_cmd_pa, uint64_t mac_list_0_pa,
                              uint64_t  mac_list_1_pa, uint64_t new_page_list_pa_val)
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
    bool_t                  septe_locked_flag = false;
    ept_level_t             sept_entry_level = LVL_PT;

    // TD Private Page
    pa_t                    td_page_pa;
    pamt_block_t            td_page_pamt_block_desc;
    bool_t                  td_page_pamt_block_locked_flag = false;
    void* td_page_p = NULL;
    pamt_entry_t* td_page_pamt_entry_p = NULL;
    bool_t                  td_page_pamt_entry_locked_flag = false;
    bool_t                  mig_locked_flag = false;

    // MBMD
    mbmd_t* mbmd_p = NULL;
    mbmd_t                  mbmd;
    hpa_and_size_t          mbmd_hpa_and_size;

    // Migration Buffers
    pa_t                    mig_buff_list_pa;
    page_list_entry_t* mig_buff_list_p = NULL;
    page_list_entry_t       mig_buff_list_entry;
    void* mig_buff_p = NULL;
    bool_t                  mig_buff_mapped = false;
    uint8_t                 buff_4k[_4KB];

    // New TD Pages
    pa_t                    new_page_list_pa;
    page_list_entry_t* new_page_list_p = NULL;
    page_list_entry_t       new_page_list_entry;

    // MAC list
    pa_t                    mac_list_pa[2];
    typedef   uint8_t       mac_list_entry_t[MAC256_LEN];
    mac_list_entry_t* mac_list_p[2] = { NULL, NULL };
    uint8_t* page_mac;
    uint8_t                 mac[MAC256_LEN];

    // Migration Stream
    migs_index_and_cmd_t    migs_i_and_cmd;
    uint16_t                migs_i;
    migsc_t* migsc_p = NULL;
    pa_t                    migsc_pa;
    bool_t                  migsc_locked_flag = false;

    bepoch_t                bepoch;
    api_error_type          return_val = TDX_OPERAND_INVALID;

    gpa_list_error_type_t gpa_list_error_type = GPA_LIST_ERROR_TYPE_SUCCESS;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    mig_buff_list_pa.raw = mig_buff_list_pa_val;
    migs_i_and_cmd.raw = migs_i_and_cmd_pa;
    mac_list_pa[0].raw = mac_list_0_pa;
    mac_list_pa[1].raw = mac_list_1_pa;
    new_page_list_pa.raw = new_page_list_pa_val;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
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
        TDH_IMPORT_MEM_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Lock the whole migration context to prevent concurrent TDH.IMPORT.TRACK
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
    if ((uint32_t)migs_i >= tdcs_p->migration_fields.num_migs - 1)   // Allow for one backward mig. stream
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
        TDX_ERROR("Failed to acquire SEPT tree lock\n");
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
        TDX_ERROR("Check on shared mig_buff_list_pa (0x%llx) failed with error 0x%llx\n", mig_buff_list_pa.raw, return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R9);
        goto EXIT;
    }

    mig_buff_list_p = (page_list_entry_t*)map_pa(mig_buff_list_pa.raw_void, TDX_RANGE_RO);

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
        mac_list_p[0] = (mac_list_entry_t*)map_pa(mac_list_pa[0].raw_void, TDX_RANGE_RO);
    }

    if (gpa_list_info.last_entry >= MAC_LIST_ENTRIES_IN_PAGE)
    {
        if ((return_val = shared_hpa_check_with_pwr_2_alignment(mac_list_pa[1], TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
        {
            TDX_ERROR("Check on shared mac_list[1] hpa (0x%llx) failed with error 0x%llx\n", mac_list_pa[1].raw, return_val);
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_R12);
            goto EXIT;
        }
        mac_list_p[1] = (mac_list_entry_t*)map_pa(mac_list_pa[1].raw_void, TDX_RANGE_RO);
    }

    /* If a new page list is provided, check that its physical address is canonical, shared,
       and aligned to 4KB, and map it. */
    if (new_page_list_pa.raw != NULL_PA)
    {
        return_val = shared_hpa_check_with_pwr_2_alignment(new_page_list_pa, TDX_PAGE_SIZE_IN_BYTES);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed on target shared HPA 0x%llx check\n", new_page_list_pa.raw);
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_R13);
            goto EXIT;
        }

        new_page_list_p = map_pa(new_page_list_pa.raw_void, TDX_RANGE_RW);
    }
    /*--------------------------------------------------
       Check and map the MBMD buffer in shared memory
    --------------------------------------------------*/
    if (mbmd_hpa_and_size.size < sizeof(mbmd_mem_t))
    {
        TDX_ERROR("mbmd_hpa_and_size.size (%llu) is too small\n", mbmd_hpa_and_size.size);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    /* Verify the MBMD physical address is canonical, shared, and aligned to 128B.
       Map the MBMD and read it. */
    mbmd_hpa_and_size.size = 0;
    pa_t mbmd_hpa_and_size_pa = { .raw = mbmd_hpa_and_size.raw };
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa_and_size_pa, MBMD_ALIGN)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", mbmd_hpa_and_size_pa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
        goto EXIT;
    }

    mbmd_p = (mbmd_t*)map_pa(mbmd_hpa_and_size_pa.raw_void, TDX_RANGE_RO);
    copy_mbmd(&mbmd, mbmd_p);

    if (TDX_SUCCESS != (return_val = check_mbmd(migs_i_and_cmd, gpa_list_info, tdcs_p,
        migsc_p, migs_i, &mbmd, mac, sizeof(mac),
        mig_buff_list_pa, mac_list_pa, new_page_list_pa)))
    {
        goto EXIT;
    }

    /*-----------------------------------------------------------------
       From this point on, operations may modify the destination TD
       state and/or migration stream state, thus many of them result
       in an import abort.  in many cases, import is aborted only
       if we're in the in-order phase.
    -----------------------------------------------------------------*/

    /*---------------------------------------------------------
                   Loop over the GPA list
    ---------------------------------------------------------*/
    for (entry_num = gpa_list_info.first_entry; entry_num <= gpa_list_info.last_entry; entry_num++)
    {
        gpa_list_entry_status_t err_status = GPA_ENTRY_STATUS_SUCCESS;
        gpa_list_entry = gpa_list_p[entry_num];
        mig_buff_list_entry = mig_buff_list_p[entry_num];
        if (new_page_list_p)
        {
            new_page_list_entry = new_page_list_p[entry_num];
        }

        // Get the page MAC.  There are 2 pages with 256 entries per page
        page_mac = (uint8_t*)mac_list_p[entry_num >> 8][entry_num & 0xFF];

        septe_locked_flag = false;

        // Prepare the IV for the next page
        migsc_p->iv_counter++;

        reset_to_next_iv(migsc_p, migsc_p->iv_counter, migs_i);
        if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (const uint8_t*)&(gpa_list_entry),
            sizeof(gpa_list_entry)) != AES_GCM_NO_ERROR)
        {
            FATAL_ERROR();
        }

        if (gpa_list_entry.operation == GPA_ENTRY_OP_NOP)
        {
            if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
            {
                FATAL_ERROR();
            }

            if (TDX_SUCCESS != compare_macs_and_update_error_statuses(mac, sizeof(mac), page_mac,
                                                                      &gpa_list_error_type,
                                                                      &return_val, &err_status))
            {
                goto FINALIZE_ENTRY;
            }

            if (!gpa_list_entry_is_valid(gpa_list_entry))
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_GPA_LIST_ENTRY);
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                err_status = GPA_ENTRY_STATUS_GPA_LIST_ENTRY_INVALID;
                goto FINALIZE_ENTRY;
            }

            gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_SKIP;
            err_status = GPA_ENTRY_STATUS_SKIPPED;
            goto FINALIZE_ENTRY;
        }

        if (!check_and_get_gpa_from_entry(gpa_list_entry, tdcs_p->executions_ctl_fields.gpaw, &page_gpa, tdcs_p->executions_ctl_fields.virt_maxpa))
        {
            TDX_ERROR("Invalid GPA entry in the list - 0x%llx\n", gpa_list_entry.raw);

            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_GPA_LIST_ENTRY);
            gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
            err_status = GPA_ENTRY_STATUS_GPA_LIST_ENTRY_INVALID;
            goto FINALIZE_ENTRY;
        }

        sept_entry_level = LVL_PT;
        if (sept_entry_ptr)
        {
            free_la(sept_entry_ptr);
        }
        /* Walk the Secure-EPT to locate the parent entry for the new TD page
         *On failure, abort the import session only if in the in-order phase.  In the out-of-order phase,
         *the page might have been promoted so SEPT walk may fail. */
        return_val = walk_private_gpa(tdcs_p, page_gpa, tdr_p->key_management_fields.hkid, &sept_entry_ptr, &sept_entry_level, &sept_entry_copy);

        if (return_val != TDX_SUCCESS)
        {
            gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER;
            return_val = api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_GPA_LIST_ENTRY);
            err_status = GPA_ENTRY_STATUS_SEPT_WALK_FAILED;
            goto FINALIZE_ENTRY;
        }

        // Lock the SEPT entry in memory
        return_val = sept_lock_acquire_host(sept_entry_ptr);
        if (TDX_SUCCESS != return_val)
        {
            gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER;
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_GPA_LIST_ENTRY);
            err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_BUSY_HOST_PRIORITY;
            goto FINALIZE_ENTRY;
        }
        septe_locked_flag = true;

        // Read the SEPT entry value again after it has been locked
        sept_entry_copy = *sept_entry_ptr;

        if (!sept_state_is_seamcall_leaf_allowed(TDH_IMPORT_MEM_LEAF, sept_entry_copy))
        {
            gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER;
            return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_GPA_LIST_ENTRY);
            err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT;
            goto FINALIZE_ENTRY;
        }

        // REMIGRATE and CANCEL can only be done during in-order import
        if (!op_state_is_import_in_order(tdcs_p->management_fields.op_state) && (gpa_list_entry.operation != GPA_ENTRY_OP_MIGRATE))
        {
            gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
            return_val = TDX_OP_STATE_INCORRECT;
            err_status = GPA_ENTRY_STATUS_OP_STATE_INCORRECT;
            goto FINALIZE_ENTRY;
        }

        /* Check if a migration buffer is expected.  If so, check the migration buffer list
           entry and map the migration buffer page. */

        if (TDX_SUCCESS != (return_val = handle_expected_mig_buf(&gpa_list_entry, mig_buff_list_entry,
                                                                 &gpa_list_error_type, &err_status,
                                                                 &mig_buff_p, &mig_buff_mapped)))
        {
            goto FINALIZE_ENTRY;
        }

        switch (gpa_list_entry.operation)
        {
        case GPA_ENTRY_OP_MIGRATE:
        {
            if (!sept_state_is_first_time_import_allowed(sept_entry_copy))
            {
                /* During in-order, this is considered an error and aborts the import
                   session.  During out-of-order, we just skip this list entry since
                   the SEPT state may have been changed by memory management operations
                   such as TDH.MEM.RANGE.BLOCKW. */
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER;
                return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_GPA_LIST_ENTRY);
                err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT; break;
            }
            /* Check that the page has not been removed in the current migration epoch.  This
               could have been done by CANCEL operation in the in-order phase, or
               TDH.MEM.PAGE.REMOVE in the out-of-order phase.
               In this case the SEPT entry's HPA bits records the migration epoch of removal. */
            if (is_sept_removed(&sept_entry_copy) && (sept_entry_copy.mig_epoch_valid) &&
                (sept_entry_copy.mig_epoch >= (uint64_t)tdcs_p->migration_fields.mig_epoch))
            {
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                return_val = api_error_with_operand_id(TDX_DISALLOWED_IMPORT_OVER_REMOVED, OPERAND_ID_GPA_LIST_ENTRY);
                err_status = GPA_ENTRY_STATUS_DISALLOWED_IMPORT_OVER_REMOVED; break;
            }

            uint8_t* buff_4k_p = buff_4k;
            if (TDX_SUCCESS != (return_val = handle_import(new_page_list_p, new_page_list_entry,
                                                           mig_buff_list_entry, &gpa_list_error_type,
                                                           &err_status, gpa_list_entry, &mig_buff_mapped,
                                                           &buff_4k_p, &mig_buff_p, &td_page_pa)))
            {
                break;
            }

            // Check and lock the new TD page in PAMT
            page_size_t leaf_size = PT_4KB;
            return_val = check_and_lock_explicit_private_hpa(td_page_pa, OPERAND_ID_NEW_PAGE_LIST_ENTRY,
                                                             _4KB, TDX_LOCK_EXCLUSIVE, PT_NDA,
                                                             &td_page_pamt_block_desc,
                                                             &td_page_pamt_entry_p,
                                                             &leaf_size,
                                                             true,   // walk_to_leaf_size,
                                                             &td_page_pamt_block_locked_flag);
            if (return_val != TDX_SUCCESS)
            {
                TDX_ERROR("Check and lock for hpa 0x%llx failed with return_val 0x%llx\n", td_page_pa.raw, return_val);
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER;
                err_status = GPA_ENTRY_STATUS_NEW_PAGE_NOT_AVAILABLE; break;
            }

            td_page_p = map_pa_with_hkid(td_page_pa.raw_void, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

            if (!gpa_list_entry.pending)
            {
                /* Decrypt the input 4KB page into a the TD page.
                   Note the need to use MOVDIR64B either as part of the decryption algorithm
                   or to initialize the page before decryption. */
                if (aes_gcm_decrypt_direct(&migsc_p->aes_gcm_context, mig_buff_p, td_page_p, _4KB) != AES_GCM_NO_ERROR)
                {
                    FATAL_ERROR();
                }
            }

            /* Calculate the MAC and compare with the proper MAC list entry.
               No need for a safe compare of the MAC: it is not a secret. */
            if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
            {
                FATAL_ERROR();
            }

            if (TDX_SUCCESS != compare_macs_and_update_error_statuses(mac, sizeof(mac), page_mac,
                                                                      &gpa_list_error_type,
                                                                      &return_val, &err_status))
            {
                break;
            }

            // Atomically increment TDR child count
            (void)_lock_xadd_64b(&tdr_p->management_fields.chldcnt, 1);

            // Update the new page’s PAMT entry
            td_page_pamt_entry_p->pt = PT_REG;
            td_page_pamt_entry_p->owner = tdr_pa.page_4k_num;
            td_page_pamt_entry_p->bepoch.mig_flag = 1;
            td_page_pamt_entry_p->bepoch.export_count = tdcs_p->migration_fields.export_count;
            td_page_pamt_entry_p->bepoch.mig_epoch = tdcs_p->migration_fields.mig_epoch;

            // Release the PAMT locks
            pamt_unwalk(td_page_pa, td_page_pamt_block_desc, td_page_pamt_entry_p, TDX_LOCK_EXCLUSIVE, PT_4KB);
            td_page_pamt_block_locked_flag = false;
            td_page_pamt_entry_p = NULL;

            // The TD may be running, so we do the SEPT updates as follows:
            //   1. Write the L1 SEPT entry as blocked
            //   2. Write any L2 aliases
            //   3. Unblock the L1 SEPT entry.
            //   Thus, any EPT violation during steps 1 and 2 in a running L2 or L1 will result in a TD exit,
            //   avoiding confusion of the L1 VMM.
            sept_set_leaf_and_keep_lock(&sept_entry_copy,
                                        gpa_list_entry.pending ? SEPT_PERMISSIONS_NONE : SEPT_PERMISSIONS_RWX,
                                        td_page_pa,
                                        gpa_list_entry.pending ? SEPT_STATE_PEND_BLOCKED_MASK : SEPT_STATE_BLOCKED_MASK);

            sept_entry_ptr->raw = sept_entry_copy.raw;

            sept_unblock(&sept_entry_copy);
            sept_lock_release_local(&sept_entry_copy);
            sept_entry_ptr->raw = sept_entry_copy.raw;

            septe_locked_flag = false;

            break;
        }
        case GPA_ENTRY_OP_REMIGRATE:
        {
            if (!sept_state_is_re_import_allowed(sept_entry_copy))
            {
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_GPA_LIST_ENTRY);
                err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT; break;
            }

            /* Get the TD page address and PAMT entry */
            td_page_pa.raw = 0;
            td_page_pa.page_4k_num = sept_entry_copy.base;
            td_page_pamt_entry_p = pamt_implicit_get(td_page_pa, PT_4KB);

            /* Check that the page has not been imported in the current migration epoch.
               PAMT.BEPOCH records the migration epoch of last import. To avoid confusion
               with a possible value of PAMT.BEPOCH used for regular blocking, the following
               method is used:
                   - Bit 63 must be 1, indicating a migration epoch.
                   - Bits 62:32 indicate the EXPORT_COUNT.
                   - Bits 31:0 indicate the migration epoch. */
            bepoch = td_page_pamt_entry_p->bepoch;
            tdx_debug_assert(bepoch.mig_flag == 1);   // Was set by previous import
            tdx_debug_assert(bepoch.export_count == tdcs_p->migration_fields.export_count);   // Was set by previous import
            if (bepoch.mig_epoch >= tdcs_p->migration_fields.mig_epoch)
            {
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                return_val = api_error_with_operand_id(TDX_MIGRATED_IN_CURRENT_EPOCH, OPERAND_ID_GPA_LIST_ENTRY);
                err_status = GPA_ENTRY_STATUS_MIGRATED_IN_CURRENT_EPOCH; break;
            }

            // Map the 4KB TD private page
            td_page_p = map_pa_with_hkid(td_page_pa.raw_void, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

            if (gpa_list_entry.pending)
            {
                // A re-imported PENDING page may only overwrite an older version that is also PENDING
                if (!is_sept_pending(&sept_entry_copy))
                {
                    gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                    return_val = api_error_with_operand_id(TDX_IMPORT_MISMATCH, OPERAND_ID_GPA_LIST_ENTRY);
                    err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT; break;
                }
            }
            else if (sept_state_is_any_pending(sept_entry_copy))
            {
                /* Decrypt the input 4KB page into a the TD page.
                   The page has been imported in the past as PENDING, thus its contents are not initialized. For the
                   current re-import as MAPPED, use MOVDIR64B either as part of the decryption algorithm or to initialize
                   the page before decryption. */
                if (aes_gcm_decrypt_direct(&migsc_p->aes_gcm_context, mig_buff_p, td_page_p, _4KB) != AES_GCM_NO_ERROR)
                {
                    FATAL_ERROR();
                }
            }
            else
            {
                /* Decrypt the input 4KB page into a the TD page.
                   The page has been imported in the past as MAPPED, thus its contents are initialized. For the
                   current re-import as MAPPED, use normal write operations as part of the decryption algorithm. */
                if (aes_gcm_decrypt(&migsc_p->aes_gcm_context, mig_buff_p, td_page_p, _4KB) != AES_GCM_NO_ERROR)
                {
                    FATAL_ERROR();
                }
            }

            /* Calculate the MAC and compare with the MAC list entry.
               No need for a safe compare of the MAC: it is not a secret. */
            if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
            {
                FATAL_ERROR();
            }

            if (TDX_SUCCESS != compare_macs_and_update_error_statuses(mac, sizeof(mac), page_mac,
                                                                      &gpa_list_error_type,
                                                                      &return_val, &err_status))
            {
                break;
            }

            sept_set_leaf_and_keep_lock(&sept_entry_copy,
                                        gpa_list_entry.pending ? SEPT_PERMISSIONS_NONE : SEPT_PERMISSIONS_RWX,
                                        td_page_pa,
                                        gpa_list_entry.pending ? SEPT_STATE_PEND_MASK : SEPT_STATE_MAPPED_MASK);

            // Update the PAMT entry
            td_page_pamt_entry_p->bepoch.mig_epoch = tdcs_p->migration_fields.mig_epoch;

            sept_lock_release_local(&sept_entry_copy);
            sept_entry_ptr->raw = sept_entry_copy.raw;

            septe_locked_flag = false;

            break;
        }
        case GPA_ENTRY_OP_CANCEL:
        {
            if (!sept_state_is_import_cancel_allowed(sept_entry_copy))
            {
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_GPA_LIST_ENTRY);
                err_status = GPA_ENTRY_STATUS_SEPT_ENTRY_STATE_INCORRECT; break;
            }

            // Calculate the MAC and compare with the MAC list entry
            if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
            {
                FATAL_ERROR();
            }

            if (TDX_SUCCESS != compare_macs_and_update_error_statuses(mac, sizeof(mac), page_mac,
                                                                      &gpa_list_error_type,
                                                                      &return_val, &err_status))
            {
                break;
            }

            // Get the TD page address and PAMT entry
            td_page_pa.raw = 0;
            td_page_pa.page_4k_num = sept_entry_copy.base;
            td_page_pamt_entry_p = pamt_implicit_get(td_page_pa, PT_4KB);
            if ((return_val = acquire_sharex_lock_hp_ex(&td_page_pamt_entry_p->entry_lock, false)) != TDX_SUCCESS)
            {
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                return_val = abort_import_session(tdcs_p, return_val, OPERAND_ID_GPA_LIST_ENTRY);
                err_status = GPA_ENTRY_STATUS_TD_PAGE_BUSY_HOST_PRIORITY; break;
            }
            td_page_pamt_entry_locked_flag = true;

            /* Check that the page has not been imported in the current migration epoch.
               PAMT.BEPOCH records the migration epoch of last import.  To avoid confusion
               with a possible value of PAMT.BEPOCH used for regular blocking, the following
               method is used:
                   - Bit 63 must be 1, indicating a migration epoch.
                   - Bits 62:32 indicate the EXPORT_COUNT.
                   - Bits 31:0 indicate the migration epoch. */
            bepoch = td_page_pamt_entry_p->bepoch;
            tdx_debug_assert(bepoch.mig_flag == 1);   // Was set by previous import
            tdx_debug_assert(bepoch.export_count == tdcs_p->migration_fields.export_count);   // Was set by previous import
            if (bepoch.mig_epoch >= tdcs_p->migration_fields.mig_epoch)
            {
                gpa_list_error_type = GPA_LIST_ERROR_TYPE_LIST_ABORT;
                return_val = api_error_with_operand_id(TDX_MIGRATED_IN_CURRENT_EPOCH, OPERAND_ID_GPA_LIST_ENTRY);
                err_status = GPA_ENTRY_STATUS_MIGRATED_IN_CURRENT_EPOCH;
                release_sharex_lock_hp_ex(&td_page_pamt_entry_p->entry_lock);
                td_page_pamt_entry_locked_flag = false;
                break;
            }

            // Update the SEPT entry in memory to the REMOVED state and record the migration epoch
            set_remove_and_release_locks_for_import(&sept_entry_copy, tdcs_p);
			atomic_mem_write_64b(&sept_entry_ptr->raw, sept_entry_copy.raw);
            septe_locked_flag = false;

            // Atomically decrement TDR child count
            (void)_lock_xadd_64b(&tdr_p->management_fields.chldcnt, (uint64_t)-1);

            /* Mark the removed page as not assigned to TDX.  Update its PAMT.PT
               to PT_NDA. PT of all the PAMT entries at the levels below and above are already
               PT_NDA. */
            td_page_pamt_entry_p->pt = PT_NDA;
            release_sharex_lock_hp_ex(&td_page_pamt_entry_p->entry_lock);
            td_page_pamt_entry_locked_flag = false;

            break;
        }
        default:
        {
            FATAL_ERROR();
        }
        } // end switch

    FINALIZE_ENTRY:
        // finilize processing current entry and prepare for the next one

        if (mig_buff_mapped)
        {
            free_la(mig_buff_p);
            mig_buff_mapped = false;
            mig_buff_p = NULL;
        }

        if (td_page_p)
        {
            free_la(td_page_p);
            td_page_p = NULL;
        }

        if (td_page_pamt_entry_p)
        {
            if (td_page_pamt_block_locked_flag)
            {
                pamt_unwalk(td_page_pa, td_page_pamt_block_desc, td_page_pamt_entry_p, TDX_LOCK_EXCLUSIVE, PT_4KB);
            }
            else
            {
                free_la(td_page_pamt_entry_p);
            }
            td_page_pamt_block_locked_flag = false;
            td_page_pamt_entry_p = NULL;
        }

        if ((err_status != GPA_ENTRY_STATUS_SUCCESS) &&
            ((gpa_list_error_type == GPA_LIST_ERROR_TYPE_LIST_ABORT) ||
             (gpa_list_error_type == GPA_LIST_ERROR_TYPE_LIST_ABORT_IN_ORDER)))
        {
            if (septe_locked_flag)
            {
                sept_lock_release(sept_entry_ptr);
                septe_locked_flag = false;
            }
        }

        if (TDX_SUCCESS != (return_val = handle_rare_errors(err_status, &gpa_list_entry, gpa_list_error_type,
                                                            &problem_ops_count, gpa_list_p, entry_num,
                                                            new_page_list_p, tdcs_p,
                                                            &new_page_list_entry, &return_val)))
        {
            goto EXIT;
        }

        // Write back the updated new page list and GPA list entries to memory
        if (new_page_list_p)
        {
            new_page_list_p[entry_num] = new_page_list_entry;
        }
        gpa_list_p[entry_num] = gpa_list_entry;

        /*--------------------------------------
           Done processing one GPA list entry
        --------------------------------------*/
        if (TDX_INTERRUPTED_RESUMABLE == (return_val = finish_entry_processing(&entry_num, gpa_list_info, migsc_p,
                                                                               mig_buff_list_pa, mac_list_pa,
                                                                               new_page_list_pa, tdcs_p, problem_ops_count)))
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

    if (new_page_list_p)
    {
        free_la(new_page_list_p);
    }

    if (mig_buff_list_p)
    {
        free_la(mig_buff_list_p);
    }

    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->f_migsc_links[migs_i]);
    }

    if (mig_locked_flag)
    {
        release_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_SHARED);
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
