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
 * @file tdh_export_track
 * @brief TDHEXPORTTRACK API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/op_state_lookup.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"

api_error_type tdh_export_track(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa, uint64_t idx_and_cmd)
{

    // TDR and TDCS
    tdr_t             *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t               tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t       tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t      *tdr_pamt_entry_ptr = NULL;
    tdcs_t            *tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t             tdr_locked_flag = false;

    bool_t             op_state_locked_flag = false; // Indicate OP is locked

    // MBMD
    mbmd_t            *mbmd_p = NULL;
    hpa_and_size_t     mbmd_hpa_and_size;
    mbmd_t             mbmd_tmp;

    // Migration Stream
    migs_index_and_cmd_t    migs_i_and_cmd;
    migsc_t                *migsc_p = NULL;
    pa_t                    migsc_pa;
    bool_t                  migsc_locked_flag = false;
    bool_t                  mig_locked_flag = false;

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    migs_i_and_cmd.raw = idx_and_cmd;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
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
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_EXCLUSIVE, false,
                                               TDH_EXPORT_TRACK_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Lock the whole migration context to prevent concurrent TDH.EXPORT.MEM
    if (acquire_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_EXCLUSIVE) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIG);
        TDX_ERROR("Failed to lock TDCS mig lock - error = %llx\n", return_val);
        goto EXIT;
    }
    mig_locked_flag = true;

    // Check the stream index
    if ((migs_i_and_cmd.migs_index != 0) || migs_i_and_cmd.reserved_31_16 || migs_i_and_cmd.reserved_62_32)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    // Check that the buffer for MBMD is large enough
    if (mbmd_hpa_and_size.size < sizeof(mbmd_t))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    mbmd_hpa_and_size.size = 0;
    pa_t mbmd_hpa_and_size_pa = {.raw = mbmd_hpa_and_size.raw};
    // Verify the MBMD physical address is canonical, shared, and aligned
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa_and_size_pa, MBMD_ALIGN)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", mbmd_hpa_and_size_pa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
        goto EXIT;
    }

    // Lock the MIGSC link
    if (!(migsc_lock(&tdcs_p->f_migsc_links[0])))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
        goto EXIT;
    }
    migsc_locked_flag = true;

    // MIGSC must already be initialized
    if (!tdcs_p->f_migsc_links[0].initialized)
    {
        TDX_ERROR("MIGSC is not initialized\n");
        return_val = TDX_MIGRATION_STREAM_STATE_INCORRECT;
        goto EXIT;
    }

    if (migs_i_and_cmd.command != MIGS_INDEX_COMMAND_INORDER_DONE)
    {
        // Transition to the next in-order epoch
        // MIG_EPOCH concurrency is protected since OP_STATE is locked in exclusive mode
        if (tdcs_p->migration_fields.mig_epoch == (MIG_EPOCH_OUT_OF_ORDER - 1))
        {
            TDX_ERROR("Migration epoch overflow\n");
            return_val = TDX_MIGRATION_EPOCH_OVERFLOW;
            goto EXIT;
        }
        tdcs_p->migration_fields.mig_epoch++;
    }
    else
    {
        // Transition to the out-of-order phase
        if (tdcs_p->management_fields.op_state != OP_STATE_PAUSED_EXPORT)
        {
            TDX_ERROR("OP state incorrect %d\n", tdcs_p->management_fields.op_state);
            return_val = TDX_OP_STATE_INCORRECT;
            goto EXIT;
        }

        // Check that DIRTY_COUNT is 0, indicating that no unexported newer versions
        // of any memory page exported so far remain
        if (tdcs_p->migration_fields.dirty_count != 0)
        {
            TDX_ERROR("Dirty count is not zero - %d\n", tdcs_p->migration_fields.dirty_count);
            return_val = TDX_EXPORTED_DIRTY_PAGES_REMAIN;
            goto EXIT;
        }

        tdcs_p->migration_fields.mig_epoch = MIG_EPOCH_OUT_OF_ORDER;
        tdcs_p->management_fields.op_state = OP_STATE_POST_EXPORT;
    }

    //---------------------------------------------------------------
    //   ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    //---------------------------------------------------------------

    // Map the MIGSC
    migsc_pa.raw = 0;
    migsc_pa.page_4k_num = tdcs_p->f_migsc_links[0].migsc_hpa;
    migsc_p = map_pa_with_hkid(migsc_pa.raw_void, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    // Prevent later resumption of a previously interrupted function
    migsc_p->interrupted_state.valid = false;

    // Map the MBMD
    mbmd_p = (mbmd_t*)map_pa(mbmd_hpa_and_size_pa.raw_void, TDX_RANGE_RW);

    tdcs_p->migration_fields.total_mb_count++;

    // Increment the IV counter so we don't reuse a previous IV even if aborted
    migsc_p->iv_counter++;

    // Build the MBMD
    basic_memset_to_zero(&mbmd_tmp, sizeof(mbmd_tmp));
    mbmd_tmp.header.size = sizeof(mbmd_tmp);
    mbmd_tmp.header.mig_version = tdcs_p->migration_fields.mig_version;
    mbmd_tmp.header.migs_index = 0;
    mbmd_tmp.header.mb_type = MB_TYPE_EPOCH_TOKEN;
    mbmd_tmp.header.reserved_1 = 0;
    mbmd_tmp.header.mb_counter = 0;   // MB counter starts at 0 for a new epoch
    mbmd_tmp.header.mig_epoch = tdcs_p->migration_fields.mig_epoch;
    mbmd_tmp.header.iv_counter = 0;   // Real value is written later, after MAC calculation
    mbmd_tmp.epoch_token.total_mb = tdcs_p->migration_fields.total_mb_count;

    // Calculate a MAC over the MBMD
    reset_to_next_iv(migsc_p, migsc_p->iv_counter, 0);

    if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (uint8_t*)&mbmd_tmp.epoch_token,
            MBMD_SIZE_NO_MAC(mbmd_tmp.epoch_token)) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }

    if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mbmd_tmp.epoch_token.mac) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }

    // Update the MBMD with values not included in the MAC calculation
    mbmd_tmp.header.iv_counter = migsc_p->iv_counter;

    // Write out the MBMD
    copy_mbmd(mbmd_p, &mbmd_tmp);

    // Reset the MB counter on a new epoch
    migsc_p->next_mb_counter = 1;

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks
    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    if (migsc_p != NULL)
    {
        free_la(migsc_p);
    }

    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->f_migsc_links[0]);
    }

    if (mig_locked_flag)
    {
        release_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_EXCLUSIVE);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp(&(tdcs_p->management_fields.op_state_lock), TDX_LOCK_EXCLUSIVE);
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
