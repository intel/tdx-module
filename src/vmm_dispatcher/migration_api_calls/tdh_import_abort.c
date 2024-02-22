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
 * @file tdh_import_abort.c
 * @brief TDH_IMPORT_ABORT API handler
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
#include "metadata_handlers/metadata_generic.h"


api_error_type tdh_import_abort(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa, uint64_t migs_i)
{
    // TDR and TDCS
    tdr_t             *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t               tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t       tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t      *tdr_pamt_entry_ptr = NULL;
    tdcs_t            *tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t             tdr_pamt_locked_flag = false;

    // MBMD
    mbmd_t            *mbmd_p = NULL;
    hpa_and_size_t     mbmd_hpa_and_size;
    mbmd_t             mbmd;

    api_error_type     return_val = TDX_OPERAND_INVALID;

    // Migration Stream
    migsc_t           *migsc_p = NULL;
    pa_t               migsc_pa;
    bool_t             migsc_locked_flag = false;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_pamt_locked_flag,
                                                 &tdr_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_NO_LOCK,
                                               false, TDH_IMPORT_ABORT_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the stream index
    if (migs_i != 0)
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

    // Verify the MBMD physical address is canonical, shared, and aligned to MBMD_ALIGN
    pa_t mbmd_hpa = { .raw = mbmd_hpa_and_size.raw };
    if ((return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa, MBMD_ALIGN)) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
        goto EXIT;
    }

    lfence();
    // Lock the MIGSC link
    if (!(migsc_lock(&tdcs_p->b_migsc_link)))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
        goto EXIT;
    }
    migsc_locked_flag = true;

    /*---------------------------------------------------------------
        ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    ---------------------------------------------------------------*/

    // Mark the import as failed
    tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;

    // Map the MBMD
    mbmd_p = (mbmd_t*)map_pa(mbmd_hpa.raw_void, TDX_RANGE_RW);

    // Map the MIGSC
    migsc_pa.raw = 0;
    migsc_pa.page_4k_num = tdcs_p->b_migsc_link.migsc_hpa;
    migsc_p = (migsc_t *)map_pa_with_hkid(migsc_pa.raw_void, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    if (!tdcs_p->b_migsc_link.initialized)
    {
        migsc_init(migsc_p, &tdcs_p->migration_fields.mig_enc_working_key);
        tdcs_p->b_migsc_link.initialized = true;
    }

    // Prevent later resumption of a previously interrupted function
    migsc_p->interrupted_state.valid = false;

    // Increment the IV counter so we don't reuse a previous IV even if aborted
    migsc_p->iv_counter++;

    // Build the MBMD
    mbmd.header.mig_version = tdcs_p->migration_fields.mig_working_version;
    mbmd.header.size = sizeof(mbmd_t);
    mbmd.header.migs_index = 0;   // Real value is written later, after MAC calculation
    mbmd.header.mb_type = MB_TYPE_ABORT_TOKEN;
    mbmd.header.reserved_1 = 0;
    mbmd.header.mb_counter = migsc_p->next_mb_counter;
    mbmd.header.iv_counter = 0;
    mbmd.header.mig_epoch = 0;
    mbmd.abort_token.reserved = 0;

    // Calculate a MAC over the MAC’ed fields of the MBMD
    reset_to_next_iv(migsc_p, migsc_p->iv_counter, 0);
    if (aes_gcm_process_aad(&migsc_p->aes_gcm_context,(uint8_t*)&mbmd.abort_token,
            (MBMD_SIZE_NO_MAC(mbmd.abort_token))) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }
    if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mbmd.abort_token.mac))
    {
        FATAL_ERROR();
    }

    // Update the MBMD with values not included in the MAC calculation
    mbmd.header.migs_index = 0;
    mbmd.header.iv_counter = migsc_p->iv_counter;


    // Write out the MBMD
    copy_mbmd(mbmd_p, &mbmd);

    // Update the migration bundle counter
    migsc_p->next_mb_counter++;

    // Return TDX_SUCCESS but with the FATAL bit set, indicating that the TD can only be torn down
    return_val = api_error_fatal(TDX_SUCCESS);

EXIT:
    // Release all acquired locks

    if (migsc_p != NULL)
    {
        free_la(migsc_p);
    }

    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->b_migsc_link);
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (tdr_pamt_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_p);
    }

    return return_val;
}
