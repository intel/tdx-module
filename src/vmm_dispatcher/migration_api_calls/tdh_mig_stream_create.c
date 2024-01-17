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
 * @file tdh_mig_stream_create
 * @brief TDHMIGSTREAMCREATE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"
#include "helpers/service_td.h"


api_error_type tdh_mig_stream_create(uint64_t migsc_pa, uint64_t target_tdr_pa)
{

    // TDR and TDCS
    tdr_t           * tdr_p = NULL;           // Pointer to the owner TDR page
    pa_t              tdr_pa;                 // Physical address of the owner TDR page
    pamt_block_t      tdr_pamt_block;         // TDR PAMT block
    pamt_entry_t    * tdr_pamt_entry_ptr;
    tdcs_t          * tdcs_p = NULL;          // Pointer to the TDCS structure
    bool_t            tdr_locked_flag = false;

    bool_t            op_state_locked_flag = false;

    // Migration Stream
    uint16_t          migsc_i;
    migsc_t         * migsc_p = NULL;          // Pointer to the MIGSC
    pa_t              migsc;                   // Physical address of the new MIGSC page
    pamt_block_t      migsc_pamt_block;        // New TD page PAMT block
    pamt_entry_t    * migsc_pamt_entry_p;      // Pointer to the TD PAMT entry
    bool_t            migsc_pamt_locked_flag = false;
    migsc_link_t      migsc_link;

    bool_t            mig_lock_flag = false;

    api_error_type     return_val = TDX_SUCCESS;

    // Input operands
    tdr_pa.raw = target_tdr_pa;
    migsc.raw = migsc_pa;

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
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_EXCLUSIVE,
                                               false, TDH_MIG_STREAM_CREATE_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Lock the whole migration context to prevent concurrent TDH.MIG.STREAM.CREATE
    if (acquire_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_EXCLUSIVE) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIG);
        goto EXIT;
    }
    mig_lock_flag = true;

    migsc_i = tdcs_p->migration_fields.num_migs;
    if (migsc_i >= MAX_MIGS)
    {
        return_val = TDX_MAX_MIGS_NUM_EXCEEDED;
        goto EXIT;
    }

    // No need to lock the MIGSC link, no concurrent function that may access it can run

    // Check and lock the new MIGSC page in PAMT
    return_val = check_lock_and_map_explicit_private_4k_hpa(migsc,
                                                            OPERAND_ID_RCX,
                                                            tdr_p,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &migsc_pamt_block,
                                                            &migsc_pamt_entry_p,
                                                            &migsc_pamt_locked_flag,
                                                            (void**)&migsc_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Explicit 4k private hpa lock failure or - error = %llx\n", return_val);
        goto EXIT;
    }
    /*---------------------------------------------------------------
        ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    ---------------------------------------------------------------*/

    // Initialize the MIGSC page contents using direct write (MOVDIR64B)
    fill_area_cacheline(migsc_p, TDX_PAGE_SIZE_IN_BYTES, 0ULL);

    /* No need to initialize the MIGSC fields.  They are initialized first time the MIGSC
       is used in each migration session */
    migsc_p->migsc_i = migsc_i;

    // Atomically increment TDR child count
    (void)_lock_xadd_64b(&tdr_p->management_fields.chldcnt, 1);

    // Update the new page’s PAMT entry
    migsc_pamt_entry_p->pt = PT_TDCX;
    migsc_pamt_entry_p->owner = tdr_pa.page_4k_num;

    // Initialize the applicable forward link entry in TDCS
    migsc_link.raw = migsc.raw;
    migsc_link.lock = 0;
    migsc_link.initialized = 0;

    tdcs_p->migsc_links[migsc_i] = migsc_link;
    tdcs_p->migration_fields.num_migs = migsc_i + 1;

EXIT:
    // Release all acquired locks
    if (op_state_locked_flag)
    {
        release_sharex_lock_hp(&(tdcs_p->management_fields.op_state_lock), TDX_LOCK_EXCLUSIVE);
    }
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_p);
    }
    if (mig_lock_flag)
    {
        release_sharex_lock(&tdcs_p->migration_fields.mig_lock, TDX_LOCK_EXCLUSIVE);
    }
    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }
    if(migsc_pamt_locked_flag)
    {
        pamt_unwalk(migsc, migsc_pamt_block, migsc_pamt_entry_p, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(migsc_p);
    }

    return return_val;
}
