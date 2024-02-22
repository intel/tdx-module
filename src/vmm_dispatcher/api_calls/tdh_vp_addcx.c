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
 * @file tdh_vp_addcx.c
 * @brief TDHVPADDCX API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/ia32_accessors.h"


api_error_type tdh_vp_addcx(uint64_t target_tdcx_pa, uint64_t target_tdvpr_pa)
{
    // TDCX related variables
    pa_t                  tdcx_pa;                  // TDCX physical address
    void                * tdcx_ptr;                 // Pointer to the TDCX page (linear address)
    pamt_block_t          tdcx_pamt_block;          // TDCX PAMT block
    pamt_entry_t        * tdcx_pamt_entry_ptr;      // Pointer to the TDCX PAMT entry
    bool_t                tdcx_locked_flag = false; // Indicate TDCX is locked

    // TDVPS related variables
    pa_t                  tdvpr_pa;                  // TDVPR physical address
    tdvps_t             * tdvps_ptr = NULL;          // Pointer to the TDVPS (multi-page linear address)
    pamt_block_t          tdvpr_pamt_block;          // TDVPR PAMT block
    pamt_entry_t        * tdvpr_pamt_entry_ptr;      // Pointer to the TDVPR PAMT entry
    bool_t                tdvpr_locked_flag = false; // Indicate TDVPR is locked

    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDVPR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS page (linear address)

    uint64_t              num_tdvps_pages;
    uint16_t              td_hkid;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdcx_pa.raw  = target_tdcx_pa;
    tdvpr_pa.raw = target_tdvpr_pa;

    // Check and lock the parent TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RDX,
                                                         TDX_LOCK_EXCLUSIVE,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_block,
                                                         &tdvpr_pamt_entry_ptr,
                                                         &tdvpr_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock a TDVPR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Get and lock the owner TDR page
    tdr_pa = get_pamt_entry_owner(tdvpr_pamt_entry_ptr);
    return_val = lock_and_map_implicit_tdr(tdr_pa,
                                           OPERAND_ID_TDR,
                                           TDX_RANGE_RW,
                                           TDX_LOCK_SHARED,
                                           &tdr_pamt_entry_ptr,
                                           &tdr_locked_flag,
                                           &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_VP_ADDCX_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // Get the TD's ephemeral HKID
    td_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the TDVPS structure.  Note that only the 1st page (TDVPR) is
    // accessible at this point.
    tdvps_ptr = (tdvps_t*)map_pa((void*)(set_hkid_to_pa(tdvpr_pa, td_hkid).full_pa), TDX_RANGE_RW);

    // Check the VCPU state
    if (tdvps_ptr->management.state != VCPU_UNINITIALIZED)
    {
        TDX_ERROR("TD VCPU is already initialized\n");
        return_val = TDX_VCPU_STATE_INCORRECT;
        goto EXIT;
    }

    // Get the current number of TDCX pages and verify
    num_tdvps_pages = tdvps_ptr->management.num_tdvps_pages;
    if (num_tdvps_pages >= MAX_TDVPS_PAGES)
    {
        TDX_ERROR("Number of TDCX pages (%llu) exceeds the allowed count (%d)\n", num_tdvps_pages, MAX_TDVPS_PAGES-1);
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    // Check, lock and map the new TDCX page
    return_val = check_lock_and_map_explicit_private_4k_hpa(tdcx_pa,
                                                            OPERAND_ID_RCX,
                                                            tdr_ptr,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &tdcx_pamt_block,
                                                            &tdcx_pamt_entry_ptr,
                                                            &tdcx_locked_flag,
                                                            (void**)&tdcx_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDCX - error = %lld\n", return_val);
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Clear the content of the TDCX page using direct writes
    // MSR and shadow MSR bitmaps pages are initialized to all -1
    if (is_l2_msr_bitmap_page_index(num_tdvps_pages))
    {
        fill_area_cacheline(tdcx_ptr, TDX_PAGE_SIZE_IN_BYTES, (~(uint64_t)0));
    }
    else
    {
        zero_area_cacheline(tdcx_ptr, TDX_PAGE_SIZE_IN_BYTES);
    }

    // Register the new TDCX in its parent TDVPS structure
    // Note that tdcx_pa[0] is the PA of TDVPR, so TDCX
    // pages start from index 1
    tdvps_ptr->management.tdvps_pa[num_tdvps_pages] = set_hkid_to_pa(tdcx_pa, td_hkid).raw;
    num_tdvps_pages++;
    tdvps_ptr->management.num_tdvps_pages = (uint8_t)num_tdvps_pages;

    // Register the new TDCX page in its owner TDR
    (void)_lock_xadd_64b(&(tdr_ptr->management_fields.chldcnt), 1);

    // Set the new TDCX page PAMT fields
    tdcx_pamt_entry_ptr->pt = PT_TDCX;
    set_pamt_entry_owner(tdcx_pamt_entry_ptr, tdr_pa);


EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }
    if (tdcx_locked_flag)
    {
        pamt_unwalk(tdcx_pa, tdcx_pamt_block, tdcx_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdcx_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }
    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
        free_la(tdr_ptr);
    }
    return return_val;
}
