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
 * @file tdh_mng_key_freeid
 * @brief TDHMNGKEYFREEID API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"


api_error_type tdh_mng_key_freeid(uint64_t target_tdr_pa)
{
    // TDX Global data
    tdx_module_global_t * global_data_ptr = get_global_data();

    // TDR related variables
    pa_t                  tdr_pa = {.raw = target_tdr_pa}; // TDR physical address
    tdr_t               * tdr_ptr;                         // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;                  // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;              // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;         // Indicate TDR is locked

    uint16_t              curr_hkid;
    bool_t                kot_locked_flag = false;         // Indicates whether KOT is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    /**
     * Check TDR (explicit access, opaque semantics, exclusive lock).
     */
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %lld\n", return_val);
        goto EXIT;
    }

    // Verify the TD's key state
    if (tdr_ptr->management_fields.lifecycle_state != TD_BLOCKED)
    {
        TDX_ERROR("TD in incorrect key state\n");
        return_val = TDX_LIFECYCLE_STATE_INCORRECT;
        goto EXIT;
    }

    // Acquire exclusive access to KOT
    if (acquire_sharex_lock_ex(&global_data_ptr->kot.lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on KOT\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_KOT);
        goto EXIT;
    }
    kot_locked_flag = true;

    /**
     * If TDH_PHYMEM_CACHE_WB was executed on all packages/cores,
     * set the KOT entry, set the KOT entry state to HKID_FREE.
     */
    curr_hkid = tdr_ptr->key_management_fields.hkid;
    tdx_debug_assert(global_data_ptr->kot.entries[curr_hkid].state == KOT_STATE_HKID_FLUSHED);
    if (global_data_ptr->kot.entries[curr_hkid].wbinvd_bitmap != 0)
    {
        TDX_ERROR("CACHEWB is not complete for this HKID (=%x)\n", curr_hkid);
        return_val = TDX_WBCACHE_NOT_COMPLETE;
        goto EXIT;
    }

    // ALL_CHECKS_PASSED: The function is guaranteed to succeed

    global_data_ptr->kot.entries[curr_hkid].state = (uint8_t)KOT_STATE_HKID_FREE;
    tdr_ptr->management_fields.lifecycle_state = (uint8_t)TD_TEARDOWN;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (kot_locked_flag)
    {
        release_sharex_lock_ex(&global_data_ptr->kot.lock);
    }
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }

    return return_val;
}
