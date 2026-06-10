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
 * @file tdh_phymem_cache_wb
 * @brief TDHPHYMEMCACHEWB API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "memory_handlers/keyhole_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"


api_error_type tdh_phymem_cache_wb(uint64_t cachewb_cmd)
{
    // TDX Global and Local data
    tdx_module_global_t * global_data_ptr = get_global_data();
    tdx_module_local_t  * local_data_ptr = get_local_data();

    // KOT and PHYMEMCACHEWB related variables
    uint64_t              curr_cachewb_cmd = cachewb_cmd;
    uint8_t               cachewb_flushed_bitmap[MAX_HKIDS];
    bool_t                flushed_bitmap_counter = false;
    uint16_t              curr_hkid;
    bool_t                kot_locked_flag = false;       // Indicates whether KOT is locked
    bool_t                cachewb_locked_flag = false;   // Indicates whether the WBT is locked
    uint64_t              intr_point_for_cachewb;        // CACHEWB interruption point
    uint64_t              cachewb_index = 0;

    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Verify the command value
    if (curr_cachewb_cmd > TDH_PHYMEM_CACHEWB_RESUME_CMD)
    {
        TDX_ERROR("Unsupported CACHEWB command given = (%llx)\n", curr_cachewb_cmd);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    /**
     * Get the index for PHYMEMCACHEWB.  Depending on the CPU, this would be current package.
     */
    cachewb_index = (uint64_t)local_data_ptr->lp_info.pkg;

    // Acquire package-scope TDHPHYMEMCACHEWB mutex
    if (acquire_mutex_lock(&global_data_ptr->wbt_entries[cachewb_index].entry_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on WBT entry for index = (%llu)\n", cachewb_index);
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_WBCACHE);
        goto EXIT;
    }
    cachewb_locked_flag = true;

    // Acquire shared access to KOT
    if (acquire_sharex_lock_sh(&global_data_ptr->kot.lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on KOT\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_KOT);
        goto EXIT;
    }
    kot_locked_flag = true;

    basic_memset_to_zero(cachewb_flushed_bitmap, sizeof(cachewb_flushed_bitmap));

    // Handle initial TDBWINVD (that is not a resumption of an interrupted TDWBINVD)
    if (curr_cachewb_cmd == TDH_PHYMEM_CACHEWB_START_CMD)
    {
        // Reset any previously saved interruption state
        global_data_ptr->wbt_entries[cachewb_index].intr_point = 0;
        intr_point_for_cachewb = 0ULL;

        /**
         * Prepare a bitmap of the HKIDs that have been reclaimed and their VCPUs
         * have been flushed.  These are the one that will be marked as done at the end.
         */
        for (curr_hkid = (uint16_t)global_data_ptr->private_hkid_min;
             curr_hkid <= (uint16_t)global_data_ptr->private_hkid_max; curr_hkid++ )
        {
            if (global_data_ptr->kot.entries[curr_hkid].state == KOT_STATE_HKID_FLUSHED)
            {
                cachewb_flushed_bitmap[curr_hkid] = true;
                flushed_bitmap_counter = true;
            }
            else
            {
                cachewb_flushed_bitmap[curr_hkid] = false;
            }
        }

        /**
         * If none of the HKIDs is ready for TDHPHYMEMCACHEWB, then abort, no point to continue.
         */
        if (!flushed_bitmap_counter)
        {
            TDX_ERROR("No HKIDS ready to be CACHEWB\n");
            return_val = TDX_NO_HKID_READY_TO_WBCACHE;
            goto EXIT;
        }

        // Store the bitmap in the CACHEWB state table
        for (curr_hkid = (uint16_t)global_data_ptr->private_hkid_min;
             curr_hkid <= (uint16_t)global_data_ptr->private_hkid_max; curr_hkid++ )
        {
            global_data_ptr->wbt_entries[cachewb_index].hkid_flushed[curr_hkid] =
                    cachewb_flushed_bitmap[curr_hkid];
        }
    }
    else // Handle resumed TDHPHYMEMCACHEWB
    {
        // Get the last interruption point for this package
        intr_point_for_cachewb = global_data_ptr->wbt_entries[cachewb_index].intr_point;

        /**
         * Verify that an interruption state has been saved, and that the current HKID
         * is the same as the saved one.
         */
        if (intr_point_for_cachewb == 0)
        {
            TDX_ERROR("No CACHEWB session to resume, interruption state is 0\n");
            return_val = TDX_WBCACHE_RESUME_ERROR;
            goto EXIT;
        }
    }

    // Execute WBNOINVDP in a loop until either done or an event has been detected
    do
    {
        // Write back the next cache sub-block
        ia32_wrmsr(IA32_WBNOINVDP_MSR_ADDR, intr_point_for_cachewb);
        intr_point_for_cachewb++;

        // If this was not the last sub-block, check for pending interrupts
        if (intr_point_for_cachewb < global_data_ptr->num_of_cached_sub_blocks)
        {
            if (is_interrupt_pending_host_side())
            {
                global_data_ptr->wbt_entries[cachewb_index].intr_point = intr_point_for_cachewb;
                TDX_LOG("There were pending interrupts during CACHEWB call\n");
                return_val = TDX_INTERRUPTED_RESUMABLE;
                goto EXIT;
            }
        }
    }
    while (intr_point_for_cachewb < global_data_ptr->num_of_cached_sub_blocks);

    // Mark the interruption point as invalid
    global_data_ptr->wbt_entries[cachewb_index].intr_point = 0;

    // At this point TDHPHYMEMCACHEWB has completed without interruption.
    // ALL_CHECKS_PASSED:  The instruction is guaranteed to succeed

    /**
     * Go over all applicable KOT entries.  For those entries where WBINVD_INIT_BITMAP
     * bit for the current package is 1, clear the same bit in the WBINVD_BITMAP.
     */
    for (curr_hkid = (uint16_t)global_data_ptr->private_hkid_min;
         curr_hkid <= (uint16_t)global_data_ptr->private_hkid_max; curr_hkid++ )
    {
        if (global_data_ptr->wbt_entries[cachewb_index].hkid_flushed[curr_hkid])
        {
            /**
             * An atomic operation is required because TDHPHYMEMCACHEWB can run
             * concurrently on other packages.
             */
            _lock_btr_32b(&global_data_ptr->kot.entries[curr_hkid].wbinvd_bitmap, (uint32_t)cachewb_index);
        }
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks
    if (kot_locked_flag)
    {
        release_sharex_lock_sh(&global_data_ptr->kot.lock);
    }
    if (cachewb_locked_flag)
    {
        release_mutex_lock(&global_data_ptr->wbt_entries[cachewb_index].entry_lock);
    }
    return return_val;
}

