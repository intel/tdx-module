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
 * @file tdh_sys_tdmr_init.c
 * @brief TDHSYSTDMRINI API handler
 */

#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"

#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"

#define TDMR_4K_PAMT_INIT_COUNT _1KB

#if (((TDMR_PAMT_INIT_COUNT * 16) % 64) != 0)
    #error "TDMR_4K_PAMT_INIT_COUNT is wrong"
#endif

api_error_type tdh_sys_tdmr_init(uint64_t tdmr_pa)
{

    tdx_module_global_t* tdx_global_data_ptr;
    tdx_module_local_t* tdx_local_data = get_local_data();
    api_error_type retval;
    bool_t lock_acquired = false;

    tdx_local_data->vmm_regs.rdx = 0ULL;

    // For each TDMR, the VMM executes a loop of SEAMCALL(TDHSYSINITTDMR),
    // providing the TDMR start address (at 1GB granularity) as an input
    if (!is_addr_aligned_pwr_of_2(tdmr_pa, _1GB) ||
        !is_pa_smaller_than_max_pa(tdmr_pa) ||
        (get_hkid_from_pa((pa_t)tdmr_pa) != 0))
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;

    }

    tdx_global_data_ptr = get_global_data();

    //   2.  Verify that the provided TDMR start address belongs to one of the TDMRs set during TDHSYSINIT
    uint32_t tdmr_index;
    for (tdmr_index = 0; tdmr_index < tdx_global_data_ptr->num_of_tdmr_entries; tdmr_index++)
    {
        if (tdmr_pa == tdx_global_data_ptr->tdmr_table[tdmr_index].base)
        {
            break;
        }
    }
    if (tdmr_index >= tdx_global_data_ptr->num_of_tdmr_entries)
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    tdmr_entry_t *tdmr_entry = &tdx_global_data_ptr->tdmr_table[tdmr_index];

    if (acquire_mutex_lock(&tdmr_entry->lock) != LOCK_RET_SUCCESS)
    {
        retval = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }

    lock_acquired = true;

    //   3.  Retrieves the TDMR’s next-to-initialize address from the internal TDMR data structure.
    //       If the next-to-initialize address is higher than the address to the last byte of the TDMR, there’s nothing to do.
    //       If successful, the function does the following:
    if (tdmr_entry->last_initialized >= (tdmr_entry->base + tdmr_entry->size))
    {
        retval = TDX_TDMR_ALREADY_INITIALIZED;
        goto EXIT;
    }

    //   4.  Initialize an (implementation defined) number of PAMT entries.
    //        The maximum number of PAMT entries to be initialized is set to avoid latency issues.
    //   5.  If the PAMT for a 1GB block of TDMR has been fully initialized, mark that 1GB block as ready for use.
    //        This means that 4KB pages in this 1GB block may be converted to private pages, e.g., by TDCALL(TDHMEMPAGEADD).
    //        This can be done concurrently with initializing other TDMRs.

    pamt_block_t pamt_block;
    pamt_block.pamt_1gb_p = (pamt_entry_t*) (tdmr_entry->pamt_1g_base
            + ((tdmr_entry->last_initialized - tdmr_entry->base) / _1GB * sizeof(pamt_entry_t)));
    pamt_block.pamt_2mb_p = (pamt_entry_t*) (tdmr_entry->pamt_2m_base
            + ((tdmr_entry->last_initialized - tdmr_entry->base) / _2MB * sizeof(pamt_entry_t)));
    pamt_block.pamt_4kb_p = (pamt_entry_t*) (tdmr_entry->pamt_4k_base
            + ((tdmr_entry->last_initialized - tdmr_entry->base) / _4KB * sizeof(pamt_entry_t)));

    pamt_init(&pamt_block, TDMR_4K_PAMT_INIT_COUNT, tdmr_entry);

    //   6.  Store the updated next-to-initialize address in the internal TDMR data structure.
    tdmr_entry->last_initialized += (TDMR_4K_PAMT_INIT_COUNT * _4KB);

    //   7.  The returned next-to-initialize address is always rounded down to 1GB, so VMM won’t attempt to use a 1GB block that is not fully initialized.
    tdx_local_data->vmm_regs.rdx = tdmr_entry->last_initialized & ~(_1GB - 1);

    retval = TDX_SUCCESS;

    EXIT:

    if (lock_acquired)
    {
        release_mutex_lock(&tdx_global_data_ptr->tdmr_table[tdmr_index].lock);
    }

    return retval;
}

