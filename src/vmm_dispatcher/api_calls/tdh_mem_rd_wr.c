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
 * @file tdh_mem_rd_wr
 * @brief TDHMEMRD and TDHMEMWR API handlers
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "auto_gen/tdvps_fields_lookup.h"

static api_error_type tdh_mem_rd_wr(uint64_t gpa, uint64_t target_tdr_pa,
                                    uint64_t data, bool_t write)
{
    tdx_module_local_t * local_data_ptr = get_local_data();

    // Temporary Variables
    uint64_t            * data_ptr = NULL;                      // Pointer to the data
    pa_t                  data_pa = {.raw = 0};                 // Physical address of the data
    pa_t                  page_gpa = {.raw = 0};                             // Target page GPA

    // TDR related variables
    pa_t                  tdr_pa;
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    // SEPT related variables
    ia32e_sept_t        * sept_entry_ptr = NULL;        // SEPT entry of the page
    ia32e_sept_t          sept_entry_copy;              // Cached SEPT entry of the page
    ept_level_t           sept_level_entry = LVL_PT;    // SEPT entry level of the page - Try 4K level
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;    // Indicate SEPT entry is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    page_gpa.raw = gpa;

    // Initialize output registers to default values
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;
    local_data_ptr->vmm_regs.r8  = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, write ? TDH_MEM_WR_LEAF : TDH_MEM_RD_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        return_val = TDX_TD_NON_DEBUG;
        TDX_ERROR("TD is a non debug!\n");
        goto EXIT;
    }

    // Verify GPA is private and aligned on 8 bytes
    if (!is_addr_aligned_pwr_of_2(page_gpa.raw, 8))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    if (acquire_sharex_lock(&tdcs_ptr->executions_ctl_fields.secure_ept_lock, TDX_LOCK_SHARED) != LOCK_RET_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT_TREE);
        TDX_ERROR("Failed to acquire SEPT tree lock");
        goto EXIT;
    }
    sept_locked_flag = true;

    // Check GPA, lock SEPT and walk to find entry
    return_val = check_and_walk_private_gpa_to_leaf(tdcs_ptr,
                                                    OPERAND_ID_RCX,
                                                    page_gpa,
                                                    tdr_ptr->key_management_fields.hkid,
                                                    &sept_entry_ptr,
                                                    &sept_level_entry,
                                                    &sept_entry_copy);

    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            return_val = api_error_with_operand_id(TDX_EPT_ENTRY_NOT_PRESENT, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry in memory
    return_val = sept_lock_acquire_host(sept_entry_ptr);
    if (TDX_SUCCESS!= return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry (again after locking)
    sept_entry_copy = *sept_entry_ptr;

    if (!sept_state_is_seamcall_leaf_allowed(write ? TDH_MEM_WR_LEAF : TDH_MEM_RD_LEAF, sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        TDX_ERROR("TDH_MEM_RW/WR is not allowed in current SEPT entry state - 0x%llx\n", sept_entry_copy.raw);
        goto EXIT;
    }

    /*---------------------------------------------------------------
          ALL_CHECKS_PASSED:  The function is guaranteed to succeed
     *---------------------------------------------------------------*/

    // Get the data HPA at 4KB resolution by inserting GPA bits 30:12 (for 1G) or 21:12 (for 2M)
    data_pa.raw = leaf_ept_entry_to_hpa(sept_entry_copy, page_gpa.raw, sept_level_entry);

    // Map and get the data pointer
    data_ptr = map_pa_with_hkid((void*)data_pa.raw, tdr_ptr->key_management_fields.hkid, write ? TDX_RANGE_RW : TDX_RANGE_RO);

    // Read the data
    local_data_ptr->vmm_regs.r8 = *data_ptr;

    // Write the data
    if (write)
    {
        *data_ptr = data;
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }

    if (septe_locked_flag)
    {
        sept_lock_release(sept_entry_ptr);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (sept_entry_ptr != NULL)
        {
            free_la(sept_entry_ptr);
        }
    }

    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }

    if (data_ptr != NULL)
    {
        free_la(data_ptr);
    }

    return return_val;
}

api_error_type tdh_mem_rd(uint64_t gpa, uint64_t target_tdr_pa)
{
    return tdh_mem_rd_wr(gpa, target_tdr_pa, 0, false);
}

api_error_type tdh_mem_wr(uint64_t gpa, uint64_t target_tdr_pa, uint64_t data)
{
    return tdh_mem_rd_wr(gpa, target_tdr_pa, data, true);
}

