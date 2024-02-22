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
 * @file tdh_mem_sept_rd_wr.c
 * @brief TDHMEMSEPTRD/TDHMEMSEPTWR API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"

#define READ_L2_ATTRIBUTES_FLAG             BIT(0)

api_error_type tdh_mem_sept_rd(page_info_api_input_t gpa_page_info, uint64_t target_tdr_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA and SEPT related variables
    pa_t                  page_gpa = {.raw = 0};        // Target page GPA
    page_info_api_input_t gpa_mappings = gpa_page_info; // GPA and level
    ia32e_sept_t        * sept_entry_ptr = NULL;        // SEPT entry of the page
    ia32e_sept_t          sept_entry_copy;              // Cached SEPT entry of the page
    ept_level_t           sept_level_entry = gpa_mappings.level; // SEPT entry level of the page
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;    // Indicate SEPT entry is locked

    bool_t                read_l2_attributes = false;

    api_error_type        return_val = UNINITIALIZE_ERROR;


    read_l2_attributes = ((target_tdr_pa & READ_L2_ATTRIBUTES_FLAG) != 0);

    tdr_pa.raw = target_tdr_pa & ~READ_L2_ATTRIBUTES_FLAG;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

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
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_MEM_SEPT_RD_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // Read of L2 attributes is only allowed in debug mode
    if (read_l2_attributes && !tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        TDX_ERROR("Read of L2 attributes is only allowed in debug mode\n");
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PT, tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &sept_entry_ptr,
                                                      &sept_level_entry,
                                                      &sept_entry_copy,
                                                      &sept_locked_flag);

    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        }
        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry
    return_val = sept_lock_acquire_host(sept_entry_ptr);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry after being locked
    sept_entry_copy.raw = sept_entry_ptr->raw;

    if (read_l2_attributes)
    {
        gpa_attr_t gpa_attr = { .raw = 0 };

        for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
        {
            if (!is_sept_free(&sept_entry_copy) && sept_state_is_aliased(sept_entry_copy, vm_id))
            {
                ia32e_sept_t* l2_sept_entry_ptr = NULL;

                return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, page_gpa,
                                          &sept_level_entry, &l2_sept_entry_ptr);

                if (return_val != TDX_SUCCESS)
                {
                    FATAL_ERROR(); // Should not happen - no need to free the L2 SEPT PTR's
                }

                // Get the L2 attributes. L2 SEPT entry does not hold a BLOCKEDW indication
                // of its own, so provide it based on the L1 state.
                gpa_attr.attr_arr[vm_id] = l2_sept_get_gpa_attr(l2_sept_entry_ptr,
                        sept_state_is_any_blockedw(sept_entry_copy));

                free_la(l2_sept_entry_ptr);
            }
        }

        // Return the L2 attributes in R8
        local_data_ptr->vmm_regs.r8 = gpa_attr.raw;
    }

    // Update Secure EPT arch entry values in RCX and RDX
    set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);

EXIT:

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

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }

    return return_val;
}
