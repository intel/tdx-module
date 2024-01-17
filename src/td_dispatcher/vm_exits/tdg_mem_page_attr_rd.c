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
 * @file tdg_mem_page_attr_rd.c
 * @brief TDGMEMPAGEATTRRD API handler
 */

#include "tdx_td_api_handlers.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"

static void basic_ept_violation_exit(pa_t gpa)
{
    vm_vmexit_exit_reason_t vm_exit_reason = {.raw = 0};
    vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;

    gpa.low_12_bits = 0;

    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, 0, 0);
}

api_error_type tdg_mem_page_attr_rd(pa_t page_gpa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    // GPA and SEPT related variables
    ia32e_sept_t *page_sept_entry_ptr = NULL; // SEPT entry of the page
    ept_level_t page_level_entry = LVL_PT;    // SEPT entry level of the page
    ia32e_sept_t page_sept_entry_copy;        // Cached SEPT entry of the page
    bool_t is_sept_locked = false;

    ia32e_sept_t *l2_septe_ptr = NULL;

    gpa_mapping_and_flags_t gpa_mapping_and_flags = {.raw = 0};
    gpa_attr_t gpa_attr = {.raw = 0};

    tdx_module_local_t *local_data_ptr = get_local_data();

    tdcs_t *tdcs_ptr = local_data_ptr->vp_ctx.tdcs;
    tdr_t *tdr_ptr = local_data_ptr->vp_ctx.tdr;

    tdx_sanity_check(tdcs_ptr != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ATTR_RD_LEAF), 0);
    tdx_sanity_check(tdr_ptr != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ATTR_RD_LEAF), 1);

    if (!check_gpa_validity(page_gpa, tdcs_ptr->executions_ctl_fields.gpaw, PRIVATE_ONLY))
    {
        TDX_ERROR("Page to accept GPA (=0x%llx) is not not valid\n", page_gpa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check SEPT and walk to find entry
    // Ignore success/failure indication - this is handled by the check below.
    page_sept_entry_ptr = secure_ept_walk(tdcs_ptr->executions_ctl_fields.eptp, page_gpa,
                                tdr_ptr->key_management_fields.hkid, &page_level_entry, &page_sept_entry_copy, false);

    // Create a copy of the SEPT entry and mark it locally as locked (guest-side only).
    return_val = sept_lock_acquire_guest(page_sept_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Can't lock guest-side lock\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    is_sept_locked = true;

    // Read the SEPT entry
    page_sept_entry_copy.raw = page_sept_entry_ptr->raw;
    // TDG.MEM.PAGE.ATTR.RD is allowed on non-blocked leaf pages
    if (!sept_state_is_tdcall_leaf_allowed(TDG_MEM_PAGE_ATTR_RD_LEAF, page_sept_entry_copy))
    {
        sept_lock_release(page_sept_entry_ptr);
        free_la(page_sept_entry_ptr);

        basic_ept_violation_exit(page_gpa);
    }

    // No failure past this point
    gpa_mapping_and_flags.raw = align_gpa_on_level(page_gpa, page_level_entry);
    gpa_mapping_and_flags.level = page_level_entry;
    gpa_mapping_and_flags.pending = sept_state_is_any_pending(page_sept_entry_copy);

    gpa_attr.attr_arr[0] = sept_get_gpa_attr(page_sept_entry_copy);

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if (!sept_state_is_aliased(page_sept_entry_copy, vm_id))
        {
            continue;
        }

        /**
         * Walk the L2 SEPT to locate the entry.
         *  Allow blocked non-leaf entries:  blocking must have happened AFTER we read the L1 SEPT entry above,
         *  so since we're running in the guest context we are protected by TLB tracking.
         */
        ia32e_sept_t l2_sept_entry_copy;

        return_val = l2_sept_walk_guest_side(tdr_ptr, tdcs_ptr, vm_id, page_gpa,
                                             &page_level_entry, &l2_sept_entry_copy, &l2_septe_ptr);
        if (return_val != TDX_SUCCESS)
        {
            FATAL_ERROR();
        }

        /**
         * Get the L2 attributes.
         *  L2 SEPT entry does not hold a BLOCKEDW indication of its own, so provide it based on the L1 state.
         */
        gpa_attr.attr_arr[vm_id] = l2_sept_get_gpa_attr(l2_septe_ptr,
                                        sept_state_is_any_blockedw(page_sept_entry_copy));

        free_la(l2_septe_ptr);
    }

    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rcx = gpa_mapping_and_flags.raw;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx = gpa_attr.raw;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rax = TDX_SUCCESS;
    return_val = TDX_SUCCESS;
    goto EXIT_NO_DEFAULT_OUTPUT;

EXIT:

    // Default output values
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rcx = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx = 0;

EXIT_NO_DEFAULT_OUTPUT:

    if (is_sept_locked)
    {
        sept_lock_release(page_sept_entry_ptr);
    }

    if (page_sept_entry_ptr != NULL)
    {
        free_la(page_sept_entry_ptr);
    }

    return return_val;
}
