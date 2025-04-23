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
 * @file tdg_mem_page_attr_wr.c
 * @brief TDGMEMPAGEATTRRD API handler
 */

#include "tdx_td_api_handlers.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"

static void ext_ept_violation_exit(pa_t gpa, ia32e_sept_t sept_entry_copy, uint16_t vm_id, ept_level_t ept_level)
{
    vmx_ext_exit_qual_t eeq = {.raw = 0};
    tdaccept_vmx_eeq_info_t eeq_info = {.raw = 0};

    vmx_exit_qualification_t exit_qual = { .raw = 0 };

    exit_qual.ept_violation.data_write             = 1;
    exit_qual.ept_violation.gpa_readable           = sept_entry_copy.l2_encoding.r;
    exit_qual.ept_violation.gpa_writeable          = sept_entry_copy.l2_encoding.w;
    exit_qual.ept_violation.gpa_executable         = sept_entry_copy.l2_encoding.x;
    exit_qual.ept_violation.gpa_exec_for_ring3_lin = sept_entry_copy.l2_encoding.xu;

    eeq_info.err_sept_level = ept_level;
    eeq_info.vm_index = vm_id;

    eeq.type = VMX_EEQ_GPA_DETAILS;
    eeq.info = eeq_info.raw;

    vm_vmexit_exit_reason_t vm_exit_reason = {.raw = 0};
    vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;

    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qual.raw, eeq.raw);
}

static api_error_type get_all_l2_sept_entries(tdr_t *tdr_ptr, tdcs_t *tdcs_ptr, tdvps_t *tdvps_ptr,
        ia32e_sept_t l1_sept_entry_copy, ia32e_sept_t *l1_sept_entry_ptr,
        ept_level_t page_level_entry, pa_t page_gpa, ia32e_sept_t *l2_septe_ptr[MAX_VMS],
        gpa_attr_t attr_mask, gpa_attr_t* new_gpa_attr)
{
    gpa_attr_single_vm_t single_vm_masked_gpa_attr;
    gpa_attr_single_vm_t single_vm_curr_gpa_attr;
    ia32e_sept_t l2_sept_entry_copy;

    api_error_type return_val = TDX_SUCCESS;
    api_error_type attribute_status = TDX_SUCCESS;

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        // Prepare the masked attributes
        attr_mask.attr_arr[vm_id].valid = 1;   // Set to 1 so we don't mask the VALID bit of new_gpa_attr.ATTR
        single_vm_masked_gpa_attr.raw = new_gpa_attr->attr_arr[vm_id].raw & attr_mask.attr_arr[vm_id].raw;

        if (!single_vm_masked_gpa_attr.valid)
        {
            continue;
        }

         // Walk the L2 SEPT to locate the entry.
         // Allow blocked non-leaf entries:  blocking must have happened AFTER we read
         // the L1 SEPT entry above, so since we're running in the guest context we are
         // protected by TLB tracking.
        if (sept_state_is_aliased(l1_sept_entry_copy, vm_id))
        {
            return_val = l2_sept_walk_guest_side(tdr_ptr, tdcs_ptr, vm_id, page_gpa,
                                                 &page_level_entry, &l2_sept_entry_copy, &l2_septe_ptr[vm_id]);
            if (return_val != TDX_SUCCESS)
            {
                FATAL_ERROR();
            }

            // Get the L2 attributes.  L2 SEPT entry does not hold a BLOCKEDW indication
            // of its own, so provide it based on the L1 state.
            single_vm_curr_gpa_attr = l2_sept_get_gpa_attr(l2_septe_ptr[vm_id],
                                         sept_state_is_any_blockedw(l1_sept_entry_copy));

            // Prepare the updated attributes
            new_gpa_attr->attr_arr[vm_id].raw = single_vm_curr_gpa_attr.raw & ~attr_mask.attr_arr[vm_id].raw;
            new_gpa_attr->attr_arr[vm_id].raw |= single_vm_masked_gpa_attr.raw;

            if (is_gpa_attr_present(new_gpa_attr->attr_arr[vm_id]))
            {
                // Check if the updated L2 attributes are legal
                if (!is_gpa_attr_legal(new_gpa_attr->attr_arr[vm_id]))
                {
                    // Don't abort yet.  Continue to loop on all VMs to collect the current attributes
                    attribute_status = TDX_PAGE_ATTR_INVALID;
                    new_gpa_attr->attr_arr[vm_id] = single_vm_curr_gpa_attr;   // Value to be returned in RDX
                }
            }
        }
        // Currently not aliased
        else if (is_gpa_attr_present(single_vm_masked_gpa_attr))
        {
            // Check if the updated L2 attributes are legal
            if (!is_gpa_attr_legal(single_vm_masked_gpa_attr))
            {
                // Don't abort yet.  Continue to loop on all VMs to collect the current attributes
                attribute_status = TDX_PAGE_ATTR_INVALID;
                new_gpa_attr->attr_arr[vm_id].raw = 0;   // Value to be returned in RDX
            }
            else
            {
                new_gpa_attr->attr_arr[vm_id] = single_vm_masked_gpa_attr;

                return_val = l2_sept_walk_guest_side(tdr_ptr, tdcs_ptr, vm_id, page_gpa,
                                                     &page_level_entry, &l2_sept_entry_copy, &l2_septe_ptr[vm_id]);
                if (return_val != TDX_SUCCESS)
                {
                    // Failure means an SEPT page is missing
                    if (tdcs_ptr->executions_ctl_fields.vm_ctls[vm_id].ept_violation_on_l2_sept_walk_failure)
                    {
                        // Do a TD exit and indicate an EPT violation to the host VM
                        sept_lock_release(l1_sept_entry_ptr);

                        // Free all previous entries.
                        for (uint16_t j = 1; j <= vm_id; j++)
                        {
                            if (l2_septe_ptr[j] != NULL)
                            {
                                free_la(l2_septe_ptr[j]);
                            }
                        }

                        free_la(l1_sept_entry_ptr);

                        ext_ept_violation_exit(page_gpa, l2_sept_entry_copy, vm_id, page_level_entry);
                    }
                    else
                    {
                        TDX_ERROR("L2 SEPT walk failed on VM(%d), level %d\n", vm_id, page_level_entry)
                        return api_error_with_l2_details(TDX_L2_SEPT_WALK_FAILED, vm_id, (uint16_t)page_level_entry);
                    }
                }
            }
        }
    }

    if (attribute_status != TDX_SUCCESS)
    {
        // We had an illegal attributes combination in the loop above, return the current attributes
        tdvps_ptr->guest_state.gpr_state.rcx = 0;
        tdvps_ptr->guest_state.gpr_state.rdx = new_gpa_attr->raw;
        return_val = attribute_status;
    }

    return return_val;
}

api_error_type tdg_mem_page_attr_wr(
    page_info_api_input_t gpa_mappings,
    gpa_attr_t new_gpa_attr,
    attr_flags_t attr_flags)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    gpa_attr_t attr_mask = attr_flags.gpa_attr;

    gpa_mapping_and_flags_t gpa_mapping_and_flags = {.raw = 0};

    // GPA and SEPT related variables
    pa_t page_gpa = {.raw = 0};                        // Target page GPA
    ia32e_sept_t *page_sept_entry_ptr = NULL;          // SEPT entry of the page
    ia32e_sept_t page_sept_entry_copy;                 // Cached SEPT entry of the page
    ept_level_t page_level_entry = gpa_mappings.level; // SEPT entry level of the page
    bool_t is_sept_locked = false;

    ia32e_sept_t *l2_septe_ptr[MAX_VMS] = {NULL};

    tdx_module_local_t *local_data_ptr = get_local_data();

    tdcs_t *tdcs_ptr = local_data_ptr->vp_ctx.tdcs;
    tdr_t *tdr_ptr = local_data_ptr->vp_ctx.tdr;
    tdvps_t *tdvps_ptr = local_data_ptr->vp_ctx.tdvps;

    tdx_sanity_check(tdcs_ptr != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ATTR_WR_LEAF), 0);
    tdx_sanity_check(tdr_ptr != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ATTR_WR_LEAF), 1);
    tdx_sanity_check(tdvps_ptr != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ATTR_WR_LEAF), 2);

    // Check the specified attributes
    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        if ((vm_id == 0) || (vm_id > tdcs_ptr->management_fields.num_l2_vms))
        {
            // For the L1 VMM and non-existing L2 VMs, input must be 0
            if (new_gpa_attr.attr_arr[vm_id].raw)
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
                goto EXIT;
            }

            if (attr_flags.raw_vm[vm_id])
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                goto EXIT;
            }
        }
        else
        {
            // If VALID is 0 then all other bits must be 0.
            // Note that we check the legality of other bits after combining with the existing values later.
            if ((new_gpa_attr.attr_arr[vm_id].raw != 0) && (new_gpa_attr.attr_arr[vm_id].valid == 0))
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
                goto EXIT;
            }
        }
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PT, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    if (!check_gpa_validity(page_gpa, tdcs_ptr->executions_ctl_fields.gpaw, PRIVATE_ONLY, tdcs_ptr->executions_ctl_fields.virt_maxpa))
    {
        TDX_ERROR("Page GPA (=0x%llx) is not not valid\n", page_gpa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // SEPT and walk to find entry
    return_val = walk_private_gpa(tdcs_ptr, page_gpa, tdr_ptr->key_management_fields.hkid,
                                  &page_sept_entry_ptr, &page_level_entry, &page_sept_entry_copy);
    if (return_val != TDX_SUCCESS)
    {
        // Do an TD exit and notify the host VMM.
        // Normally, the host VMM is expected to demote the page and re-enter the TD
        async_tdexit_ept_violation(page_gpa, gpa_mappings.level, page_sept_entry_copy,
                                   page_level_entry, page_sept_entry_ptr, VMX_EEQ_ATTR_WR);
    }

    // Lock the SEPT entry in memory
    // This is required to ensure its state doesn't change until we process all L2 SEPT entries
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

    if (!is_secure_ept_leaf_entry(&page_sept_entry_copy) && !is_sept_free(&page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_PAGE_SIZE_MISMATCH, page_level_entry);
        goto EXIT;
    }

    // We have arrived at a leaf SEPT entry at the requested level
    if (!sept_state_is_tdcall_leaf_allowed(TDG_MEM_PAGE_ATTR_WR_LEAF, page_sept_entry_copy))
    {
        // TDG.MEM.PAGE.ATTR.WR is allowed only on guest-writable or non-blocked pending leaf pages
        // This is under host VMM control so do an EPT violation TD exit
        sept_lock_release(page_sept_entry_ptr);

        async_tdexit_ept_violation(page_gpa, gpa_mappings.level, page_sept_entry_copy,
                                   page_level_entry, page_sept_entry_ptr, VMX_EEQ_ATTR_WR);
    }

    // Step 1:  L1 attributes (currently none)
    new_gpa_attr.attr_arr[0] = sept_get_gpa_attr(page_sept_entry_copy);

    // Step 2:  Walk the L2 SEPT trees, get to the L2 SEPT entries and check the validity
    //          of the combined attributes to be written
    return_val = get_all_l2_sept_entries(tdr_ptr, tdcs_ptr, tdvps_ptr, page_sept_entry_copy, page_sept_entry_ptr,
                    page_level_entry, page_gpa, l2_septe_ptr, attr_mask, &new_gpa_attr);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == TDX_PAGE_ATTR_INVALID)
        {
            goto EXIT_NO_DEFAULT_OUTPUT;
        }
        else
        {
            goto EXIT;
        }
    }

    // Step 3:  Commit - update the L2 SEPT attributes

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if (sept_state_is_aliased(page_sept_entry_copy, vm_id))
        {
            if (new_gpa_attr.attr_arr[vm_id].valid)
            {
                if (is_gpa_attr_present(new_gpa_attr.attr_arr[vm_id]))
                {
                    l2_sept_update_gpa_attr(l2_septe_ptr[vm_id], new_gpa_attr.attr_arr[vm_id]);
                }
                else
                {
                    // Remove the L2 alias
                    atomic_mem_write_64b(&l2_septe_ptr[vm_id]->raw, SEPT_STATE_L2_FREE_MASK);

                    sept_clear_aliased(page_sept_entry_ptr, vm_id);

                    // Update new_gpa_attr.ATTR[vm] to reflect no alias.
                    // This value is returned as an output of TDG.MEM.PAGE.ATTR.WR below.
                    new_gpa_attr.attr_arr[vm_id].raw = 0;
                    new_gpa_attr.attr_arr[vm_id].valid = 1;
                }
            }
        }
        // Currently not aliased
        else if (l2_septe_ptr[vm_id] != NULL)
        {
            // Create the L2 page alias
            // The L2 SEPT entry is created as L2_BLOCKED if the page is pending
            sept_l2_set_leaf(l2_septe_ptr[vm_id], new_gpa_attr.attr_arr[vm_id],
                             sept_get_pa(&page_sept_entry_copy), sept_state_is_any_pending(page_sept_entry_copy));

            sept_set_aliased(page_sept_entry_ptr, vm_id);
        }

        if (attr_flags.vm_arr[vm_id].do_invept)
        {
            // Flush the TLB context and extended paging structure (EPxE) caches associated
            // with the VM, using INVEPT single-context invalidation (type 1). */
            flush_td_asid(tdr_ptr, tdcs_ptr, vm_id);

            // Currently there is no need to invalidate soft-translated GPAs, they are all in the L1 context
        }
    }

    // Update the return values
    gpa_mapping_and_flags.raw = gpa_mappings.raw;
    gpa_mapping_and_flags.pending = sept_state_is_any_pending(page_sept_entry_copy);

    tdvps_ptr->guest_state.gpr_state.rcx = gpa_mapping_and_flags.raw;
    tdvps_ptr->guest_state.gpr_state.rdx = new_gpa_attr.raw;
    tdvps_ptr->guest_state.gpr_state.rax = TDX_SUCCESS;
    return_val = TDX_SUCCESS;
    goto EXIT_NO_DEFAULT_OUTPUT;

EXIT:

    // Default output values
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rcx = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx = 0;

EXIT_NO_DEFAULT_OUTPUT:

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if (l2_septe_ptr[vm_id] != NULL)
        {
            free_la(l2_septe_ptr[vm_id]);
        }
    }

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
