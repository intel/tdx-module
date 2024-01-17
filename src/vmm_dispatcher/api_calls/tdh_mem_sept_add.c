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
 * @file tdh_mem_sept_add
 * @brief TDHMEMSEPTADD API handler
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

static void init_new_sept_page(tdr_t* tdr_ptr, pa_t tdr_pa, pa_t sept_page_pa,
                               pamt_entry_t* sept_page_pamt_entry_ptr, uint64_t sept_page_init_val)
{
    void* sept_page_ptr;

    // Map the new SEPT EPT page
    sept_page_ptr = map_pa_with_hkid(sept_page_pa.raw_void, tdr_ptr->key_management_fields.hkid, TDX_RANGE_RW);

    // Initialize the new Secure EPT page using the TD’s ephemeral private HKID and direct writes(MOVDIR64B)
    fill_area_cacheline(sept_page_ptr, TDX_PAGE_SIZE_IN_BYTES, sept_page_init_val);

    // Update the new Secure EPT page’s PAMT entry
    sept_page_pamt_entry_ptr->pt = PT_EPT;
    set_pamt_entry_owner(sept_page_pamt_entry_ptr, tdr_pa);
    sept_page_pamt_entry_ptr->bepoch.raw = 0;

    // Increment TDR child count, use an atomic operation since we have SHARED lock on TDR
    (void)_lock_xadd_64b(&(tdr_ptr->management_fields.chldcnt), 1);

    free_la(sept_page_ptr);
}

static api_error_type process_l1_page(tdx_module_local_t* local_data_ptr, uint64_t version,
                                      pa_t sept_page_pa[MAX_VMS], pa_t flagged_sept_page_pa[MAX_VMS],
                                      ept_level_t page_level_entry, ia32e_sept_t page_sept_entry_copy,
                                      pamt_block_t sept_page_pamt_block[MAX_VMS], pamt_entry_t* sept_page_pamt_entry_ptr[MAX_VMS],
                                      bool_t sept_page_locked_flag[MAX_VMS], bool_t allow_existing)
{
    api_error_type return_val;

    if (sept_page_pa[0].raw == NULL_PA)
    {
        /* No new L1 SEPT page was provided.  This is only allowed for version 1 or higher, and an L1 SEPT page
           must already exist.  The existing L1 SEPT entry should be non-leaf, mapped. */
        if (version == 0)
        {
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        }
        if (!is_sept_nl_mapped(&page_sept_entry_copy))
        {
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
            TDX_ERROR("Parent entry is not non-leaf and mapped - 0x%llx\n", page_sept_entry_copy.raw);
            return api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        }
    }
    else
    {
        // A new L1 SEPT page was provided
        // Verify the parent entry located for new SEPT page is FREE

        if (is_sept_free(&page_sept_entry_copy))
        {
            // Prepare the new L1 SEPT page. The page will be added later after all checks are done.
            // Check and lock the new SEPT page in PAMT
            return_val = check_and_lock_explicit_4k_private_hpa(sept_page_pa[0],
                                                                OPERAND_ID_R8,
                                                                TDX_LOCK_EXCLUSIVE,
                                                                PT_NDA,
                                                                &sept_page_pamt_block[0],
                                                                &sept_page_pamt_entry_ptr[0],
                                                                &sept_page_locked_flag[0]);

            if (return_val != TDX_SUCCESS)
            {
                TDX_ERROR("Failed to check/lock the new SEPT EPT page 0x%llx - error = %llx\n",
                           sept_page_pa[0].raw, return_val);
                return return_val;
            }
        }
        else
        {
            // An SEPT page already exists
            if (allow_existing)
            {
                flagged_sept_page_pa[0].raw |= BIT(63); // Set bit 63 to indicate that the page has not been used
            }
            else
            {
                set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
                TDX_ERROR("SEPT page already exists - 0x%llx, but existing pages are not allowed\n", page_sept_entry_copy.raw);
                return api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
            }
        }
    }   // A new L1 SEPT page was provided

    return TDX_SUCCESS;
}

static api_error_type process_l2_pages(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, pa_t sept_page_pa[MAX_VMS],
                                       pa_t flagged_sept_page_pa[MAX_VMS],
                                       pa_t page_gpa, ept_level_t page_level_entry,
                                       pamt_block_t sept_page_pamt_block[MAX_VMS], pamt_entry_t* sept_page_pamt_entry_ptr[MAX_VMS],
                                       bool_t sept_page_locked_flag[MAX_VMS], ia32e_sept_t* page_sept_entry_ptr[MAX_VMS],
                                       bool_t allow_existing)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    for (uint16_t vm_id = 1; vm_id < MAX_VMS; vm_id++)
    {
        if (sept_page_pa[vm_id].raw == NULL_PA)
        {
            continue;
        }

        // Check that the request is for an existing L2 VM
        if (vm_id > tdcs_ptr->management_fields.num_l2_vms)
        {
            TDX_ERROR("Requested VM (%d) doesn't exist\n", vm_id);
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8 + vm_id);
        }

        // Walk the L2 SEPT tree to locate the parent entry for the new SEPT page
        return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, page_gpa, &page_level_entry, &page_sept_entry_ptr[vm_id]);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("L2 SEPT walk failed on VM(%d), level %d\n", vm_id, page_level_entry)
            set_arch_l2_septe_details_in_vmm_regs(*page_sept_entry_ptr[vm_id], vm_id,
                    tdcs_ptr->executions_ctl_fields.attributes.debug, page_level_entry, get_local_data());
            return api_error_with_l2_details(TDX_L2_SEPT_WALK_FAILED, vm_id, (uint16_t)page_level_entry);
        }

        if (is_l2_sept_free(page_sept_entry_ptr[vm_id]))
        {
            // Prepare the new L2 SEPT page.  The page will be added later after all checks are done.
            return_val = check_and_lock_explicit_4k_private_hpa(sept_page_pa[vm_id],
                                                                OPERAND_ID_R8 + vm_id,
                                                                TDX_LOCK_EXCLUSIVE,
                                                                PT_NDA,
                                                                &sept_page_pamt_block[vm_id],
                                                                &sept_page_pamt_entry_ptr[vm_id],
                                                                &sept_page_locked_flag[vm_id]);

            if (return_val != TDX_SUCCESS)
            {
                TDX_ERROR("Failed to check/lock the new SEPT EPT page 0x%llx for VM (%d) - error = %llx\n",
                           sept_page_pa[vm_id].raw, vm_id, return_val);
                return return_val;
            }
        }
        else
        {
            // An SEPT page already exists
            if (allow_existing)
            {
                flagged_sept_page_pa[vm_id].raw |= BIT(63); // Set bit 63 to indicate that the page has not been used
            }
            else
            {
                TDX_ERROR("L2 SEPT 0x%llx is not free, and existing not allowed!\n", page_sept_entry_ptr[vm_id]->raw);
                set_arch_l2_septe_details_in_vmm_regs(*page_sept_entry_ptr[vm_id], vm_id,
                        tdcs_ptr->executions_ctl_fields.attributes.debug, page_level_entry, get_local_data());
                return api_error_with_l2_details(TDX_L2_SEPT_ENTRY_NOT_FREE, vm_id, (uint16_t)page_level_entry);
            }
        }
    }

    return TDX_SUCCESS;
}

static api_error_type add_l1_and_l2_pages(uint64_t version, tdr_t* tdr_ptr, pa_t tdr_pa, pa_t sept_page_pa[MAX_VMS],
                                          pa_t flagged_sept_page_pa[MAX_VMS],
                                          pamt_entry_t* sept_page_pamt_entry_ptr[MAX_VMS],
                                          ia32e_sept_t* page_sept_entry_ptr[MAX_VMS],
                                          uint64_t original_rcx,
                                          uint64_t original_rdx)
{
    // Local data for return values
    tdx_module_local_t* local_data_ptr = get_local_data();

    bool_t sept_page_added_flag = false;

    if (!(flagged_sept_page_pa[0].raw & BIT(63)))
    {
        // There's a new SEPT page (non-NULL and not pre-existing)
        init_new_sept_page(tdr_ptr, tdr_pa, sept_page_pa[0], sept_page_pamt_entry_ptr[0], SEPTE_INIT_VALUE);

        // Update the L1 SEPT entry in memory with the new Secure EPT page HPA and NL_MAPPED state.
        // Keep the L1 SEPT entry locked.
        sept_set_mapped_non_leaf(page_sept_entry_ptr[0], sept_page_pa[0], true);

        // Nullify the page HPA to indicate it no longer needs to be allocated
        flagged_sept_page_pa[0].raw = NULL_PA;
        sept_page_added_flag = true;
    }

    if (version > 0)
    {
        for (uint16_t vm_id = 1; vm_id < MAX_VMS; vm_id++)
        {
            if (!(flagged_sept_page_pa[vm_id].raw & BIT(63)))
            {
                // There's a new SEPT page (non-NULL and not pre-existing)
                // Check for a pending interrupt only if at least one SEPT page has been added
                if ((true == sept_page_added_flag) && is_interrupt_pending_host_side())
                {
                    // Restore the original RCX and RDX values and terminate the flow
                    local_data_ptr->vmm_regs.rcx = original_rcx;
                    local_data_ptr->vmm_regs.rdx = original_rdx;
                    TDX_ERROR("Pending interrupt\n");
                    return TDX_INTERRUPTED_RESUMABLE;
                }

                init_new_sept_page(tdr_ptr, tdr_pa, sept_page_pa[vm_id], sept_page_pamt_entry_ptr[vm_id], SEPTE_L2_INIT_VALUE);

                // Set the alias indication in the L1 SEPT entry
                sept_set_aliased(page_sept_entry_ptr[0], vm_id);

                // Map the new page in the parent table
                sept_l2_set_mapped_non_leaf(page_sept_entry_ptr[vm_id], sept_page_pa[vm_id]);

                // Nullify the page HPA to indicate it no longer needs to be allocated
                flagged_sept_page_pa[vm_id].raw = NULL_PA;

                sept_page_added_flag = true;
            }
        }
    }

    return TDX_SUCCESS;
}

api_error_type tdh_mem_sept_add(page_info_api_input_t sept_level_and_gpa,
                                td_handle_and_flags_t target_tdr_and_flags,
                                uint64_t target_sept_page_pa,
                                uint64_t version)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa = { .raw = 0 };     // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA and SEPT related variables
    pa_t                  page_gpa;                             // Target page GPA
    page_info_api_input_t gpa_mappings = sept_level_and_gpa;    // GPA and SEPT level
    ia32e_sept_t        * page_sept_entry_ptr[MAX_VMS] = { 0 }; // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;                 // Cached SEPT entry of the page
    ept_level_t           page_level_entry = sept_level_and_gpa.level;  // SEPT entry level of the page parent
    bool_t                sept_locked_flag = false;  // Indicate SEPT tree is locked
    bool_t                septe_locked_flag = false; // Indicate SEPT entry is locked

    // New SEPT EPT page variables
    pa_t                  flagged_sept_page_pa[MAX_VMS] = { 0 };     // Physical address of the new Secure-EPT page
    pa_t                  sept_page_pa[MAX_VMS] = { 0 };             // Physical address of the new Secure-EPT page - can be modified
    pamt_block_t          sept_page_pamt_block[MAX_VMS] = { 0 };     // New Secure-EPT page PAMT block
    pamt_entry_t        * sept_page_pamt_entry_ptr[MAX_VMS] = { 0 }; // Pointer to the Secure-EPT PAMT entry
    bool_t                sept_page_locked_flag[MAX_VMS] = { 0 };    // Indicate SEPT EPT page PAMT entry is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    uint64_t original_rcx = local_data_ptr->vmm_regs.rcx;  // Original value of RCX, to be restored in case on an interrupt
    uint64_t original_rdx = local_data_ptr->vmm_regs.rdx;  // Original value of RDX, to be restored in case on an interrupt

    sept_page_pa[0].raw = target_sept_page_pa;

    if (version > 0)
    {
        sept_page_pa[1].raw = local_data_ptr->vmm_regs.r9;
        sept_page_pa[2].raw = local_data_ptr->vmm_regs.r10;
        sept_page_pa[3].raw = local_data_ptr->vmm_regs.r11;
    }

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0;
    local_data_ptr->vmm_regs.rdx = 0;

    // Only versions 0 and 1 are supported
    if (version > 1)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT_NO_GPR_CHANGE;
    }

    // If the input new SEPT page pa is not NULL_PA, then we ignore bit 63
    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        // If the input new SEPT page pa is not NULL_PA, then we ignore bit 63
        if (sept_page_pa[vm_id].raw != NULL_PA)
        {
            sept_page_pa[vm_id].raw &= ~BIT(63);
        }
        flagged_sept_page_pa[vm_id].raw = sept_page_pa[vm_id].raw;
    }



    // Check the TD handle in RDX
    if (target_tdr_and_flags.reserved_0 || target_tdr_and_flags.reserved_1)
    {
        TDX_ERROR("Input TD handle (0x%llx) is not valid\n", target_tdr_and_flags.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    tdr_pa.page_4k_num  = target_tdr_and_flags.tdr_hpa_51_12;

    // Check, lock and map the owner TDR page (Shared lock!)
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
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
                                               false, TDH_MEM_SEPT_ADD_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PD, tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // Step #1:
    // L1 SEPT tree walk and state checks

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &page_sept_entry_ptr[0],
                                                      &page_level_entry,
                                                      &page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry in memory
    return_val = sept_lock_acquire_host(page_sept_entry_ptr[0]);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry (again after locking)
    page_sept_entry_copy = *page_sept_entry_ptr[0];

    // Check if the L1 SEPT entry state is allowed.  Refined checks are done below.
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_SEPT_ADD_LEAF, page_sept_entry_copy))
    {
        TDX_ERROR("L1 SEPT sate (0x%llx) is not allowed for this SEAMCALL\n", page_sept_entry_copy.raw);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Step #2:
    // Check and lock the new L1 and L2 SEPT physical pages.

    // Process the L1 SEPT page. Either add a new page or make sure it exists.
    return_val = process_l1_page(local_data_ptr, version, sept_page_pa, flagged_sept_page_pa,
                                 page_level_entry, page_sept_entry_copy,
                                 sept_page_pamt_block, sept_page_pamt_entry_ptr, sept_page_locked_flag,
                                 target_tdr_and_flags.allow_existing);

    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Process the L2 SEPT pages
    if (version > 0)
    {
        return_val = process_l2_pages(tdr_ptr, tdcs_ptr, sept_page_pa, flagged_sept_page_pa, page_gpa, page_level_entry,
                                      sept_page_pamt_block, sept_page_pamt_entry_ptr, sept_page_locked_flag,
                                      page_sept_entry_ptr, target_tdr_and_flags.allow_existing);

        if (return_val != TDX_SUCCESS)
        {
            goto EXIT;
        }
    }

    // Step #3:
    // Add the new L1 and L2 SEPT pages
    return_val = add_l1_and_l2_pages(version, tdr_ptr, tdr_pa, sept_page_pa, flagged_sept_page_pa,
                                     sept_page_pamt_entry_ptr, page_sept_entry_ptr, original_rcx, original_rdx);

    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:

    if (version > 0)
    {
        local_data_ptr->vmm_regs.r8  = flagged_sept_page_pa[0].raw;
        local_data_ptr->vmm_regs.r9  = flagged_sept_page_pa[1].raw;
        local_data_ptr->vmm_regs.r10 = flagged_sept_page_pa[2].raw;
        local_data_ptr->vmm_regs.r11 = flagged_sept_page_pa[3].raw;
    }

EXIT_NO_GPR_CHANGE:

    // Release all acquired locks and free keyhole mappings

    if (septe_locked_flag)
    {
        sept_lock_release(page_sept_entry_ptr[0]);
    }

    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        if (sept_page_locked_flag[vm_id])
        {
            pamt_unwalk(sept_page_pa[vm_id], sept_page_pamt_block[vm_id], sept_page_pamt_entry_ptr[vm_id],
                        TDX_LOCK_EXCLUSIVE, PT_4KB);
        }

        if (page_sept_entry_ptr[vm_id] != NULL)
        {
            free_la(page_sept_entry_ptr[vm_id]);
        }
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
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
