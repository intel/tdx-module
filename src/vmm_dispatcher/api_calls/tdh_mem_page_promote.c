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
 * @file tdh_mem_page_promote
 * @brief TDHMEMPAGEPROMOTE API handler
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

static api_error_type is_sept_page_valid_for_merge(ia32e_paging_table_t* merged_sept_page_ptr,
                                                   ept_level_t merged_sept_parent_level_entry,
                                                   uint32_t* locked_entries)
{
    api_error_type  return_val;

    tdx_debug_assert(merged_sept_parent_level_entry != LVL_PT);
    ept_level_t leaf_entry_level = merged_sept_parent_level_entry - 1;

    uint64_t merged_page_size = ((merged_sept_parent_level_entry == LVL_PDPT) ? _1GB : _2MB);
    uint64_t leaf_page_size = ((merged_sept_parent_level_entry == LVL_PDPT) ? _2MB : _4KB);

    *locked_entries = 0;

    ia32e_sept_t first_sept_copy = { .raw = 0 };

    for (uint32_t i = 0; i < 512; i++)
    {
        ia32e_sept_t* current_sept = &merged_sept_page_ptr->sept[i];
        ia32e_sept_t current_sept_copy;

        return_val = sept_lock_acquire_host(current_sept);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Can't acquire SEPT host side lock. Error Code = 0x%llx\n", return_val);
            return return_val;
        }

        *locked_entries += 1;

        // Read the copy after locking
        current_sept_copy = *current_sept;

        sept_cleanup_if_pending(&current_sept_copy, leaf_entry_level);

        IF_RARE (i == 0)
        {
            uint64_t start_addr = leaf_ept_entry_to_hpa(current_sept_copy, 0, leaf_entry_level);

            if (!is_addr_aligned_pwr_of_2(start_addr, merged_page_size))
            {
                TDX_ERROR("Starting address 0x%llx is not aligned on marged page size %d\n",
                        start_addr, merged_page_size);
                return TDX_EPT_INVALID_PROMOTE_CONDITIONS;
            }

            if (!sept_state_is_mapped_or_pending(current_sept_copy))
            {
                TDX_ERROR("SEPT[0] state is not mapped or pending - 0x%llx\n", current_sept_copy.raw);
                return TDX_EPT_INVALID_PROMOTE_CONDITIONS;
            }

            first_sept_copy = current_sept_copy;
        }
        else
        {
            first_sept_copy.raw += leaf_page_size;
            if (current_sept_copy.raw != first_sept_copy.raw)
            {
                TDX_ERROR("Entry [%d] (0x%llx) - Invalid stride or SEPT state not matching the first entry\n",
                            i, current_sept_copy.raw);
                return TDX_EPT_INVALID_PROMOTE_CONDITIONS;
            }
        }
    }

    return TDX_SUCCESS;
}

// Scan the L2 Secure EPT page content and verify all 512 entries:
//  First entry is either L2_FREE or leaf (L2_MAPPED or L2_BLOCKED)
//  If first entry is free (L2_FREE)
//    - All L2 SEPT entries are identical
//  If first entry is leaf (L2_MAPPED or L2_BLOCKED):
//    - All 512 L2 SEPT entries in the page are equal, except PA.
//    Note: No PA check is done. The function assumes that is_sept_page_valid_for_merge()
//    was called before, therefore L2 addresses are implicitly correct if no L2 entry is L2_FREE.
static api_error_type is_l2_sept_page_valid_for_merge(ia32e_paging_table_t* merged_sept_page_ptr,
                                                      ept_level_t merged_sept_parent_level_entry)
{
    tdx_debug_assert(merged_sept_parent_level_entry != LVL_PT);
    ept_level_t leaf_entry_level = merged_sept_parent_level_entry - 1;

    uint64_t start_addr = leaf_ept_entry_to_hpa(merged_sept_page_ptr->sept[0], 0, leaf_entry_level);
    uint64_t merged_page_size = ((merged_sept_parent_level_entry == LVL_PDPT) ? _1GB : _2MB);

    ia32e_sept_t first_sept_copy = { .raw = 0 };
    bool_t is_free = false;

    for (uint32_t i = 0; i < 512; i++)
    {
        ia32e_sept_t* current_sept = &merged_sept_page_ptr->sept[i];
        ia32e_sept_t current_sept_copy;

        current_sept_copy = *current_sept;

        IF_RARE (i == 0)
        {
            is_free = is_l2_sept_free(&current_sept_copy);

            if (!is_free && (!is_addr_aligned_pwr_of_2(start_addr, merged_page_size) ||
                             !is_secure_ept_leaf_entry(&current_sept_copy)))
            {
                TDX_ERROR("Starting address 0x%llx is not aligned on marged page size %d, or entry not leaf 0x%llx\n",
                        start_addr, merged_page_size, current_sept_copy.raw);
                return TDX_EPT_INVALID_PROMOTE_CONDITIONS;
            }

            first_sept_copy = current_sept_copy;
            first_sept_copy.base = 0;
        }
        else
        {
            current_sept_copy.base = 0;

            if (current_sept_copy.raw != first_sept_copy.raw)
            {
                TDX_ERROR("Entry [%d] (0x%llx) - Invalid stride or SEPT state not matching the first entry\n",
                            i, current_sept_copy.raw);
                return TDX_EPT_INVALID_PROMOTE_CONDITIONS;
            }
        }
    }

    return TDX_SUCCESS;
}

api_error_type tdh_mem_page_promote(page_info_api_input_t gpa_page_info, uint64_t target_tdr_pa, uint64_t version)
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
    bool_t                op_state_locked_flag = false;
    // GPA and SEPT related variables
    pa_t                  page_gpa = {.raw = 0};        // Target page GPA
    page_info_api_input_t gpa_mappings = gpa_page_info; // GPA and level
    ia32e_sept_t        * merged_sept_page_sept_entry_ptr[MAX_VMS] = { 0 }; // SEPT entry of the page
    ia32e_sept_t          merged_sept_page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           merged_sept_parent_level_entry = gpa_mappings.level; // SEPT entry level of the page
    ept_level_t           l2_sept_parent_level_entry = gpa_mappings.level; // SEPT entry level of the page for level 2 walks
    pa_t                  merged_sept_page_pa[MAX_VMS];
    ia32e_paging_table_t* merged_sept_page_ptr[MAX_VMS] = { 0 };
    pamt_entry_t        * merged_sept_page_pamt_entry_ptr[MAX_VMS] = { 0 };
    bool_t                merged_sept_page_pamt_locked_flag[MAX_VMS] = { 0 };
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;

    // Merged page related variable
    pa_t                  merged_page_pa;

    api_error_type        return_val = UNINITIALIZE_ERROR;
    uint32_t locked_entries = 0;

    tdr_pa.raw = target_tdr_pa;

    uint64_t original_rcx = local_data_ptr->vmm_regs.rcx;  // Original value of RCX, to be restored in case on an interrupt
    uint64_t original_rdx = local_data_ptr->vmm_regs.rdx;  // Original value of RDX, to be restored in case on an interrupt

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    if (version > 0)
    {
        local_data_ptr->vmm_regs.r9  = NULL_PA;
        local_data_ptr->vmm_regs.r10 = NULL_PA;
        local_data_ptr->vmm_regs.r11 = NULL_PA;
    }

    // Only versions 0 and 1 are supported
    if (version > 1)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    // Check, lock and map the owner TDR page
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
                                               false, TDH_MEM_PAGE_PROMOTE_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    if (!verify_page_info_input(gpa_mappings, LVL_PD, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mappings);

    // Step #1:

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &merged_sept_page_sept_entry_ptr[0],
                                                      &merged_sept_parent_level_entry,
                                                      &merged_sept_page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(merged_sept_page_sept_entry_copy, merged_sept_parent_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry in memory
    return_val = sept_lock_acquire_host(merged_sept_page_sept_entry_ptr[0]);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(merged_sept_page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry (again after locking)
    merged_sept_page_sept_entry_copy = *merged_sept_page_sept_entry_ptr[0];

    // Verify the promoted entry is an non-leaf entry and its state allows promotion
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MEM_PAGE_PROMOTE_LEAF, merged_sept_page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(merged_sept_page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
        TDX_ERROR("Is leaf entry, or not allowed in current SEPT entry - 0x%llx!\n", merged_sept_page_sept_entry_copy.raw);
        goto EXIT;
    }

    // Verify the TLB tacking of the blocked page has been completed
    merged_sept_page_pa[0].raw = merged_sept_page_sept_entry_copy.base << 12;

    if ((return_val = pamt_implicit_get_and_lock(merged_sept_page_pa[0], PT_4KB,
                      TDX_LOCK_EXCLUSIVE, &merged_sept_page_pamt_entry_ptr[0])) != TDX_SUCCESS)
    {
        TDX_ERROR("Can't acquire lock on merged page pamt entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    merged_sept_page_pamt_locked_flag[0] = true;

    if (sept_state_is_tlb_tracking_required(merged_sept_page_sept_entry_copy) &&
        op_state_is_tlb_tracking_required(tdcs_ptr->management_fields.op_state))
    {
        // The TD may be running and this page must be blocked and tracked before it's removed.

        // Verify the entry is *BLOCKED (originally MAPPED or PENDING)
        if (!sept_state_is_any_blocked(merged_sept_page_sept_entry_copy))
        {
            return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(merged_sept_page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
            TDX_ERROR("Promoted SEPT entry is not blocked - 0x%llx\n", merged_sept_page_sept_entry_copy.raw);
            goto EXIT;
        }

        // Check TLB tracking
        if (!is_tlb_tracked(tdcs_ptr, merged_sept_page_pamt_entry_ptr[0]->bepoch))
        {
            TDX_ERROR("Target splitted page TLB tracking not done\n");
            return_val = api_error_with_operand_id(TDX_TLB_TRACKING_NOT_DONE, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Step #2

    // Map the Secure-EPT page before merging
    merged_sept_page_ptr[0] = map_pa_with_hkid(merged_sept_page_pa[0].raw_void,
                                            tdr_ptr->key_management_fields.hkid, TDX_RANGE_RW);

    // Scan the Secure EPT page content and verify all 512 entries:
    //   - Are leaf SEPT_PRESENT entries(this also implies that the corresponding pages
    //     are PT_REG)
    //   - Have contiguous HPA mapping aligned to the promoted range size
    if ((return_val = is_sept_page_valid_for_merge(merged_sept_page_ptr[0],
            merged_sept_parent_level_entry, &locked_entries)) != TDX_SUCCESS)
    {
        TDX_ERROR("Target SEPT is not valid for merging\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(merged_sept_page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
        goto EXIT;
    }

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if (sept_state_is_aliased(merged_sept_page_sept_entry_copy, vm_id))
        {
            // Check for a pending interrupt
            // Interruption is not restartable, no need to save state.  We haven't committed anything yet.
            if (is_interrupt_pending_host_side())
            {
                // Restore the original RCX and RDX values and terminate the flow
                local_data_ptr->vmm_regs.rcx = original_rcx;
                local_data_ptr->vmm_regs.rdx = original_rdx;
                TDX_ERROR("Pending interrupt\n");
                return_val = TDX_INTERRUPTED_RESTARTABLE;
                goto EXIT;
            }

            // Walk the L2 SEPT to locate the non-leaf entry mapping the large range
            return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, page_gpa, &l2_sept_parent_level_entry,
                                      &merged_sept_page_sept_entry_ptr[vm_id]);
            if ((return_val != TDX_SUCCESS))
            {
                FATAL_ERROR(); // Should not happen since the large range is aliased
            }

            // L2 SEPT entry was found
            ia32e_sept_t l2_merged_sept_page_sept_entry_copy = *merged_sept_page_sept_entry_ptr[vm_id];

            // The L2 SEPT entry must be a non-leaf entry since the L1 SEPT entry is a non-leaf
            tdx_sanity_check(!is_secure_ept_leaf_entry(&l2_merged_sept_page_sept_entry_copy) &&
                             !is_l2_sept_free(&l2_merged_sept_page_sept_entry_copy),
                             SCEC_SEAMCALL_SOURCE(TDH_MEM_PAGE_PROMOTE_LEAF), 0);

            merged_sept_page_pa[vm_id].raw = merged_sept_page_sept_entry_ptr[vm_id]->base << 12;

            if ((return_val = pamt_implicit_get_and_lock(merged_sept_page_pa[vm_id], PT_4KB,
                                TDX_LOCK_EXCLUSIVE, &merged_sept_page_pamt_entry_ptr[vm_id])) != TDX_SUCCESS)
            {
                TDX_ERROR("Can't acquire lock on L2 (%d) merged page pamt entry\n", vm_id);
                return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
                goto EXIT;
            }
            merged_sept_page_pamt_locked_flag[vm_id] = true;

            // Map the L2 Secure EPT page to be merged and removed
            merged_sept_page_ptr[vm_id] = map_pa_with_hkid(merged_sept_page_pa[vm_id].raw_void,
                                                           tdr_ptr->key_management_fields.hkid,
                                                           TDX_RANGE_RW);
            
            // Scan the L2 Secure EPT page content and verify all 512 entries match the conditions for promotion
            return_val = is_l2_sept_page_valid_for_merge(merged_sept_page_ptr[vm_id], l2_sept_parent_level_entry);

            if (return_val != TDX_SUCCESS)
            {
                TDX_ERROR("Target L2 (%d) SEPT is not valid for merging\n", vm_id);
                return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
                set_arch_septe_details_in_vmm_regs(merged_sept_page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
                goto EXIT;
            }
        }
        else
        {
            // Nullify the L2 SEPT entry pointer so it won't be used later
            merged_sept_page_sept_entry_ptr[vm_id] = NULL;
        }
    }

    // Step #3:

    // Check for a pending interrupt
    // Interruption is not restartable, no need to save state.  We haven't committed anything yet.
    if (is_interrupt_pending_host_side())
    {
        // Restore the original RCX and RDX values and terminate the flow
        local_data_ptr->vmm_regs.rcx = original_rcx;
        local_data_ptr->vmm_regs.rdx = original_rdx;
        TDX_ERROR("Pending interrupt\n");
        return_val = TDX_INTERRUPTED_RESTARTABLE;
        goto EXIT;
    }

    // Get the merge page address
    merged_page_pa.raw = leaf_ept_entry_to_hpa(merged_sept_page_ptr[0]->sept[0], 0,
                                          (ept_level_t)(merged_sept_parent_level_entry - 1));

    // Merge PAMT range of the promoted page
    if ((return_val = pamt_promote(merged_page_pa, (page_size_t)merged_sept_parent_level_entry)) != TDX_SUCCESS)
    {
        TDX_ERROR("Couldn't not merge the destined page in PAMT\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Step #4:
    // Commit

    //---------------------------------------------------------------
    //  ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    //---------------------------------------------------------------

    locked_entries = 0;

    // Atomically map the merged Secure-EPT entry to SEPT_PRESENT leaf entry,
    // pointing to the merged HPA range

    for (uint16_t vm_id = 0; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if ((vm_id == 0) || (merged_sept_page_sept_entry_ptr[vm_id] != NULL))
        {
            // The first SEPTE of VM 0 is locked so the large page SEPTE remains locked.
            atomic_mem_write_64b(&merged_sept_page_sept_entry_ptr[vm_id]->raw, merged_sept_page_ptr[vm_id]->sept[0].raw);

            (void)_lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, (uint64_t)-1);
            merged_sept_page_pamt_entry_ptr[vm_id]->pt = PT_NDA; // PT = PT_NDA, OWNER = 0

            if ((version > 0) && (vm_id > 0))
            {
                local_data_ptr->vmm_regs.gprs[GPR_LIST_R9_INDEX + (vm_id - 1)] =
                        merged_sept_page_pa[vm_id].raw;
            }
        }
        else // vm_id > 0 and sept entry is null
        {
            if (version > 0)
            {
                local_data_ptr->vmm_regs.gprs[GPR_LIST_R9_INDEX + (vm_id - 1)] = NULL_PA;
            }
        }
    }

    local_data_ptr->vmm_regs.rcx = merged_sept_page_pa[0].raw;

EXIT:

    // Release all acquired locks and free keyhole mappings

    for (uint32_t j = 0; j < locked_entries; j++)
    {
        ia32e_sept_t* current_sept = &merged_sept_page_ptr[0]->sept[j];
        sept_lock_release(current_sept);
    }

    for (uint16_t vm_id = 0; vm_id < MAX_VMS; vm_id++)
    {
        if (merged_sept_page_ptr[vm_id] != NULL)
        {
            free_la(merged_sept_page_ptr[vm_id]);
        }

        if (merged_sept_page_pamt_locked_flag[vm_id])
        {
            pamt_implicit_release_lock(merged_sept_page_pamt_entry_ptr[vm_id], TDX_LOCK_EXCLUSIVE);
        }

        if (merged_sept_page_sept_entry_ptr[vm_id] != NULL)
        {
            free_la(merged_sept_page_sept_entry_ptr[vm_id]);
        }
    }

    if (septe_locked_flag)
    {
        sept_lock_release(merged_sept_page_sept_entry_ptr[0]);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
    }

    if (tdcs_ptr != NULL)
    {
        if (op_state_locked_flag)
        {
            release_sharex_lock_hp_sh(&(tdcs_ptr->management_fields.op_state_lock));
        }
        free_la(tdcs_ptr);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }

    return return_val;
}
