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
 * @file tdh_mem_page_relocate.c
 * @brief TDHMEMPAGERELOCATE API handler
 */

#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"

api_error_type tdh_mem_page_relocate(uint64_t source_page_pa,
                                    uint64_t target_tdr_pa,
                                    uint64_t target_page_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr = NULL;            // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // Page target
    pa_t                  target_pa;                        // Physical address of the new TD page target
    pamt_block_t          target_page_pamt_block;           // New TD page PAMT block
    pamt_entry_t        * target_page_pamt_entry_ptr;       // Pointer to the TD PAMT entry
    bool_t                target_page_locked_flag = false;  // Indicate TD page is locked
    void*                 target_ptr = NULL;

    // Currently mapped page
    pa_t                  mapped_gpa = {.raw = 0};                        // mapped TD page GPA
    page_info_api_input_t gpa_mappings = {.raw = source_page_pa};         // GPA and level
    ia32e_sept_t        * mapped_page_sept_entry_ptr = NULL;              // SEPT entry of the page
    ia32e_sept_t          mapped_page_sept_entry_copy;                    // Cached SEPT entry of the page
    ept_level_t           mapped_page_level_entry = gpa_mappings.level;   // SEPT entry level of the mapped page
    bool_t                sept_locked_flag = false;                       // Indicate SEPT is locked
    bool_t                septe_locked_flag = false;                      // Indicate SEPT entry is locked
    pa_t                  source_pa = {.raw = 0};
    pamt_entry_t*         mapped_page_pamt_ptr = NULL;                    // Currently mapped TD page PAMT block
    void*                 mapped_ptr = NULL;
    bool_t                merged_page_pamt_locked_flag = false;

    api_error_type        return_val = TDX_SUCCESS;

    tdr_pa.raw = target_tdr_pa;
    target_pa.raw = target_page_pa;

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
                                               false, TDH_MEM_PAGE_RELOCATE, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!verify_page_info_input(gpa_mappings, LVL_PT, LVL_PT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mappings.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    mapped_gpa = page_info_to_pa(gpa_mappings);

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      mapped_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &mapped_page_sept_entry_ptr,
                                                      &mapped_page_level_entry,
                                                      &mapped_page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(mapped_page_sept_entry_copy, mapped_page_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock the SEPT entry in memory
    return_val = sept_lock_acquire_host(mapped_page_sept_entry_ptr);
    if (TDX_SUCCESS != return_val)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(mapped_page_sept_entry_copy, mapped_page_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT host-side lock attempt\n");
        goto EXIT;
    }
    septe_locked_flag = true;

    // Read the SEPT entry (again after locking)
    mapped_page_sept_entry_copy = *mapped_page_sept_entry_ptr;

    // Verify the located entry points is a leaf entry and relocate is allowed
    if (!is_secure_ept_leaf_entry(&mapped_page_sept_entry_copy) ||
        !sept_state_is_seamcall_leaf_allowed(TDH_MEM_PAGE_RELOCATE, mapped_page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(mapped_page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
        TDX_ERROR("Is leaf entry, or not allowed in current SEPT entry - 0x%llx!\n", mapped_page_sept_entry_copy.raw);
        goto EXIT;
    }


    // Get currently mapped page HPA
    source_pa.raw = leaf_ept_entry_to_hpa(mapped_page_sept_entry_copy, mapped_gpa.raw, mapped_page_level_entry);

    // Verify mapped HPA is different than target HPA
    if (source_pa.full_pa == target_pa.full_pa)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Verify the TLB tacking of the blocked page has been completed
    if ((return_val = pamt_implicit_get_and_lock(source_pa, (page_size_t)mapped_page_level_entry,
                      TDX_LOCK_EXCLUSIVE, &mapped_page_pamt_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Can't acquire lock on mapped page pamt entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    merged_page_pamt_locked_flag = true;

    if (sept_state_is_tlb_tracking_required(mapped_page_sept_entry_copy) &&
        op_state_is_tlb_tracking_required(tdcs_ptr->management_fields.op_state))
    {
        // The TD may be running and this page must be blocked and tracked before it's removed.

        // Verify the entry is *BLOCKED (originally MAPPED or PENDING)
        if (!sept_state_is_any_blocked(mapped_page_sept_entry_copy))
        {
            return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(mapped_page_sept_entry_copy, gpa_mappings.level, local_data_ptr);
            TDX_ERROR("Relocated SEPT entry is not blocked - 0x%llx\n", mapped_page_sept_entry_copy.raw);
            goto EXIT;
        }

        // Check TLB tracking
        if (!is_tlb_tracked(tdcs_ptr, mapped_page_pamt_ptr->bepoch))
        {
            TDX_ERROR("Target splitted page TLB tracking not done\n");
            return_val = api_error_with_operand_id(TDX_TLB_TRACKING_NOT_DONE, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Check, lock and map the new TD page
    return_val = check_lock_and_map_explicit_private_4k_hpa(target_pa,
                                                            OPERAND_ID_R8,
                                                            tdr_ptr,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &target_page_pamt_block,
                                                            &target_page_pamt_entry_ptr,
                                                            &target_page_locked_flag,
                                                            (void**)&target_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map the new TD page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Copy the current mapped page content to the target page, using the TDs
    // ephemeral private HKID and direct writes(MOVDIR64B)
    if (!sept_state_is_any_pending(mapped_page_sept_entry_copy))
    {
        mapped_ptr = map_pa_with_hkid(source_pa.raw_void, tdr_ptr->key_management_fields.hkid, TDX_RANGE_RO);
        cache_aligned_copy_direct((uint64_t)mapped_ptr, (uint64_t)target_ptr, TDX_PAGE_SIZE_IN_BYTES);
    }

    // Free the currently mapped HPA by setting its PAMT to PT_NDA
    mapped_page_pamt_ptr->pt = PT_NDA;

    // Update the target pages PAMT entry with the PT_REG page
    // type and the TDR physical address as the OWNER
    target_page_pamt_entry_ptr->pt = PT_REG;
    set_pamt_entry_owner(target_page_pamt_entry_ptr, tdr_pa);
    target_page_pamt_entry_ptr->bepoch.raw = 0;

    // Update HPA and unblock any L2 aliases
    // This is done before unblocking the L1 SEPT entry.  This way, if there's an EPT violation in an
    // L2 VM before we blocked the L2 SEPT entries, the VM exit handler will understand that the
    // range has been blocked and will TD exit to the host VMM.

    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        if (!sept_state_is_aliased(mapped_page_sept_entry_copy, vm_id))
        {
            continue;
        }

        ia32e_sept_t* l2_sept_entry_ptr = NULL;

        return_val = l2_sept_walk(tdr_ptr, tdcs_ptr, vm_id, mapped_gpa, &mapped_page_level_entry, &l2_sept_entry_ptr);
        if (return_val != TDX_SUCCESS)
        {
            FATAL_ERROR(); // Should not happen - no need to free the L2 SEPT PTR's
        }

        ia32e_sept_t l2_epte_val = {.raw = l2_sept_entry_ptr->raw};
        l2_epte_val.base = target_pa.full_pa >> 12;

        if (!sept_state_is_any_pending(mapped_page_sept_entry_copy))
        {
            sept_l2_unblock(&l2_epte_val);
        }

        atomic_mem_write_64b(&l2_sept_entry_ptr->raw, l2_epte_val.raw);

        free_la(l2_sept_entry_ptr);
    }

    // Update the Secure EPT entry with the target page
    // HPA and SEPT_PRESENT state
    ia32e_sept_t epte_val = {.raw = mapped_page_sept_entry_copy.raw};
    epte_val.base = target_pa.full_pa >> 12;
    sept_unblock(&epte_val);

    // Write the whole 64-bit EPT entry in a single operation
    atomic_mem_write_64b(&mapped_page_sept_entry_ptr->raw, epte_val.raw);

    // Update RCX with the old physical page HPA
    local_data_ptr->vmm_regs.rcx = source_pa.raw;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (target_page_locked_flag)
    {
        pamt_unwalk(target_pa, target_page_pamt_block, target_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(target_ptr);
    }

    if (mapped_ptr)
    {
        free_la(mapped_ptr);
    }

    if (merged_page_pamt_locked_flag)
    {
        pamt_implicit_release_lock(mapped_page_pamt_ptr, TDX_LOCK_EXCLUSIVE);
    }

    if (septe_locked_flag)
    {
        sept_lock_release(mapped_page_sept_entry_ptr);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (mapped_page_sept_entry_ptr != NULL)
        {
            free_la(mapped_page_sept_entry_ptr);
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
