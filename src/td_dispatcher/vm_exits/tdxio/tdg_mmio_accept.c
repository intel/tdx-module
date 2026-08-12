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
 * @file tdg_tdi_mmio_accept.c
 * @brief TDGMMIOACCEPT API handler
 */

#include "tdxio/tdxio_td_api_handlers.h"
#include "td_transitions/td_exit.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"

_STATIC_INLINE_ void ept_violation_exit(
    const pa_t gpa,
    const ept_level_t req_level,
    const ia32e_sept_t sept_entry,
    const bool_t is_leaf,
    const ept_level_t ept_level,
    ia32e_sept_t *const sept_entry_ptr)
{
    tdaccept_vmx_eeq_info_t eeq_info = {.raw = 0};
    eeq_info.req_sept_level = req_level;
    eeq_info.err_sept_level = ept_level;
    eeq_info.err_sept_state = sept_get_arch_state(sept_entry);
    eeq_info.err_sept_is_leaf = is_leaf;

    vmx_ext_exit_qual_t eeq = {.raw = 0};
    eeq.type = VMX_EEQ_ACCEPT;
    eeq.info = eeq_info.raw;

    vmx_exit_qualification_t exit_qual = { .raw = 0 };

    vm_vmexit_exit_reason_t vm_exit_reason = {.raw = 0};
    vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;

    if (sept_entry_ptr != NULL)
    {
        free_la(sept_entry_ptr);
    }


    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qual.raw, eeq.raw);
}

api_error_type tdg_tdi_mmio_accept(
    page_info_api_input_t gpa_mapping,
    uint64_t mmio_pa_offset)
{
    tdx_module_local_t *local_data = get_local_data();
    pa_t mmio_pa = {.raw = 0};

    // GPA and SEPT related variables
    pa_t page_gpa = {.raw = 0};                                    // Target page GPA
    ia32e_sept_t *page_sept_entry_ptr = NULL;                      // SEPT entry of the page
    ia32e_sept_t cached_sept_entry;                                // Cached SEPT entry of the page
    ept_level_t page_level_entry = (ept_level_t)gpa_mapping.level; // SEPT entry level of the page

    bool_t is_septe_locked = false;

    api_error_type return_val = UNINITIALIZE_ERROR;

    if(!check_gpa_validity((pa_t) gpa_mapping.raw, local_data->vp_ctx.tdcs->executions_ctl_fields.gpaw, PRIVATE_ONLY, local_data->vp_ctx.tdcs->executions_ctl_fields.virt_maxpa) ||
        !verify_page_info_input(gpa_mapping, LVL_PT, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mapping.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    mmio_pa = hpa_of_handle(
        mmio_pa_offset,
        local_data->vp_ctx.tdr);

    if (shared_hpa_check_with_pwr_2_alignment(mmio_pa, get_page_size_per_level(page_level_entry)) != TDX_SUCCESS ||
        get_hkid_from_pa(mmio_pa) != 0)
    {
        TDX_ERROR("Invalid mmio_pa = 0x%llx\n", mmio_pa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Check GPA shared bit, lock SEPT and walk to find entry
    page_gpa.page_4k_num = gpa_mapping.gpa;
    return_val = walk_private_gpa(
        local_data->vp_ctx.tdcs,
        page_gpa,
        local_data->vp_ctx.tdr->key_management_fields.hkid,
        &page_sept_entry_ptr,
        &page_level_entry,
        &cached_sept_entry,
        true);

    // Read the SEPT entry without locking, it is only used to provide an error indication
    bool_t is_leaf = is_secure_ept_leaf_entry(&cached_sept_entry, false);

    if (return_val != TDX_SUCCESS)
    {
        /**
         * Case 1.1:
         *  SEPT walk failed and terminated due to a guest-accessible (MAPPED, BLOCKEDW or EXPORTED*) *leaf* entry
         *  at a level > requested ACCEPT size (e.g. 2 MB PTE for a 4 KB request)
         */
        if (is_leaf &&
            sept_state_is_guest_accessible_leaf(cached_sept_entry))
        {
            TDX_ERROR("SEPT walk failed and terminated due to a guest-accessible \
                        (MAPPED, BLOCKEDW or EXPORTED*) *leaf* entry at a level > requested ACCEPT size\n");
            return_val = api_error_with_operand_id(TDX_PAGE_ALREADY_ACCEPTED, page_level_entry);
            goto EXIT;
        }
        else
        {
            /**
             * Case 1.2:
             *  SEPT walk failed and terminated due to a non-guest-accessible (BLOCKED, PENDING*
             *  etc. *leaf* entry at a level > requested ACCEPT size (e.g. 2 MB PTE PENDING leaf for a 4 KB request).
             *
             * Or
             *
             * Case 2:
             *  SEPT walk failed due to intermediate paging structure missing or inaccessible (e.g.missing PDE for a 4 KB request).
             */
            TDX_ERROR("SEPT walk failed and terminated due to a non-guest-accessible (BLOCKED, PENDING etc.)");
            TDX_ERROR("*leaf* entry at a level > requested ACCEPT size.\n");
            TDX_ERROR("Or, SEPT walk failed due to intermediate paging structure missing or inaccessible\n");

            ept_violation_exit(
                page_gpa,
                (ept_level_t)gpa_mapping.level,
                cached_sept_entry,
                is_leaf,
                page_level_entry,
                page_sept_entry_ptr);
        }
    }

    // The SEPT entry will be locked later, after we check it is PENDING
    // Lock the L1 SEPT entry
    return_val = sept_lock_acquire_guest(page_sept_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock the L1 SEPT entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    is_septe_locked = true;
    cached_sept_entry.raw = page_sept_entry_ptr->raw;

    /**
     * Case 3:
     *  SEPT walk terminated at a non-leaf entry (e.g. ACCEPT requested 2M but page mapped as 4K)
     */
    if (!is_leaf &&
        !is_sept_free(&cached_sept_entry))
    {
        TDX_ERROR("SEPT walk terminated at a non-leaf entry (e.g. ACCEPT requested 2M but page mapped as 4K)\n");
        return_val = api_error_with_operand_id(TDX_MMIO_ACCEPT_SIZE_MISMATCH, page_level_entry);
        goto EXIT;
    }

    /**
     * Case 4.1:
     *  SEPT walk terminated with a guest-accessible (MAPPED, BLOCKEDW or EXPORTED_*) leaf entry at level ==
     *  requested ACCEPT size
     */
    if (is_leaf &&
        sept_state_is_guest_accessible_leaf(cached_sept_entry))
    {
        TDX_ERROR("SEPT walk terminated with a guest-accessible \
                    (MAPPED, BLOCKEDW or EXPORTED_*) leaf entry at level == requested ACCEPT size\n");
        return_val = api_error_with_operand_id(TDX_PAGE_ALREADY_ACCEPTED, page_level_entry);
        goto EXIT;
    }

    /*
     * Case 4.2/4.3:
     *  SEPT walk terminated with a non-ACCEPTable (not PENDING nor PENDING_EXPORTED_DIRTY) leaf entry
     *  at level == requested ACCEPT size
     */
    if (!sept_state_is_tdcall_leaf_allowed(TDG_TDI_MMIO_ACCEPT_LEAF, cached_sept_entry))
    {
        TDX_ERROR("SEPT walk terminated with a non-ACCEPTable (not PENDING nor PENDING_EXPORTED_DIRTY) \
                    leaf entry at level == requested ACCEPT size\n");

        if (is_septe_locked)
        {
            sept_lock_release(page_sept_entry_ptr);
        }

        ept_violation_exit(
            page_gpa,
            (ept_level_t)gpa_mapping.level,
            cached_sept_entry,
            is_leaf,
            page_level_entry,
            page_sept_entry_ptr);
    }

    pa_t mmio_pa_with_hkid = set_hkid_to_pa(mmio_pa, local_data->vp_ctx.tdr->key_management_fields.hkid);
    if (mmio_pa_with_hkid.page_4k_num != cached_sept_entry.base)
    {
        TDX_ERROR("Invalid hpa offset (mmio_tdr_pa.page_4k_num = 0x%llx)\n", mmio_pa_with_hkid.page_4k_num);
        TDX_ERROR("cached_sept_entry.base = 0x%llx)\n", cached_sept_entry.base);
        return_val = api_error_with_operand_id(TDX_MMIO_INVALID_HPA_OFFSET, OPERAND_ID_RCX);
        goto EXIT;
    }

    // At this point we know that the page was MMIO_PENDING when we sampled the SEPT entry above.

    /**
     * We're running in the guest TD context and the EPT walk was successful.
     * This means the page and is guaranteed by TLB tracking to exist at least
     * until the next TD exit, septe_p is valid throughout this function, and the page can be freely written.
     * However the state of the SEPT entry itself may change concurrently by the host VMM.
     */

    // Prepare a new SEPT entry value as MAPPED or EXPORTED_DIRTY as required
    cached_sept_entry.r = 1;
    cached_sept_entry.w = 1;
    cached_sept_entry.x = 1;
    sept_update_state(&cached_sept_entry, SEPT_STATE_MMIO_MAPPED_MASK, false, false);

    // Update lock bit before writing the entry
    cached_sept_entry.raw |= BIT(SEPT_ENTRY_TDEL_BIT_POSITION);

    // Write the SEPT entry to memory in a singe write oepration
    atomic_mem_write_64b(&page_sept_entry_ptr->raw, cached_sept_entry.raw);

    return_val = TDX_SUCCESS;
EXIT:

    if (is_septe_locked)
    {
        sept_lock_release(page_sept_entry_ptr);
    }

    if (page_sept_entry_ptr != NULL)
    {
        free_la(page_sept_entry_ptr);
    }
    return return_val;
}
