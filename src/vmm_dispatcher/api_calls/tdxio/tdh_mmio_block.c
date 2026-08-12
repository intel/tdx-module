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
 * @file tdh_mmio_block.c
 * @brief TDHMMIOBLOCK API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/mmiomt.h"
#include "memory_handlers/sept_manager.h"

api_error_type tdh_mmio_block(
    page_info_api_input_t gpa_mapping,
    pa_t tdr_pa)
{
    // TDR related variables
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_walk_result_t tdr_pamt_walk_result;
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)
    bool_t is_op_state_locked = false;

    // GPA and SEPT related variables
    pa_t page_gpa = {.raw = 0};                                    // Target page GPA
    ia32e_sept_t *page_sept_entry_ptr = NULL;                      // SEPT entry of the page
    ia32e_sept_t cached_sept_entry;                                // Cached SEPT entry of the page
    ept_level_t page_level_entry = (ept_level_t)gpa_mapping.level; // SEPT entry level of the page
    bool_t is_sept_locked = false;                                 // Indicate SEPT is locked
    bool_t is_host_side_locked = false;

    mmiomt_data_t *mmiomt_data_ptr = NULL;

    tdx_module_local_t* local_data_ptr = get_local_data();
    api_error_type return_val = UNINITIALIZE_ERROR;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0;
    local_data_ptr->vmm_regs.rdx = 0;

    // Check and lock TDR page
    return_val = check_lock_and_map_explicit_tdr(
        tdr_pa,
        OPERAND_ID_RDX,
        TDX_RANGE_RO,
        TDX_LOCK_SHARED,
        PT_TDR,
        &tdr_pamt_walk_result,
        &is_tdr_locked,
        &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(
        tdr_ptr,
        TDX_RANGE_RW,
        TDX_LOCK_SHARED,
        false,
        TDH_MMIO_BLOCK_LEAF,
        &tdcs_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    is_op_state_locked = true;

    /* Verify GPA mapping input */
    if (!verify_page_info_input(gpa_mapping, LVL_PT, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mapping.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    /*  check GPA shared bit, lock SEPT and walk to find entry */
    page_gpa.page_4k_num = gpa_mapping.gpa;
    return_val = lock_sept_check_and_walk_private_gpa(
        tdcs_ptr,
        OPERAND_ID_RCX,
        page_gpa,
        tdr_ptr->key_management_fields.hkid,
        TDX_LOCK_EXCLUSIVE,
        &page_sept_entry_ptr,
        &page_level_entry,
        &cached_sept_entry,
        &is_sept_locked,
        false);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(cached_sept_entry, page_level_entry, local_data_ptr);
        }
        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    return_val = sept_lock_acquire_host(page_sept_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on SEPT host lock\n");
        set_arch_septe_details_in_vmm_regs(cached_sept_entry, page_level_entry, local_data_ptr);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    is_host_side_locked = true;

    // Read the SEPT entry (again after locking)
    cached_sept_entry = *page_sept_entry_ptr;
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MMIO_BLOCK_LEAF, cached_sept_entry))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(cached_sept_entry, page_level_entry, local_data_ptr);
        TDX_ERROR("TDH_MMIO_MAP is not allowed in current SEPT entry state\n");
        goto EXIT;
    }

    ia32e_sept_t new_septe_val;
    new_septe_val.raw = cached_sept_entry.raw;

    if (is_sept_mmio_mapped(&new_septe_val))
    {
        sept_update_state(&new_septe_val, SEPT_STATE_MMIO_BLOCKED_MASK, false, false);
    }
    else if (is_sept_mmio_pending(&new_septe_val))
    {
        sept_update_state(&new_septe_val, SEPT_STATE_MMIO_BLOCKED_MASK, false, false);
    }
    else
    {
        fatal_error(FATAL_ERROR_ID_123, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    // Update_permissions to none
    new_septe_val.r = 0;
    new_septe_val.w = 0;
    new_septe_val.x = 0;

    // Update the SEPT entry in memory
    atomic_mem_write_64b(&page_sept_entry_ptr->raw, new_septe_val.raw);


    // Get mmio_pa used without any HKID
    pa_t mmio_pa = {.raw = 0};
    mmio_pa.page_4k_num = page_sept_entry_ptr->base;
    mmiomt_data_ptr = mmiomt_implicit_get(mmio_pa, (mmiomt_lvl_t)page_level_entry);

    // Update mmiomt_data bepoch
    mmiomt_data_ptr->bepoch.raw = tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch;

    return_val = TDX_SUCCESS;
EXIT:

    if (mmiomt_data_ptr != NULL)
    {
        free_la(mmiomt_data_ptr);
    }

    if (is_host_side_locked)
    {
        sept_lock_release(page_sept_entry_ptr);
    }

    if (is_sept_locked)
    {
        release_sharex_lock_hp_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (page_sept_entry_ptr != NULL)
        {
            free_la(page_sept_entry_ptr);
        }
    }


    if (is_op_state_locked)
    {
        release_sharex_lock_hp_sh(&(tdcs_ptr->management_fields.op_state_lock));
    }

    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    if (is_tdr_locked)
    {
        if (tdr_ptr != NULL)
        {
            free_la(tdr_ptr);
        }
        pamt_unwalk(&tdr_pamt_walk_result);
    }
    return return_val;
}
