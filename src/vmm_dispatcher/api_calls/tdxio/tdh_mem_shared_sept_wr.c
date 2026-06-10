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
 * @file tdh_mem_shared_sept_wr.c
 * @brief TDHMEMSHAREDSEPTWR API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"

api_error_type tdh_mem_shared_sept_wr(
    page_info_api_input_t gpa_page_info,
    pa_t tdr_pa,
    ia32e_sept_t ept_entry)
{
    tdx_module_local_t *local_data_ptr = get_local_data();

    // TDR related variables
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_block_t tdr_pamt_block;             // TDR PAMT block
    pamt_entry_t *tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)
    bool_t op_state_locked_flag = false;     // Indicate OP is locked

    // GPA and SEPT related variables
    pa_t gpa_pa = {.raw = 0};                                        // Target page GPA
    ia32e_sept_t *page_sept_entry_ptr = NULL;                        // SEPT entry of the page
    ia32e_sept_t cached_sept_entry;                                  // Cached SEPT entry of the page
    ept_level_t page_level_entry = (ept_level_t)gpa_page_info.level; // SEPT entry level of the page
    bool_t is_sept_locked = false;                                   // Indicate SEPT is locked

    api_error_type return_val = UNINITIALIZE_ERROR;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0;
    local_data_ptr->vmm_regs.rdx = 0;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(
        tdr_pa,
        OPERAND_ID_RDX,
        TDX_RANGE_RO,
        TDX_LOCK_SHARED,
        PT_TDR,
        &tdr_pamt_block,
        &tdr_pamt_entry_ptr,
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
        TDH_MEM_SHARED_SEPT_WR_LEAF,
        &tdcs_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Verify GPA
    uint32_t shared_bit_ept_level = LVL_PML4 + tdcs_ptr->executions_ctl_fields.gpaw;
    pa_t gpa = {.raw = gpa_page_info.raw};

    if (!verify_page_info_input(gpa_page_info, (ept_level_t)shared_bit_ept_level, (ept_level_t)shared_bit_ept_level) ||
        !get_gpa_shared_bit(gpa_page_info.raw, tdcs_ptr->executions_ctl_fields.gpaw) ||
        !check_gpa_validity(gpa, tdcs_ptr->executions_ctl_fields.gpaw, false, tdcs_ptr->executions_ctl_fields.virt_maxpa))
    {
        TDX_ERROR("Invalid gpa_page_info (=0x%llx)\n", gpa_page_info.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Walk the Secure-EPT based on GPA and LEVEL to locate the EPT entry
    gpa_pa.page_4k_num = gpa_page_info.gpa;
    return_val = lock_sept_and_walk_gpa(
        tdcs_ptr,
        OPERAND_ID_RCX,
        gpa_pa,
        TDX_LOCK_SHARED,
        &page_sept_entry_ptr,
        &page_level_entry,
        &cached_sept_entry,
        &is_sept_locked);
    if (return_val != TDX_SUCCESS)
    {

        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            TDX_ERROR("Failed on SEPT lock or walk - error = %llx\n", return_val);
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(cached_sept_entry, page_level_entry, local_data_ptr);
        }
        goto EXIT;
    }

    //	Set the EPT entry value to EPTE_VAL
    page_sept_entry_ptr->raw = ept_entry.raw;

    // Success
    return_val = TDX_SUCCESS;

EXIT:
    if (is_sept_locked)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (page_sept_entry_ptr != NULL)
        {
            free_la(page_sept_entry_ptr);
        }
    }

    if (op_state_locked_flag)
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
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
    }
    return return_val;
}
