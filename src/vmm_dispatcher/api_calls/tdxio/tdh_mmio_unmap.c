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
 * @file tdh_mmio_unmap.c
 * @brief TDHMMIOUNMAP API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "tdxio/mmiomt.h"
#include "common/accessors/ia32_accessors.h"
#include "tdxio/devifmt.h"
#include "tdxio/iommu.h"

api_error_type tdh_mmio_unmap(
    page_info_api_input_t gpa_mapping,
    pa_t tdr_pa)
{
    // Local data for return values
    tdx_module_local_t *local_data_ptr = get_local_data();

    // TDR related variables
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_walk_result_t tdr_pamt_walk_result;
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)
    bool_t is_op_state_locked = false;

    // GPA and SEPT related variables
    pa_t page_gpa = {.raw = 0};                                    // Target page GPA
    ia32e_sept_t *page_sept_entry_ptr = NULL;                      // SEPT entry of the page
    ia32e_sept_t page_sept_entry_copy;                             // Cached SEPT entry of the page
    ept_level_t page_level_entry = (ept_level_t)gpa_mapping.level; // SEPT entry level of the page
    bool_t is_sept_locked = false;                                 // Indicate SEPT is locked
    bool_t is_host_side_locked = false;                            // Indicate SEPTE is locked

    mmiomt_data_t *mmiomt_data_ptr = NULL;
    // DEVIFCS related variables
    devifcs_t *devifcs_ptr = NULL;               // Pointer to the DEVIFCS

    // DEVIFMT variables
    devif_verify_param_t devif_verify_param = {0};
    function_id_reg_t function_id_reg = {.raw = 0};

    stream_info_t *stream_info_ptr = NULL;
    iommu_config_t *iommu_config_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0;
    local_data_ptr->vmm_regs.rdx = 0;

    // Check, lock and map the owner TDR page (Shared lock!)
    return_val = check_lock_and_map_explicit_tdr(
        tdr_pa,
        OPERAND_ID_RDX,
        TDX_RANGE_RW,
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
        TDH_MMIO_UNMAP_LEAF,
        &tdcs_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    is_op_state_locked = true;

    // Verify that GPA mapping input reserved fields equal zero
    if (!verify_page_info_input(gpa_mapping, LVL_PT, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mapping.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa.page_4k_num = gpa_mapping.gpa;
    return_val = lock_sept_check_and_walk_private_gpa(
        tdcs_ptr,
        OPERAND_ID_RCX,
        page_gpa,
        tdr_ptr->key_management_fields.hkid,
        TDX_LOCK_SHARED,
        &page_sept_entry_ptr,
        &page_level_entry,
        &page_sept_entry_copy,
        &is_sept_locked,
        false);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    return_val = sept_lock_acquire_host(page_sept_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on SEPT host lock\n");
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    is_host_side_locked = true;

    // Read the SEPT entry (again after locking)
    page_sept_entry_copy = *page_sept_entry_ptr;
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MMIO_UNMAP_LEAF, page_sept_entry_copy))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
        TDX_ERROR("TDH_MMIO_MAP is not allowed in current SEPT entry state\n");
        goto EXIT;
    }

    pa_t mmio_pa = {.raw = 0};
    mmio_pa.page_4k_num = page_sept_entry_ptr->base;
    mmiomt_data_ptr = mmiomt_implicit_get(mmio_pa, (mmiomt_lvl_t)page_level_entry);

    if (sept_state_is_tlb_tracking_required(page_sept_entry_copy) &&
        op_state_is_tlb_tracking_required(tdcs_ptr->management_fields.op_state))
    {
        // The TD may be running and this page must be blocked and tracked before it's removed.

        // Verify the entry is *BLOCKED (originally MAPPED or PENDING)
        if (!sept_state_is_any_blocked(page_sept_entry_copy))
        {
            return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, gpa_mapping.level, local_data_ptr, tdcs_ptr->executions_ctl_fields.attributes.debug);
            TDX_ERROR("MMIO SEPT entry is not blocked - 0x%llx\n", page_sept_entry_copy.raw);
            goto EXIT;
        }

        return_val = is_tlb_and_iotlb_tracked(tdcs_ptr, mmiomt_data_ptr->bepoch);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Lock, map and check devifcs
    function_id_reg.function_id.raw = mmiomt_data_ptr->function_id;
    return_val = tdh_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_RCX,
        &devif_verify_param);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    devifcs_ptr = devif_verify_param.devifcs_ptr;
    // Get stream info pointer from devif info
    devif_id_t devif_id = devif_verify_param.devifcs_ptr->devif_id;
    iommu_id_t iommu_id = devif_id.iommu_id;
    /**
     * @note - No need to lock the IOMMU since the IOMMU is already mapped, and no other TD can get this IOMMU
     */
    iommu_config_ptr = &get_global_data()->iommu_configs[iommu_id.raw];

    stream_info_ptr = map_stream_info_from_devifcs(devif_id, iommu_config_ptr);
    // Verify DEVIFCS TDISP state is UNLOCKED or fail with TDX_DEVIF_TDISP_INVALID_STATE
    if ((devifcs_ptr->tdisp_sts != TDISP_STATE_CONFIG_UNLOCKED) &&
        (stream_info_ptr->stream_sts.stream_block != 1))
    {
        TDX_ERROR("TDISP state is not configured unlocked (state = %u)\n", devifcs_ptr->tdisp_sts);
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    /**
     *  Set the SEPT entry local copy to FREE & unlocked.
     *  TLB tracking checked that the guest can't change this SEPT so concurrency
     *  is guaranteed by the host-side lock.
     *  Page removal is allowed during the out-of-order import phase.  However,
     *  the page’s SEPT entry is not marked as FREE when the page is removed.  Instead,
     *  the SEPT entry state is set to REMOVED.
     */
    septe_set_free_or_removed_and_release_locks(&page_sept_entry_copy, tdcs_ptr);
    atomic_mem_write_64b(&page_sept_entry_ptr->raw, page_sept_entry_copy.raw);

    is_host_side_locked = false;

    // Update DEVIF and MMIOMT state variables(atomic)
    mmiomt_data_ptr->mapped = 0;
    _lock_xadd_64b(&(devifcs_ptr->mmio_page_cnt), (uint64_t)-1);

    // Return success and remove MMIO page base HPA
    local_data_ptr->vmm_regs.r8 = remove_hkid_from_pa(mmio_pa).full_pa;

    return_val = TDX_SUCCESS;

EXIT:
    if (stream_info_ptr != NULL)
    {
        free_la(stream_info_ptr);
    }

    // Release all acquired locks and free keyhole mappings
    devif_unmap_devifcs(&devif_verify_param);

    if (mmiomt_data_ptr)
    {
        free_la(mmiomt_data_ptr);
    }

    if (is_host_side_locked)
    {
        sept_lock_release(page_sept_entry_ptr);
    }

    if (is_sept_locked)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
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
