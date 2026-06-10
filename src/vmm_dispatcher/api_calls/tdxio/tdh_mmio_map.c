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
 * @file tdh_mmio_map.c
 * @brief TDHMMIOMAP API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "tdxio/mmiomt.h"
#include "tdxio/devifmt.h"
#include "tdxio/ide_stream.h"
#include "tdxio/iommu.h"

api_error_type tdh_mmio_map(
    page_info_api_input_t gpa_mapping,
    pa_t tdr_pa,
    pa_t mmio_pa)
{
    // TDR related variables
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_walk_result_t tdr_pamt_walk_result;
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)
    bool_t op_state_locked_flag = false;

    // GPA and SEPT related variables
    pa_t page_gpa = {.raw = 0};                                    // Target page GPA
    ia32e_sept_t *page_sept_entry_ptr = NULL;                      // SEPT entry of the page
    ia32e_sept_t cached_sept_entry;                                // Cached SEPT entry of the page
    ept_level_t page_level_entry = (ept_level_t)gpa_mapping.level; // SEPT entry level of the page
    bool_t is_sept_locked = false;                                 // Indicate SEPT is locked
    bool_t is_host_side_locked = false;                            // Indicate SEPTE is locked

    api_error_code_e errc = UNINITIALIZE_ERROR;

    // mmiomt_walk variables
    mmiomt_idx_t mmiomt_idx = {.raw = 0};
    mmiomt_walk_res_t mmiomt_walk_res = {0};
    mmiomt_entry_t *mmiomt_entry_ptr = NULL;
    bool_t is_mmiomt_walked = false; // Indicates mmiomt_walk was successful

    // DEVIFMT variables
    devif_verify_param_t devif_verify_param = {0};
    function_id_reg_t function_id_reg = {.raw = 0};

    stream_info_t *stream_info_ptr = NULL;
    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    tdx_module_local_t *local_data_ptr = get_local_data();

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0;
    local_data_ptr->vmm_regs.rdx = 0;

    api_error_type return_val = UNINITIALIZE_ERROR;
    // Check, lock and map the owner TDR page (Shared lock!)
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

    // Map the TDCS structure and check its state.
    return_val = check_state_map_tdcs_and_lock(
        tdr_ptr,
        TDX_RANGE_RW,
        TDX_LOCK_SHARED,
        false,
        TDH_MMIO_MAP_LEAF,
        &tdcs_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    /* Verify GPA mapping input */
    if (!verify_page_info_input(gpa_mapping, LVL_PT, LVL_PDPT))
    {
        TDX_ERROR("Input GPA page info (0x%llx) is not valid\n", gpa_mapping.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa = page_info_to_pa(gpa_mapping);
    if (!check_gpa_validity(page_gpa, tdcs_ptr->executions_ctl_fields.gpaw, PRIVATE_ONLY, tdcs_ptr->executions_ctl_fields.virt_maxpa))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Failed on GPA check - error = 0x%llx\n", return_val);
        goto EXIT;
    }

    /*Verify MMIO pa input - Check PA validity and alignment */
    errc = shared_hpa_check_with_pwr_2_alignment(
        mmio_pa,
        get_gpa_alignment(gpa_mapping));
    if (errc != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to verify MMIO - error = %llx\n", errc);
        return_val = api_error_with_operand_id(errc, OPERAND_ID_R8);
        goto EXIT;
    }

    if (get_hkid_from_pa(mmio_pa) != 0)
    {
        TDX_ERROR("Failed to verify MMIO - error = %llx\n", errc);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    /*  check GPA shared bit, lock SEPT and walk to find entry */
    return_val = lock_sept_check_and_walk_private_gpa(
        tdcs_ptr,
        OPERAND_ID_RCX,
        page_gpa,
        tdr_ptr->key_management_fields.hkid,
        TDX_LOCK_SHARED,
        &page_sept_entry_ptr,
        &page_level_entry,
        &cached_sept_entry,
        &is_sept_locked);
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
    if (!sept_state_is_seamcall_leaf_allowed(TDH_MMIO_MAP_LEAF, cached_sept_entry))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_STATE_INCORRECT, OPERAND_ID_RCX);
        set_arch_septe_details_in_vmm_regs(cached_sept_entry, page_level_entry, local_data_ptr);
        TDX_ERROR("TDH_MMIO_MAP is not allowed in current SEPT entry state\n");
        goto EXIT;
    }

    mmiomt_idx.pa = mmio_pa.page_4k_num;
    mmiomt_idx.level = (mmiomt_lvl_t)gpa_mapping.level;
    errc = mmiomt_walk(
        mmiomt_idx,
        true,
        TDX_RANGE_RW,
        &is_mmiomt_walked,
        &mmiomt_walk_res);
    if (errc != TDX_SUCCESS)
    {
        TDX_ERROR("MMIOMT walk failed\n");
        return_val = api_error_with_operand_id(errc, OPERAND_ID_RCX);
        goto EXIT;
    }

    mmiomt_entry_ptr = mmiomt_walk_res.mmiomt_path_arr[mmiomt_idx.level];
    if (mmiomt_entry_ptr->type != MMIOMT_DATA ||
        mmiomt_entry_ptr->data.mapped)
    {
        TDX_ERROR("Invalid MMIOMT entry - MMIOMT type (=%u) is not MMIOMT_DATA, or data is not mapped (data.mapped = %u)\n",
                  mmiomt_entry_ptr->type, mmiomt_entry_ptr->data.mapped);
        return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_RCX);
        goto EXIT;
    }

    function_id_reg.function_id.raw = mmiomt_entry_ptr->data.function_id;

    // Lock, map and check devifcs
    return_val = tdh_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_R8,
        &devif_verify_param);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    if (devif_verify_param.devifcs_ptr->tdr_pa.raw != tdr_pa.raw)
    {
        TDX_ERROR("TD is not the page owner (page owner = 0x%llx, tdr_pa = 0x%llx)\n",
                  devif_verify_param.devifcs_ptr->tdr_pa.raw, tdr_pa.raw);
        return_val = api_error_with_operand_id(TDX_MMIO_DEVIF_OWNER_MISMATCH, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Check MMIO page falls within DEVIF associated Selective IDE address range
    devif_id_t devif_id = devif_verify_param.devifcs_ptr->devif_id;
    iommu_id_t iommu_id = devif_id.iommu_id;

    iommu_config_ptr = &get_global_data()->iommu_configs[iommu_id.raw];

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        iommu_id.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check or lock IOMMU id %u\n", iommu_id.raw);
        goto EXIT;
    }

    stream_info_ptr = map_stream_info_from_devifcs(devif_id, iommu_config_ptr);
    // IDE-Stream must not be blocked
    if (stream_info_ptr->stream_sts.stream_block == 1)
    {
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_BLOCKED, OPERAND_ID_R8);
        TDX_ERROR("IDE-Stream is blocked\n");
        goto EXIT;
    }


    mmiomt_entry_ptr->data.mapped = 1;
    _lock_xadd_64b(&(devif_verify_param.devifcs_ptr->mmio_page_cnt), 1);

    sept_set_leaf_and_release_locks_given_hpa_and_hkid(
        page_sept_entry_ptr,
        SEPT_PERMISSIONS_NONE,
        mmio_pa,
        tdr_ptr->key_management_fields.hkid,
        SEPT_STATE_MMIO_PENDING_MASK);

    is_host_side_locked = false;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (stream_info_ptr != NULL)
    {
        free_la(stream_info_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    devif_unmap_devifcs(&devif_verify_param);

    if (is_mmiomt_walked)
    {
        mmiomt_unwalk(&mmiomt_walk_res);
    }

    if (is_host_side_locked)
    {
        sept_lock_release(page_sept_entry_ptr);
    }

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
        pamt_unwalk(&tdr_pamt_walk_result);
    }
    return return_val;
}
