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
 * @file tdh_dmar_block.c
 * @brief TDHDMARREMOVE API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/dmar.h"

api_error_type tdh_dmar_remove(dmar_idx_t dmar_idx)
{
    iommu_config_t *iommu_config = NULL;
    bool_t is_iommu_locked = false;

    dmar_walk_res_t dmar_walk_res = {0};
    bool_t is_dmar_walked = false;
    dmar_state_info_t dmar_state_info = {{0}};

    // TDR related variables
    pa_t tdr_pa = {.raw = 0};
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_entry_t *tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)

    pa_t sept_pa = {.raw = 0};
    pamt_entry_t *sept_pamt_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Verify dmar_index
    if (!is_valid_dmar_idx(dmar_idx))
    {
        TDX_ERROR("Invalid DMAR index (=0x%llx)\n", dmar_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        dmar_idx.iommu_id.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Get entry pointer in DMAR table and verify index
    api_error_code_e err_code = dmar_walk(
        dmar_idx,
        true,
        true,
        TDX_RANGE_RW,
        false,
        &is_dmar_walked,
        &dmar_walk_res);
    if (err_code != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(err_code, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify DMAR entry mapping state is state is DMAR_BLOCKED
    dmar_state_info = dmar_get_state_info(&dmar_walk_res);
    if (dmar_state_info.map_sts != DMAR_BLOCKED)
    {
        TDX_ERROR("DMAR mapping state(=%u) is not DMAR_BLOCKED/PENDING_BLOCKED\n", (uint8_t)dmar_state_info.map_sts);
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    if (dmar_state_info.inv_sts != DMAR_INV_DONE)
    {
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_INV_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    switch (dmar_idx.level)
    {
    case DMAR_RTE_LVL:
        return_val = dmar_rte_remove(&dmar_walk_res);
        break;
    case DMAR_CTE_LVL:
        return_val = dmar_cte_remove(
            &dmar_walk_res,
            &dmar_state_info);
        break;
    case DMAR_PDE_LVL:
        return_val = dmar_pde_remove(&dmar_walk_res);
        break;
    case DMAR_PASIDTE_LVL:

        // Nothing to do, in case the PASIDTE wasn't accepted
        if (dmar_walk_res.pasidte_ptr->slptptr == 0)
        {
            return_val = TDX_SUCCESS;
            goto EXIT_SUCCESS;
        }

        sept_pa.page_4k_num = dmar_walk_res.pasidte_ptr->slptptr;
        sept_pamt_ptr = pamt_implicit_get(sept_pa, PT_4KB);
        tdr_pa = get_pamt_entry_owner(sept_pamt_ptr);

        return_val = lock_and_map_implicit_tdr(
            tdr_pa,
            OPERAND_ID_TDR,
            TDX_RANGE_RO,
            TDX_LOCK_SHARED,
            &tdr_pamt_entry_ptr,
            &is_tdr_locked,
            &tdr_ptr);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
            goto EXIT;
        }

        // Map TDCS structure and check its state.
        tdcs_ptr = map_implicit_tdcs(
            tdr_ptr,
            TDX_RANGE_RW,
            false);

        return_val = dmar_pasidte_remove(
            dmar_idx,
            tdcs_ptr);
        break;
    default:
        fatal_error(FATAL_ERROR_ID_119, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

EXIT_SUCCESS:

    if (return_val == TDX_SUCCESS)
    {
        // Update DMAR entry
        dmar_state_info.map_sts = DMAR_FREE;
        dmar_set_state_info(&dmar_walk_res, dmar_state_info);
    }

EXIT:

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
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
    }

    if (sept_pamt_ptr != NULL)
    {
        free_la(sept_pamt_ptr);
    }

    if (is_dmar_walked)
    {
        dmar_unwalk(&dmar_walk_res);
    }

    release_iommu_lock(is_iommu_locked, iommu_config);

    return return_val;
}
