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
 * @file tdh_dmar_add.c
 * @brief TDHDMARADD API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/dmar.h"

static api_error_type is_valid_dmar_add_entry(
    const dmar_lvl_t dmar_lvl,
    const dmar_entry_t *const dmar_entry_ptr)
{
    uint8_t start_q_idx = 0;
    // Verify DMAR_VAL reserved inputs are 0 depending on the relevant DMAR entry
    switch (dmar_lvl)
    {
    case DMAR_RTE_LVL:
        start_q_idx = sizeof(dmar_rte_t) / sizeof(uint64_t);
        break;
    case DMAR_CTE_LVL:
        start_q_idx = sizeof(dmar_cte_t) / sizeof(uint64_t);
        break;
    case DMAR_PDE_LVL:
        start_q_idx = sizeof(dmar_pde_t) / sizeof(uint64_t);
        break;
    case DMAR_PASIDTE_LVL:
        start_q_idx = sizeof(dmar_pasidte_t) / sizeof(uint64_t);
        break;
    default:
        TDX_ERROR("Invalid dmar level %u\n", dmar_lvl);
        FATAL_ERROR();
    }

    for (uint8_t curr_q = start_q_idx; curr_q < sizeof(dmar_entry_t) / sizeof(uint64_t); curr_q++)
    {
        if (dmar_entry_ptr->raw.qwords[curr_q] != 0)
        {
            uint16_t operand_id = curr_q == 0? OPERAND_ID_RDX: curr_q + OPERAND_ID_R8 - 1;
            TDX_ERROR("dmar_val_%u  != 0\n", curr_q);
            return api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
        }
    }

    return TDX_SUCCESS;
}

api_error_type tdh_dmar_add(
    dmar_idx_t dmar_idx,
    uint64_t dmar_val_1,
    uint64_t dmar_val_2,
    uint64_t dmar_val_3,
    uint64_t dmar_val_4,
    uint64_t dmar_val_5,
    uint64_t dmar_val_6,
    uint64_t dmar_val_7,
    uint64_t dmar_val_8)
{
    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    dmar_walk_res_t dmar_walk_res = {0};
    bool_t is_dmar_walked = false;

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Verify dmar_index
    if (!is_valid_dmar_idx(dmar_idx))
    {
        TDX_ERROR("Invalid DMAR index (0x%llx)\n", dmar_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        dmar_idx.iommu_id.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    dmar_entry_t dmar_entry = {
        .raw.qwords[0] = dmar_val_1,
        .raw.qwords[1] = dmar_val_2,
        .raw.qwords[2] = dmar_val_3,
        .raw.qwords[3] = dmar_val_4,
        .raw.qwords[4] = dmar_val_5,
        .raw.qwords[5] = dmar_val_6,
        .raw.qwords[6] = dmar_val_7,
        .raw.qwords[7] = dmar_val_8};

    return_val = is_valid_dmar_add_entry(dmar_idx.level, &dmar_entry);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Get entry pointer in DMAR table and verify index
    api_error_code_e dmar_err_code = dmar_walk(
        dmar_idx,
        true,
        true,
        TDX_RANGE_RW,
        false,
        &is_dmar_walked,
        &dmar_walk_res);
    if (dmar_err_code != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(dmar_err_code, OPERAND_ID_RCX);
        TDX_ERROR("DMAR walk failed - error = %llx\n", return_val);
        goto EXIT;
    }

    dmar_state_info_t dmar_state_info = dmar_get_state_info(&dmar_walk_res);
    if (dmar_state_info.map_sts != DMAR_FREE)
    {
        TDX_ERROR("DMAR entry mapping state(=%u) does not equal DMAR_FREE\n", (uint8_t)dmar_state_info.map_sts);
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    pamt_entry_t pamt_val = {
        .pt = PT_IOMMU_MT,
        .owner = dmar_idx.iommu_id.raw,
        .bepoch.raw = iommu_config_ptr->iommu_generation};

    switch (dmar_state_info.level)
    {
    case DMAR_RTE_LVL:
        return_val = dmar_rte_add(
            &dmar_walk_res,
            dmar_state_info,
            &dmar_entry,
            &pamt_val);
        break;
    case DMAR_CTE_LVL:
        return_val = dmar_cte_add(
            &dmar_walk_res,
            dmar_state_info,
            &dmar_entry,
            &pamt_val);
        break;
    case DMAR_PDE_LVL:
        return_val = dmar_pde_add(
            &dmar_walk_res,
            dmar_state_info,
            &dmar_entry,
            &pamt_val);
        break;
    case DMAR_PASIDTE_LVL:
        return_val = dmar_pasidte_add(
            &dmar_walk_res,
            dmar_state_info,
            &dmar_entry,
            dmar_idx.iommu_id);
        break;
    default:
        TDX_ERROR("Invalid dmar level %u\n", dmar_state_info.level);
        FATAL_ERROR();
    }

EXIT:
    if (is_dmar_walked)
    {
        dmar_unwalk(&dmar_walk_res);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
