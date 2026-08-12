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
 * @brief TDHDMARBLOCK API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/dmar.h"
#include "tdxio/devifmt.h"

api_error_type tdh_dmar_block(dmar_idx_t dmar_idx)
{
    iommu_config_t *iommu_config = NULL;
    bool_t is_iommu_locked = false;

    dmar_walk_res_t dmar_walk_res = {0};
    bool_t is_dmar_walked = false;

    devif_verify_param_t devif_verify_param = {0};
    dmar_state_info_t dmar_state_info = {{0}};
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

    // Verify DMAR entry mapping state is state is DMAR_PRESENT or DMAR_PENDING
    dmar_state_info = dmar_get_state_info(&dmar_walk_res);
    if (dmar_state_info.map_sts != DMAR_PRESENT &&
        dmar_state_info.map_sts != DMAR_PENDING)
    {
        TDX_ERROR("DMAR mapping state(=%u) is not DMAR_PRESENT/PENDING\n", (uint8_t)dmar_state_info.map_sts);
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Block and update DMAR entry state
    if (dmar_idx.level != (dmar_lvl_t)DMAR_PASIDTE_LVL)
    {
        // Verify all child nodes are free
        if (!is_dmar_child_entires_free(&dmar_walk_res))
        {
            return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_RCX);
            goto EXIT;
        }

        dmar_state_info.map_sts = DMAR_BLOCKED;
        // INV_STATE will only take effect if level == CTE
        dmar_state_info.inv_sts = DMAR_INV_PENDING;
        dmar_set_state_info(&dmar_walk_res, dmar_state_info);
    }
    else // == DMAR_PASIDTE_LVL
    {
        function_id_reg_t function_id_reg = {0};
        function_id_reg.function_id.rid = dmar_idx.rid;

        return_val = tdh_devifmt_get_devifcs(
            function_id_reg,
            TDX_RANGE_RO,
            OPERAND_ID_RCX,
            &devif_verify_param);
        if (return_val != TDX_SUCCESS)
        {
            goto EXIT;
        }

        // Update PASIDT entry state to blocked
        dmar_walk_res.pasidte_ptr->inv_state = DMAR_INV_PENDING;
        dmar_set_pasidte_state(dmar_walk_res.pasidte_ptr, DMAR_PASIDTE_BLOCKED);
    }

    return_val = TDX_SUCCESS;
EXIT:

    devif_unmap_devifcs(&devif_verify_param);

    if (is_dmar_walked)
    {
        dmar_unwalk(&dmar_walk_res);
    }

    release_iommu_lock(is_iommu_locked, iommu_config);

    return return_val;
}
