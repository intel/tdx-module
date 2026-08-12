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
 * @file tdh_dmar_read.c
 * @brief TDHDMAREAD API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/dmar.h"

api_error_type tdh_dmar_read(dmar_idx_t dmar_idx)
{
    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    dmar_walk_res_t dmar_walk_res = {0};
    bool_t is_dmar_walked = false;

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
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Get entry pointer in DMAR table and verify index
    api_error_code_e err_code = dmar_walk(
        dmar_idx,
        true,
        false,
        TDX_RANGE_RO,
        false,
        &is_dmar_walked,
        &dmar_walk_res);
    if (err_code != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(err_code, OPERAND_ID_RCX);
        goto EXIT;
    }

    dmar_arc_read(&dmar_walk_res);
    return_val = TDX_SUCCESS;
EXIT:
    if (is_dmar_walked)
    {
        dmar_unwalk(&dmar_walk_res);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
