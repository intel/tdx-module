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
 * @file tdh_spdm_create.c
 * @brief TDHSPDMCREATE API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/tdx_locks.h"
#include "memory_handlers/keyhole_manager.h"
#include "helpers/helpers.h"

#include "tdxio/iommu.h"
#include "tdxio/spdm.h"

api_error_type tdh_spdm_create(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id,
    pa_t spdm_info_pa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    spdmdir_entry_t *spdmdir_entry_ptr = NULL;

    spdm_info_t *spdm_info_ptr = NULL;
    pamt_entry_t *spdm_info_pamt_entry_ptr = NULL;
    pamt_block_t spdm_info_pamt_block;
    bool_t is_spdm_info_pamt_locked = false;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        iommu_id_reg.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify spdm_id operand
    if (spdm_id >= MAX_SPDM_SESSION_ID)
    {
        TDX_ERROR("Invalid spdm id = %llu\n", spdm_id);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Input PA HKID must be 0
    if (get_hkid_from_pa(spdm_info_pa))
    {
        TDX_ERROR("Input PA (=0x%llx) is not zero\n", spdm_info_pa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    return_val = check_and_lock_explicit_4k_private_hpa(
        spdm_info_pa,
        OPERAND_ID_R8,
        TDX_LOCK_EXCLUSIVE,
        PT_NDA,
        &spdm_info_pamt_block,
        &spdm_info_pamt_entry_ptr,
        &is_spdm_info_pamt_locked);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check and lock spdm_info_pamt_entry_ptr\n");
        goto EXIT;
    }

    spdmdir_entry_ptr = map_and_lock_spdmdir_entry(iommu_config_ptr, spdm_id);
    if (spdmdir_entry_ptr == NULL)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Check that the spdmdir is not already present
    if (spdmdir_entry_ptr[spdm_id].present != 0)
    {
        TDX_ERROR("SPDM entry already present\n");
        return_val = api_error_with_operand_id(TDX_SPDM_ENTRY_ALREADY_PRESENT, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Initialize spdm_info_page
    spdm_info_ptr = (spdm_info_t *)map_pa_with_global_hkid(
        spdm_info_pa.raw_void,
        TDX_RANGE_RW);
    zero_area_cacheline(spdm_info_ptr, TDX_PAGE_SIZE_IN_BYTES);

    spdm_info_ptr->state = SPDM_STATE_NOT_BOUND;

    // Update PAMT entry of SPDM info to mark hosting IOMMU as the owner
    spdm_info_pamt_entry_ptr->pt = PT_IOMMU_MT;
    spdm_info_pamt_entry_ptr->owner = iommu_id_reg.iommu_id.raw;
    spdm_info_pamt_entry_ptr->bepoch.raw = iommu_config_ptr->iommu_generation;

    // Increment count of SPDM sessions
    iommu_config_ptr->active_spdm_session_count++;

    // Unlock the SPDM entry
    spdmdir_entry_ptr[spdm_id].present = 1;
    spdmdir_entry_ptr[spdm_id].addr = spdm_info_pa.page_4k_num;

    return_val = TDX_SUCCESS;

EXIT:

    if (spdm_info_ptr != NULL)
    {
        free_la(spdm_info_ptr);
    }

    if (spdmdir_entry_ptr != NULL)
    {
        unlock_spdmdir_entry(spdmdir_entry_ptr, spdm_id);
        free_la(spdmdir_entry_ptr);
    }

    if (is_spdm_info_pamt_locked)
    {
        pamt_unwalk(spdm_info_pa, spdm_info_pamt_block, spdm_info_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
