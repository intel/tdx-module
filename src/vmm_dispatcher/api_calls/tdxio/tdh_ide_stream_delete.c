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
 * @file tdh_ide_stream_delete.c
 * @brief TDHIDESTREAMDELETE API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/iommu.h"
#include "tdxio/spdm.h"
#include "helpers/helpers.h"

api_error_type tdh_ide_stream_delete(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id_reg)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    stream_info_t *stream_info_ptr = NULL;
    stream_info_t *stream_info_base_ptr = NULL;
    stream_exinfo_t *stream_exinfo_ptr = NULL;
    pamt_entry_t *stream_exinfo_pamt_entry = NULL;

    spdmdir_entry_t *spdmdir_entry_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    tdx_module_local_t *local_data = get_local_data();

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

    // Verify Stream ID
    if (stream_id_reg.raw >= MAX_IDE_STREAM_ID)
    {
        TDX_ERROR("Stream ID - %u is greater than max IDE Streams allowd\n", stream_id_reg.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    pa_t stream_info_pa = stream_id_reg.stream_id.page_selector == 1 ? iommu_config_ptr->stinfopa_1 : iommu_config_ptr->stinfopa_0;
    stream_info_base_ptr = (stream_info_t *)map_pa_with_global_hkid(
        stream_info_pa.raw_void,
        TDX_RANGE_RW);
    stream_info_ptr = &stream_info_base_ptr[stream_id_reg.stream_id.index];

    if (stream_info_ptr->stream_sts.config_lock == 0)
    {
        TDX_ERROR("IDE Stream not configured\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_NOT_CONFIGURED, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (stream_info_ptr->stream_sts.stream_block == 0)
    {
        TDX_ERROR("IDE Stream not blocked\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_NOT_BLOCKED, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Map stream extended info page with exclusive lock in PAMT
    return_val = pamt_implicit_get_and_lock(
        stream_info_ptr->stream_exinfo_pa,
        PT_4KB,
        TDX_LOCK_EXCLUSIVE,
        &stream_exinfo_pamt_entry,
        false);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to get or lock stream exinfo pamt entry. Stream exinfo page address 0x%llx\n", stream_info_ptr->stream_exinfo_pa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }

    stream_exinfo_ptr = (stream_exinfo_t *)map_pa_with_global_hkid(
        stream_info_ptr->stream_exinfo_pa.raw_void,
        TDX_RANGE_RW);

    // Lock check and map SPDM info
    return_val = lock_check_and_map_spdm_metadata(
        stream_exinfo_ptr->spdm_id,
        OPERAND_ID_RDX,
        iommu_config_ptr,
        SPDM_STATE_BOUND,
        &spdm_info_ptr,
        &spdmdir_entry_ptr);
    if(return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // There should not be any device interfaces active
    // Devif creation acquires shared lock on the stream extended info page
    if (stream_exinfo_ptr->devif_ref_cnt != 0)
    {
        TDX_ERROR("There are active device interfaces on the device\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_HAS_DEVICE_INTERFACES, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Clear and initialize stream info and return the freed extended info page address
    local_data->vmm_regs.rcx = remove_hkid_from_pa(stream_info_ptr->stream_exinfo_pa).raw;
    basic_memset_to_zero(stream_info_ptr, sizeof(stream_info_t));

    // Update PAMT entry of SPDM info to mark hosting IOMMU as the owner
    stream_exinfo_pamt_entry->owner = 0;
    stream_exinfo_pamt_entry->bepoch.raw = 0;
    stream_exinfo_pamt_entry->pt = PT_NDA;

    // Decrement count of active streams
    spdm_info_ptr->active_stream_count--;
    return_val = TDX_SUCCESS;

EXIT:

    if (spdm_info_ptr != NULL)
    {
        free_la(spdm_info_ptr);
    }

    if (spdmdir_entry_ptr != NULL)
    {
        unlock_spdmdir_entry(spdmdir_entry_ptr, stream_exinfo_ptr->spdm_id);
        free_la(spdmdir_entry_ptr);
    }

    if (stream_exinfo_ptr != NULL)
    {
        free_la(stream_exinfo_ptr);
    }

    if (stream_exinfo_pamt_entry != NULL)
    {
        pamt_implicit_release_lock(stream_exinfo_pamt_entry, TDX_LOCK_EXCLUSIVE);
    }

    if (stream_info_base_ptr != NULL)
    {
        free_la(stream_info_base_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
