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
 * @file tdh_devif_remove.c
 * @brief TDHDEVIFREMOVE API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/devif.h"
#include "tdxio/iommu.h"
#include "tdxio/devifmt.h"

api_error_type tdh_devif_remove(function_id_reg_t function_id_reg)
{
    // DEVIFCS related variables
    devif_verify_param_t devif_verify_param = {0};
    page_size_t page_leaf_size = PT_4KB;
    pamt_entry_t *td_tdisp_msg_buff_pamt_entry_ptr = NULL;
    pamt_entry_t *vmm_tdisp_msg_buff_pamt_entry_ptr = NULL;
    pamt_entry_t *devifcs_root_pamt_ptr = NULL;

    stream_info_t *stream_info_ptr = NULL;
    stream_exinfo_t *stream_exinfo_ptr = NULL;

    // TDR related variables
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_entry_t *tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    bool_t is_tdr_locked = false;            // Indicate TDR is locked

    // IOMMU related variables
    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Lock, map and check devifcs
    return_val = tdh_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RO,
        OPERAND_ID_RCX,
        &devif_verify_param);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        devif_verify_param.devifcs_ptr->devif_id.iommu_id.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Get stream info pointer from devif info
    stream_info_ptr = map_stream_info_from_devifcs(devif_verify_param.devifcs_ptr->devif_id, iommu_config_ptr);

    // Verify TDISP and IDE stream state
    if (devif_verify_param.devifcs_ptr->tdisp_sts != TDISP_STATE_CONFIG_UNLOCKED &&
        stream_info_ptr->stream_sts.stream_block != 1)
    {
        TDX_ERROR("TDISP state (=%u) is not TDISP_STATE_CONFIG_UNLOCKED, \
                    or stream is not blocked (stream_sts.stream_block = %u)\n", \
                    (uint8_t)devif_verify_param.devifcs_ptr->tdisp_sts, stream_info_ptr->stream_sts.stream_block);
        return_val = api_error_with_operand_id(TDX_DEVIF_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check that DMAR is not mapped
    if (devif_verify_param.devifcs_ptr->dmar_mapped_flag)
    {
        TDX_ERROR("DMAR is mapped\n");
        return_val = api_error_with_operand_id(TDX_DEVIF_HAS_MAPPED_DMA, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check and lock TDR page
    return_val = lock_and_map_implicit_tdr(
        devif_verify_param.devifcs_ptr->tdr_pa,
        OPERAND_ID_TDR,
        TDX_RANGE_RW,
        TDX_LOCK_SHARED,
        &tdr_pamt_entry_ptr,
        &is_tdr_locked,
        &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    if (!tdr_ptr->management_fields.fatal &&
        devif_verify_param.devifcs_ptr->mmio_page_cnt)
    {
        TDX_ERROR("DEVIF has mapped MMIO\n");
        return_val = api_error_with_operand_id(TDX_DEVIF_HAS_MAPPED_MMIO, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Get DEVIFCS PA
    devifmt_entry_t *devifmt_leaf_entry_ptr = devif_verify_param.devifmt_walk_res.devifmt_path_arr[DEVIFMT_L0];
    pa_t devifcs_pa = {.raw = 0};
    devifcs_pa.page_4k_num = devifmt_leaf_entry_ptr->pa;

    return_val = pamt_implicit_get_and_lock(
        devifcs_pa,
        page_leaf_size,
        TDX_LOCK_EXCLUSIVE,
        &devifcs_root_pamt_ptr,
        false);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to get and lock DEVIFCS root pamt\n")
        goto EXIT;
    }

    // Update PAMT of DEVIFCS and the TDISP message buffers
    return_val = pamt_implicit_get_and_lock(
        devif_verify_param.devifcs_ptr->td_tdisp_msg_buff_pa,
        page_leaf_size,
        TDX_LOCK_EXCLUSIVE,
        &td_tdisp_msg_buff_pamt_entry_ptr,
        false);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to get and lock td_tdisp_msg_buff_pamt_entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    return_val = pamt_implicit_get_and_lock(
        devif_verify_param.devifcs_ptr->vmm_tdisp_msg_buff_pa,
        page_leaf_size,
        TDX_LOCK_EXCLUSIVE,
        &vmm_tdisp_msg_buff_pamt_entry_ptr,
        false);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to get and lock vmm_tdisp_msg_buff_pamt_entry\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Update PAMT of DEVIFCS and the TDISP message buffers
    // to indicate they are free
    td_tdisp_msg_buff_pamt_entry_ptr->pt = PT_NDA;
    vmm_tdisp_msg_buff_pamt_entry_ptr->pt = PT_NDA;
    devifcs_root_pamt_ptr->pt = PT_NDA;

    // Map stream_exinfo
    stream_exinfo_ptr = map_pa_with_global_hkid(
        stream_info_ptr->stream_exinfo_pa.raw_void,
        TDX_RANGE_RW);

    _lock_xadd_64b(&stream_exinfo_ptr->devif_ref_cnt, (uint64_t)-1);
    _lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, (uint64_t)NUM_OF_CHILD_REMOVE_DEVIF);
    _lock_xadd_64b(&tdr_ptr->tdx_io_fields.devif_ref_cnt, (uint64_t)-1);

    // Update the DEVIFMT leaf entry present bit to 0
    devif_verify_param.devifmt_walk_res.devifmt_path_arr[DEVIFMT_L0]->p = 0;
    devif_verify_param.devifmt_walk_res.devifmt_path_arr[DEVIFMT_L0]->pa = 0;

    return_val = TDX_SUCCESS;
    tdx_module_local_t *local_data_ptr = get_local_data();
    local_data_ptr->vmm_regs.rcx = remove_hkid_from_pa(devif_verify_param.devifcs_ptr->td_tdisp_msg_buff_pa).raw;
    local_data_ptr->vmm_regs.rdx = remove_hkid_from_pa(devif_verify_param.devifcs_ptr->vmm_tdisp_msg_buff_pa).raw;
    local_data_ptr->vmm_regs.r8 = remove_hkid_from_pa(devif_verify_param.devifcs_ptr->tdr_pa).raw;

EXIT:

    if (stream_exinfo_ptr != NULL)
    {
        free_la(stream_exinfo_ptr);
    }

    if (vmm_tdisp_msg_buff_pamt_entry_ptr != NULL)
    {
        pamt_implicit_release_lock(vmm_tdisp_msg_buff_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE);
    }

    if (td_tdisp_msg_buff_pamt_entry_ptr != NULL)
    {
        pamt_implicit_release_lock(td_tdisp_msg_buff_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE);
    }

    if (devifcs_root_pamt_ptr != NULL)
    {
        pamt_implicit_release_lock(devifcs_root_pamt_ptr, TDX_LOCK_EXCLUSIVE);
    }

    if (is_tdr_locked)
    {
        if (tdr_ptr != NULL)
    {
        free_la(tdr_ptr);
        }
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
    }

    if (stream_info_ptr != NULL)
    {
        free_la(stream_info_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
