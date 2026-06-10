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
 * @file tdh_devif_create.c
 * @brief TDHDEVIFCREATE API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"

#include "tdxio/iommu.h"
#include "tdxio/spdm.h"
#include "tdxio/devifmt.h"
#include "tdxio/devif.h"

api_error_type tdh_devif_create(
    devif_id_t devif_id,
    pa_t tdr_pa,
    pa_t devifcs_root_pa,
    pa_t td_tdisp_msg_buffer_pa,
    pa_t vmm_tdisp_msg_buffer_pa)
{
    // DEVIFCS related variables
    devifcs_t *devifcs_ptr = NULL;               // DEVIFCS pointer
    pamt_block_t devifcs_pamt_block;             // PAMT of DEVICS root page
    pamt_entry_t *devifcs_pamt_entry_ptr = NULL; // Pointer to the DEVIFCS PAMT entry
    bool_t is_devifcs_locked = false;            // Flag indicating PAMT entry of DEVIFCS root is locked

    // TDR related variables
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_block_t tdr_pamt_block;             // TDR PAMT block
    pamt_entry_t *tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    bool_t tdr_locked_flag = false;          // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)

    // TD TDISP buffer related variables
    void *td_tdisp_buff_ptr = NULL;                    // TDISP buffer pointer
    pamt_block_t td_tdisp_buff_pamt_block;             // PAMT of DEVICS root page
    pamt_entry_t *td_tdisp_buff_pamt_entry_ptr = NULL; // Pointer to the DEVIFCS PAMT entry
    bool_t is_td_tdisp_buff_locked = false;            // Flag indicating PAMT entry of DEVIFCS root is locked

    // VMM TDISP buffer related variables
    void *vmm_tdisp_buff_ptr = NULL;                    // TDISP buffer pointer
    pamt_block_t vmm_tdisp_buff_pamt_block;             // PAMT of DEVICS root page
    pamt_entry_t *vmm_tdisp_buff_pamt_entry_ptr = NULL; // Pointer to the DEVIFCS PAMT entry
    bool_t is_vmm_tdisp_buff_locked = false;            // Flag indicating PAMT entry of DEVIFCS root is locked

    // DEVIFMT parameters
    devifmt_entry_t *devifmt_leaf_entry_ptr = NULL;
    devifmt_idx_t devif_idx = {0};
    devifmt_walk_res_t devifmt_walk_res = {0};
    bool_t is_devifmt_walked = false;

    // Internal parameters
    stream_info_t *stream_info_ptr = NULL;
    stream_exinfo_t *stream_exinfo_ptr = NULL;

    spdmdir_entry_t *spdmdir_entry_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    bool_t op_state_locked_flag = false; // Indicate OP is locked

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Check and lock DEVIFCS page
    return_val = check_and_lock_explicit_4k_private_hpa(
        devifcs_root_pa,
        OPERAND_ID_R8,
        TDX_LOCK_EXCLUSIVE,
        PT_NDA,
        &devifcs_pamt_block,
        &devifcs_pamt_entry_ptr,
        &is_devifcs_locked);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock DEVIFCS (0x%llx) - error = 0x%llx\n", devifcs_root_pa.raw, return_val);
        goto EXIT;
    }

    // Check and lock TDR page
    return_val = check_lock_and_map_explicit_tdr(
        tdr_pa,
        OPERAND_ID_RDX,
        TDX_RANGE_RW,
        TDX_LOCK_SHARED,
        PT_TDR,
        &tdr_pamt_block,
        &tdr_pamt_entry_ptr,
        &tdr_locked_flag,
        &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map TDCS structure and check its state.
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED, false,
                                               TDH_DEVIF_CREATE_LEAF, &tdcs_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Check and lock the TD TDISP buffer page
    return_val = check_and_lock_explicit_4k_private_hpa(
        td_tdisp_msg_buffer_pa,
        OPERAND_ID_R9,
        TDX_LOCK_EXCLUSIVE,
        PT_NDA,
        &td_tdisp_buff_pamt_block,
        &td_tdisp_buff_pamt_entry_ptr,
        &is_td_tdisp_buff_locked);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock TD TDISP buffer (0x%llx) - error = %llx\n", td_tdisp_msg_buffer_pa.raw, return_val);
        goto EXIT;
    }

    // Check and lock the VMM TDISP buffer page
    return_val = check_and_lock_explicit_4k_private_hpa(
        vmm_tdisp_msg_buffer_pa,
        OPERAND_ID_R10,
        TDX_LOCK_EXCLUSIVE,
        PT_NDA,
        &vmm_tdisp_buff_pamt_block,
        &vmm_tdisp_buff_pamt_entry_ptr,
        &is_vmm_tdisp_buff_locked);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock VMM TDISP buffer (0x%llx) - error = %llx\n", vmm_tdisp_msg_buffer_pa.raw, return_val);
        goto EXIT;
    }

    // Verify DEVIF parameters
    if (!verify_function_id(devif_id.function_id) ||
        devif_id.devif_type != DEVIF_TYPE_PFVF)
    {
        TDX_ERROR("devif_id invalid - function id(=%lx) is not valid, or devif_type(=%lu) is not DEVIF_TYPE_PFVF\n",
                  devif_id.function_id, devif_id.devif_type);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify DEVIF function_id is not already assigned
    devif_idx.function_id = devif_id.function_id;
    devif_idx.level = DEVIFMT_L0;

    return_val = devifmt_walk(devif_idx, true, DEVIFMT_HP_LOCK_MODE, false, &is_devifmt_walked, &devifmt_walk_res);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    devifmt_leaf_entry_ptr = devifmt_walk_res.devifmt_path_arr[DEVIFMT_L0];
    if (devifmt_leaf_entry_ptr->p != 0)
    {
        TDX_ERROR("DEVIFMT entry not present\n");
        return_val = api_error_with_operand_id(TDX_DEVIFMT_ALREADY_PRESENT, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        devif_id.iommu_id.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check or lock IOMMU id %u\n", devif_id.iommu_id);
        goto EXIT;
    }

    // Get stream info pointer from devif info
    stream_info_ptr = map_stream_info_from_devifcs(devif_id, iommu_config_ptr);

    // Verify IDE stream ID
    if (stream_info_ptr->stream_sts.stream_type != IDE_STREAM_SEL_IDE ||
        (stream_info_ptr->stream_sts.config_lock != 1) ||
        stream_info_ptr->stream_sts.stream_block)
    {
        TDX_ERROR("IDE stream type (=%u) is not selective IDE stream, \
                    or stream is not configured (stream_sts.config_lock = %u) \
                    or stream status is blocked (stream_sts.stream_block = %u)\n",
                  stream_info_ptr->stream_sts.stream_type, stream_info_ptr->stream_sts.config_lock,
                  stream_info_ptr->stream_sts.stream_block);
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify DEVIF_ID rid
    if ((devif_id.function_id.rid.raw < stream_info_ptr->ide_rid_assoc_reg.base) ||
        (devif_id.function_id.rid.raw > stream_info_ptr->ide_rid_assoc_reg.limit))
    {
        TDX_ERROR(" invalid rid - \
                    (devif_id.function_id.rid.raw = 0x%x, ide_rid_assoc_reg.base = 0x%x, \
                    ide_rid_assoc_reg.limit = 0x%x)\n",
                  devif_id.function_id.rid.raw, stream_info_ptr->ide_rid_assoc_reg.base,
                  stream_info_ptr->ide_rid_assoc_reg.limit);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Map stream_exinfo
    stream_exinfo_ptr = map_pa_with_global_hkid(
        stream_info_ptr->stream_exinfo_pa.raw_void,
        TDX_RANGE_RW);

    return_val = lock_check_and_map_spdm_metadata(
        stream_exinfo_ptr->spdm_id,
        OPERAND_ID_RCX,
        iommu_config_ptr,
        SPDM_STATE_BOUND,
        &spdm_info_ptr,
        &spdmdir_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Update IDE stream info, atomically update reference counter
    _lock_xadd_64b(&stream_exinfo_ptr->devif_ref_cnt, 1);

    // Update TDR counters (atomic)
    _lock_xadd_64b(&tdr_ptr->tdx_io_fields.devif_ref_cnt, 1);
    _lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, NUM_OF_CHILD_ADD_DEVIF);

    // Map DEVIFCS
    devifcs_ptr = map_pa_with_global_hkid(
        devifcs_root_pa.raw_void,
        TDX_RANGE_RW);

    // Initialize DEVIFCS
    zero_area_cacheline(devifcs_ptr, TDX_PAGE_SIZE_IN_BYTES);
    devifcs_ptr->devif_id = devif_id;
    devifcs_ptr->td_tdisp_msg_buff_pa = td_tdisp_msg_buffer_pa;
    devifcs_ptr->vmm_tdisp_msg_buff_pa = vmm_tdisp_msg_buffer_pa;
    devifcs_ptr->spdm_id = stream_exinfo_ptr->spdm_id;
    devifcs_ptr->tdisp_version = spdm_info_ptr->binding_info.tdisp_version;

    devifcs_ptr->mmio_reporting_offset = tdr_ptr->tdx_io_fields.rnd_hpa_offset;

    devifcs_ptr->tdisp_sts = TDISP_STATE_CONFIG_UNLOCKED;
    devifcs_ptr->td_tdisp_req_sts = TDISP_REQ_AVAILABLE;

    devifcs_ptr->valid = false;
    devifcs_ptr->dmar_mapped_flag = false;
    tdx_memcpy(&devifcs_ptr->dev_info_hash, sizeof(devifcs_ptr->dev_info_hash),
               &spdm_info_ptr->binding_info.dev_info_hash, sizeof(spdm_info_ptr->binding_info.dev_info_hash));

    devifcs_ptr->tdr_pa = tdr_pa;
    devifcs_ptr->dev_report_offset = 0;
    devifcs_ptr->dev_report_len = TDISP_PAYLOAD_MAX_SIZE;

    // Set DEVIFMT entry to present and the pa to devifcs_root_pa
    devifmt_leaf_entry_ptr->p = 1;
    devifmt_leaf_entry_ptr->pa = devifcs_root_pa.page_4k_num;

    // Update PAMT of DEVIFCS root page
    set_pamt_entry_owner(devifcs_pamt_entry_ptr, tdr_pa);
    devifcs_pamt_entry_ptr->pt = PT_DEVIFCS_R;

    // Update PAMT of TD TDISP buffer page
    set_pamt_entry_owner(td_tdisp_buff_pamt_entry_ptr, tdr_pa);
    td_tdisp_buff_pamt_entry_ptr->pt = PT_DEVIFCS_NR;

    // Map TD TDISP buffer page
    td_tdisp_buff_ptr = map_pa_with_global_hkid(
        td_tdisp_msg_buffer_pa.raw_void,
        TDX_RANGE_RW);

    // Update PAMT of VMM TDISP buffer page
    set_pamt_entry_owner(vmm_tdisp_buff_pamt_entry_ptr, tdr_pa);
    vmm_tdisp_buff_pamt_entry_ptr->pt = PT_DEVIFCS_NR;

    // Map VMM TDISP buffer page
    vmm_tdisp_buff_ptr = map_pa_with_global_hkid(
        vmm_tdisp_msg_buffer_pa.raw_void,
        TDX_RANGE_RW);

    // Initialize TD and VMM TDISP_MSG_BUFF page to zero
    zero_area_cacheline(td_tdisp_buff_ptr, TDX_PAGE_SIZE_IN_BYTES);
    zero_area_cacheline(vmm_tdisp_buff_ptr, TDX_PAGE_SIZE_IN_BYTES);

EXIT:
    // TODO: check release order
    //  Release all acquired locks and free keyhole mappings
    if (vmm_tdisp_buff_ptr != NULL)
    {
        free_la(vmm_tdisp_buff_ptr);
    }

    if (td_tdisp_buff_ptr != NULL)
    {
        free_la(td_tdisp_buff_ptr);
    }

    if (devifcs_ptr != NULL)
    {
        free_la(devifcs_ptr);
    }

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

    if (stream_info_ptr != NULL)
    {
        free_la(stream_info_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    if (is_devifmt_walked)
    {
        devifmt_unwalk(&devifmt_walk_res);
    }

    if (is_vmm_tdisp_buff_locked)
    {
        pamt_unwalk(vmm_tdisp_msg_buffer_pa, vmm_tdisp_buff_pamt_block, vmm_tdisp_buff_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }

    if (is_td_tdisp_buff_locked)
    {
        pamt_unwalk(td_tdisp_msg_buffer_pa, td_tdisp_buff_pamt_block, td_tdisp_buff_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp_sh(&(tdcs_ptr->management_fields.op_state_lock));
    }

    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    if (tdr_locked_flag)
    {
        if (tdr_ptr != NULL)
        {
            free_la(tdr_ptr);
        }
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
    }

    if (is_devifcs_locked)
    {
        pamt_unwalk(devifcs_root_pa, devifcs_pamt_block, devifcs_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }

    return return_val;
}
