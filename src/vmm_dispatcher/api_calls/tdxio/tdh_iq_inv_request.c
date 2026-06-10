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
 * @file tdh_iq_inv_request.c
 * @brief TDHIQINVREQUEST API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/inv_queue.h"
#include "tdxio/vtbar.h"
#include "tdxio/dmar.h"
#include "tdxio/seam_sai.h"

api_error_type tdh_iq_inv_request(
    iommu_id_reg_t iommu_id_reg,
    inv_req_type_e inv_req_type,
    uint64_t inv_subject,
    uint64_t inv_wait_dsc_qword_1,
    uint64_t inv_wait_dsc_qword_2,
    uint64_t inv_wait_dsc_qword_3,
    uint64_t inv_wait_dsc_qword_4)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    // TDR related variables
    pa_t tdr_pa = {.raw = inv_subject};
    tdr_t *tdr_ptr = NULL;                   // Pointer to the TDR page (linear address)
    pamt_block_t tdr_pamt_block;             // TDR PAMT block
    pamt_entry_t *tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)
    bool_t op_state_locked_flag = false;
    bool_t is_epoch_locked = false;

    rid_pasid_t rid_pasid = {.raw = inv_subject};

    dmar_walk_res_t dmar_walk_res = {0};
    dmar_state_info_t dmar_state_info = {0};
    bool_t is_dmar_walked = false;

    vtbar_t *vtbar_ptr = NULL;
    inv_desc_t *iq_ptr = NULL;
    iq_ctx_entry_t *iq_ctx_ptr = NULL;

    return_val = tdh_check_and_lock_iommu_config(
        iommu_id_reg.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock IOMMU id %u - error 0x%llx\n", iommu_id_reg.iommu_id, return_val);
        goto EXIT;
    }

    // INV_REQ_TYPE must be valid and trusted IQ must have enough space per INV_REQ_TYPE
    if (inv_req_type >= INV_REQ_MAX)
    {
        TDX_ERROR("Invalid invalidation request type (%u)\n", inv_req_type);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    uint16_t req_num_desc;

    if (inv_req_type == INV_REQ_RTE || inv_req_type == INV_REQ_PDE)
    {
        req_num_desc = INV_WAIT_DESC_SIZE;
    }
    else if (inv_req_type == INV_REQ_PASIDTE)
    {
        req_num_desc = INV_REQ_WAIT_AND_IOTLB_DESC_SIZE;
    }
    else
    {
        req_num_desc = INV_REQ_AND_WAIT_DESC_SIZE;
    }

    if (iommu_config_ptr->iq_free_cnt < req_num_desc)
    {
        TDX_ERROR("Not enough free space in the invalidation queue (free space: %u, required space: %u)\n", iommu_config_ptr->iq_free_cnt, req_num_desc);
        return_val = api_error_with_operand_id(TDX_IOMMU_IQ_QUEUE_FULL, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (inv_req_type == INV_REQ_IOTLB)
    {
        // Lock TDR page
        return_val = check_lock_and_map_explicit_tdr(
            tdr_pa,
            OPERAND_ID_R8,
            TDX_RANGE_RO,
            TDX_LOCK_SHARED,
            PT_TDR,
            &tdr_pamt_block,
            &tdr_pamt_entry_ptr,
            &is_tdr_locked,
            &tdr_ptr);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to check/lock/map a TDR - error = 0x%llx\n", return_val);
            goto EXIT;
        }

        // Map TDCS structure and check its state.
        return_val = check_state_map_tdcs_and_lock(
            tdr_ptr,
            TDX_RANGE_RW,
            TDX_LOCK_SHARED,
            false,
            TDH_IQ_INV_REQUEST_LEAF,
            &tdcs_ptr);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("State check or TDCS lock failure - error = 0x%llx\n", return_val);
            goto EXIT;
        }
        op_state_locked_flag = true;

        // Acquire TDCS epoch lock or fail with TDX_OPERAND_BUSY
        if (acquire_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock) != LOCK_RET_SUCCESS)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);
            TDX_ERROR("Failed to acquire TDCS epoch lock - error = 0x%llx\n", return_val);
            goto EXIT;
        }
        is_epoch_locked = true;

        // Check that IOTLB invalidation session is not in progress or not required
        iotlb_inv_tracker_t iotlb_inv_tracker = tdcs_ptr->tdxio_fields.iotlb_track_array[iommu_id_reg.iommu_id.raw];
        if (iotlb_inv_tracker.inv_epoch == (tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch & BIT(0)) ||
            iotlb_inv_tracker.pasidte_ref_cnt == 0)
        {
            TDX_ERROR("IOTLB invalidation is not required\n");
            return_val = TDX_IOMMU_IOTLB_TRACKING_NOT_REQUIRED;
            goto EXIT;
        }

        if (iotlb_inv_tracker.inv_req != 0)
        {
            TDX_ERROR("IOTLB invalidation is in progress\n");
            return_val = TDX_IOMMU_IOTLB_TRACKING_NOT_DONE;
            goto EXIT;
        }
    }
    else // inv_req_type == INV_REQ_PASIDTE || INV_REQ_PDE || INV_REQ_CTE || INV_REQ_RTE
    {
        if (rid_pasid.rsvd0 != 0 ||
            rid_pasid.rsvd1 != 0)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            TDX_ERROR("RID reserved bits are not set to zero (rid_pasid - 0x%llx), error - 0x%llx\n", rid_pasid.raw, return_val);
            goto EXIT;
        }

        dmar_idx_t dmar_idx = {
            .rsvd = 0,
            .pasid = rid_pasid.pasid,
            .rid = rid_pasid.rid,
            .iommu_id = iommu_id_reg.iommu_id,
        };

        switch (inv_req_type)
        {
        case INV_REQ_CTE:
            dmar_idx.level = DMAR_CTE_LVL;
            break;
        case INV_REQ_RTE:
            dmar_idx.level = DMAR_RTE_LVL;
            break;
        case INV_REQ_PDE:
            dmar_idx.level = DMAR_PDE_LVL;
            break;
        case INV_REQ_PASIDTE:
            dmar_idx.level = DMAR_PASIDTE_LVL;
            break;
        default:
            FATAL_ERROR();
        }

        return_val = dmar_walk(
            dmar_idx,
            true,
            true,
            TDX_RANGE_RW,
            false,
            &is_dmar_walked,
            &dmar_walk_res);
        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
            TDX_ERROR("dmar_walk error = 0x%llx\n", return_val);
            goto EXIT;
        }
        is_dmar_walked = true;

        // Check that DMAR entry is blocked
        dmar_state_info = dmar_get_state_info(&dmar_walk_res);
        if (dmar_state_info.map_sts != DMAR_BLOCKED)
        {
            TDX_ERROR("Invalid dmar state info (%u)\n", dmar_state_info.map_sts);
            return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_R8);
            goto EXIT;
        }
        // Check that DMAR invalidation state is INV_PENDING
        if (dmar_state_info.inv_sts != DMAR_INV_PENDING)
        {
            TDX_ERROR("Invalidation pending\n");
            return_val = api_error_with_operand_id(TDX_DMAR_INVALID_INV_STATE, OPERAND_ID_R8);
            goto EXIT;
        }
    }

    // inv_wait_desc must be valid
    inv_desc_t inv_wait_desc = {{0}};
    inv_wait_desc.wait.raw.qwords[0] = inv_wait_dsc_qword_1;
    inv_wait_desc.wait.raw.qwords[1] = inv_wait_dsc_qword_2;
    inv_wait_desc.wait.raw.qwords[2] = inv_wait_dsc_qword_3;
    inv_wait_desc.wait.raw.qwords[3] = inv_wait_dsc_qword_4;

    if (inv_wait_desc.wait.type != INV_DESC_WAIT || // Type must be 0x5
        inv_wait_desc.wait.type_2 != 0 ||
        inv_wait_desc.wait.rsvd0 != 0 ||
        inv_wait_desc.wait.rsvd1 != 0 ||
        (inv_wait_desc.wait.pg_request_drain == 1 && iommu_config_ptr->iommu_cap.pds == 0) || // PD must be 0 if IOMMU ECAP_REG.PSD is 0
        inv_wait_desc.wait.fence_flag == 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        TDX_ERROR("Invalid wait descriptor 0x%llx, error - 0x%llx\n", inv_wait_desc.wait.raw, return_val);
        goto EXIT;
    }

    // inv_wait_desc (STATUS_ADDRESS) must be a 4B aligned and shared HPA address
    pa_t status_address = {.raw = inv_wait_desc.wait.status_address};
    if (shared_hpa_check_with_pwr_2_alignment(status_address, 4) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        TDX_ERROR("Invalid (not shared/ not 4KB aligned) status_address within wait descriptor 0x%llx, error - 0x%llx\n", status_address, return_val);
        goto EXIT;
    }

    if (inv_wait_desc.wait.rsvd2 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R11);
        TDX_ERROR("Invalid wait descriptor 0x%llx, error - 0x%llx\n", inv_wait_desc.wait.raw, return_val);
        goto EXIT;
    }

    if (inv_wait_desc.wait.rsvd3 != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R12);
        TDX_ERROR("Invalid wait descriptor 0x%llx, error - 0x%llx\n", inv_wait_desc.wait.raw, return_val);
        goto EXIT;
    }

    socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
    hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

    vtbar_ptr = map_vtbar(
        socket_io_info_ptr,
        hiop_info_ptr);

    uint64_t t_iqt_idx = vtbar_read_reg64(vtbar_ptr, VTBAR_T_IQT_REG_OFFSET) / IQ_ENTRY_SIZE_IN_BYTES;
    iq_ptr = (inv_desc_t *)map_iq_entry(iommu_config_ptr->t_iqaddr, t_iqt_idx);
    iq_ctx_ptr = (iq_ctx_entry_t *)map_iq_entry(iommu_config_ptr->iqctxaddr, t_iqt_idx);

    iq_ctx_entry_t iq_ctx_desc = {{0}};
    pa_t inv_subject_pa = {.raw = 0};
    inv_desc_t inv_desc = {{0}};

    switch (inv_req_type)
    {
    case INV_REQ_RTE:
        inv_subject_pa = dmar_walk_res.rte_pa;
        break;
    case INV_REQ_CTE:
        inv_subject_pa = dmar_walk_res.cte_pa;
        // Queue a context cache invalidation descriptor
        inv_desc.cc.type = INV_DESC_CC;
        inv_desc.cc.granularity = CC_G_GLOBAL;
        inv_desc.cc.sid = rid_pasid.rid.raw;
        iq_enqueue(
            iommu_config_ptr,
            &inv_desc,
            &iq_ctx_desc,
            &iq_ptr,
            &iq_ctx_ptr,
            &t_iqt_idx);
        break;
    case INV_REQ_PDE:
        inv_subject_pa = dmar_walk_res.pde_pa;
        break;
    case INV_REQ_PASIDTE:
        inv_subject_pa = dmar_walk_res.pasidte_pa;

        // Queue a pasid cache invalidation descriptor
        inv_desc.pc.type = INV_DESC_PC;
        inv_desc.pc.granularity = PC_G_PASID_SELECTIVE_WITHIN_DOMAIN;
        inv_desc.pc.did = (uint16_t)dmar_walk_res.pasidte_ptr->did;
        inv_desc.pc.pasid = rid_pasid.pasid;
        iq_enqueue(
            iommu_config_ptr,
            &inv_desc,
            &iq_ctx_desc,
            &iq_ptr,
            &iq_ctx_ptr,
            &t_iqt_idx);

        // Queue a IOTLB invalidation descriptor
        inv_desc_t iotlb_inv_desc = {{0}};
        iotlb_inv_desc.iotlb.type = INV_DESC_IOTLB;
        iotlb_inv_desc.iotlb.granularity = IOTLB_G_DOMAIN_SELECTIVE;
        iotlb_inv_desc.iotlb.did = (uint16_t)dmar_walk_res.pasidte_ptr->did;
        iotlb_inv_desc.iotlb.drain_reads = 1;
        iotlb_inv_desc.iotlb.drain_writes = 1;
        iq_enqueue(
            iommu_config_ptr,
            &iotlb_inv_desc,
            &iq_ctx_desc,
            &iq_ptr,
            &iq_ctx_ptr,
            &t_iqt_idx);
        break;
    case INV_REQ_IOTLB:
        inv_subject_pa = tdr_pa;

        // Queue a IOTLB invalidation descriptor
        inv_desc.iotlb.type = INV_DESC_IOTLB;
        inv_desc.iotlb.granularity = IOTLB_G_DOMAIN_SELECTIVE;
        inv_desc.iotlb.did = (uint16_t)(tdr_ptr->key_management_fields.hkid | BIT(iommu_config_ptr->iommu_cap.did_msb));
        inv_desc.iotlb.drain_reads = 1;
        inv_desc.iotlb.drain_writes = 1;
        iq_enqueue(
            iommu_config_ptr,
            &inv_desc,
            &iq_ctx_desc,
            &iq_ptr,
            &iq_ctx_ptr,
            &t_iqt_idx);

        // Mark invalidation queued
        tdcs_ptr->tdxio_fields.iotlb_track_array[iommu_id_reg.iommu_id.raw].inv_req = 1;
        break;
    default:
        FATAL_ERROR();
    }

    if (inv_req_type != INV_REQ_IOTLB)
    {
        // Update DMAR entry INV state
        dmar_state_info.inv_sts = DMAR_INV_QUEUED;
        dmar_set_state_info(&dmar_walk_res, dmar_state_info);
    }

    // Queue inv_dsc_wait and tracking IQ context
    iq_ctx_desc.track_flag = 1;
    iq_ctx_desc.inv_req_type = inv_req_type;
    iq_ctx_desc.inv_target_pa = inv_subject_pa;
    iq_enqueue(
        iommu_config_ptr,
        &inv_wait_desc,
        &iq_ctx_desc,
        &iq_ptr,
        &iq_ctx_ptr,
        &t_iqt_idx);

    // Decrement IQ free count
    iommu_config_ptr->iq_free_cnt -= req_num_desc;

    // Write the new tail into IOMMU using SEAM SAI
    enable_seam_sai_generation();
    vtbar_write_reg64(vtbar_ptr, VTBAR_T_IQT_REG_OFFSET, t_iqt_idx * IQ_ENTRY_SIZE_IN_BYTES);
    disable_seam_sai_generation();

    return_val = TDX_SUCCESS;

EXIT:

    if (iq_ctx_ptr != NULL)
    {
        free_la(iq_ctx_ptr);
    }

    if (iq_ptr != NULL)
    {
        free_la(iq_ptr);
    }

    if (vtbar_ptr != NULL)
    {
        free_la(vtbar_ptr);
    }

    if (is_dmar_walked)
    {
        dmar_unwalk(&dmar_walk_res);
    }

    if (is_epoch_locked)
    {
        release_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock);
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
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
