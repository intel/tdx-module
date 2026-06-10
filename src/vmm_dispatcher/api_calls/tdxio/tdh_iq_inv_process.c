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
 * @file tdh_iq_inv_process.c
 * @brief TDHIQINVPROCESS API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/inv_queue.h"
#include "tdxio/vtbar.h"
#include "tdxio/dmar.h"

api_error_type tdh_iq_inv_process(iommu_id_reg_t iommu_id_reg)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    vtbar_t *vtbar_ptr = NULL;
    iq_ctx_entry_t *iq_ctx_ptr = NULL;

    dmar_walk_res_t dmar_walk_res = {0};
    dmar_state_info_t dmar_state_info = {0};

    tdr_t *tdr_ptr = NULL;
    pamt_block_t tdr_pamt_block;             // TDR PAMT block
    pamt_entry_t *tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)

    return_val = tdh_check_and_lock_iommu_config(
        iommu_id_reg.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock IOMMU id %u\n", iommu_id_reg.iommu_id);
        goto EXIT;
    }

    socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
    hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

    vtbar_ptr = map_vtbar(
        socket_io_info_ptr,
        hiop_info_ptr);

    uint64_t t_iqh_idx = vtbar_read_reg64(vtbar_ptr, VTBAR_T_IQH_REG_OFFSET) / IQ_ENTRY_SIZE_IN_BYTES;
    iq_ctx_ptr = (iq_ctx_entry_t *)map_iq_entry(iommu_config_ptr->iqctxaddr, iommu_config_ptr->iq_sw_head_idx);

    void *object_ptr = NULL;

    while (iommu_config_ptr->iq_sw_head_idx != t_iqh_idx)
    {
        if (iq_ctx_ptr->track_flag)
        {
            pa_t object_pa = iq_ctx_ptr->inv_target_pa;

            mapping_type_t mapping_type = iq_ctx_ptr->inv_req_type == INV_REQ_IOTLB ? TDX_RANGE_RO : TDX_RANGE_RW;
            // The TDR get's mapped differently in the relevant switch case
            if (iq_ctx_ptr->inv_req_type != INV_REQ_IOTLB)
            {
                object_ptr = map_pa(object_pa.raw_void, mapping_type);
            }

            switch (iq_ctx_ptr->inv_req_type)
            {
            case INV_REQ_RTE:
                dmar_walk_res.dmar_level = DMAR_RTE_LVL;
                dmar_walk_res.rte_ptr = object_ptr;
                break;
            case INV_REQ_CTE:
                dmar_walk_res.dmar_level = DMAR_CTE_LVL;
                dmar_walk_res.cte_ptr = object_ptr;
                break;
            case INV_REQ_PDE:
                dmar_walk_res.dmar_level = DMAR_PDE_LVL;
                dmar_walk_res.pde_ptr = object_ptr;
                break;
            case INV_REQ_PASIDTE:
                dmar_walk_res.dmar_level = DMAR_PASIDTE_LVL;
                dmar_walk_res.pasidte_ptr = object_ptr;
                break;
            case INV_REQ_IOTLB:
                // TDR and TDCS must be valid and mapped implicitly because TDCS cannot
                // be reclaimed untill all related IOTLB in progress invalidations are done
                // Check, lock and map the owner TDR page (Shared lock!)
                return_val = check_lock_and_map_explicit_tdr(
                    object_pa,
                    OPERAND_ID_RCX,
                    mapping_type,
                    TDX_LOCK_SHARED,
                    PT_TDR,
                    &tdr_pamt_block,
                    &tdr_pamt_entry_ptr,
                    &is_tdr_locked,
                    &tdr_ptr);
                if (return_val != TDX_SUCCESS)
                {
                    TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
                    goto EXIT;
                }

                // Implicitly map tdcs
                tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW, false);

                // Acquire TDCS epoch lock or fail with TDX_OPERAND_BUSY
                if (acquire_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock) != LOCK_RET_SUCCESS)
                {
                    return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);
                    TDX_ERROR("Failed to acquire TDCS epoch lock\n");
                    free_la(tdcs_ptr);

                    free_la(tdr_ptr);
                    pamt_unwalk(object_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);

                    goto EXIT;
                }

                iotlb_inv_tracker_t *iotlb_inv_tracker = &tdcs_ptr->tdxio_fields.iotlb_track_array[iommu_id_reg.iommu_id.raw];
                iotlb_inv_tracker->inv_epoch = (tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch & BIT(0));
                _lock_xadd_64b(&tdcs_ptr->tdxio_fields.prev_iotlb_cnt, (uint64_t)-1);
                iotlb_inv_tracker->inv_req = 0;

                // End of critical section, release the lock
                release_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock);

                free_la(tdcs_ptr);
                pamt_unwalk(object_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);

                // Note, tdr_ptr gets unmapped at the end of the while loop
                object_ptr = tdr_ptr;

                break;
            default:
                TDX_ERROR("Invalid invalidation request type (%u)\n", iq_ctx_ptr->inv_req_type);
                FATAL_ERROR();
            }

            if (iq_ctx_ptr->inv_req_type != INV_REQ_IOTLB)
            {
                dmar_state_info = dmar_get_state_info(&dmar_walk_res);
                dmar_state_info.inv_sts = DMAR_INV_DONE;
                dmar_set_state_info(&dmar_walk_res, dmar_state_info);
            }

            free_la(object_ptr);
        }

        uint32_t cur_sw_head = iommu_config_ptr->iq_sw_head_idx;
        // Advance SW head and wrap around if needed
        iommu_config_ptr->iq_sw_head_idx = (iommu_config_ptr->iq_sw_head_idx + 1) % (iommu_config_ptr->t_iqaddr.size * NUM_IQ_ENTRIES_IN_PAGE);

        // Reset iq_free_cnt after processing each entry section
        // Note: a single increment is used, since each invalidation entry is constructed from multiple sections
        iommu_config_ptr->iq_free_cnt++;

        // If new SW head is not on same page as current page where its mapped
        if (cur_sw_head != iommu_config_ptr->iq_sw_head_idx)
        {
            // Unmap previous pointer
            free_la(iq_ctx_ptr);
            // Remap to new page
            iq_ctx_ptr = (iq_ctx_entry_t *)map_iq_entry(iommu_config_ptr->iqctxaddr, iommu_config_ptr->iq_sw_head_idx);
        }
        else
        {
            // Advance pointer
            iq_ctx_ptr++;
        }


        // Check if interrupt pending unless this is the final round
        if (iommu_config_ptr->iq_sw_head_idx != t_iqh_idx &&
            is_interrupt_pending_host_side())
        {
            return_val = TDX_INTERRUPTED_RESUMABLE;
            goto EXIT;
        }
    }

    return_val = TDX_SUCCESS;

EXIT:

    if (iq_ctx_ptr != NULL)
    {
        free_la(iq_ctx_ptr);
    }
    if (vtbar_ptr != NULL)
    {
        free_la(vtbar_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
