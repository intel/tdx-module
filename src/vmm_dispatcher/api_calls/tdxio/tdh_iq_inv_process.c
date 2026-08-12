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
#include "common/memory_handlers/sept_manager.h"

_STATIC_INLINE_ void emulate_wait_complete(
    tdr_t *const tdr_ptr,
    tdcs_t *const tdcs_ptr,
    tdcs_tdxio_fields_t *const tdcs_tdxio_fields_ptr)
{
    if (!tdcs_tdxio_fields_ptr->status_complete_wr)
    {
        return;
    }

    uint32_t *wait_status_ptr = NULL;
    api_error_type return_val = UNINITIALIZE_ERROR;
    ia32e_sept_t *sept_entry;
    ia32e_sept_t sept_entry_copy;
    ept_level_t ept_level = LVL_PT;
    bool_t sept_locked_flag = false;

    // Do not call again
    tdcs_tdxio_fields_ptr->status_complete_wr = false;

    /**
     * @brief Get the HPA for the Status Complete GPA. The page must be guest accessible (Mapped) otherwise
     * TDX Module does not write the status and doesn't call EPT violation.
     * VMM can block the page but it can simply not commit the TD invalidations. With the implementation
     * of "pinned" pages, the VMM will not be able to block the private page.
     */
    return_val = lock_sept_check_and_walk_private_gpa_to_leaf(tdcs_ptr,
                                                                OPERAND_ID_RCX,
                                                                tdcs_tdxio_fields_ptr->status_complete_gpa,
                                                                tdr_ptr->key_management_fields.hkid,
                                                                TDX_LOCK_SHARED,
                                                                &sept_entry,
                                                                &ept_level,
                                                                &sept_entry_copy,
                                                                &sept_locked_flag);
    
    if (return_val != TDX_SUCCESS)
    {
        return; // No error, just a silent Status Write drop
    }

    // Now we can map and write status
    pa_t wait_status_gpa_with_hkid = {.raw = leaf_ept_entry_to_hpa(*sept_entry, tdcs_tdxio_fields_ptr->status_complete_gpa.raw, ept_level)};
    wait_status_ptr = (uint32_t *)map_pa(wait_status_gpa_with_hkid.raw_void, TDX_RANGE_RW);

    *wait_status_ptr = tdcs_tdxio_fields_ptr->status_complete_data;
    free_la(wait_status_ptr);

    tdcs_tdxio_fields_ptr->status_complete_wr = false;

    if (sept_locked_flag)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        free_la(sept_entry);
    }
}

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
    pamt_walk_result_t tdr_pamt_walk_result;
    bool_t is_tdr_locked = false;            // Indicate TDR is locked
    tdcs_t *tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)
    bool_t op_state_locked_flag = false;

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

            mapping_type_t mapping_type =
                (iq_ctx_ptr->inv_req_type == INV_REQ_IOTLB ||
                 iq_ctx_ptr->inv_req_type == INV_REQ_TD)
                    ? TDX_RANGE_RO
                    : TDX_RANGE_RW;
            // The TDR get's mapped differently in the relevant switch case
            if (iq_ctx_ptr->inv_req_type != INV_REQ_IOTLB &&
                iq_ctx_ptr->inv_req_type != INV_REQ_TD)
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
            // No break
            case INV_REQ_TD:
                // TDR and TDCS must be valid and mapped implicitly because TDCS cannot
                // be reclaimed untill all related IOTLB in progress invalidations are done
                // Check, lock and map the owner TDR page (Shared lock!)
                return_val = check_lock_and_map_explicit_tdr(
                    object_pa,
                    OPERAND_ID_RCX,
                    mapping_type,
                    TDX_LOCK_SHARED,
                    PT_TDR,
                    &tdr_pamt_walk_result,
                    &is_tdr_locked,
                    &tdr_ptr);
                if (return_val != TDX_SUCCESS)
                {
                    TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
                    goto EXIT;
                }

                tdcs_tdxio_fields_t *tdcs_tdxio_fields_ptr = NULL;

                if (iq_ctx_ptr->inv_req_type == INV_REQ_IOTLB)
                {
                    // Implicitly map tdcs
                    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW, false);
                    tdcs_tdxio_fields_ptr = &tdcs_ptr->tdxio_fields;

                    return_val = acquire_sharex_lock_hp_ex(&tdcs_tdxio_fields_ptr->tdinv_lock, false);
                    if (return_val != TDX_SUCCESS)
                    {
                        TDX_ERROR("Failed to acquire lock on tdinv_lock\n")
                        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
                        free_la(tdcs_ptr);

                        free_la(tdr_ptr);
                        pamt_unwalk(&tdr_pamt_walk_result);
                        goto EXIT;
                    }

                    // Acquire TDCS epoch lock or fail with TDX_OPERAND_BUSY
                    if (acquire_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock) != LOCK_RET_SUCCESS)
                    {
                        TDX_ERROR("Failed to acquire TDCS epoch lock\n");
                        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);

                        release_sharex_lock_hp_ex(&tdcs_tdxio_fields_ptr->tdinv_lock);

                        free_la(tdcs_ptr);
                        free_la(tdr_ptr);
                        pamt_unwalk(&tdr_pamt_walk_result);

                        goto EXIT;
                    }

                    iotlb_inv_tracker_t *iotlb_inv_tracker = &tdcs_ptr->tdxio_fields.iotlb_track_array[iommu_id_reg.iommu_id.raw];
                    iotlb_inv_tracker->inv_epoch = (tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch & BIT(0));
                    _lock_xadd_64b(&tdcs_ptr->tdxio_fields.prev_iotlb_cnt, (uint64_t)-1);
                    iotlb_inv_tracker->inv_req = 0;

                    if (tdcs_tdxio_fields_ptr->req_active &&
                        get_qword_bm(tdcs_tdxio_fields_ptr->req_iommu_bm.qwords, iommu_id_reg.raw))
                    {
                        set_qword_bm(tdcs_tdxio_fields_ptr->req_iommu_bm.qwords, iommu_id_reg.raw, false);
                        if (tdx_memcmp_to_zero(&tdcs_tdxio_fields_ptr->req_iommu_bm, sizeof(tdcs_tdxio_fields_ptr->req_iommu_bm)) &&
                            !tdr_ptr->management_fields.fatal)
                        {
                            emulate_wait_complete(tdr_ptr, tdcs_ptr, tdcs_tdxio_fields_ptr);
                            tdcs_tdxio_fields_ptr->req_active = false;
                        }
                    }

                    // End of critical section, release the lock
                    release_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock);
                }
                else // INV_REQ_TD
                {
                    // Map the TDCS structure and check the state
                    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_IQ_INV_PROCESS_LEAF, &tdcs_ptr);


                    if (return_val != TDX_SUCCESS)
                    {
                        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
                        free_la(tdr_ptr);
                        pamt_unwalk(&tdr_pamt_walk_result);
                        goto EXIT;
                    }
                    op_state_locked_flag = true;

                    tdcs_tdxio_fields_ptr = &tdcs_ptr->tdxio_fields;

                    return_val = acquire_sharex_lock_hp_ex(&tdcs_tdxio_fields_ptr->tdinv_lock, false);
                    if (return_val != TDX_SUCCESS)
                    {
                        TDX_ERROR("Failed to acquire lock on tdinv_lock\n")
                        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);

                        release_sharex_lock_hp_sh(&(tdcs_ptr->management_fields.op_state_lock));
                        free_la(tdcs_ptr);

                        free_la(tdr_ptr);
                        pamt_unwalk(&tdr_pamt_walk_result);
                        goto EXIT;
                    }

                    if (tdcs_tdxio_fields_ptr->req_active)
                    {
                        tdcs_tdxio_fields_ptr->iotlb_complete[iommu_id_reg.raw]++;
                        if (tdcs_tdxio_fields_ptr->iotlb_complete[iommu_id_reg.raw] == tdcs_tdxio_fields_ptr->req_num)
                        {
                            set_qword_bm(tdcs_tdxio_fields_ptr->req_iommu_bm.qwords, iommu_id_reg.raw, false);
                            if (tdx_memcmp_to_zero(&tdcs_tdxio_fields_ptr->req_iommu_bm, sizeof(tdcs_tdxio_fields_ptr->req_iommu_bm)) &&
                                !tdr_ptr->management_fields.fatal)
                            {
                                emulate_wait_complete(tdr_ptr, tdcs_ptr, tdcs_tdxio_fields_ptr);
                                tdcs_tdxio_fields_ptr->req_active = false;
                            }
                        }
                    }
                }

                // End of critical section, release the lock
                release_sharex_lock_hp_ex(&tdcs_tdxio_fields_ptr->tdinv_lock);
                if (op_state_locked_flag)
                {
                    release_sharex_lock_hp_sh(&(tdcs_ptr->management_fields.op_state_lock));
                    op_state_locked_flag = false;
                }
                free_la(tdcs_ptr);
                pamt_unwalk(&tdr_pamt_walk_result);

                // Note, tdr_ptr gets unmapped at the end of the while loop
                object_ptr = tdr_ptr;

                break;
            default:
                TDX_ERROR("Invalid invalidation request type (%u)\n", iq_ctx_ptr->inv_req_type);
                fatal_error(FATAL_ERROR_ID_120, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
            }

            if (iq_ctx_ptr->inv_req_type != INV_REQ_IOTLB &&
                iq_ctx_ptr->inv_req_type != INV_REQ_TD)
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
