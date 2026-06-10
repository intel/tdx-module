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
 * @file tdg_dmar_accept.c
 * @brief TDGDMARACCEPT API handler
 */

#include "tdxio/tdxio_td_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/inv_queue.h"
#include "td_transitions/td_exit.h"

api_error_type tdg_iq_inv_request(
    uint64_t num_inv_desc,
    pa_t req_gpa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    tdx_module_local_t *local_data = get_local_data();

    void *vmm_inv_desc_buff = NULL;
    bool_t is_tdinv_locked = false;

    tdcs_tdxio_fields_t *tdcs_tdxio_fields_ptr = &local_data->vp_ctx.tdcs->tdxio_fields;

    // NUM_INV_DESCS >= 1 and NUM_INV_DESCS < 128 (127+1 wait descriptor at max)
    if (num_inv_desc == 0 ||
        num_inv_desc > MAX_TD_INV_DES_COUNT)
    {
        TDX_ERROR("num_inv_desc (=%llu) is zero or exceeds the max allowed size (=%u\n", num_inv_desc, MAX_TD_INV_DES_COUNT);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // REQ_PA is a valid TD's GPA.
    if (!is_addr_aligned_any(req_gpa.raw, TDX_PAGE_SIZE_IN_BYTES))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    return_val = check_walk_and_map_guest_side_gpa(
        local_data->vp_ctx.tdcs,
        local_data->vp_ctx.tdvps,
        req_gpa,
        local_data->vp_ctx.tdr->key_management_fields.hkid,
        TDX_RANGE_RO,
        true,
        (void **)&vmm_inv_desc_buff);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to walk and map destination page (destination pa = 0x%llx)\n", req_gpa.raw);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }

    return_val = acquire_sharex_lock_hp_ex(&tdcs_tdxio_fields_ptr->tdinv_lock, true);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on tdinv_lock\n")
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }
    is_tdinv_locked = true;

    // TDCS.REQ_ACTIVE must be 0. There is no outstanding TDG invalidation request. Only 1 at time is allowed, or TDX_GUEST_INV_IN_PROGRESS returned
    if (tdcs_tdxio_fields_ptr->req_active)
    {
        TDX_ERROR("TD invalidation already requested\n")
        return_val = api_error_with_operand_id(TDX_GUEST_INV_IN_PROGRESS, 0);
        goto EXIT;
    }

    tdcs_tdxio_fields_ptr->status_complete_wr = false;

    // Copy the VMM's input to a trusted buffer
    inv_desc_t *local_inv_buff = (inv_desc_t *)local_data->vp_ctx.tdcs->td_inv_req_buff;
    basic_memset_to_zero(local_data->vp_ctx.tdcs->td_inv_req_buff, TDX_PAGE_SIZE_IN_BYTES);
    tdx_memcpy(local_data->vp_ctx.tdcs->td_inv_req_buff, TDX_PAGE_SIZE_IN_BYTES, vmm_inv_desc_buff, num_inv_desc * sizeof(*local_inv_buff));

    for (uint16_t i = 0; i < num_inv_desc; i++)
    {
        if (local_inv_buff[i].type == INV_DESC_IOTLB)
        {
            if (local_inv_buff[i].iotlb.granularity != IOTLB_G_DOMAIN_SELECTIVE &&
                local_inv_buff[i].iotlb.granularity != IOTLB_G_PAGE_SELECTIVE_WITHIN_DOMAIN)
            {
                TDX_ERROR("Invalid IOTLB granularity, at idx = %u\n", i);
                return_val = api_error_with_operand_id(TDX_GUEST_INV_INVALID_DESC, i);
                goto EXIT;
            }

            uint8_t dynamic_val = local_inv_buff[i].iotlb.granularity == IOTLB_G_DOMAIN_SELECTIVE ? 0 : 1;

            if (local_inv_buff[i].iotlb.drain_writes != 1 ||
                local_inv_buff[i].iotlb.drain_reads != 1 ||
                local_inv_buff[i].iotlb.rsvd0 != 0 ||
                local_inv_buff[i].iotlb.did != 0 ||
                local_inv_buff[i].iotlb.rsvd1 != 0 ||
                local_inv_buff[i].iotlb.ih != dynamic_val ||
                local_inv_buff[i].iotlb.rsvd2 != 0 ||
                local_inv_buff[i].iotlb.rsvd3 != 0 ||
                local_inv_buff[i].iotlb.rsvd4 != 0)
            {
                TDX_ERROR("Invalid IOTLB descriptor fields, at idx = %u\n", i);
                return_val = api_error_with_operand_id(TDX_GUEST_INV_INVALID_DESC, i);
                goto EXIT;
            }

            // The address mask and the address are only relevant for PAGE-SELECTIVE-WITHIN-DOMAIN descriptor
            if (local_inv_buff[i].iotlb.granularity == IOTLB_G_DOMAIN_SELECTIVE &&
                (local_inv_buff[i].iotlb.am != 0 || local_inv_buff[i].iotlb.addr != 0))
            {
                TDX_ERROR("Invalid IOTLB descriptor fields, at idx = %u\n", i)
                return_val = api_error_with_operand_id(TDX_GUEST_INV_INVALID_DESC, i);
                goto EXIT;
            }
        }
        else if (local_inv_buff[i].type == INV_DESC_WAIT)
        {
            // The WAIT descriptor has to be the last one
            if (i != num_inv_desc - 1)
            {
                TDX_ERROR("Wait descriptor is not last, at idx = %u\n", i)
                return_val = api_error_with_operand_id(TDX_GUEST_INV_INVALID_DESC, i);
                goto EXIT;
            }

            if (local_inv_buff[i].wait.interrupt_flag != 0 ||
                local_inv_buff[i].wait.pg_request_drain != 0 ||
                local_inv_buff[i].wait.rsvd0 != 0 ||
                local_inv_buff[i].wait.type_2 != 0 ||
                local_inv_buff[i].wait.rsvd1 != 0 ||
                local_inv_buff[i].wait.status_write != 1 ||
                local_inv_buff[i].wait.rsvd2 != 0 ||
                local_inv_buff[i].wait.rsvd3 != 0)
            {
                TDX_ERROR("Invalid WAIT descriptor fields\n");
                return_val = api_error_with_operand_id(TDX_GUEST_INV_INVALID_DESC, i);
                goto EXIT;
            }

            // Verify the descriptor's GPA is aligned
            if (!is_addr_aligned_pwr_of_2(local_inv_buff[i].wait.status_address, 4) ||
                !check_gpa_validity((pa_t)local_inv_buff[i].wait.status_address,
                                    local_data->vp_ctx.tdcs->executions_ctl_fields.gpaw,
                                    PRIVATE_ONLY,
                                    local_data->vp_ctx.tdcs->executions_ctl_fields.virt_maxpa))
            {
                TDX_ERROR("Invalid WAIT descriptor GPA\n");
                return_val = api_error_with_operand_id(TDX_GUEST_INV_INVALID_DESC, i);
                goto EXIT;
            }

            tdcs_tdxio_fields_ptr->status_complete_wr = true;
            tdcs_tdxio_fields_ptr->status_complete_gpa.raw = local_inv_buff[i].wait.status_address;
            tdcs_tdxio_fields_ptr->status_complete_data = local_inv_buff[i].wait.status_data;
        }
        else
        {
            TDX_ERROR("Invalid descriptor type at index= %u\n", i);
            return_val = api_error_with_operand_id(TDX_GUEST_INV_INVALID_DESC, i);
            goto EXIT;
        }
    }

    // Descriptors are verified. Initialize the invalidation tracker
    basic_memset_to_zero((void *)&tdcs_tdxio_fields_ptr->req_iommu_bm, sizeof(tdcs_tdxio_fields_ptr->req_iommu_bm));
    bool_t is_inv_required = false;

    // Verify and set the iommu bitmap in case TDI invalidation is requried
    for (uint8_t i = 0; i < TOT_NUM_IOMMUS; i++)
    {
        if (local_data->vp_ctx.tdcs->tdxio_fields.iotlb_track_array[i].pasidte_ref_cnt != 0)
        {
            is_inv_required = true;
            set_qword_bm(tdcs_tdxio_fields_ptr->req_iommu_bm.qwords, i, true);
        }
    }

    if (!is_inv_required)
    {
        tdcs_tdxio_fields_ptr->status_complete_wr = false;

        TDX_ERROR("No guest invalidation is required\n");
        return_val = api_error_with_operand_id(TDX_GUEST_INV_NOT_REQUIRED, OPERAND_ID_RDX);
        goto EXIT;
    }

    basic_memset_to_zero(tdcs_tdxio_fields_ptr->iotlb_committed, TOT_NUM_IOMMUS);
    basic_memset_to_zero(tdcs_tdxio_fields_ptr->iotlb_complete, TOT_NUM_IOMMUS);
    // decrement the required invalidations, if the last entry is a wait descriptor
    tdcs_tdxio_fields_ptr->req_num = tdcs_tdxio_fields_ptr->status_complete_wr ? (uint8_t)num_inv_desc - 1 : (uint8_t)num_inv_desc;

    tdcs_tdxio_fields_ptr->req_active = true;

    return_val = TDX_SUCCESS;

EXIT:

    if (is_tdinv_locked)
    {
        release_sharex_lock_hp_ex(&tdcs_tdxio_fields_ptr->tdinv_lock);
    }

    if (vmm_inv_desc_buff != NULL)
    {
        free_la(vmm_inv_desc_buff);
    }

    if (return_val == TDX_SUCCESS)
    {
        // l2_details should hold the number of requests
        // Note req_num is uint8_t so only need to add low bits
        local_data->vp_ctx.tdvps->guest_state.gpr_state.rax = TDX_SUCCESS;
        api_error_code_e tdexit_case = TDX_IOTLB_INV_REQUEST;
        vm_vmexit_exit_reason_t vm_vmexit_exit_reason = {.raw = tdcs_tdxio_fields_ptr->req_num};
        async_tdexit_to_vmm(tdexit_case, vm_vmexit_exit_reason, 0, 0, 0, 0);
    }

    return return_val;
}
