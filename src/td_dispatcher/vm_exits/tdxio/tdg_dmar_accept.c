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
#include "tdxio/devif.h"
#include "tdxio/dmar.h"
#include "td_transitions/td_exit.h"
#include "tdxio/devifmt.h"

api_error_type tdg_dmar_accept(
    function_id_reg_t function_id_reg,
    dmar_target_t dmar_target,
    uint64_t param1,
    uint64_t param2,
    uint64_t param3,
    uint64_t param4,
    uint64_t param5,
    uint64_t param6,
    uint64_t param7,
    uint64_t param8)
{
    // DEVIFCS related variables
    devif_verify_param_t devif_verify_param = {0};

    // dmar_walk related variables
    dmar_idx_t dmar_idx = {.raw = 0};
    dmar_walk_res_t dmar_walk_res = {0};
    bool_t is_dmar_walked = false;
    api_error_code_e dmar_err_code = UNINITIALIZE_ERROR;
    dmar_pasidte_t local_pasidte;
    api_error_type return_val = UNINITIALIZE_ERROR;

    tdx_module_local_t *local_data_ptr = get_local_data();
    tdr_t *tdr_ptr = local_data_ptr->vp_ctx.tdr;    // Pointer to the TDR page (linear address)
    tdcs_t *tdcs_ptr = local_data_ptr->vp_ctx.tdcs; // Pointer to the TDCS structure (Multi-page)

    bool_t is_epoch_locked = false;

    // Verify target is valid (Should be 0-3) and that the reserved fields are zero
    if ((dmar_target.vm_idx > tdcs_ptr->management_fields.num_l2_vms) ||
        dmar_target.pasid ||
        dmar_target.rsrvd)
    {
        TDX_ERROR("Invalid dmar target value (0x%x)\n", dmar_target.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (param1)
    {
        TDX_ERROR("param1 (0x%llx) is not zero\n", param1);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }
    if (param2)
    {
        TDX_ERROR("param2 (0x%llx) is not zero\n", param2);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }
    if (param3)
    {
        TDX_ERROR("param3 (0x%llx) is not zero\n", param3);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }
    if (param4)
    {
        TDX_ERROR("param4 (0x%llx) is not zero\n", param4);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R11);
        goto EXIT;
    }
    if (param5)
    {
        TDX_ERROR("param5 (0x%llx) is not zero\n", param5);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R12);
        goto EXIT;
    }
    if (param6)
    {
        TDX_ERROR("param6 (0x%llx) is not zero\n", param6);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R13);
        goto EXIT;
    }
    if (param7)
    {
        TDX_ERROR("param7 (0x%llx) is not zero\n", param7);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R14);
        goto EXIT;
    }
    if (param8)
    {
        TDX_ERROR("param8 (0x%llx) is not zero\n", param8);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R15);
        goto EXIT;
    }

    return_val = tdg_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_RCX,
        true,
        &devif_verify_param,
        NULL);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    if (devif_verify_param.devifcs_ptr->tdisp_sts != TDISP_STATE_CONFIG_LOCKED &&
        devif_verify_param.devifcs_ptr->tdisp_sts != TDISP_STATE_RUN)
    {
        TDX_ERROR("TDISP is not in TDISP_STATE_CONFIG_LOCKED (tdisp_sts = %u)\n",
                  devif_verify_param.devifcs_ptr->tdisp_sts);
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    if (devif_verify_param.devifcs_ptr->tdr_pa.raw != local_data_ptr->vp_ctx.tdr_pa.raw)
    {
        TDX_ERROR("TD is not the page owner (page owner = 0x%llx, tdr_pa = 0x%llx)\n",
                  devif_verify_param.devifcs_ptr->tdr_pa.raw, local_data_ptr->vp_ctx.tdr_pa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Construct dmar_idx
    dmar_idx.level = DMAR_PASIDTE_LVL;
    dmar_idx.pasid = 0; // Note: Walk must use RID_PASID
    dmar_idx.rid = devif_verify_param.devifcs_ptr->devif_id.function_id.rid;
    dmar_idx.iommu_id = devif_verify_param.devifcs_ptr->devif_id.iommu_id;

    dmar_err_code = dmar_walk(
        dmar_idx,
        false,
        false,
        TDX_RANGE_RW,
        true,
        &is_dmar_walked,
        &dmar_walk_res);
    if (dmar_err_code != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(dmar_err_code, OPERAND_ID_DMAR);
        TDX_ERROR("DMAR walk failed - error = %llx\n", return_val);
        goto EXIT;
    }

    dmar_state_info_t dmar_state_info = dmar_get_state_info(&dmar_walk_res);
    // Check that the PASID table entry state is DMAR_PENDING or DMAR_PRESENT
    if ((dmar_state_info.map_sts != DMAR_PENDING) &&
        (dmar_state_info.map_sts != DMAR_PRESENT))
    {
        TDX_ERROR("DMAR mapping state (=%u) is not DMAR_PENDING or DMAR_PRESENT\n", dmar_state_info.map_sts);
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_DMAR);
        goto EXIT;
    }

    pa_t eptp_pa = {.raw = 0};
    eptp_pa.page_4k_num = tdcs_ptr->executions_ctl_fields.eptp.fields.base_pa;
    eptp_pa = set_hkid_to_pa(eptp_pa, tdr_ptr->key_management_fields.hkid);

    tdx_memcpy(
        &local_pasidte, sizeof(local_pasidte),
        dmar_walk_res.pasidte_ptr, sizeof(*dmar_walk_res.pasidte_ptr));

    // Determine SLPTR according to EPT level and GPAW
    if (dmar_target.vm_idx == L1_TD)
    {
        if (tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl == LVL_PML4 ||
            tdcs_ptr->executions_ctl_fields.gpaw)
        {
            local_pasidte.slptptr = eptp_pa.page_4k_num;
        }
        else
        { // 5-level EPTP enabled && GPAW 48
            ia32e_ept_t *eptp_page = (ia32e_ept_t *)map_pa(eptp_pa.raw_void, TDX_RANGE_RO);
            local_pasidte.slptptr = eptp_page[0].fields_4k.base;
            free_la(eptp_page);
        }
    }
    else // For VM_IDX 1..3 or VM_IDX == 0 && 5-level EPTP enabled && GPAW 48
    {
        // Set SLPTR to L2 SEPT of the VM_IDX
        local_pasidte.slptptr = get_l2_septp_with_hkid(tdr_ptr, tdcs_ptr, dmar_target.vm_idx).fields.base_pa;
    }

    // If DMAR_PENDING
    if (dmar_state_info.map_sts == DMAR_PENDING)
    {
        // PASIDTE Adress Width and Second Stage Access/Dirty bit Enable are set according the SEPT
        if (tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl == LVL_PML4)
        {
            local_pasidte.aw = AW_48_BIT;
        }
        else // tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl == LVL_PML5
        {
            local_pasidte.aw = AW_57_BIT;
        }
        local_pasidte.slade = tdcs_ptr->executions_ctl_fields.eptp.fields.enable_ad_bits;

        local_pasidte.did |= tdr_ptr->key_management_fields.hkid;

        // Acquire TDCS epoch lock or fail with TDX_OPERAND_BUSY
        if (acquire_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock) != LOCK_RET_SUCCESS)
        {
            TDX_ERROR("Failed to acquire epoch lock on TDCS\n");
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);
            goto EXIT;
        }
        is_epoch_locked = true;

        // Update IOTLB tracking
        if (increment_iotlb_tracker_pasidte_ref_cnt(&tdcs_ptr->tdxio_fields.iotlb_track_array[dmar_idx.iommu_id.raw], 1) == 0)
        {
            _lock_xadd_64b(&tdcs_ptr->tdxio_fields.curr_iotlb_cnt, 1);
            tdcs_ptr->tdxio_fields.iotlb_track_array[dmar_idx.iommu_id.raw].inv_epoch = (tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch & BIT(0));
        }
    }

    // Update PASIDT entry state to present
    dmar_set_pasidte_state(&local_pasidte, DMAR_PASIDTE_PRESENT);
    dmar_set_pasidte_inv_state(&local_pasidte, DMAR_INV_PENDING);

    tdx_memcpy(
        dmar_walk_res.pasidte_ptr, sizeof(*dmar_walk_res.pasidte_ptr),
        &local_pasidte, sizeof(local_pasidte));

    // Set DMAR mapping state in DEVIFCS to TRUE
    devif_verify_param.devifcs_ptr->dmar_mapped_flag = true;
    return_val = TDX_SUCCESS;

EXIT:
    if (is_epoch_locked)
    {
        release_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock);
    }

    if (is_dmar_walked)
    {
        dmar_unwalk(&dmar_walk_res);
    }

    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
