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
    uint64_t guest_pasid,
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
    api_error_type return_val = UNINITIALIZE_ERROR;

    // Verify reserved GPRs (for TDX-IO Gen 2) are 0
    if (guest_pasid)
    {
        TDX_ERROR("guest_pasid (0x%llx) is not zero\n", guest_pasid);
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

    if (devif_verify_param.devifcs_ptr->tdisp_sts != TDISP_STATE_CONFIG_LOCKED)
    {
        TDX_ERROR("TDISP is not in TDISP_STATE_CONFIG_LOCKED (tdisp_sts = %u)\n",
                    devif_verify_param.devifcs_ptr->tdisp_sts);
        return_val = api_error_with_operand_id(TDX_DEVIF_TDISP_INVALID_STATE, OPERAND_ID_RCX);
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
    if (dmar_state_info.map_sts != DMAR_PENDING)
    {
        TDX_ERROR("DMAR mapping state (=%u) is not DMAR_PENDING\n", dmar_state_info.map_sts);
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_DMAR);
        goto EXIT;
    }

    // Update PASIDT entry state to present
    dmar_set_pasidte_state(dmar_walk_res.pasidte_ptr, DMAR_PASIDTE_PRESENT);
    dmar_set_pasidte_inv_state(dmar_walk_res.pasidte_ptr, DMAR_INV_PENDING);

    // Set DMAR mapping state in DEVIFCS to TRUE
    devif_verify_param.devifcs_ptr->dmar_mapped_flag = true;
    return_val = TDX_SUCCESS;
EXIT:

    if (is_dmar_walked)
    {
        dmar_unwalk(&dmar_walk_res);
    }

    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
