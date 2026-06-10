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
 * @file tdh_iommu_getreg.c
 * @brief TDHIOMMUGETREG API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/iommu.h"

api_error_type tdh_iommu_getreg(
    uint64_t param,
    iommu_register_id_e reg_id)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    uint64_t return_reg_value = 0;

    tdx_module_local_t *local_data_ptr = get_local_data();
    local_data_ptr->vmm_regs.r8 = 0;

    if (reg_id == IOMMU_ID)
    {
        // param is VTBAR_PA
        uint64_t vtbar_pa;
        vtbar_pa = param;

        iommu_id_reg_t iommu_id_reg = {.raw = 0};
        if (!get_vtbar_iommu(vtbar_pa, &iommu_id_reg))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
            goto EXIT;
        }
        return_reg_value = iommu_id_reg.raw;
    }
    else
    {
        // param is IOMMU_ID
        iommu_id_reg_t iommu_id_reg = {.raw = param};

        // Verify iommu_id operand
        if (iommu_id_reg.raw >= TOT_NUM_IOMMUS)
        {
            TDX_ERROR("Invalid IOMMU index (=%u)\n", iommu_id_reg.raw)
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
            goto EXIT;
        }

        // Prevent invalid access to iommu_configs arr
        lfence();

        tdx_module_global_t *tdx_global_data_ptr = get_global_data();
        hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, NULL);

        // Ensure MCHECK verified the HIOP associated with this IOMMU
        if (hiop_info_ptr->hiop_rp_bit_vector == 0)
        {
            TDX_ERROR("HIOP RP bitmap is zero\n");
            return_val = TDX_IOMMU_INVALID_STATE;
            goto EXIT;
        }

        iommu_config_t *iommu_config = &tdx_global_data_ptr->iommu_configs[iommu_id_reg.iommu_id.raw];

        if (reg_id == IOMMU_STATE)
        {
            return_reg_value = (uint64_t)iommu_config->state;
        }
        else if (reg_id == T_IQPAGE)
        {
            return_reg_value = iommu_config->t_iqaddr.raw;
        }
        else if (reg_id == IQCTXPAGE)
        {
            return_reg_value = iommu_config->iqctxaddr.raw;
        }
        else if (reg_id == T_RTPAGE)
        {
            return_reg_value = iommu_config->t_rtaddr.raw;
        }
        else if (reg_id == STINFOPA_0)
        {
            return_reg_value = iommu_config->stinfopa_0.raw;
        }
        else if (reg_id == STINFOPA_1)
        {
            return_reg_value = iommu_config->stinfopa_1.raw;
        }
        else if (reg_id == SPDMDIRPA)
        {
            return_reg_value = iommu_config->spdmdirpa.raw;
        }
        else
        {
            TDX_ERROR("Invalid reg_id (=0x%llx)\n", (uint64_t)reg_id);
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            goto EXIT;
        }
    }

    // Set output
    local_data_ptr->vmm_regs.r8 = return_reg_value;
    if (reg_id == T_RTPAGE)
    {
        local_data_ptr->vmm_regs.r8 = remove_hkid_from_pa((pa_t)local_data_ptr->vmm_regs.r8).raw;
    }

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}
