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
 * @file tdh_iommu_setreg.c
 * @brief TDHIOMMUSETREG API handler
 */
#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"

#include "tdxio/iommu.h"
#include "tdxio/seam_sai.h"

api_error_type tdh_iommu_setreg(
    iommu_id_reg_t iommu_id_reg,
    iommu_register_id_e reg_id,
    uint64_t reg_value)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    pamt_entry_t *pamt_entry_ptr = NULL;
    pamt_block_t pamt_block;
    bool_t pamt_entry_is_locked = false;

    void *reg_value_ptr = NULL;
    vtbar_t *vtbar_ptr = NULL;

    bool_t iommu_config_lock_taken = false;
    bool_t seam_sai_is_enabled = false;

    // Verify iommu_id operand is within bounds
    if (iommu_id_reg.raw >= TOT_NUM_IOMMUS)
    {
        TDX_ERROR("Invalid IOMMU index (=%u)\n", iommu_id_reg.iommu_id.raw)
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Prevent invalid access to iommu_configs arr
    lfence();

    // Check for REG_ID will be done later in the flow
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();

    tdx_debug_assert(iommu_id_reg.iommu_id.socket_id < NUM_OF_SOCKETS);
    tdx_debug_assert(iommu_id_reg.iommu_id.hiop_id < NUM_OF_HIOPS);

    socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
    hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

    // Ensure MCHECK verified this IOMMU
    if (hiop_info_ptr->hiop_rp_bit_vector == 0)
    {
        TDX_ERROR("HIOP RP bitmap is zero\n");
        return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    iommu_config_t *iommu_config_ptr = &tdx_global_data_ptr->iommu_configs[iommu_id_reg.iommu_id.raw];

    // Acquire IOMMU config entry lock
    if (acquire_sharex_lock_hp_ex(&iommu_config_ptr->lock, false) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to acquire IOMMU config entry lock\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }
    iommu_config_lock_taken = true;

    if ((iommu_config_ptr->config_in_progress && reg_id != CONFIG_IOMMU) ||
        (iommu_config_ptr->clear_in_progress && reg_id != CLEAR_IOMMU))
    {
        TDX_ERROR("CLEAR/CONFIG IOMMU is still in progress\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    switch (reg_id)
    {
    case T_IQPAGE:
    case IQCTXPAGE:
    case T_RTPAGE:
    case STINFOPA_0:
    case STINFOPA_1:
    case SPDMDIRPA:
        // State check (VALID_IOMMU_STATE)
        if (iommu_config_ptr->state != IOMMU_STATE_INIT)
        {
            TDX_ERROR("Invalid IOMMU state %u\n", iommu_config_ptr->state);
            return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
            goto EXIT;
        };

        if (reg_value == 0)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }

        // Pamt walk to address, lock pamt entry
        if ((return_val = check_and_lock_explicit_4k_private_hpa(
                 (pa_t)reg_value,
                 OPERAND_ID_R8,
                 TDX_LOCK_EXCLUSIVE,
                 PT_NDA,
                 &pamt_block,
                 &pamt_entry_ptr,
                 &pamt_entry_is_locked)) != TDX_SUCCESS)
        {
            goto EXIT;
        }

        // Check relevant register_id page and update IOMMU_CFG field
        if (reg_id == T_IQPAGE)
        {
            return_val = check_and_update_iq_buffer(
                &iommu_config_ptr->t_iqaddr,
                reg_value);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }
        }
        else if (reg_id == IQCTXPAGE)
        {
            return_val = check_and_update_iq_buffer(
                &iommu_config_ptr->iqctxaddr,
                reg_value);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }
        }
        else
        {
            // T_RTPAGE, STINFOPA_0, STINFOPA_1, SPDMDIRPA
            pa_t *dest_page = NULL;
            if (reg_id == T_RTPAGE)
            {
                dest_page = &iommu_config_ptr->t_rtaddr;
            }
            else if (reg_id == STINFOPA_0)
            {
                dest_page = &iommu_config_ptr->stinfopa_0;
            }
            else if (reg_id == STINFOPA_1)
            {
                dest_page = &iommu_config_ptr->stinfopa_1;
            }
            else
            {
                dest_page = &iommu_config_ptr->spdmdirpa;
            }

            tdx_debug_assert(dest_page != NULL);

            if (dest_page->raw != 0)
            {
                TDX_ERROR("Page already configure to IOMMU\n")
                return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_R8);
                goto EXIT;
            }
            dest_page->raw = reg_value;

            if (reg_id == T_RTPAGE)
            {
                *dest_page = set_hkid_to_pa(*dest_page, get_global_data()->hkid);
            }
        }

        // Update PAMT entry
        pamt_entry_ptr->owner = iommu_id_reg.iommu_id.raw;
        pamt_entry_ptr->pt = PT_IOMMU_MT;
        pamt_entry_ptr->bepoch.raw = iommu_config_ptr->iommu_generation;

        // Map page and initialize using MOVDIR64
        reg_value_ptr = map_pa_with_global_hkid((void *)reg_value, TDX_RANGE_RW);
        zero_area_cacheline(reg_value_ptr, TDX_PAGE_SIZE_IN_BYTES);
        free_la(reg_value_ptr);
        break;
    case CONFIG_IOMMU:
    case CONFIG_RP:
    case GCMD_REG:
    case CLEAR_IOMMU:
    case CLEAR_RP:
        // State check (VALID_IOMMU_STATE)
        if ((reg_id == CONFIG_IOMMU && iommu_config_ptr->state != IOMMU_STATE_INIT) ||
            (reg_id != CONFIG_IOMMU && reg_id != CLEAR_IOMMU && iommu_config_ptr->state != IOMMU_STATE_CONFIGURED))
        {
            TDX_ERROR("Invalid IOMMU state = 0x%u\n", iommu_config_ptr->state)
            return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RDX);
            goto EXIT;
        }

        // Enable SEAM SAI generation
        enable_seam_sai_generation();
        seam_sai_is_enabled = true;

        // Map VTBAR page
        vtbar_ptr = map_vtbar(
            socket_io_info_ptr,
            hiop_info_ptr);

        if (reg_id == CONFIG_IOMMU)
        {
            return_val = configure_iommu(
                socket_io_info_ptr,
                hiop_info_ptr,
                vtbar_ptr,
                iommu_config_ptr,
                reg_value);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }
        }
        else if (reg_id == CONFIG_RP)
        {
            return_val = configure_rp(
                socket_io_info_ptr,
                hiop_info_ptr,
                vtbar_ptr,
                iommu_config_ptr,
                reg_value);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }
        }
        else if (reg_id == GCMD_REG)
        {
            return_val = iommu_setreg_gcmd(
                vtbar_ptr,
                reg_value);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }
        }
        else if (reg_id == CLEAR_IOMMU)
        {
            return_val = clear_iommu(
                socket_io_info_ptr,
                hiop_info_ptr,
                vtbar_ptr,
                iommu_config_ptr,
                reg_value);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }
        }
        else // reg_id == CLEAR_RP
        {
            return_val = clear_rp(
                socket_io_info_ptr,
                hiop_info_ptr,
                iommu_config_ptr,
                reg_value);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }
        }
        break;
    default:
        // Invalid register ID
        TDX_ERROR("Invalid register ID (=0x%llx)\n", reg_id);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    };

    return_val = TDX_SUCCESS;

EXIT:
    if (vtbar_ptr != NULL)
    {
        free_la(vtbar_ptr);
    }

    if (seam_sai_is_enabled)
    {
        disable_seam_sai_generation();
    }

    if (pamt_entry_is_locked)
    {
        pamt_unwalk((pa_t)reg_value, pamt_block, pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }

    if (iommu_config_lock_taken)
    {
        release_sharex_lock_hp_ex(&iommu_config_ptr->lock);
    }
    return return_val;
}
