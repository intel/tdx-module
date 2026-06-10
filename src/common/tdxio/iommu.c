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
 * @file iommu.c
 * @brief
 */

#include "tdxio/iommu.h"
#include "tdxio/rp_cfg_page.h"
#include "tdxio/seam_sai.h"
#include "tdxio/kcbar.h"
#include "tdxio/ide_stream.h"

bool_t is_valid_initial_iommu_state(void)
{
    vtbar_t *vtbar_ptr = NULL;
    hiop_info_t *hiop_info_ptr = NULL;
    socket_io_info_t *socket_io_info_ptr = NULL;
    iommu_config_t *iommu_config_ptr = NULL;

    ests0_reg_t ests0_reg = {.raw = 0};
    iommu_id_t iommu_id = {.raw = 0};

    tdx_module_global_t *tdx_global_data_ptr = get_global_data();

    if (!tdx_global_data_ptr->tdx_io_supported)
    {
        return true;
    }

    for (uint8_t socket_id = 0; socket_id < NUM_OF_SOCKETS; socket_id++)
    {
        iommu_id.socket_id = socket_id;
        socket_io_info_ptr = get_socket_io_info(iommu_id);

        for (uint8_t hiop_id = 0; hiop_id < NUM_OF_HIOPS; hiop_id++)
        {
            iommu_id.hiop_id = hiop_id;
            hiop_info_ptr = get_hiop_info(iommu_id, socket_io_info_ptr);

            if (hiop_info_ptr->hiop_rp_bit_vector == 0)
            {
                continue;
            }

            vtbar_ptr = map_vtbar(
                socket_io_info_ptr,
                hiop_info_ptr);

            ests0_reg.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ESTS0_REG_OFFSET);

            free_la(vtbar_ptr);

            if (ests0_reg.tms != 0) // IOMMU is in TDX mode
            {
                // When in TDX mode, check that IOMMU state is configured
                iommu_id.hiop_id = hiop_id;
                iommu_config_ptr = &tdx_global_data_ptr->iommu_configs[iommu_id.raw];

                if (iommu_config_ptr->state != IOMMU_STATE_CONFIGURED)
                {
                    return false;
                }
            }
        };
    };

    return true;
}

api_error_type check_and_update_iq_buffer(
    iq_buffer_t *const invq_page,
    const uint64_t page_pa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    if (invq_page->raw == 0)
    {
        // First page
        invq_page->raw = page_pa;
    }
    else
    {
        uint64_t target_base = ((iq_buffer_t)page_pa).base;
        if (invq_page->size >= MAX_NUM_IOMMU_IQ_PAGES ||
            (invq_page->base + invq_page->size) != target_base)
        {
            TDX_ERROR("Invalid invq_page = 0x%llx (target_base = 0x%llx)\n", invq_page->raw, target_base)
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }
    }
    invq_page->size++;
    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}

api_error_type configure_iommu(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    vtbar_t *const vtbar_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    kcbar_t *kcbar_ptr = NULL;

    gsts_reg_t gsts_reg = {.raw = 0};
    bool_t is_iommu_wac_set = false;
    bool_t is_hiop_wac_set = false;
    bool_t is_kcbar_wac_set = false;

    // Verify register value is zero
    if (reg_value != 0)
    {
        TDX_ERROR("reg_value (=0x%llx) should be zero\n", reg_value);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    if (!iommu_config_ptr->config_in_progress)
    {
        // Verify IOMMU configuration fields were initialized
        // Verify IQ and IQCTX buffer sizes are power of two and have equal values
        if (iommu_config_ptr->t_rtaddr.raw == 0 ||
            iommu_config_ptr->t_iqaddr.raw == 0 ||
            iommu_config_ptr->iqctxaddr.raw == 0 ||
            iommu_config_ptr->stinfopa_0.raw == 0 ||
            iommu_config_ptr->stinfopa_1.raw == 0 ||
            iommu_config_ptr->spdmdirpa.raw == 0 ||
            !is_pwr_of_2(iommu_config_ptr->t_iqaddr.size) ||
            iommu_config_ptr->t_iqaddr.size != iommu_config_ptr->iqctxaddr.size)
        {
            TDX_ERROR("Invalid IOMMU configuration\n");
            return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
            goto EXIT;
        }

        // Set SEAM only write access SAI policy for VTBAR (ECMD and GCMD are now write protected)
        iommu_config_ptr->iommu_wac_value = set_seam_mode_wac(
            socket_io_info_ptr,
            vtbar_ptr,
            IOMMU_WAC);
        is_iommu_wac_set = true;

        // Set SEAM only write access SAI policy for HIOP
        iommu_config_ptr->hiop_wac_value = set_seam_mode_wac(
            socket_io_info_ptr,
            (void *)hiop_info_ptr,
            HIOP_WAC);
        is_hiop_wac_set = true;

        // Read and verify registers in VTBAR
        gsts_reg.raw = vtbar_read_reg32(vtbar_ptr, VTBAR_GSTS_REG_OFFSET);
        iqh_reg_t t_iqh_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_T_IQH_REG_OFFSET)};
        pmen_reg_t pmen_reg = {.raw = vtbar_read_reg32(vtbar_ptr, VTBAR_PMEN_REG_OFFSET)};
        ests0_reg_t ests0_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ESTS0_REG_OFFSET)};
        rta_addr_reg_t rta_addr_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_RTADDR_REG_OFFSET)};
        ecrsp_reg_t ecrsp_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ECRSP_REG_OFFSET)};

        if (ecrsp_reg.ip != 0 ||   // Enhanced command must not be in progress
            ests0_reg.tms != 0 ||  // IOMMU must not be in TDX mode
            gsts_reg.rtps == 0 ||  // VMM root table pointer must be set
            gsts_reg.qies == 0 ||  // VMM queue invalidations must be enabled
            gsts_reg.tes == 0 ||   // Translation must be enabled
            pmen_reg.raw != 0 ||   // PRM and DMA access to it must both be disabled
            rta_addr_reg.ttm != 1) // RTADDR must be in scalable mode
        {
            TDX_ERROR("Invalid VTBAR registers\n");
            return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
            goto EXIT;
        }

        // The T_IQH offset (256-bit aligned) must be within the queue allocated pages
        if (t_iqh_reg.raw >= (iommu_config_ptr->t_iqaddr.size * TDX_PAGE_SIZE_IN_BYTES))
        {
            TDX_ERROR("T_IQH is not within the queue allocated pages\n");
            return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
            goto EXIT;
        }

        kcbar_ptr = map_kcbar(
            socket_io_info_ptr,
            hiop_info_ptr);

        // Set SEAM only write access SAI policy for kcbar
        iommu_config_ptr->kcb_wac_value = set_seam_mode_wac(
            socket_io_info_ptr,
            kcbar_ptr,
            KCB_WAC);
        is_kcbar_wac_set = true;

        if (!is_kcbar_disabled(kcbar_ptr))
        {
            return_val = api_error_with_operand_id(TDX_IOMMU_KCB_MUST_BE_DISABLED, OPERAND_ID_RCX);
            goto EXIT;
        }

        // Program T_RTADDR_REG adding TDX global HKID to its HPA
        rta_addr_reg_t trusted_rta_addr_reg = {.raw = (set_hkid_to_pa(iommu_config_ptr->t_rtaddr, get_global_data()->hkid)).raw};
        trusted_rta_addr_reg.ttm = 1; // Scalable mode
        vtbar_write_reg64(vtbar_ptr, VTBAR_T_RTADDR_REG_OFFSET, trusted_rta_addr_reg.raw);

        // Program T_IQA_REG adding TDX global HKID to its HPA
        pa_t iqa_pa = {.raw = iommu_config_ptr->t_iqaddr.raw};
        iqa_reg_t iqa_reg = {.raw = 0};
        iqa_reg.raw = (set_hkid_to_pa(iqa_pa, get_global_data()->hkid)).raw;
        iqa_reg.dw = 1; // 256-bit descriptors
        iqa_reg.qs = get_ln2_value(iommu_config_ptr->t_iqaddr.size);
        vtbar_write_reg64(vtbar_ptr, VTBAR_T_IQA_REG_OFFSET, iqa_reg.raw);

        // IOMMU_CFG.IQ_FREE_CNT = (IOMMU_CFG.T_IQADDR[7:0] * 128) – 1
        iommu_config_ptr->iq_free_cnt = (uint16_t)((iommu_config_ptr->t_iqaddr.size * NUM_IQ_ENTRIES_IN_PAGE) - 1);
        // IOMMU_CFG.IQ_SW_HEAD_IDX = VTBAR[T_IQH_REG] / 32
        iommu_config_ptr->iq_sw_head_idx = (uint32_t)(t_iqh_reg.raw / IQ_ENTRY_SIZE_IN_BYTES);
        // VTBAR[T_IQT_REG] = VTBAR[T_IQH_REG]
        // Make the queue empty (head and tail are equal)
        vtbar_write_reg64(vtbar_ptr, VTBAR_T_IQT_REG_OFFSET, t_iqh_reg.raw);

        // Cache required IOMMU configurations
        vtbar_cap_reg_t vtbar_cap_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_CAP_REG_OFFSET)};
        iommu_config_ptr->iommu_cap.did_msb = (uint8_t)(vtbar_cap_reg.nd * 2 + 4 - 1);

        vtbar_ecap_reg_t vtbar_ecap_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ECAP_REG_OFFSET)};
        iommu_config_ptr->iommu_cap.pds = (uint16_t)vtbar_ecap_reg.pds;

        // Set TDX mode register in VTBAR
        return_val = set_tdx_mode(vtbar_ptr);
        if (return_val != TDX_SUCCESS)
        {
            if (return_val == TDX_IOMMU_ECMD_TIMEOUT)
            {
                // Timeout happened but IOMMU can still theoretically complete ECMD(TDX_MODE) after
                // return so TDX Module shall not release WACs, leave IOMMU in the INIT state and
                // set config_in_progress flag. VMM must invoke the call again to complete the IOMMU
                // configuration.
                iommu_config_ptr->config_in_progress = true;
            }

            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }
    }
    else // config_in_progress
    {
        // In the ECMD-in-progress state. The WAC's are taken.
        // In this state only check the In-Progress flag became zero
        return_val = is_valid_ecrsp_reg(vtbar_ptr);
        if (return_val == TDX_IOMMU_ECMD_TIMEOUT)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }

        // The command has completed with or without errors. We're no longer in-progress
        iommu_config_ptr->config_in_progress = false;

        kcbar_ptr = map_kcbar(socket_io_info_ptr, hiop_info_ptr);
        is_kcbar_wac_set = true;
        is_hiop_wac_set = true;
        is_iommu_wac_set = true;

        if (return_val != TDX_SUCCESS)
        {
            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Invoke the 2nd GSTS check, avoiding an attack with malicious VMM issuing GCMD right before CONFIGURE_IOMMU and
    // GCMD is finished after the initial GSTS checks. Root table pointer must be set and queue invalidation
    // and translation must stay enabled.
    gsts_reg.raw = vtbar_read_reg32(vtbar_ptr, VTBAR_GSTS_REG_OFFSET);
    if (gsts_reg.rtps == 0 || // VMM root table pointer must be set
        gsts_reg.qies == 0 || // VMM queue invalidations must be enabled
        gsts_reg.tes == 0)    // Translation must be enabled
    {
        return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Set IOMMU config state
    iommu_config_ptr->state = IOMMU_STATE_CONFIGURED;

    return_val = TDX_SUCCESS;

EXIT:
    // Remove SAI policy from VRBAR & KCBAR in case of failure
    if (return_val != TDX_SUCCESS &&
        (!iommu_config_ptr->config_in_progress))
    {
        if (is_kcbar_wac_set)
        {
            remove_seam_mode_wac(
                socket_io_info_ptr,
                kcbar_ptr,
                KCB_WAC,
                iommu_config_ptr->kcb_wac_value);
        }

        if (is_hiop_wac_set)
        {
            remove_seam_mode_wac(
                socket_io_info_ptr,
                (void *)hiop_info_ptr,
                HIOP_WAC,
                iommu_config_ptr->hiop_wac_value);
        }

        if (is_iommu_wac_set)
        {
            remove_seam_mode_wac(
                socket_io_info_ptr,
                vtbar_ptr,
                IOMMU_WAC,
                iommu_config_ptr->iommu_wac_value);
        }
    }

    if (kcbar_ptr != NULL)
    {
        free_la(kcbar_ptr);
    }

    return return_val;
}

api_error_type clear_iommu(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    vtbar_t *const vtbar_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    kcbar_t *kcbar_ptr = NULL;
    bool_t clear_wac_flag = false;

    if (reg_value != 0)
    {
        TDX_ERROR("reg_value (=0x%llx) is not zero\n", reg_value);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // We are here with the following states:
    // Case 1. state != INIT && clear_in_progress == false. Clear configured IOMMU: tdx_clear, check, restore wacs, advance generation
    // Case 2. state == INIT && clear_in_progress == false. Cleanup unconfigured IOMMU: advance the generation
    // Case 3. state != INIT && clear_in_progress == true.  Invalid  state
    // Case 4. state == INIT && clear_in_progress == true.  Complete clearing IOMMU: check, restore wacs, advance generation

    // Can be called in INIT state for cleanup and generation increase
    if (iommu_config_ptr->state != IOMMU_STATE_INIT)
    { // Cases 1, 3

        if (iommu_config_ptr->clear_in_progress) // Case 3 is an invalid state
        {
            TDX_ERROR("IOMMU can't be in an INIT and clear_in_progress state\n");
            fatal_error(FATAL_ERROR_ID_85, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        }

        // Verify IOMMU state or fail with TDX_IOMMU_INVALID_STATE
        // Root port must be cleared
        // SPDM sessions must be removed
        if (iommu_config_ptr->rp_reg_sts != 0 ||              // Root port must be cleared
            iommu_config_ptr->active_spdm_session_count != 0) // SPDM sessions must be removed
        {
            TDX_ERROR("RP not cleared, or there are active SPDM sessions (RP = 0x%x, active_spdm_session_count = %lu)\n",
                      iommu_config_ptr->rp_reg_sts, iommu_config_ptr->active_spdm_session_count);
            return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
            goto EXIT;
        }

        // Clear TDX-IO configured VTBAR registers
        return_val = clear_tdx_mode(vtbar_ptr);
        if (return_val != TDX_SUCCESS)
        {
            if (return_val == TDX_IOMMU_ECMD_TIMEOUT)
            {
                // In an unlikely situation of the timeout TDX Module doesn't
                // have a confirmation of the IOMMU completion of Clear TDX Mode.
                // 1. We must mark the IOMMU state as INIT (the real IOMMU state is unclear, it can't be marked CONFIGURED anymore)
                // 2. We set the clear_in_progress state, it'll prevent re-configuring IOMMU while it's not completely INIT.
                // 3. We don't release the IOMMU to VMM (pages/generation, WACs, etc.).
                // Thus on TDX_IOMMU_ECMD_TIMEOUT the VMM must repeat the request again, in order to resolve the IOMMU state.
                iommu_config_ptr->clear_in_progress = true;
                iommu_config_ptr->state = IOMMU_STATE_INIT;
            }

            return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
            goto EXIT;
        }

        // Set UOMMU state back to INIT
        iommu_config_ptr->state = IOMMU_STATE_INIT;
        clear_wac_flag = true;
    }
    else // state == IOMMU_STATE_INIT
    {
        // Cases 2, 4
        if (iommu_config_ptr->clear_in_progress) // Case 4
        {
            // In the ECMD-in-progress state. Keep checking when In-Progress flag becomes zero
            return_val = is_valid_ecrsp_reg(vtbar_ptr);
            if (return_val != TDX_SUCCESS)
            {
                if (return_val != TDX_IOMMU_ECMD_TIMEOUT)
                {
                    // ECMD completed with error. We can't release the IOMMU, Only can repeat&loop ECMD,
                    // staying in clear_in_progress == true. ECRSP will be checked on  next call.
                    execute_ecmd(vtbar_ptr);
                }

                return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
                goto EXIT;
            }

            // ECMD completed with success. We're eventually out of the TDX Mode
            iommu_config_ptr->clear_in_progress = false;
            clear_wac_flag = true;
        }
    }

    if (clear_wac_flag)
    {
        // Clear SEAM only write access policy for KCBAR
        kcbar_ptr = map_kcbar(
            socket_io_info_ptr,
            hiop_info_ptr);

        remove_seam_mode_wac(
            socket_io_info_ptr,
            kcbar_ptr,
            KCB_WAC,
            iommu_config_ptr->kcb_wac_value);

        remove_seam_mode_wac(
            socket_io_info_ptr,
            (void *)hiop_info_ptr,
            HIOP_WAC,
            iommu_config_ptr->hiop_wac_value);

        // Clear SEAM only write access SAI policy for VTBAR
        remove_seam_mode_wac(
            socket_io_info_ptr,
            vtbar_ptr,
            IOMMU_WAC,
            iommu_config_ptr->iommu_wac_value);
    }

    // Initialize IOMMU structure
    iommu_config_ptr->t_rtaddr.raw = 0;
    iommu_config_ptr->t_iqaddr.raw = 0;
    iommu_config_ptr->iqctxaddr.raw = 0;
    iommu_config_ptr->stinfopa_0.raw = 0;
    iommu_config_ptr->stinfopa_1.raw = 0;
    iommu_config_ptr->spdmdirpa.raw = 0;

    // Increment IOMMU generation
    iommu_config_ptr->iommu_generation++;

    return_val = TDX_SUCCESS;
EXIT:
    if (kcbar_ptr != NULL)
    {
        free_la(kcbar_ptr);
    }

    return return_val;
}

api_error_type iommu_setreg_gcmd(
    vtbar_t *const vtbar_ptr,
    const uint64_t reg_value)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    // Verify register value
    gcmd_input_t gcmd_input = {.raw = (uint32_t)reg_value};
    if (gcmd_input.rsvd != 0 ||
        gcmd_input.bit_pos == GCMD_TE_BIT_POS || // VMM cannot disable IOMMU tranlation
        gcmd_input.bit_pos == GCMD_QIE_BIT_POS)  // VMM cannot disable invalidation queue
    {
        TDX_ERROR("Invalid gcmd = 0x%lx\n", gcmd_input.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Set GCMD_REG in VTBAR, no need to poll for GSTS
    set_gcmd(vtbar_ptr, gcmd_input.bit_pos, gcmd_input.bit_val);

    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}

api_error_type verify_rp_operand(
    const rp_bdf_reg_t rp_bdf_reg,
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    uint8_t *const rp_idx)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    // Verify reg_value reserved bits are zero
    if (rp_bdf_reg.reserved != 0)
    {
        TDX_ERROR("rp_bdf_reg reserved field is not zero (rp_bdf_reg = 0x%llx)\n", rp_bdf_reg.raw)
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }
    rp_bdf_t tmp_rp_bdf = {.raw = rp_bdf_reg.rp_bdf.raw};

    // Verify RP is attached to this IOMMU
    if (hiop_info_ptr->hiop_bus_base != tmp_rp_bdf.bus)
    {
        TDX_ERROR("Root port is not attached to this IOMMU (hiop_bus_base = 0x%x, rp_bdf.bus = 0x%x)\n",
                  hiop_info_ptr->hiop_bus_base, tmp_rp_bdf.bus);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Verify RP device and function are one of the valid values
    for (*rp_idx = 0; *rp_idx < NUM_OF_RP; (*rp_idx)++)
    {
        if (((hiop_info_ptr->hiop_rp_bit_vector & (uint16_t)BIT(*rp_idx)) != 0) &&
            socket_io_info_ptr->hiop_rp_df[*rp_idx] == tmp_rp_bdf.dev_func)
        {
            return_val = TDX_SUCCESS;
            goto EXIT;
        }
    }

    TDX_ERROR("Invalid RP device and function\n");
    return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);

EXIT:
    return return_val;
}

api_error_type configure_rp(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    vtbar_t *const vtbar_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    rp_cfg_page_t *rp_cfg_page_ptr = NULL;
    bool_t rp_seam_wac_set = false;

    // Verify no enhanced command is in progress
    ecrsp_reg_t ecrsp_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ECRSP_REG_OFFSET)};
    if (ecrsp_reg.ip)
    {
        TDX_ERROR("ecrsp_reg.ip != 0 (ecrsp_reg = 0x%llx)\n", ecrsp_reg.raw);
        return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify IOMMU is in TDX mode
    ests0_reg_t ests0_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ESTS0_REG_OFFSET)};
    if (ests0_reg.tms == 0)
    {
        TDX_ERROR("ests0_reg.tms == 0 (ests0_reg = 0x%llx)\n", ests0_reg.raw);
        return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // VTBAR.GSTS.RTPS == 1
    gsts_reg_t gsts_reg = {.raw = vtbar_read_reg32(vtbar_ptr, VTBAR_GSTS_REG_OFFSET)};
    if (gsts_reg.rtps == 0)
    {
        TDX_ERROR("gsts_reg.rtps == 0 (gsts_reg = 0x%llx)\n", gsts_reg.raw);
        return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify RP operand and extract its index in the IOMMU
    rp_bdf_reg_t rp_bdf_reg = {.raw = reg_value};
    uint8_t rp_idx = 0;
    return_val = verify_rp_operand(
        rp_bdf_reg,
        socket_io_info_ptr,
        hiop_info_ptr,
        &rp_idx);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify this RP is not already configured
    if ((iommu_config_ptr->rp_reg_sts & (uint16_t)BIT(rp_idx)) != 0)
    {
        TDX_ERROR("RP already configured 0x%x\n", iommu_config_ptr->rp_reg_sts);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Map RP_CFG_PAGE
    rp_cfg_page_ptr = map_rp_mmcfg(
        hiop_info_ptr,
        rp_bdf_reg.rp_bdf.dev_func);

    // Set SEAM only write access SAI policy for this RP IDE ECAP registers
    iommu_config_ptr->rp_wac_value[rp_idx] = set_seam_mode_wac(
        socket_io_info_ptr,
        rp_cfg_page_ptr,
        RP_WAC);

    rp_seam_wac_set = true;

    if (!is_ide_disabled(
            socket_io_info_ptr,
            rp_cfg_page_ptr))
    {
        return_val = api_error_with_operand_id(TDX_IOMMU_RP_IDE_MUST_BE_DISABLED, OPERAND_ID_R8);
        goto EXIT;
    }

    // Set RP status bit to mark it as configured
    iommu_config_ptr->rp_reg_sts |= (uint16_t)BIT(rp_idx);

    return_val = TDX_SUCCESS;

EXIT:
    if ((return_val != TDX_SUCCESS) && rp_seam_wac_set)
    {
        remove_seam_mode_wac(
            socket_io_info_ptr,
            rp_cfg_page_ptr,
            RP_WAC,
            iommu_config_ptr->rp_wac_value[rp_idx]);
    }

    if (rp_cfg_page_ptr != NULL)
    {
        free_la(rp_cfg_page_ptr);
    }

    return return_val;
}

api_error_type clear_rp(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    rp_cfg_page_t *rp_cfg_page_ptr = NULL;

    if (iommu_config_ptr->active_spdm_session_count != 0)
    {
        TDX_ERROR("IOMMU has active sessions (num of active sessions = %lu)",
                  iommu_config_ptr->active_spdm_session_count);
        return_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    rp_bdf_reg_t rp_bdf = {.raw = reg_value};
    uint8_t rp_idx = 0;
    // Verify RP operand and extract its index in the IOMMU
    return_val = verify_rp_operand(
        rp_bdf,
        socket_io_info_ptr,
        hiop_info_ptr,
        &rp_idx);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify this RP is configured
    if ((iommu_config_ptr->rp_reg_sts & (uint16_t)BIT(rp_idx)) == 0)
    {
        TDX_ERROR("RP is not configured 0x%x\n", iommu_config_ptr->rp_reg_sts);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Map RP MMCFG page
    rp_cfg_page_ptr = map_rp_mmcfg(
        hiop_info_ptr,
        rp_bdf.rp_bdf.dev_func);

    // Clear SEAM only write access SAI policy from this RP IDE ECAP registers
    remove_seam_mode_wac(
        socket_io_info_ptr,
        rp_cfg_page_ptr,
        RP_WAC,
        iommu_config_ptr->rp_wac_value[rp_idx]);

    // Clear RP status bit
    iommu_config_ptr->rp_reg_sts &= ~(uint16_t)BIT(rp_idx);

    return_val = TDX_SUCCESS;

EXIT:
    if (rp_cfg_page_ptr != NULL)
    {
        free_la(rp_cfg_page_ptr);
    }
    return return_val;
}

