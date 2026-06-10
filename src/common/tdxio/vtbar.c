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
 * @file vtbar.c
 */

#include "tdxio/vtbar.h"
#include "tdxio/dmar.h"

#define ECMD_BUSY_WAIT_USEC (5 * USECOND)
#define ECMD_WAIT_TIMEOUT_LOOP_MSEC  ((20 * MSECOND) / ECMD_BUSY_WAIT_USEC)

api_error_type is_valid_ecrsp_reg(const void *const vtbar_ptr)
{
    ecrsp_reg_t ecrsp_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ECRSP_REG_OFFSET)};

    if (ecrsp_reg.ip == 1)
    {
        // ECMD hasn't complete
        return TDX_IOMMU_ECMD_TIMEOUT;
    }

    if (ecrsp_reg.sc != 0)
    {
        // ECMD failed
        return TDX_IOMMU_ECMD_ERROR;
    }
    return TDX_SUCCESS;
}

api_error_type execute_ecmd(void *const vtbar_ptr)
{
    api_error_type return_val = TDX_IOMMU_ECMD_TIMEOUT;

    // Write ECMD_CMD_SET_TDX_MODE
    ecmd_reg_t ecmd_reg = {.raw = 0};
    ecmd_reg.cmd = ECMD_CMD_SET_TDX_MODE;
    vtbar_write_reg64(vtbar_ptr, VTBAR_ECMD_REG_OFFSET, ecmd_reg.raw);

    const uint64_t tsc_ratio = get_tsc_ratio();

    // Wait while command-in-progress is on
    for (int i = 0; i < ECMD_WAIT_TIMEOUT_LOOP_MSEC && return_val != TDX_SUCCESS; i++)
    {
        busy_wait_usec(ECMD_BUSY_WAIT_USEC, tsc_ratio);
        return_val = is_valid_ecrsp_reg(vtbar_ptr);
    }
    return return_val;
}

api_error_type set_tdx_mode(vtbar_t *const vtbar_ptr)
{
    uint8_t tdx_reserved_keyid_bits = (uint8_t)get_global_data()->plt_common_config.ia32_tme_activate.tdx_reserved_keyid_bits;
    tdx_debug_assert(tdx_reserved_keyid_bits < BIT(4));

    tdx_mode_reg_t tdx_mode_reg = {.raw = 0};
    tdx_mode_reg.l = tdx_reserved_keyid_bits;
    tdx_mode_reg.tm = 1;
    vtbar_write_reg64(vtbar_ptr, VTBAR_TDX_MODE_REG_OFFSET, tdx_mode_reg.raw);

    return execute_ecmd(vtbar_ptr);
}

api_error_type clear_tdx_mode(vtbar_t *const vtbar_ptr)
{
    ests0_reg_t ests0_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_ESTS0_REG_OFFSET)};
    iqt_reg_t t_iqt_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_T_IQT_REG_OFFSET)};
    iqh_reg_t t_iqh_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_T_IQH_REG_OFFSET)};
    rta_addr_reg_t rta_addr_reg = {.raw = vtbar_read_reg64(vtbar_ptr, VTBAR_T_RTADDR_REG_OFFSET)};

    // Fail if,
    if (ests0_reg.tms == 0 ||                                        // There are valid mappings in the trusted translation table
        t_iqh_reg.raw != t_iqt_reg.raw ||                            // Trusted IQ must be empty
        (is_valid_ecrsp_reg(vtbar_ptr) == TDX_IOMMU_ECMD_TIMEOUT) || // An enhanced command in progress
        (!is_dmar_root_table_empty(rta_addr_reg)))                   // Root table not empty
    {
        TDX_ERROR("Root table not empty, or invalid vtbar regs (ests0_reg.tms = %u, \
                    t_iqh_reg.raw = 0x%llx, t_iqt_reg.raw = 0x%llx, Or ECMD hasn't complete)\n",
                  ests0_reg.tms, t_iqh_reg.raw, t_iqt_reg.raw);
        return TDX_IOMMU_INVALID_STATE;
    }

    // Set following trusted registers to 0 i.e. their reset default values
    vtbar_write_reg64(vtbar_ptr, VTBAR_T_RTADDR_REG_OFFSET, 0);
    vtbar_write_reg64(vtbar_ptr, VTBAR_T_IQA_REG_OFFSET, 0);
    vtbar_write_reg64(vtbar_ptr, VTBAR_TDX_MODE_REG_OFFSET, 0);

    return execute_ecmd(vtbar_ptr);
}

void set_gcmd(
    vtbar_t *const vtbar_ptr,
    const uint8_t bit_pos,
    const bool_t bit_value)
{
    tdx_debug_assert(bit_pos < sizeof(gcmd_input_t) * 8);

    gsts_reg_t gsts_reg = {.raw = vtbar_read_reg32(vtbar_ptr, VTBAR_GSTS_REG_OFFSET)};
    gsts_reg.raw &= VTBAR_GSTS_RESET_ONE_SHOT_BITS_MASK;

    gcmd_input_t gcmd_reg;
    if (bit_value)
    {
        gcmd_reg.raw = gsts_reg.raw | (uint32_t)BIT(bit_pos);
    }
    else
    {
        gcmd_reg.raw = gsts_reg.raw & (uint32_t)~BIT(bit_pos);
    }

    vtbar_write_reg32(vtbar_ptr, VTBAR_GCMD_REG_OFFSET, gcmd_reg.raw);
}
