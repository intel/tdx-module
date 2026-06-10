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
 * @file seam_sai.h
 * @brief SEAM_SAI operations
 */

#ifndef SEAM_SAI_H_
#define SEAM_SAI_H_

#include "helpers/helpers.h"
#include "x86_defs/msr_defs.h"
#include "data_structures/tdxio/seam_sai_defs.h"

_STATIC_INLINE_ uint16_t get_sai_reg_offset(
    const socket_io_info_t *const socket_info_ptr,
    const sai_reg_offset_e sai_reg_offset)
{
    switch (sai_reg_offset)
    {
    case RP_WAC:
        return socket_info_ptr->rp_seam_os_w_pg_wac_offset;
    case IOMMU_WAC:
        return socket_info_ptr->iommu_seam_os_w_pg_wac_offset;
    case KCB_WAC:
        return socket_info_ptr->kcb_seam_os_w_pg_wac_offset;
    case HIOP_WAC:
        return socket_info_ptr->hiop_seam_os_w_pg_wac_offset;
    default:
        fatal_error(FATAL_ERROR_ID_90, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
}

/**
 * @brief Set SEAM mode write access restrictions
 *
 * @param socket_info_ptr
 * @param vtbar_ptr, refers to KCBAR, VTBAR and RP_CFG_PAGE
 * @param sai_reg_offset
 *
 * @note Use 2 32bit reads/writes for MMCFG operations which don't support 64bit reads/writes
 *
 * @return Previous WAC value which is stored in the relevant placeholder in the iommu_config
 */
_STATIC_INLINE_ uint64_t set_seam_mode_wac(
    const socket_io_info_t *const socket_info_ptr,
    void *const bar_ptr,
    const sai_reg_offset_e sai_reg_offset)
{
    uint16_t offset_val = get_sai_reg_offset(
        socket_info_ptr,
        sai_reg_offset);

    uint64_t prev_wac_val = 0;

    // See WA https://hsdes.intel.com/appstore/article/#/13011437466
    if (sai_reg_offset == HIOP_WAC)
    {
        if (offset_val != 0)
        {
            prev_wac_val = hiop_read_reg64((hiop_info_t *)bar_ptr, offset_val);
            // Write SAI value
            hiop_write_reg64((hiop_info_t *)bar_ptr, offset_val, socket_info_ptr->seam_only_sai_value);
        }
    }
    else
    {
        // Store previous WAC value value
        prev_wac_val = vol_read_reg64_with_32((void *)((uint64_t)bar_ptr + offset_val));
        // Write SAI value
        vol_write_reg64_with_32(
            (void *)((uint64_t)bar_ptr + offset_val),
            socket_info_ptr->seam_only_sai_value);
    }

    return prev_wac_val;
}

/**
 * @brief Remove SEAM mode write access restrictions by restoring the previous WAC value from the relevant palceholder in the iommu_config
 *
 * @param socket_info_ptr
 * @param vtbar_ptr, refers to KCBAR, VTBAR and RP_CFG_PAGE
 * @param sai_reg_offset
 *
 * @note Use 2 32bit reads/writes for MMCFG operations which don't support 64bit reads/writes
 */
_STATIC_INLINE_ void remove_seam_mode_wac(
    const socket_io_info_t *const socket_info_ptr,
    void *const bar_ptr,
    const sai_reg_offset_e sai_reg_offset,
    const uint64_t previous_wac_val)
{
    uint16_t offset_val = get_sai_reg_offset(
        socket_info_ptr,
        sai_reg_offset);

    // See WA https://hsdes.intel.com/appstore/article/#/13011437466
    if (sai_reg_offset == HIOP_WAC)
    {
        // Write SAI value
        if (offset_val != 0)
        {
            hiop_write_reg64((hiop_info_t *)bar_ptr, offset_val, previous_wac_val);
        }
    }
    else
    {
        vol_write_reg64_with_32((void *)((uint64_t)bar_ptr + offset_val), previous_wac_val);
    }
}

_STATIC_INLINE_ void enable_seam_sai_generation()
{
    ia32_wrmsr(ENABLE_SEAM_SAI_MSR, SEAM_SAI_GEN_ENABLE);
}

_STATIC_INLINE_ void disable_seam_sai_generation()
{
    ia32_wrmsr(ENABLE_SEAM_SAI_MSR, SEAM_SAI_GEN_DISABLE);
}

#endif // SEAM_SAI_H_
