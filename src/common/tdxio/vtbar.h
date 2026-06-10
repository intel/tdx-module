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
 * @file vtbar.h
 * @brief VTBAR helper functions
 */

#ifndef SRC_COMMON_TDXIO_VTBAR_H_
#define SRC_COMMON_TDXIO_VTBAR_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "helpers/helpers.h"
#include "tdxio/io_accessors.h"

#include "tdxio/iommu_common.h"
#include "data_structures/tdxio/vtbar_defs.h"


_STATIC_INLINE_ uint64_t get_vtbar_pa(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr)
{
    pa_t vtbar_addr_reg_pa = {.raw = hiop_info_ptr->hiop_mmcfg_base + (uint64_t)socket_io_info_ptr->hiop_iommu_vtbar_offset};
    return pci_64bit_read(vtbar_addr_reg_pa) & ~BIT(VTBAR_ENABLE_BIT);
}

_STATIC_INLINE_ vtbar_t *map_vtbar(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr)
{
    uint64_t vtbar_pa = get_vtbar_pa(socket_io_info_ptr, hiop_info_ptr);
    return (vtbar_t *)map_pa_with_global_hkid_uncached((void *)vtbar_pa, TDX_RANGE_RW);
}

_STATIC_INLINE_ uint32_t vtbar_read_reg32(
    const vtbar_t *const vtbar_ptr,
    const vtbar_32_reg_e reg_offset)
{
    return vol_read_reg32((void *)((uint64_t)vtbar_ptr + reg_offset));
}

_STATIC_INLINE_ void vtbar_write_reg32(
    vtbar_t *const vtbar_ptr,
    const vtbar_32_reg_e reg_offset,
    const uint32_t reg_val)
{
    vol_write_reg32((void *)((uint64_t)vtbar_ptr + reg_offset), reg_val);
}

_STATIC_INLINE_ uint64_t vtbar_read_reg64(
    const vtbar_t *const vtbar_ptr,
    const vtbar_64_reg_e reg_offset)
{
    return vol_read_reg64((void *)((uint64_t)vtbar_ptr + reg_offset));
}

_STATIC_INLINE_ void vtbar_write_reg64(
    vtbar_t *const vtbar_ptr,
    const vtbar_64_reg_e reg_offset,
    const uint64_t reg_val)
{
    vol_write_reg64((void *)((uint64_t)vtbar_ptr + reg_offset), reg_val);
}

api_error_type set_tdx_mode(vtbar_t *const vtbar_ptr);
api_error_type clear_tdx_mode(vtbar_t *const vtbar_ptr);
api_error_type is_valid_ecrsp_reg(const void *const vtbar_ptr);

/**
 * @brief Execute ECMD. Currently SET_TDX_MODE is supported
 *  The helper does the following:
 *      1. Issues ECMD(SET_TDX_MODE) command to IOMMU.
 *      2. Waits 5 useconds (according to Eric Geisler, ~2.5 usec is an estimate for ECMD(TDX_MODE) to complete).
 *      3. Break, if ERESP.IP == 0, else repeat the loop for ~20 milliseconds.
 *      4. If the timeout expired, return TDX_IOMMU_ECMD_TIMEOUT.
 *      5. If ERESP.IP == 0, check the command completion ERESP.SC == 0, else return TDX_IOMMU_ECMD_ERROR.
 *
 * @note On TDX_IOMMU_ECMD_TIMEOUT IOMMU should not be released to VMM (WACs, generation ,etc.). VMM must repeat the request to resolve
 *       the IOMMU port state.
 * On TDX_IOMMU_ECMD_ERROR WACs/IOMMU to be released with the error code on CONFIGURE_IOMMU, kept on CLEAR_IOMMU. VMM may repeat the request
 *
 * @param vtbar
 *
 * @return api_error_type
 */
api_error_type execute_ecmd(void *const vtbar_ptr);

void set_gcmd(
    vtbar_t *const vtbar_ptr,
    const uint8_t bit_pos,
    const bool_t bit_value);

#endif /* SRC_COMMON_TDXIO_VTBAR_H_ */
