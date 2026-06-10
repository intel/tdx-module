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
 * @file iommu.h
 * @brief IOMMU handlers
 */

#ifndef IOMMU_H_
#define IOMMU_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "helpers/helpers.h"

#include "data_structures/tdxio/iommu_defs.h"
#include "data_structures/tdxio/kcbar_defs.h"
#include "tdxio/iommu_common.h"
#include "tdxio/vtbar.h"

_STATIC_INLINE_ bool_t get_vtbar_iommu(
    const uint64_t vtbar_pa,
    iommu_id_reg_t *const iommu_id_reg)
{
    uint64_t hiop_info_vtbar_pa = 0;
    hiop_info_t *hiop_info_ptr = NULL;
    socket_io_info_t *socket_io_info_ptr = NULL;

    for (uint8_t socket_id = 0; socket_id < NUM_OF_SOCKETS; socket_id++)
    {
        iommu_id_reg->iommu_id.socket_id = socket_id;
        socket_io_info_ptr = get_socket_io_info(iommu_id_reg->iommu_id);
        for (uint8_t hiop_id = 0; hiop_id < NUM_OF_HIOPS; hiop_id++)
        {
            iommu_id_reg->iommu_id.hiop_id = hiop_id;
            hiop_info_ptr = get_hiop_info(iommu_id_reg->iommu_id, socket_io_info_ptr);
            if (hiop_info_ptr->hiop_rp_bit_vector == 0)
            {
                continue;
            }
            hiop_info_vtbar_pa = get_vtbar_pa(
                socket_io_info_ptr,
                hiop_info_ptr);
            if (vtbar_pa == hiop_info_vtbar_pa)
            {
                return true;
            };
        };
    };

    TDX_ERROR("Failed to find IOMMU vtbar (IOMMU ID = %u)\n", iommu_id_reg->iommu_id.raw);
    return false;
}

/**
 * @brief Verifies the initial IOMMU state:
 *        - IOMMU entries are not in TDX mode
 *
 * @return bool_t
 */

 bool_t is_valid_initial_iommu_state(void);

/**
 * @brief Add T_IQPAGE/IQCTXPAGE continuously
 *
 * @param invq_page
 * @param page_pa
 *
 * @return api_error_type
 */
api_error_type check_and_update_iq_buffer(
    iq_buffer_t *const invq_page,
    const uint64_t page_pa);

/**
 * @brief Configure IOMMU
 *
 * @param socket_io_info_ptr
 * @param hiop_info_ptr
 * @param vtbar_ptr
 * @param iommu_config_ptr
 * @param reg_value
 *
 * @return api_error_type
 */
api_error_type configure_iommu(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    vtbar_t *const vtbar_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value);

/**
 * @brief Clear IOMMU
 *
 * @param socket_io_info_ptr
 * @param hiop_info_ptr
 * @param vtbar_ptr
 * @param iommu_config_ptr
 * @param reg_value
 *
 * @return api_error_type
 */
api_error_type clear_iommu(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    vtbar_t *const vtbar_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value);

/**
 * @brief Handle GCMD_REG case in tdh_iommu_setreg
 *
 * @param vtbar_ptr
 * @param reg_value
 *
 * @return api_error_type
 */
api_error_type iommu_setreg_gcmd(
    vtbar_t *const vtbar_ptr,
    const uint64_t reg_value);

/**
 * @brief Helper used in configure_rp
 *
 * @param rp_bdf_reg
 * @param socket_io_info_ptr
 * @param hiop_info_ptr
 * @param rp_idx
 * @return api_error_type
 */
api_error_type verify_rp_operand(
    const rp_bdf_reg_t rp_bdf_reg,
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    uint8_t *const rp_idx);

/**
 * @brief Configure root port
 *
 * @param socket_io_info_ptr
 * @param hiop_info_ptr
 * @param vtbar_ptr
 * @param iommu_config_ptr
 * @param reg_value
 *
 * @return api_error_type
 */
api_error_type configure_rp(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    vtbar_t *const vtbar_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value);

/**
 * @brief Clear root port
 *
 * @param socket_io_info_ptr
 * @param hiop_info_ptr
 * @param vtbar_ptr
 * @param iommu_config_ptr
 * @param reg_value
 *
 * @return api_error_type
 */
api_error_type clear_rp(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    iommu_config_t *const iommu_config_ptr,
    const uint64_t reg_value);

_STATIC_INLINE_ uint64_t increment_iotlb_tracker_pasidte_ref_cnt(
    iotlb_inv_tracker_t *const iotlb_inv_tracker_ptr,
    const uint64_t inc_val)
{
    const uint64_t prev_ref_cnt = iotlb_inv_tracker_ptr->pasidte_ref_cnt;

    // Assign all of the fields individually to avoid an overflow once the ref count is incremente
    iotlb_inv_tracker_t tmp_iotlb_inv_tracker;
    tmp_iotlb_inv_tracker.pasidte_ref_cnt = iotlb_inv_tracker_ptr->pasidte_ref_cnt + inc_val;
    tmp_iotlb_inv_tracker.inv_req = iotlb_inv_tracker_ptr->inv_req;
    tmp_iotlb_inv_tracker.inv_epoch = iotlb_inv_tracker_ptr->inv_epoch;
    tmp_iotlb_inv_tracker.reserved = iotlb_inv_tracker_ptr->reserved;

    // Atomic assignment
    iotlb_inv_tracker_ptr->raw = tmp_iotlb_inv_tracker.raw;

    return prev_ref_cnt;
}

/**
 * @brief Host side call of general_check_and_lock_iommu_config that ACQUIRES the lock
 *        check
 *        - iommu_id < max iommu
 *        - lock can be acquired (if @param lock_iommu is set)
 *        - is in the expected_iommu_state
 *        - rp_bitmap
 *
 * @param iommu_id
 * @param operand_id
 * @param expected_iommu_state
 * @param rp_configured
 * @param iommu_config_p
 *
 * @return Success or Error type
 */
_STATIC_INLINE_ api_error_type tdh_check_and_lock_iommu_config(
    const uint64_t iommu_id_val,
    const uint64_t operand_id,
    bool_t *const is_iommu_locked_ptr,
    iommu_config_t **iommu_config_ptr)
{
    return general_check_and_lock_iommu_config(
        iommu_id_val,
        operand_id,
        false,
        is_iommu_locked_ptr,
        iommu_config_ptr);
}

_STATIC_INLINE_ uint16_t hiop_read_reg16(
    const hiop_info_t *const hiop_info_ptr,
    const uint16_t reg_offset)
{
    pa_t hiop_reg_pa = {.raw = hiop_info_ptr->hiop_mmcfg_base + reg_offset};

    uint16_t *hiop_reg_ptr = (uint16_t *)map_pa_with_global_hkid_uncached(
        hiop_reg_pa.raw_void,
        TDX_RANGE_RO);
    uint16_t hiop_val = vol_read_reg16(hiop_reg_ptr);
    free_la(hiop_reg_ptr);

    return hiop_val;
}

/**
 * @brief Read 64bit register from the HIOP space
 *
 * @param hiop_info_ptr
 * @param reg_offset
 *
 * @return uint64_t
 */
_STATIC_INLINE_ uint64_t hiop_read_reg64(
    const hiop_info_t *const hiop_info_ptr,
    const uint16_t reg_offset)
{
    pa_t hiop_reg_pa = {.raw = hiop_info_ptr->hiop_mmcfg_base + reg_offset};
    return pci_64bit_read(hiop_reg_pa);
}

/**
 * @brief Write 64bit register to the HIOP space
 *
 * @param hiop_info_ptr
 * @param reg_offset
 * @param val
 */
_STATIC_INLINE_ void hiop_write_reg64(
    const hiop_info_t *const hiop_info_ptr,
    const uint16_t reg_offset,
    const uint64_t val)
{
    pa_t hiop_reg_pa = {.raw = hiop_info_ptr->hiop_mmcfg_base + reg_offset};
    pci_64bit_write(hiop_reg_pa, val);
}


// TODO: remove getter after A0 support is deprecated
_STATIC_INLINE_ uint16_t get_shadow_rp_mapping(const uint16_t rp_idx)
{
    if (get_global_data()->is_gnr_a0_cpuid)
    {
        // WA - https://hsdes.intel.com/appstore/article/#/13012256686
        const uint8_t bank_decoder_to_rp_mapping[] = {0, 4, 1, 5, 2, 6, 3, 7};
        return bank_decoder_to_rp_mapping[rp_idx];
    }
    // 1:1 mapping
    return rp_idx;
}

#endif // IOMMU_H_
