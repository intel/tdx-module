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

#ifndef __PRESERVING_H__
#define __PRESERVING_H__

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "data_structures/tdx_global_data.h"

typedef union handoff_s
{
    struct
    {
        uint64_t handoff_version        : 16;
        uint64_t avoid_compat_sensitive :  1;
        uint64_t reserved               : 47;
    };

    uint64_t raw;
} handoff_t;

/**
 * @note Syntax definition for the handoff data structure:
 *          Each handoff version will have its own ifdef block to determine the handoff order and size as defined in the arch spredsheets
 *          If a handoff version is no longer supported, the ifdef block will be removed.
 */

/**
 * @note The fields below are relevant for all preserving versions
 */
#define HANDOFF_KOT_ENTRIES_SIZE 8 * 2048
tdx_static_assert(sizeof_field(tdx_module_global_t, kot.entries) == HANDOFF_KOT_ENTRIES_SIZE, PRESERVING_HOD_KOT_ENTRIES_SIZE);

#define HANDOFF_WBT_ENTRIES_SIZE 2064 * 8
tdx_static_assert(sizeof_field(tdx_module_global_t, wbt_entries) == HANDOFF_WBT_ENTRIES_SIZE, PRESERVING_HOD_WBT_ENTRIES_SIZE);

#define HANDOFF_TDMR_TABLE_SIZE 320 * 64
tdx_static_assert(sizeof_field(tdx_module_global_t, tdmr_table) == HANDOFF_TDMR_TABLE_SIZE, PRESERVING_HOD_TDMR_ENTRIES_SIZE);

#define HANDOFF_NUM_OF_TDMR_ENTRIES_SIZE 4
tdx_static_assert(sizeof_field(tdx_module_global_t, num_of_tdmr_entries) == HANDOFF_NUM_OF_TDMR_ENTRIES_SIZE, PRESERVING_HOD_TDMR_ENTRIES_COUNT_SIZE);

#define HANDOFF_HKID_SIZE 2
tdx_static_assert(sizeof_field(tdx_module_global_t, hkid) == HANDOFF_HKID_SIZE, PRESERVING_HOD_HKID_ENTRIES_SIZE);

#define HANDOFF_PKG_CONFIG_BITMAP_SIZE 4
tdx_static_assert(sizeof_field(tdx_module_global_t, pkg_config_bitmap) == HANDOFF_PKG_CONFIG_BITMAP_SIZE, PRESERVING_HOD_PKG_CONFIG_BITMAP_SIZE);

// Skipped fields for TDX Connect coming from HV == 0
#define HANDOFF_SKIPPED_IOMMU_CONFIGS_SIZE 128 * 378
tdx_static_assert(sizeof_field(tdx_module_global_t, iommu_configs) == HANDOFF_SKIPPED_IOMMU_CONFIGS_SIZE, PRESERVING_HOD_SKIPPED_IOMMU_CONFIGS_SIZE);
#define HANDOFF_SKIPPED_MMIOMT_ROOT_SIZE 32
tdx_static_assert(sizeof_field(tdx_module_global_t, mmiomt_root_node) == HANDOFF_SKIPPED_MMIOMT_ROOT_SIZE, PRESERVING_HOD_SKIPPED_MMIOMT_ROOT_SIZE);
#define HANDOFF_SKIPPED_TDIMT_ROOT_SIZE 8
tdx_static_assert(sizeof_field(tdx_module_global_t, devifmt_root_node) == HANDOFF_SKIPPED_TDIMT_ROOT_SIZE, PRESERVING_HOD_SKIPPED_TDIMT_ROOT_SIZE);


/**
 * @note Starting from HV 1, the handoff structure is reordered and deprecates TDX Connect fields handoff data from TDX 2.0
 */
#if (TDX_MODULE_HV == 1)

#define HANDOFF_DYNAMIC_PAMT_ENABLED_SIZE 1
tdx_static_assert(sizeof_field(tdx_module_global_t, dynamic_pamt_enabled) == HANDOFF_DYNAMIC_PAMT_ENABLED_SIZE, PRESERVING_HOD_DYNAMIC_PAMT_ENABLED_SIZE);

#define HANDOFF_TD_BUILD_COUNT_SIZE 2
tdx_static_assert(sizeof_field(tdx_module_global_t, td_build_count) == HANDOFF_TD_BUILD_COUNT_SIZE, PRESERVING_HOD_TD_BUILD_COUNT_SIZE);

#define HANDOFF_MIG_INTERRUPTED_COUNT_SIZE 2
tdx_static_assert(sizeof_field(tdx_module_global_t, mig_interrupted_count) == HANDOFF_MIG_INTERRUPTED_COUNT_SIZE, PRESERVING_HOD_MIG_INTERRUPTED_COUNT_SIZE);

#define TDX_HANDOFF_SIZE (HANDOFF_KOT_ENTRIES_SIZE +          \
                          HANDOFF_WBT_ENTRIES_SIZE +          \
                          HANDOFF_TDMR_TABLE_SIZE +           \
                          HANDOFF_NUM_OF_TDMR_ENTRIES_SIZE +  \
                          HANDOFF_HKID_SIZE +                 \
                          HANDOFF_PKG_CONFIG_BITMAP_SIZE +    \
                          HANDOFF_DYNAMIC_PAMT_ENABLED_SIZE + \
                          HANDOFF_TD_BUILD_COUNT_SIZE +       \
                          HANDOFF_MIG_INTERRUPTED_COUNT_SIZE)

#endif // (TDX_MODULE_HV == 1)

#define TDX_MIN_HANDOFF_PAGES ((ROUND_UP(TDX_HANDOFF_SIZE, _4KB)) / _4KB)
tdx_static_assert(TDX_MIN_HANDOFF_PAGES > 0, TDX_MIN_HANDOFF_PAGES);
#define TDX_RESERVED_PADDING_SIZE ((TDX_MIN_HANDOFF_PAGES * _4KB) - TDX_HANDOFF_SIZE)

#define TDX_HANDOFF_V0_PAGES (25) // TDX 2.0.12 and earlier handoff size
#define HANDOFF_V0_SIZE (_4KB * TDX_HANDOFF_V0_PAGES)

/**
 * @brief Called by TDH.SYS.SHUTDOWN to populate handoff data with values of some
 *        variables for the next TDX module
 *
 * @param size - max size of data buffer, in bytes
 * @param data - pointer to handoff data buffer
 *
 * @return size of handoff data filled in data buffer, in bytes (0 = failure)
 */
uint32_t prepare_handoff_data(uint32_t size, uint8_t *data);

/**
 * @brief Called by TDH.SYS.UPDATE to initialize some variables from the handoff
 *        data prepared by the previous TDX module
 *
 * @param hv - handoff data version
 * @param size - size of handoff data in buffer, in bytes
 * @param data - pointer to handoff data buffer
 *
 */
void retrieve_handoff_data(uint16_t hv, uint32_t size, uint8_t *data);

#endif // __PRESERVING_H__