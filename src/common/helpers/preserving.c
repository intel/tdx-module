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

#include "preserving.h"
#include "helpers/helpers.h"

_STATIC_INLINE_ void copy_global_field_to_handoff(
    void *const src_ptr,
    const uint32_t src_size,
    uint8_t **dst_pointer,
    uint32_t *const dst_size_ptr,
    uint32_t *const written_size_ptr)
{
    tdx_memcpy(*dst_pointer, *dst_size_ptr, src_ptr, src_size);
    *dst_pointer += src_size;
    *dst_size_ptr -= src_size;
    *written_size_ptr += src_size;
}

_STATIC_INLINE_ void copy_global_field_from_handoff(
    void *dst_ptr,
    const uint32_t field_size,
    uint8_t **src_data)
{
    tdx_memcpy(dst_ptr, field_size, *src_data, field_size);
    *src_data += field_size;
}

uint32_t prepare_handoff_data(uint32_t size, uint8_t *data)
{
    /**
     * @brief The function fills the handoff buffer with data variables that satisfy the following conditions:
     *          1)  Not initialized by TDH.SYS.INIT or TDH.SYS.LP.INIT
     *          2)  Persist across multiple SEAMCALLs
     *          3)  Maintained inside SEAM range
     *
     * @note all write size checks are done by tdx_memcpy inside
     */

    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    uint32_t written_size = 0;

    // Copy KOT entries (no need to copy the lock)
    copy_global_field_to_handoff(&tdx_global_data_ptr->kot.entries, HANDOFF_KOT_ENTRIES_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy WBT entries
    copy_global_field_to_handoff(&tdx_global_data_ptr->wbt_entries, HANDOFF_WBT_ENTRIES_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy TDMR_TABLE
    copy_global_field_to_handoff(&tdx_global_data_ptr->tdmr_table, HANDOFF_TDMR_TABLE_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy TDMR_ENTRIES
    copy_global_field_to_handoff(&tdx_global_data_ptr->num_of_tdmr_entries, HANDOFF_NUM_OF_TDMR_ENTRIES_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy TDX_HKID
    copy_global_field_to_handoff(&tdx_global_data_ptr->hkid, HANDOFF_HKID_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy PKG_CONFIG_BITMAP
    copy_global_field_to_handoff(&tdx_global_data_ptr->pkg_config_bitmap, HANDOFF_PKG_CONFIG_BITMAP_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy dynamic PAMT setting
    bool_t dynamic_pamt_enabled = tdx_global_data_ptr->dynamic_pamt_enabled;
    copy_global_field_to_handoff(&dynamic_pamt_enabled, HANDOFF_DYNAMIC_PAMT_ENABLED_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy TD_BUILD_COUNT
    copy_global_field_to_handoff(&tdx_global_data_ptr->td_build_count, HANDOFF_TD_BUILD_COUNT_SIZE,
                                 &data, &size,
                                 &written_size);

    // Copy MIG_INTERRUPTED_COUNT
    copy_global_field_to_handoff(&tdx_global_data_ptr->mig_interrupted_count, HANDOFF_MIG_INTERRUPTED_COUNT_SIZE,
                                 &data, &size,
                                 &written_size);

    // Clear padding (DiD)
    basic_memset_to_zero(data, TDX_RESERVED_PADDING_SIZE);

    return written_size;
}

_STATIC_INLINE_ void retrieve_handoff_data_default(
    tdx_module_global_t *const tdx_global_data_ptr,
    uint8_t **data)
{
    // Copy KOT entries (no need to copy the lock)
    copy_global_field_from_handoff(&tdx_global_data_ptr->kot.entries, HANDOFF_KOT_ENTRIES_SIZE, data);

    // Copy WBT entries
    copy_global_field_from_handoff(&tdx_global_data_ptr->wbt_entries, HANDOFF_WBT_ENTRIES_SIZE, data);

    // Copy TDMR_TABLE
    copy_global_field_from_handoff(&tdx_global_data_ptr->tdmr_table, HANDOFF_TDMR_TABLE_SIZE, data);

    // Copy TDMR_ENTRIES
    copy_global_field_from_handoff(&tdx_global_data_ptr->num_of_tdmr_entries, HANDOFF_NUM_OF_TDMR_ENTRIES_SIZE, data);

    // Copy TDX_HKID
    copy_global_field_from_handoff(&tdx_global_data_ptr->hkid, HANDOFF_HKID_SIZE, data);

    // Copy PKG_CONFIG_BITMAP
    copy_global_field_from_handoff(&tdx_global_data_ptr->pkg_config_bitmap, HANDOFF_PKG_CONFIG_BITMAP_SIZE, data);
}

_STATIC_INLINE_ void retrieve_handoff_data_v0(
    tdx_module_global_t *const tdx_global_data_ptr,
    uint8_t *data)
{
    // Skip IOMMU_CONFIGS
    data += HANDOFF_SKIPPED_IOMMU_CONFIGS_SIZE;

    // Skip MMIOMT_ROOT_NODE
    data += HANDOFF_SKIPPED_MMIOMT_ROOT_SIZE;

    // Skip DEVIFMT_ROOT_NODE
    data += HANDOFF_SKIPPED_TDIMT_ROOT_SIZE;

    // Copy dynamic PAMT setting
    copy_global_field_from_handoff(&tdx_global_data_ptr->dynamic_pamt_enabled, HANDOFF_DYNAMIC_PAMT_ENABLED_SIZE, &data);

    // For HV 0 ,set PL.TD_BUILD_COUNT and PL.MIG_INTERRUPTED_COUNT to 0.
    tdx_global_data_ptr->td_build_count = 0;
    tdx_global_data_ptr->mig_interrupted_count = 0;
}

_STATIC_INLINE_ void retrieve_handoff_data_v1(
    tdx_module_global_t *const tdx_global_data_ptr,
    uint8_t *data)
{
    // Copy dynamic PAMT setting
    copy_global_field_from_handoff(&tdx_global_data_ptr->dynamic_pamt_enabled, HANDOFF_DYNAMIC_PAMT_ENABLED_SIZE, &data);

    // Copy TD_BUILD_COUNT
    copy_global_field_from_handoff(&tdx_global_data_ptr->td_build_count, HANDOFF_TD_BUILD_COUNT_SIZE, &data);

    // Copy MIG_INTERRUPTED_COUNT
    copy_global_field_from_handoff(&tdx_global_data_ptr->mig_interrupted_count, HANDOFF_MIG_INTERRUPTED_COUNT_SIZE, &data);
}

void retrieve_handoff_data(uint16_t hv, uint32_t size, uint8_t *data)
{
    // The function extracts the values of some data variables from the handoff data buffer

    // tdx_sanity_check(TDX_HANDOFF_SIZE <= size, FATAL_ERROR_ID_179, 5);
    UNUSED(size);

    tdx_module_global_t *tdx_global_data_ptr = get_global_data();

    retrieve_handoff_data_default(tdx_global_data_ptr, &data);

    switch (hv)
    {
    case 0:
        retrieve_handoff_data_v0(tdx_global_data_ptr, data);
        break;
    case 1:
        retrieve_handoff_data_v1(tdx_global_data_ptr, data);
        break;
    default:
        fatal_error(FATAL_ERROR_ID_371, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
}