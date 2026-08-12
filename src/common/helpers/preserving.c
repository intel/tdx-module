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
#include GLOBAL_CONSTANTS_HEADER


void prepare_handoff_data(const uint16_t curr_hv)
{
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    td_preserving_hod_t *td_preserving_hod_ptr = (td_preserving_hod_t *)get_sysinfo_table()->data_rgn_base;

    // Verify the preserving buffer is big enough to contain all handoff data
    const uint32_t handoff_data_buff_size = (tdx_global_data_ptr->num_handoff_pages + 1) * TDX_PAGE_SIZE_IN_BYTES;
    tdx_sanity_check((handoff_data_buff_size > 0) && (handoff_data_buff_size >= sizeof(td_preserving_hod_t)), FATAL_ERROR_ID_303, 1);

    td_preserving_hod_ptr->header.valid = true;
    td_preserving_hod_ptr->header.hv = curr_hv;
    td_preserving_hod_ptr->header.size = sizeof(td_preserving_hod_t) - sizeof(handoff_data_header_t);

    // The implementation doesn't support downgrading
    tdx_sanity_check(NO_DOWNGRADE == 1, FATAL_ERROR_ID_304, curr_hv);

    // Populate HV0 fields
    tdx_memcpy(
        td_preserving_hod_ptr->kot_entries, HANDOFF_KOT_ENTRIES_SIZE,
        tdx_global_data_ptr->kot.entries, HANDOFF_KOT_ENTRIES_SIZE);

    tdx_memcpy(
        td_preserving_hod_ptr->wbt_entries, HANDOFF_WBT_ENTRIES_SIZE,
        tdx_global_data_ptr->wbt_entries, HANDOFF_WBT_ENTRIES_SIZE);

    tdx_memcpy(
        td_preserving_hod_ptr->tdmr_table, HANDOFF_TDMR_TABLE_SIZE,
        tdx_global_data_ptr->tdmr_table, HANDOFF_TDMR_TABLE_SIZE);

    td_preserving_hod_ptr->num_of_tdmr_entries = tdx_global_data_ptr->num_of_tdmr_entries;
    td_preserving_hod_ptr->hkid = tdx_global_data_ptr->hkid;
    td_preserving_hod_ptr->package_config_bitmap = tdx_global_data_ptr->pkg_config_bitmap;
    td_preserving_hod_ptr->dynamic_pamt_enabled = tdx_global_data_ptr->dynamic_pamt_enabled;

    // Populate HV1 fields
    td_preserving_hod_ptr->td_build_count = tdx_global_data_ptr->td_build_count;
    td_preserving_hod_ptr->mig_interrupted_count = tdx_global_data_ptr->mig_interrupted_count;

    // Populate HV2 fields

    // Populate HV3 fields
}

_STATIC_INLINE_ void retrieve_handoff_data_default(
    const td_preserving_hod_t *const td_preserving_hod_ptr,
    tdx_module_global_t *const tdx_global_data_ptr)
{
    // Populate HV0 fields
    tdx_memcpy(
        tdx_global_data_ptr->kot.entries, HANDOFF_KOT_ENTRIES_SIZE,
        td_preserving_hod_ptr->kot_entries, HANDOFF_KOT_ENTRIES_SIZE);

    tdx_memcpy(
        tdx_global_data_ptr->wbt_entries, HANDOFF_WBT_ENTRIES_SIZE,
        td_preserving_hod_ptr->wbt_entries, HANDOFF_WBT_ENTRIES_SIZE);

    tdx_memcpy(
        tdx_global_data_ptr->tdmr_table, HANDOFF_TDMR_TABLE_SIZE,
        td_preserving_hod_ptr->tdmr_table, HANDOFF_TDMR_TABLE_SIZE);

    tdx_global_data_ptr->num_of_tdmr_entries = td_preserving_hod_ptr->num_of_tdmr_entries;
    tdx_global_data_ptr->hkid = td_preserving_hod_ptr->hkid;
    tdx_global_data_ptr->pkg_config_bitmap = td_preserving_hod_ptr->package_config_bitmap;
}


_STATIC_INLINE_ void retrieve_handoff_data_generic(
    const td_preserving_hod_t *const td_preserving_hod_ptr,
    tdx_module_global_t *const tdx_global_data_ptr,
    const uint64_t hv)
{
    UNUSED(hv);
    // Populate HV0 fields
    tdx_global_data_ptr->dynamic_pamt_enabled = td_preserving_hod_ptr->dynamic_pamt_enabled;

    // Populate HV1 fields
    tdx_global_data_ptr->td_build_count = td_preserving_hod_ptr->td_build_count;
    tdx_global_data_ptr->mig_interrupted_count = td_preserving_hod_ptr->mig_interrupted_count;

    // Populate HV2 fields
}

void retrieve_handoff_data(const uint16_t prev_hv)
{
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    td_preserving_hod_t *td_preserving_hod_ptr = (td_preserving_hod_t *)get_sysinfo_table()->data_rgn_base;

    /**
     * @brief 'default' fields are the common fields between handoff data with HV 0 and above
     */
    retrieve_handoff_data_default(td_preserving_hod_ptr, tdx_global_data_ptr);

    /**
     * @brief the 'generic' helper is used for all handoff data with HV >=3.
     */
    retrieve_handoff_data_generic(td_preserving_hod_ptr, tdx_global_data_ptr, prev_hv);
}
