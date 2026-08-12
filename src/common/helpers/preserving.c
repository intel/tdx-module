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

    // Populate HV0 fields
    tdx_memcpy(
        td_preserving_hod_ptr->kot_entries, sizeof(td_preserving_hod_ptr->kot_entries),
        tdx_global_data_ptr->kot.entries, sizeof(tdx_global_data_ptr->kot.entries));

    tdx_memcpy(
        td_preserving_hod_ptr->wbt_entries, sizeof(td_preserving_hod_ptr->wbt_entries),
        tdx_global_data_ptr->wbt_entries, sizeof(tdx_global_data_ptr->wbt_entries));

    tdx_memcpy(
        td_preserving_hod_ptr->tdmr_table, sizeof(td_preserving_hod_ptr->tdmr_table),
        tdx_global_data_ptr->tdmr_table, sizeof(tdx_global_data_ptr->tdmr_table));

    td_preserving_hod_ptr->num_of_tdmr_entries = tdx_global_data_ptr->num_of_tdmr_entries;
    td_preserving_hod_ptr->hkid = tdx_global_data_ptr->hkid;
    td_preserving_hod_ptr->package_config_bitmap = tdx_global_data_ptr->pkg_config_bitmap;
    td_preserving_hod_ptr->dynamic_pamt_enabled = tdx_global_data_ptr->dynamic_pamt_enabled;

    // Populate HV1 fields
    td_preserving_hod_ptr->td_build_count = tdx_global_data_ptr->td_build_count;
    td_preserving_hod_ptr->mig_interrupted_count = tdx_global_data_ptr->mig_interrupted_count;

    // Populate HV2 fields
    td_preserving_hod_ptr->non_blocking_export = tdx_global_data_ptr->non_blocking_export_configured;
    td_preserving_hod_ptr->write_blocking_export_used = tdx_global_data_ptr->write_blocking_export_used;

    basic_memset_to_zero(td_preserving_hod_ptr->round_up_to_4k_1, sizeof(td_preserving_hod_ptr->round_up_to_4k_1));
}

_STATIC_INLINE_ void retrieve_handoff_data_default(const td_preserving_hod_t *const td_preserving_hod_ptr, tdx_module_global_t *const tdx_global_data_ptr)
{
    // Populate HV0 fields
    tdx_memcpy(
        tdx_global_data_ptr->kot.entries, sizeof(tdx_global_data_ptr->kot.entries),
        td_preserving_hod_ptr->kot_entries, sizeof(td_preserving_hod_ptr->kot_entries));

    tdx_memcpy(
        tdx_global_data_ptr->wbt_entries, sizeof(tdx_global_data_ptr->wbt_entries),
        td_preserving_hod_ptr->wbt_entries, sizeof(td_preserving_hod_ptr->wbt_entries));

    tdx_memcpy(
        tdx_global_data_ptr->tdmr_table, sizeof(tdx_global_data_ptr->tdmr_table),
        td_preserving_hod_ptr->tdmr_table, sizeof(td_preserving_hod_ptr->tdmr_table));

    tdx_global_data_ptr->num_of_tdmr_entries = td_preserving_hod_ptr->num_of_tdmr_entries;
    tdx_global_data_ptr->hkid = td_preserving_hod_ptr->hkid;
    tdx_global_data_ptr->pkg_config_bitmap = td_preserving_hod_ptr->package_config_bitmap;
}

_STATIC_INLINE_ void retrieve_handoff_data_with_skipped_v0(const td_preserving_skipped_hod_t *const td_preserving_hod_ptr, tdx_module_global_t *const tdx_global_data_ptr)
{
    /**
     * @note td_preserving_skipped_hod_t already takes the skipped TDX Connect fields
     *       into account when setting the dynamic PAMT enable bit
     */
    tdx_global_data_ptr->dynamic_pamt_enabled = td_preserving_hod_ptr->dynamic_pamt_enabled;

    tdx_global_data_ptr->non_blocking_export_configured = false;
    tdx_global_data_ptr->write_blocking_export_used = WRITE_BLOCKING_EXPORT_POSSIBLY_USED;
}

_STATIC_INLINE_ void retrieve_handoff_data_generic(const td_preserving_hod_t *const td_preserving_hod_ptr,
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
    if (hv < 2)
    {
        tdx_global_data_ptr->non_blocking_export_configured = false;
        tdx_global_data_ptr->write_blocking_export_used = WRITE_BLOCKING_EXPORT_POSSIBLY_USED;
    }
    else
    {
        tdx_global_data_ptr->non_blocking_export_configured = td_preserving_hod_ptr->non_blocking_export;
        tdx_global_data_ptr->write_blocking_export_used = td_preserving_hod_ptr->write_blocking_export_used;
    }
}

void retrieve_handoff_data(const uint16_t prev_hv)
{
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    td_preserving_hod_t *td_preserving_hod_ptr = (td_preserving_hod_t *)get_sysinfo_table()->data_rgn_base;

    /**
     * @brief 'default' fields are the common fields between handoff data with HV 0 and above
     */
    retrieve_handoff_data_default(td_preserving_hod_ptr, tdx_global_data_ptr);

    if (prev_hv == 0)
    {
        /**
         * @brief handoff data with HV 0 contains deprecated TDX Connect fields which are therefore skipped when deserialized
         */
        retrieve_handoff_data_with_skipped_v0((void *)td_preserving_hod_ptr, tdx_global_data_ptr);
    }
    else
    {
        /**
         * @brief the 'generic' helper is used for all handoff data with HV >=3.
         */
        retrieve_handoff_data_generic(td_preserving_hod_ptr, tdx_global_data_ptr, prev_hv);
    }
}
