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

#ifndef __PRESERVING_DEFS_H__
#define __PRESERVING_DEFS_H__

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "data_structures/tdx_global_data.h"

#pragma pack(push, 1)

typedef struct handoff_data_header_s
{
    bool_t   valid;
    uint8_t  reserved;
    uint16_t hv;
    uint32_t size; // Size of the handoff data excluding this header
} handoff_data_header_t;
tdx_static_assert(sizeof(handoff_data_header_t) == 8, handoff_data_header_t);

typedef union handoff_s
{
    struct
    {
        uint64_t handoff_version : 16;
        uint64_t avoid_compat_sensitive : 1;
        uint64_t reserved : 47;
    };

    uint64_t raw;
} handoff_input_param_t;
tdx_static_assert(sizeof(handoff_input_param_t) == 8, handoff_input_param_t);

typedef struct handoff_data_blob_s
{
    struct
    {
        uint16_t uid;     // Unique ID
        uint8_t version;  // Struct version
        uint8_t reserved; // Set to zero
        uint32_t size;    // Blob size including header
    } header;

    uint8_t data; // Data blob, variable size
} handoff_dynamic_blob_t;
tdx_static_assert(sizeof(handoff_dynamic_blob_t) == 9, handoff_dynamic_blob_t);

#define HANDOFF_DYNAMIC_BLOB_HEADER_SIZE (8)
tdx_static_assert(sizeof_field(handoff_dynamic_blob_t, header) == HANDOFF_DYNAMIC_BLOB_HEADER_SIZE, HANDOFF_DYNAMIC_BLOB_HEADER_SIZE);


#define HANDOFF_BLOB_ENTRY_IOMMU_CONFIG_SIZE (0)
#define HANDOFF_BLOB_ENTRY_MMIOMT_ROOT_SIZE (0)
#define HANDOFF_BLOB_ENTRY_TDIMT_ROOT_SIZE (0)



// Data size + header size
#define HANDOFF_BLOB_ENTRY_NRX_MEM_POOL_SIZE (0)


typedef enum
{
    HANDOFF_DYNAMIC_BLOB_IOMMU_CONFIG_ID = 0,
    HANDOFF_DYNAMIC_BLOB_MMIOMT_ROOT_ID  = 1,
    HANDOFF_DYNAMIC_BLOB_TDIMT_ROOT_ID   = 2,
    HANDOFF_DYNAMIC_BLOB_NRX_MEM_POOL_ID = 3,
    // Note, must be last
    HANDOFF_DYNAMIC_BLOB_COUNT
} handoff_dynamic_blob_id_e;
typedef uint8_t handoff_dynamic_blob_id_t;

#define IS_HANDOFF_DYNAMIC_BLOB_SUPPORTED (MODULE_HV >= 3)

#define HANDOFF_DYNAMIC_BLOBS_SIZE (HANDOFF_BLOB_ENTRY_IOMMU_CONFIG_SIZE + \
                                    HANDOFF_BLOB_ENTRY_MMIOMT_ROOT_SIZE +  \
                                    HANDOFF_BLOB_ENTRY_TDIMT_ROOT_SIZE + \
                                    HANDOFF_BLOB_ENTRY_NRX_MEM_POOL_SIZE)

// Used as padding to achieve 4KB alignment
#define HANDOFF_RESERVED_V2_SIZE (3945)
#define HANDOFF_RESERVED_V3_SIZE (TDX_PAGE_SIZE_IN_BYTES - (HANDOFF_DYNAMIC_BLOBS_SIZE % TDX_PAGE_SIZE_IN_BYTES))

typedef struct td_preserving_hod_s
{
    handoff_data_header_t header;

    // v0 fields
    kot_entry_t kot_entries[MAX_HKIDS];           // was kot_entry_arr
    wbt_entry_t wbt_entries[MAX_PKGS];            // was wbt_entry_arr
    tdmr_entry_t tdmr_table[MAX_TDMRS];           // was tdmr_entry_arr
    uint32_t num_of_tdmr_entries;                 // unchanged
    uint16_t hkid;                                // unchanged
    uint32_t package_config_bitmap;               // was pkg_config_bitmap
    bool_t dynamic_pamt_enabled;                  // unchanged

    // v1 fields
    uint16_t td_build_count; // Not naturally aligned
    uint16_t mig_interrupted_count;

    // v2_v3 fields
    // Padding to complete 4KB alignment
    uint8_t round_up_to_4k_1[HANDOFF_RESERVED_V2_SIZE];
} td_preserving_hod_t;
tdx_static_assert((sizeof(td_preserving_hod_t) % TDX_PAGE_SIZE_IN_BYTES) == 0, td_preserving_hod_t);

#define TD_PRESERVING_HANDOFF_PAGE_COUNT (sizeof(td_preserving_hod_t) / TDX_PAGE_SIZE_IN_BYTES)

// Static asserts to ensure that the field sizes in tdx_module_global_t match td_preserving_hod_t
#define HANDOFF_KOT_ENTRIES_SIZE (sizeof_field(td_preserving_hod_t, kot_entries))
tdx_static_assert(sizeof_field(tdx_module_global_t, kot.entries) == sizeof_field(td_preserving_hod_t, kot_entries), TD_PRESERVING_HOD_KOT_ENTRIES_SIZE2);

#define HANDOFF_WBT_ENTRIES_SIZE (sizeof_field(td_preserving_hod_t, wbt_entries))
tdx_static_assert(sizeof_field(tdx_module_global_t, wbt_entries) == sizeof_field(td_preserving_hod_t, wbt_entries), PRESERVING_HOD_WBT_ENTRIES_SIZE2);

#define HANDOFF_TDMR_TABLE_SIZE (sizeof_field(td_preserving_hod_t, tdmr_table))
tdx_static_assert(sizeof_field(tdx_module_global_t, tdmr_table) == sizeof_field(td_preserving_hod_t, tdmr_table), PRESERVING_HOD_TDMR_TABLE_SIZE2);

#define HANDOFF_NUM_OF_TDMR_ENTRIES_SIZE (sizeof_field(td_preserving_hod_t, num_of_tdmr_entries))
tdx_static_assert(sizeof_field(tdx_module_global_t, num_of_tdmr_entries) == sizeof_field(td_preserving_hod_t, num_of_tdmr_entries), PRESERVING_HOD_NUM_OF_TDMR_ENTRIES_SIZE2);

#define HANDOFF_HKID_SIZE (sizeof_field(td_preserving_hod_t, hkid))
tdx_static_assert(sizeof_field(tdx_module_global_t, hkid) == sizeof_field(td_preserving_hod_t, hkid), PRESERVING_HOD_HKID_SIZE2);

#define HANDOFF_PACKAGE_CONFIG_BITMAP_SIZE (sizeof_field(td_preserving_hod_t, package_config_bitmap))
tdx_static_assert(sizeof_field(tdx_module_global_t, pkg_config_bitmap) == sizeof_field(td_preserving_hod_t, package_config_bitmap), PRESERVING_HOD_PACKAGE_CONFIG_BITMAP_SIZE2);

#define HANDOFF_DYNAMIC_PAMT_ENABLED_SIZE (sizeof_field(td_preserving_hod_t, dynamic_pamt_enabled))
tdx_static_assert(sizeof_field(tdx_module_global_t, dynamic_pamt_enabled) == sizeof_field(td_preserving_hod_t, dynamic_pamt_enabled), PRESERVING_HOD_DYNAMIC_PAMT_ENABLED_SIZE2);

#define HANDOFF_TD_BUILD_COUNT_SIZE (sizeof_field(td_preserving_hod_t, td_build_count))
tdx_static_assert(sizeof_field(tdx_module_global_t, td_build_count) == sizeof_field(td_preserving_hod_t, td_build_count), PRESERVING_HOD_TD_BUILD_COUNT_SIZE2);

#define HANDOFF_MIG_INTERRUPTED_COUNT_SIZE (sizeof_field(td_preserving_hod_t, mig_interrupted_count))
tdx_static_assert(sizeof_field(tdx_module_global_t, mig_interrupted_count) == sizeof_field(td_preserving_hod_t, mig_interrupted_count), PRESERVING_HOD_MIG_INTERRUPTED_COUNT_SIZE2);

tdx_static_assert((TDX_PAGE_SIZE_IN_BYTES - (offsetof(td_preserving_hod_t, round_up_to_4k_1) % TDX_PAGE_SIZE_IN_BYTES)) == HANDOFF_RESERVED_V2_SIZE, HANDOFF_RESERVED_V2_SIZE);


#pragma pack(pop)

#endif // __PRESERVING_DEFS_H__
