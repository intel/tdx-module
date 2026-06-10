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
 * @file iommu_defs.h
 * @brief IOMMU definitions and structures
 */

#ifndef IOMMU_DEFS_H_
#define IOMMU_DEFS_H_

#include "tdx_basic_types.h"
#include "helpers/tdx_locks.h"

// TODO change the interface in DMR to use the actual values
#define NUM_OF_SOCKETS (8)
#define NUM_OF_HIOPS (16)
#define NUM_OF_RP_DF (16) // This is only used for the MCHECK interface
#define NUM_OF_RP (8)
#define TOT_NUM_IOMMUS (NUM_OF_SOCKETS * NUM_OF_HIOPS)

#define MAX_NUM_IOMMU_IQ_PAGES (128)
#define IQ_ENTRY_SIZE_IN_BYTES (32)
#define NUM_IQ_ENTRIES_IN_PAGE (TDX_PAGE_SIZE_IN_BYTES / IQ_ENTRY_SIZE_IN_BYTES)

typedef enum
{
    IOMMU_ID     = 0x80000001,
    IOMMU_STATE  = 0x80000002,
    T_IQPAGE     = 0x80000003,
    IQCTXPAGE    = 0x80000004,
    T_RTPAGE     = 0x80000005,
    STINFOPA_0   = 0x80000006,
    STINFOPA_1   = 0x80000007,
    SPDMDIRPA    = 0x80000008,
    CONFIG_IOMMU = 0x80000009,
    CLEAR_IOMMU  = 0x8000000A,
    CONFIG_RP    = 0x8000000B,
    CLEAR_RP     = 0x8000000C,
    GCMD_REG     = 0x8000000D
} iommu_register_id_e ;

typedef enum
{
    IOMMU_STATE_INIT,
    IOMMU_STATE_CONFIGURED
} iommu_states_e;
typedef uint8_t iommu_states_t;

#pragma pack(push, 1)

typedef union
{
    struct
    {
        uint8_t hiop_id : 4;
        uint8_t socket_id : 4;
        uint8_t rsvd;
    };

    uint16_t raw;
} iommu_id_t;
tdx_static_assert(sizeof(iommu_id_t) == 2, iommu_id_t);

typedef union
{
    struct
    {
        iommu_id_t iommu_id;
        uint64_t rsvd : 48;
    };
    uint64_t raw;
} iommu_id_reg_t;
tdx_static_assert(sizeof(iommu_id_reg_t) == 8, iommu_id_reg_t);

typedef union
{
    struct
    {
        uint64_t size : 8;
        uint64_t rsvd : 4;
        uint64_t base : 52;
    };
    struct
    {
        uint64_t : 12;
        uint64_t page_4k_num : (MAX_PA - 12);
    };
    uint64_t raw;
} iq_buffer_t;
tdx_static_assert(sizeof(iq_buffer_t) == 8, iq_buffer_t);

typedef union
{
    struct
    {
        uint8_t dev_func;
        uint8_t bus;
    };
    uint16_t raw;
} rp_bdf_t;
tdx_static_assert(sizeof(rp_bdf_t) == 2, rp_bdf_t);

typedef union
{
    struct
    {
        rp_bdf_t rp_bdf;
    };
    // Done to preserve alignment
    struct
    {
        uint64_t : 16;
        uint64_t reserved : 48; // 64 - 16
    };
    uint64_t raw;
} rp_bdf_reg_t;
tdx_static_assert(sizeof(rp_bdf_reg_t) == 8, rp_bdf_reg_t);

typedef union
{
    struct
    {
        uint16_t did_msb : 5; // 4:0 MSB of widest domain ID supported
        uint16_t pds : 1;     // 5 Page-request drain support
        uint16_t rsvd : 10;   // 15:6
    };
    uint16_t raw;
} iommu_capabilities_t;
tdx_static_assert(sizeof(iommu_capabilities_t) == 2, iommu_capabilities_t);

#define HIOP_BAR_SIZE (64 * _1KB)
typedef ALIGN(8) struct
{
    uint64_t pmem_base;  // Prefetchable memory base
    uint64_t pmem_limit; // Prefetchable memory limit
    uint64_t bar_base;   // HIOP bar base (limit is always 64KB)
} hiop_pmem_bar_range_t;
tdx_static_assert(sizeof(hiop_pmem_bar_range_t) == 24, hiop_pmem_bar_range_t);

typedef union
{
    struct
    {
        uint16_t iose : 1;                              // [0] I/O Space Enable
        uint16_t mse : 1;                               // [1] emory Space Enable
        uint16_t bme : 1;                               // [2] Bus Master Enable
        uint16_t sce : 1;                               // [3] Special Cycle Enable
        uint16_t mwie : 1;                              // [4] Memory Write and Invalidate
        uint16_t VGA_PALETTE_SNOOP_ENABLE : 1;          // [5] VGA Palette Snoop
        uint16_t PERRE : 1;                             // [6] Parity Error Response
        uint16_t IDSEL_STEPPING_WAIT_CYCLE_CONTROL : 1; // [7] IDSEL Stepping/Wait Cycle Control
        uint16_t SERRE : 1;                             // [8] SERR Enable
        uint16_t FAST_BACK_TO_BACK_ENABLE : 1;          // [9] Fast Back-to-Back Transactions Enable
        uint16_t reserved : 6;                          // [15:10] zero
    };
    uint16_t raw;
} pmem_pcicmd_t;
tdx_static_assert(sizeof(hiop_pmem_bar_range_t) == 24, hiop_pmem_bar_range_t);

typedef ALIGN(8) struct
{
    iommu_states_t state;
    uint8_t padding;
    sharex_hp_lock_t lock;
    uint16_t rp_reg_sts; // rootport bitmap
    uint16_t active_spdm_session_count;
    uint8_t reserved[5]; // Added to preserve alignment
    uint8_t padding_1;
    iommu_capabilities_t iommu_cap;
    pa_t t_rtaddr;
    iq_buffer_t t_iqaddr;
    iq_buffer_t iqctxaddr;
    pa_t stinfopa_0;
    pa_t stinfopa_1;
    pa_t spdmdirpa;
    uint64_t iommu_generation;
    uint16_t iq_free_cnt;
    uint16_t padding2;
    uint32_t iq_sw_head_idx;
    uint64_t iommu_wac_value;
    uint64_t hiop_wac_value;
    uint64_t kcb_wac_value;
    uint64_t rp_wac_value[NUM_OF_RP];
    hiop_pmem_bar_range_t pmem_range[NUM_OF_RP];
    bool_t config_in_progress;
    bool_t clear_in_progress;
} iommu_config_t;
tdx_static_assert((offsetof(iommu_config_t, iommu_generation) % sizeof(uint64_t)) == 0, iommu_config_t);
tdx_static_assert(sizeof(iommu_config_t) == 362, iommu_config_t);

#pragma pack(pop)

#define MMCFG_RANGE_SIZE (_1MB)
// Complies with PAS0.76
typedef struct
{
    uint64_t hiop_mmioh_base;
    uint64_t hiop_mmioh_limit;
    uint64_t hiop_mmcfg_base;
    uint16_t hiop_rp_bit_vector;
    uint8_t hiop_bus_base;
    uint8_t hiop_bus_limit;
    // Offset to BANKn_BAR_1_1_0_CFG register. The offset and below are per RP, indexed by HIOP_RP_BIT_VECTOR
    uint16_t bar_offst[NUM_OF_RP];
    uint32_t reserved;
} hiop_info_t;
tdx_static_assert(sizeof(hiop_info_t) == 48, hiop_info_t);

// HIOP shadow registers. Note, BANKn_BAR_1_1_0_CFG register is the part of hiop_info_t above.
typedef struct
{
    uint16_t pcicmd_offst;
    uint16_t secbus_offst;
    uint16_t subbus_offst;
    uint16_t pbas_offst;
    uint16_t plim_offst;
    uint16_t pbasu_offst;
    uint16_t plimu_offst;
} hiop_shadow_regs_t;
tdx_static_assert(sizeof(hiop_shadow_regs_t) == 14, hiop_shadow_regs_t);

typedef struct
{
    uint16_t hiop_kcbar_offset;
    uint16_t hiop_iommu_vtbar_offset;
    uint16_t reserved_0;
    uint16_t rp_seam_os_w_pg_wac_offset;
    uint16_t hiop_seam_os_w_pg_wac_offset;
    uint16_t iommu_seam_os_w_pg_wac_offset;
    uint16_t reserved_1;
    uint16_t kcb_seam_os_w_pg_wac_offset;
    uint8_t hiop_rp_df[NUM_OF_RP_DF];
    uint64_t seam_only_sai_value;
    uint8_t reserved_2[24];
    hiop_info_t hiop_info[NUM_OF_HIOPS];
    hiop_shadow_regs_t pci_shadow[NUM_OF_RP];
    uint8_t reserved_3[76];
    uint8_t ide_ecap_num_lnk_ide_regs;
    uint8_t ide_ecap_num_sel_ide_regs;
    uint16_t ide_ecap_ofst;
} socket_io_info_t;
tdx_static_assert(sizeof(socket_io_info_t) == _1KB, socket_io_info_t);

typedef struct
{
    socket_io_info_t socket_io_info[NUM_OF_SOCKETS];
} io_system_info_table_t;
tdx_static_assert(sizeof(io_system_info_table_t) == (_1KB * NUM_OF_SOCKETS), io_system_info_table_t);

#endif // IOMMU_DEFS_H_
