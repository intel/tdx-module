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
 * @file vtbar_defs.h
 * @brief
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDXIO_VTBAR_DEFS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDXIO_VTBAR_DEFS_H_

#include "tdx_basic_types.h"

#pragma pack(push, 1)

#define VTBAR_GSTS_RESET_ONE_SHOT_BITS_MASK (0x96ffffff)

// truncated layout of CAP_REG
typedef union
{
    struct
    {
        uint64_t nd : 3; // Number of domains supported
        uint64_t : 61;
    };
    uint64_t raw;
} vtbar_cap_reg_t;
tdx_static_assert(sizeof(vtbar_cap_reg_t) == 8, vtbar_cap_reg_t);

typedef union
{
    struct
    {

        uint64_t : 42;    // TDX-IO don't care
        uint64_t pds : 1; // PDS: Page-request Drain Support
        uint64_t : 21;    // TDX-IO don't care
    };
    uint64_t raw;
} vtbar_ecap_reg_t;
tdx_static_assert(sizeof(vtbar_ecap_reg_t) == 8, ecap_reg_t);

// Root Table Address register
typedef union
{
    struct
    {
        uint64_t reserved : 10;
        // TTM: Translation table mode, TDX-IO supports only 0x01 (scalable mode)
        uint64_t ttm : 2;
        // Root table address
        uint64_t rta : 52;
    };
    uint64_t raw;
} rta_addr_reg_t;
tdx_static_assert(sizeof(rta_addr_reg_t) == 8, rta_addr_reg_t);

// Invalidation Queue Head register
typedef union
{
    struct
    {
        uint64_t reserved1 : 5;
        // Queue head
        uint64_t qh_idx : 14; // 256bit granularity suitable for inv descriptors
        // Root table address
        uint64_t reserved2 : 45;
    };
    uint64_t raw;
} iqh_reg_t;
tdx_static_assert(sizeof(iqh_reg_t) == 8, iqh_reg_t);

// Invalidation Queue Tail register
typedef union
{
    struct
    {
        uint64_t reserved1 : 5;
        // Queue tail
        uint64_t qt_idx : 14; // 256bit granularity suitable for inv descriptors
        // Root table address
        uint64_t reserved2 : 45;
    };
    uint64_t raw;
} iqt_reg_t;
tdx_static_assert(sizeof(iqt_reg_t) == 8, iqt_reg_t);

// Invalidate Queue Address register
typedef union
{
    struct
    {
        // Queue Size
        uint64_t qs : 3;
        uint64_t reserved : 8;
        // Descriptor width
        uint64_t dw : 1;
        // Queue base address
        uint64_t iqa : 52;
    };
    uint64_t raw;
} iqa_reg_t;
tdx_static_assert(sizeof(iqa_reg_t) == 8, iqa_reg_t);

typedef union
{
    struct
    {
        // TDX mode bit, when set to 1, the IOMMU is in TDX mode
        uint64_t tm : 1;
        // The number of physical address bits starting at
        // (HAW-1) that are reserved for Intel TDX use to
        // encode TDX private Key ID.
        uint64_t l : 4;
        // Reserved
        uint64_t rsvd : 59;
    };
    uint64_t raw;
} tdx_mode_reg_t;
tdx_static_assert(sizeof(tdx_mode_reg_t) == 8, tdx_mode_reg_t);

// Global status register
typedef union
{
    struct
    {
        // 22:0, Reserved
        uint32_t : 23;
        // 23, CFIS: Compatibility format interrupt status
        uint32_t cfis : 1;
        // 24, Interrupt remapping table pointer status
        uint32_t irtps : 1;
        // 25, Interrupt remapping enable status
        uint32_t ires : 1;
        // 26, Queued invalidation enable status
        uint32_t qies : 1;
        // 27, Write buffer flush status
        uint32_t wbfs : 1;
        // 28, Advanced fault logging status
        uint32_t afls : 1;
        // 29, Fault logging status
        uint32_t fls : 1;
        // 30, Root table pointer status
        uint32_t rtps : 1;
        // 31, Translation enable status
        uint32_t tes : 1;
    };
    uint32_t raw;
} gsts_reg_t;
tdx_static_assert(sizeof(gsts_reg_t) == 4, gsts_reg_t);

#define VTBAR_GCMD_SRTP_BIT_POS (30)

#define GCMD_TE_BIT_POS  (31)
#define GCMD_QIE_BIT_POS  (26)
// Global command register
typedef union
{
    struct
    {
        uint32_t bit_pos : 5;
        uint32_t bit_val : 1;
        uint32_t rsvd : 26;
    };
    uint32_t raw;
} gcmd_input_t;
tdx_static_assert(sizeof(gcmd_input_t) == 4, gcmd_input_t);

typedef union
{
    struct
    {
        uint32_t prs : 1;
        uint32_t rsvd : 30;
        uint32_t epm : 1;
    };
    uint32_t raw;
} pmen_reg_t;
tdx_static_assert(sizeof(pmen_reg_t) == 4, pmen_reg_t);

typedef union
{
    struct
    {
        uint64_t rsvd0 : 1;
        // TDX Mode Status    0: TDX mode disabled
        uint64_t tms : 1;
        uint64_t rsvd1 : 62;
    };
    uint64_t raw;
} ests0_reg_t;
tdx_static_assert(sizeof(ests0_reg_t) == 8, ests0_reg_t);

typedef enum
{
    ECMD_CMD_SET_TDX_MODE = 1,
    ECMD_CMD_RESET_PERFMON_COUNTER_CONFIGURATION = 242
} ecmd_cmds_e;
typedef uint8_t ecmd_cmds_t;

typedef union
{
    struct
    {
        // Writes to this field are dropped while ERESP_REG.IP is 1. White to this field clear all fields in enhanced command response register and sets ERESP_REG.IP to 1.
        // Commands of interest to TDX-IO are listed below:
        // 01: SET_TDX_MODE
        // 242: RESET_PERFMON_COUNTER_CONFIGURATION
        uint64_t cmd : 8;
        uint64_t rsvd : 8;
        // 63:16  OA: Operand A   Operand specification is command specific. Writes to this field are dropped while ERESP_REG.IP is 1.
        // This field is unused for the two commands listed above that are of interest for TDX-IO.
        uint64_t operand_a : 48;
    };
    uint64_t raw;
} ecmd_reg_t;
tdx_static_assert(sizeof(ecmd_reg_t) == 8, ecmd_reg_t);

typedef union
{
    struct
    {
        uint64_t ip : 1; //  In Progress (0: Command has been completed, 1: Command is in progress)
        uint64_t sc : 7; //  Status Code (0: Command successful, 1 - unknown cmd, 2 - abort due to in-flight GCMD/PMR, other - reserved)
        uint64_t dont_care : 56;
    };
    uint64_t raw;
} ecrsp_reg_t;
tdx_static_assert(sizeof(ecrsp_reg_t) == 8, ecrsp_reg_t);

typedef struct
{
    // Use dedicated accessors to access specific registers
    uint8_t raw[_4KB];
} vtbar_t;

#define VTBAR_ENABLE_BIT (0)
#define VTBAR_SIZE (_1KB * 64)

typedef enum
{
    // Taken from VT-d spec
    VTBAR_GCMD_REG_OFFSET = 0x18,
    VTBAR_GSTS_REG_OFFSET = 0x1C,
    VTBAR_PMEN_REG_OFFSET = 0x64
} vtbar_32_reg_e;

// Taken from TDX_IO PAS 0.79
typedef enum
{
    VTBAR_CAP_REG_OFFSET      = 0x8,
    VTBAR_RTADDR_REG_OFFSET   = 0x20,
    VTBAR_ECAP_REG_OFFSET     = 0x10,
    VTBAR_TDX_MODE_REG_OFFSET = 0x220,
    VTBAR_T_RTADDR_REG_OFFSET = 0x228,
    VTBAR_T_IQH_REG_OFFSET    = 0x230,
    VTBAR_T_IQT_REG_OFFSET    = 0x238,
    VTBAR_T_IQA_REG_OFFSET    = 0x240,
    VTBAR_ECMD_REG_OFFSET     = 0x400,
    VTBAR_ECRSP_REG_OFFSET    = 0x410,
    VTBAR_ESTS0_REG_OFFSET    = 0x420
} vtbar_64_reg_e;

#pragma pack(pop)

#endif /* SRC_COMMON_DATA_STRUCTURES_TDXIO_VTBAR_DEFS_H_ */
