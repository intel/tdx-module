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
 * @file inv_queue_defs.h
 * @brief Invalidation Queue definitions and structures
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDXIO_INVQUEUE_DEFS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDXIO_INVQUEUE_DEFS_H_

#include "tdx_basic_types.h"

#pragma pack(push, 1)

typedef enum
{
    INV_REQ_IOTLB   = 0x00,
	INV_REQ_RTE     = 0x01,
    INV_REQ_CTE     = 0x02,
    INV_REQ_PDE     = 0x03,
    INV_REQ_PASIDTE = 0x04,
    INV_REQ_TD      = 0x05,
    INV_REQ_MAX
} inv_req_type_e;
typedef uint32_t inv_type_t;

typedef enum
{
    INV_DESC_CC   = 1,
    INV_DESC_IOTLB = 2,
    INV_DESC_WAIT  = 5,
    INV_DESC_PC    = 7
} inv_desc_type_e;

#define INV_WAIT_DESC_SIZE (1) // Wait descriptor only
#define INV_REQ_AND_WAIT_DESC_SIZE (2) // Invalidation + Wait descriptors
#define INV_REQ_WAIT_AND_IOTLB_DESC_SIZE (3)// Invalidation + IOTLB + Wait descriptors

#define CC_G_GLOBAL (1)
#define PC_G_PASID_SELECTIVE_WITHIN_DOMAIN (1)
#define IOTLB_G_DOMAIN_SELECTIVE (2)
#define IOTLB_G_PAGE_SELECTIVE_WITHIN_DOMAIN (3)

/**
 * @struct iotlb_inv_tracker_t
 *
 * @brief An array of IOTLB_INV_TRACKER_T fields is used to track IOTLB invalidations per IOMMU and per TD.
 */
typedef union
{
    struct
    {
        uint64_t pasidte_ref_cnt : 37; //RID size (16) + PASID size (20) + 1
        uint64_t inv_req : 1;
        uint64_t inv_epoch : 1;
        uint64_t reserved : 25;
    };
    uint64_t raw;
} iotlb_inv_tracker_t;
tdx_static_assert(sizeof(iotlb_inv_tracker_t) == 8, iotlb_inv_tracker_t);

/**
 * @struct inv_desc_cc_t
 *
 * @brief Context-cache invalidate descriptor
 */
typedef union
{
    struct
    {
        uint64_t type : 4; // Constant 0x1
        uint64_t granularity : 2;
        uint64_t rsvd0 : 10;
        uint64_t did : 16;    // Domain ID
        uint64_t sid : 16;    // Source ID
        uint64_t fm : 2; // Function maks
        uint64_t rsvd1 : 14;
        uint64_t rsvd2;
        uint64_t rsvd3;
        uint64_t rsvd4;
    };
    uint256_t raw;
} inv_desc_cc_t;
tdx_static_assert(sizeof(inv_desc_cc_t) == 32, inv_desc_cc_t);

/**
 * @struct inv_desc_pc_t
 *
 * @brief PASID-cache invalidate descriptor
 */
typedef union
{
    struct
    {
        uint64_t type : 4; // Constant 0x7
        uint64_t granularity : 2;
        uint64_t rsvd0 : 10;
        uint64_t did : 16;        // Domain ID
        uint64_t pasid : 20; // PASID
        uint64_t rsvd1 : 12;
        uint64_t rsvd2;
        uint64_t rsvd3;
        uint64_t rsvd4;
    };
    uint256_t raw;
} inv_desc_pc_t;
tdx_static_assert(sizeof(inv_desc_pc_t) == 32, inv_desc_pc_t);

/**
 * @struct inv_desc_iotlb_t
 *
 * @brief IOTLB-cache invalidate descriptor
 */
typedef union
{
    struct
    {
        uint64_t type : 4;
        uint64_t granularity : 2;
        uint64_t drain_writes : 1;
        uint64_t drain_reads : 1;
        uint64_t rsvd0 : 8;
        uint64_t did : 16;
        uint64_t rsvd1 : 32;

        uint64_t am : 6;
        uint64_t ih : 1;
        uint64_t rsvd2 : 5;
        uint64_t addr : 52;

        uint64_t rsvd3;
        uint64_t rsvd4;
    };
    uint256_t raw;
} inv_desc_iotlb_t;
tdx_static_assert(sizeof(inv_desc_iotlb_t) == 32, inv_desc_iotlb_t);

/**
 * @struct inv_desc_wait_t
 *
 * @brief Wait invalidate descriptor
 */
typedef union
{
    struct
    {
        uint64_t type : 4; // Constant 0x5
        uint64_t interrupt_flag : 1;
        uint64_t status_write : 1;
        uint64_t fence_flag : 1;
        uint64_t pg_request_drain : 1;
        uint64_t rsvd0 : 1;
        uint64_t type_2 : 3;
        uint64_t rsvd1 : 20;
        uint64_t status_data : 32;

        uint64_t status_address;
        uint64_t rsvd2;
        uint64_t rsvd3;
    };
    uint256_t raw;
} inv_desc_wait_t;
tdx_static_assert(sizeof(inv_desc_wait_t) == 32, inv_desc_wait_t);

/**
 * @struct inv_desc_t
 *
 * @brief Invalidate descriptor
 */
typedef union
{
    uint64_t type : 4;
    inv_desc_cc_t cc;
    inv_desc_pc_t pc;
    inv_desc_iotlb_t iotlb;
    inv_desc_wait_t wait;
    uint256_t raw;
} inv_desc_t;
tdx_static_assert(sizeof(inv_desc_t) == 32, inv_desc_t);

/**
 * @struct iq_ctx_entry_t
 *
 * @brief IQ Context metadata structure
 */
typedef union
{
    struct
    {
        uint64_t track_flag : 1;
        uint64_t inv_req_type : 4;
        uint64_t rsvd0 : 59;

        pa_t inv_target_pa;

        uint64_t rsvd1;
        uint64_t rsvd2;
    };
    uint256_t raw;
} iq_ctx_entry_t;

typedef union
{
    struct
    {
        rp_bdf_t rid; // Requester ID (BDF)
        uint16_t rsvd0;
        uint32_t pasid : 20;
        uint32_t rsvd1 : 12;
    };
    uint64_t raw;
} rid_pasid_t;
tdx_static_assert(sizeof(rid_pasid_t) == 8, rid_pasid_t);

#define MAX_TD_INV_DES_COUNT (TDX_PAGE_SIZE_IN_BYTES / sizeof(inv_desc_t))

typedef union
{
    struct
    {
        inv_type_t inv_type;
        uint16_t pool_size; // Number of descriptors VMM commits in this request
        uint16_t reserved;  // must be zero
    };
    uint64_t raw;
} inv_req_type_t;
tdx_static_assert(sizeof(inv_req_type_t) == 8, inv_req_type_t);

#pragma pack(pop)

#endif /* SRC_COMMON_DATA_STRUCTURES_TDXIO_INVQUEUE_DEFS_H_ */
