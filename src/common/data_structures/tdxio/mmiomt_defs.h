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
 * @file mmiomt_defs.h
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_MMIOMT_DEFS_H_
#define SRC_COMMON_DATA_STRUCTURES_MMIOMT_DEFS_H_

#include "x86_defs/x86_defs.h"
#include "memory_handlers/pamt_manager.h"
#include "tdisp_defs.h"

// Bit 0 indicates the exclusive lock in mmiomt_entry_t, i.e. Qnode as well as data node
#define MMIOMT_ENTRY_XLOCK_BIT (0UL)
#define MMIOMT_QNODE_TBL_SIZE (128)

typedef enum
{
    MMIOMT_QNODE = 0,
    MMIOMT_DATA  = 1
} mmiomt_type_e;
typedef uint8_t mmiomt_type_t;

/**
 * @brief Enumeration of MMIOMT entry levels
 */
typedef enum
{
    // Level 0 MMIOMT entry that can have type QNODE with all present bits clear (i.e. free) or DATA holding the metadata of a 4KB MMIO page
    MMIOMT_L0 = 0,
    // Level 1 MMIOMT entry that can have type QNODE or DATA holding the metadata of a 2MB MMIO page
    MMIOMT_L1 = 1,
    // Level 2 MMIOMT entry that can have type QNODE or DATA holding the metadata of a 1GB MMIO page
    MMIOMT_L2 = 2,
    // Level 3 MMIOMT entry of QNODE type
    MMIOMT_L3 = 3,
    // Level 4 MMIOMT entry of QNODE type
    MMIOMT_L4 = 4,
    // MMIOMT root level entry of QNODE type
    MMIOMT_L_ROOT = 5,
} mmiomt_lvl_e;
typedef uint8_t mmiomt_lvl_t;

typedef union
{
    struct
    {
        uint64_t level :3;  // [2:0] ID of IOMMU hosting the DMAR table
        uint64_t rsvd1 :9;  // [11:3] Requister ID
        uint64_t pa :40;    // [51:12] MMIO physical address
        uint64_t rsvd2 :12; // [63:52]
    };

    struct
    {
        uint64_t low_21_bits : 21;
        uint64_t page_2m_num : (MAX_PA - 21);
    };

    struct
    {
        uint64_t low_30_bits : 30;
        uint64_t page_1g_num : (MAX_PA - 30);
    };

    struct
    {
        uint64_t :12;                        // [11:0] Unused
        uint64_t l0_idx :7;                  // [18:12] L0 entry idx
        uint64_t l1_q_idx :2;                // [20:19] Qword idx in L1 entry
        uint64_t l1_idx :7;                  // [27:21] L1 entry idx
        uint64_t l2_q_idx :2;                // [29:28] Qword idx in L2 entry
        uint64_t l2_idx :7;                  // [36:30] L2 entry idx
        uint64_t l3_q_idx :2;                // [38:37] Qword idx in L3 entry
        uint64_t l3_idx :7;                  // [45:39] L3 entry idx
        uint64_t l4_q_idx :2;                // [47:46] Qword idx in L4 entry
        uint64_t l4_idx :MAX_PA - 48;        // [MAX_HPA - 1:48] L4 entry idx
    };
    uint64_t raw;
} mmiomt_idx_t;
tdx_static_assert(sizeof(mmiomt_idx_t) == 8, mmiomt_idx_t);

/**
 * @brief Inner node within the Qnode
 */
typedef union
{
    struct
    {
        uint64_t rsvd1 :11; // [10:0]
        uint64_t p :1;      // [11] Present flag
        uint64_t pa :40;    // [51:12] HPA address of next MMIOMD page
        uint64_t rsvd2 :12; // [63:52]
    };
    uint64_t raw;
} mmiomt_node_t;
tdx_static_assert(sizeof(mmiomt_node_t) == 8, mmiomt_node_t);

/**
 * @note Only the first bit in @struct mmiomt_qnode_t holds an exclusive xlock
 */
typedef mmiomt_node_t mmiomt_qnode_t[MMIOMT_L4];
tdx_static_assert(sizeof(mmiomt_qnode_t) == 32, mmiomt_qnode_t);

typedef union
{
    struct
    {
        uint64_t rsvd :3;   // [2:0] Includes type && xlock
        uint64_t mapped :1; // [3] Flag indicating the MMIO page is mapped (when set the MMIOMT entry cannot be set or removed)
        uint64_t rsvd1 :8;  // [11:4]
        uint64_t function_id :32; // [43:12] FUNCTION_ID the MMIO page is used for
        uint64_t rsvd2 :20; // [63:44]

        bepoch_t bepoch; // [127:64]

        uint64_t rsvd3; // [191:128]
        uint64_t rsvd4; // [255:192]
    };
    uint256_t raw;
} mmiomt_data_t;
tdx_static_assert(sizeof(mmiomt_data_t) == 32, mmiomt_data_t);

typedef union
{
    struct
    {
        uint64_t xlock :1; // Exclusive lock
        uint64_t type :2;
    };

    mmiomt_qnode_t qnode;
    mmiomt_data_t data;
    uint256_t raw;
} mmiomt_entry_t;
tdx_static_assert(sizeof(mmiomt_entry_t) == 32, mmiomt_entry_t);

typedef union
{
    struct
    {
        uint64_t type :2;
        uint64_t rsvd1 :10;
        uint64_t function_id :32;
        uint64_t rsvd2 :20;
    };
    uint64_t raw;
} mmiomt_set_info_t;
tdx_static_assert(sizeof(mmiomt_set_info_t) == 8, mmiomt_set_info_t);

typedef struct
{
    mmiomt_idx_t mmiomt_idx;                            // Index includes lowest reached level
    bool_t entry_locked;                                // Flag indicating whether entry at LEVEL was exclusively locked (using the entry lock).
    mmiomt_entry_t *mmiomt_path_arr[MMIOMT_L_ROOT + 1]; // Array of L0 … L4 QNODE/DATA entry pointers (only valid where index >= LEVEL).
    pamt_walk_result_t pamt_walk_result_arr[MMIOMT_L_ROOT]; // Array of PAMT walk results per MMIOMT walk
} mmiomt_walk_res_t;

#endif /* SRC_COMMON_DATA_STRUCTURES_MMIOMT_DEFS_H_ */
