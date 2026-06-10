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
 * @file dmar_defs.h
 * @brief DMAR definitions and structures
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDXIO_DMAR_DEFS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDXIO_DMAR_DEFS_H_

#include "memory_handlers/pamt_manager.h"

// Used by RTE
#define MAX_RT_ENTRIES_PER_PAGE    (TDX_PAGE_SIZE_IN_BYTES / sizeof(dmar_rte_t))
#define MAX_CT_ENTRIES_PER_PAGE    (TDX_PAGE_SIZE_IN_BYTES / sizeof(dmar_cte_t))

#define RTE_PDE_PASIDTE_LOCK_BIT (11UL)

// Used by CTE
#define PDTS_IDX_CONST (0X7U)
#define NUM_CT_PAGES_TO_MAP (0X1U)
#define MIN_NUM_PD_PAGES (0X1U)
#define MAX_NUM_PD_PAGES (32U)
#define MAX_PD_ENTRIES_PER_PAGE    (TDX_PAGE_SIZE_IN_BYTES / sizeof(dmar_pde_t))
#define CTE_LOCK_BIT (8UL)

// Used by PDE
#define NUM_PASIDT_PAGES_TO_MAP (0X1U)
#define MAX_PASIDT_ENTRIES_PER_PAGE (TDX_PAGE_SIZE_IN_BYTES / sizeof(dmar_pasidte_t))
#define GET_PD_NUM_OF_ENTRIES(cte_ptr) BIT(PDTS_IDX_CONST + cte_ptr->pdts)

// Used by PASIDTE
#define AW_48_BIT (0b10)
#define AW_57_BIT (0b11)

typedef union
{
    uint64_t qwords[8];
    uint32_t dwords[16];
    uint8_t bytes[64];
} uint512_t;
tdx_static_assert(sizeof(uint512_t) == 64, uint512_t);

/**
 * @brief Enum for different DMAR levels
 *        RTE is the highest level and PASIDTE is the leaf level
 */
typedef enum
{
    DMAR_PASIDTE_LVL = 0,
    DMAR_PDE_LVL     = 1,
    DMAR_CTE_LVL     = 2,
    DMAR_RTE_LVL     = 3,
    DMAR_INV_LVL     = 4
} dmar_lvl_e;
typedef uint8_t dmar_lvl_t;

/**
 * @brief Enum for different DMAR mapping states
 */
typedef enum
{
    DMAR_FREE            = 0,
    DMAR_PENDING         = 1,
    DMAR_BLOCKED         = 2,
    DMAR_PRESENT         = 3
} dmar_map_sts_e;
typedef uint8_t dmar_map_sts_t;

/**
 * @brief Enum for different DMAR invalidation states
 */
typedef enum
{
    DMAR_INV_PENDING = 0,
    DMAR_INV_QUEUED  = 1,
    DMAR_INV_DONE    = 3
} dmar_inv_sts_e;
typedef uint8_t dmar_inv_sts_t;

#pragma pack(push,1)
typedef union
{
    struct
    {
        dmar_lvl_t level :3;       // 2:0
        dmar_map_sts_t map_sts :8; // 10:3
        dmar_inv_sts_t inv_sts :3; // 13:11
        uint8_t pd_cnt :5;        // 18:14
    };
    // Done to preserve alignment
    struct
    {
        uint64_t :19;
        uint64_t rsvd :45;
    };
    uint64_t raw;
} dmar_state_info_t;
tdx_static_assert(sizeof(dmar_state_info_t) == 8, dmar_state_info_t);

typedef union
{
    struct
    {
        uint32_t level :3;   // 2:0 Lowest DMAR level dmar_walk should reach
        uint32_t rsvd :9;    // 11:3
        uint32_t pasid :20;  // 31:12
        rp_bdf_t rid;        // 47:32 Requester ID
        iommu_id_t iommu_id; // 64:48
    };

    struct
    {
        /**
         * Extract DMA indexing from RID and PASID bits
         */
        uint64_t :12;           // 11:0
        uint64_t pasidt_idx :6; // 17:12 PASID table index from RID and PASID
        uint64_t pd_idx :14;    // 31:18 PASID dir index from RID and PASID
        /**
         * @note RT 'steals' the upper bit of CT (of device number) and uses it to indicate if we are using the upper or lower context table.
         *       This is why CT's index is only 7 bits i.e. max 127 devices/functions.
         *       The following holds:
         *       1. RT is 8B and not 16B
         *       2. If the lower bit of rt_idx is set, then we are looking at the upper context table
         *       3. if the lower bit of rt_idx is not set, then we are looking at the lower context table
         *       4. We don't need to use a bdf_t param each time in order to know in which context table we are actually located in!
         */
        uint64_t ct_idx :7;  // 39:32 Context table index from RID and PASID
        uint64_t rt_idx :9;  // 47:40 Root table index from RID and PASID
    };

    uint64_t raw;
} dmar_idx_t;
tdx_static_assert(sizeof(dmar_idx_t) == 8, dmar_idx_t);

/**
 * @struct dmar_rte_t
 *
 * @brief Scalable-mode Root-Entry Format
 *
 * @note RT 'steals' the upper bit of CT (of device number) and uses it to indicate if we are using the upper or lower context table.
 *       The following holds:
 *       1. RT is 8B and not 16B
 *       2. If the lower bit of dmar_idx_t.rt_idx is set, then we are looking at the upper context table
 *       3. if the lower bit of dmar_idx_t.rt_idx is not set, then we are looking at the lower context table
 *       4. We don't need to use a bdf_t param each time in order to know in which context table we are actually located in!
 */
typedef union
{
    struct
    {
        uint64_t p :1;      // 0 Present
        uint64_t rsvd :11;  // 11:1 Full reserved bit-field
        uint64_t ctp :52;   // 63:12 Context Table Pointer
    };

    struct
    {
        uint64_t :8;           // 7:0
        uint64_t inv_state :2; // 9:8 SW managed field for storing the entry invalidation state
        uint64_t blocked :1;   // 10 blocked state - SW managed field for storing the entry state
        uint64_t locked :1;    // 11 lock bit (part of reserved)
    };

    uint64_t raw;
} dmar_rte_t;
tdx_static_assert(sizeof(dmar_rte_t) == 8, dmar_rte_t);

/**
 * @brief Enum for different Root Table Entry states
 */
typedef enum
{
    DMAR_RTE_FREE           = 0x000,
    DMAR_RTE_PRESENT        = 0x001,
    DMAR_RTE_BLOCKED        = 0x400,
    DMAR_RTE_STATE_BIT_MASK = 0x401,
    DMAR_RTE_RESET_STATE_BIT_MASK = 0x701
} dmar_rte_state_e;

/**
 * @struct dmar_cte_t
 *
 * @brief Scalable-Mode Context-Entry Format
 */
typedef union
{
    struct
    {
        uint64_t p :1;            // 0 Present
        uint64_t fpd :1;          // 1 Fault Processing Disable
        uint64_t dte :1;          // 2 Device-TLB Enable
        uint64_t paside :1;       // 3 PASID Enable
        uint64_t pre :1;          // 4 Page Request Enable
        uint64_t rsvd1 :4;        // 8:5 Full reserved1 bit-field
        uint64_t pdts :3;         // 11:9 PASID Directory Size, value of X in this field indicates that the PASID-directory has 2^(X+7) entries
        uint64_t pasiddirptr :52; // 63:12 PASID Directory Pointer

        uint64_t rid_pasid :20; // 83:64 Requester ID to PASID Assignment
        uint64_t rid_priv :1;   // 84 Requester ID to Privilege Mode Requested Assignment
        uint64_t rsvd2 :43;     // 127:85  Full reserved2 bit-field

        uint64_t rsvd3; // 191:128 Full reserved3 bit-field
        uint64_t rsvd4; // 255:192  Full reserved4 bit-field
    };

    struct
    {
        uint64_t :7;         // 6:0
        uint64_t blocked :1; // 7 blocked state - SW managed field for storing the entry state
        uint64_t locked :1;  // 8 lock bit
    };

    struct
    {
        uint64_t :64;                    // 63:0
        uint64_t pasidt_idx :6;          // 69:64 PASID table index from RID and PASID
        uint64_t pd_idx :14;             // 83:70 PASID dir index from RID and PASID
        uint64_t :1;                     // 84
        uint64_t inv_state :2;           // 86:85 SW managed field for storing the entry invalidation state
        uint64_t :36;                    // 122:87
        uint64_t pde_cnt :5;             // 127:123
    };

    uint256_t raw;
} dmar_cte_t;
tdx_static_assert(sizeof(dmar_cte_t) == 32, dmar_cte_t);

/**
 * @brief Enum for different Context Entry states
 */
typedef enum
{
    DMAR_CTE_FREE           = 0x000,
    DMAR_CTE_PRESENT        = 0x001,
    DMAR_CTE_BLOCKED        = 0x080,
    DMAR_CTE_STATE_BIT_MASK = 0x081
} dmar_cte_state_e;

/**
 * @struct dmar_pde_t
 *
 * @brief Scalable-Mode PASID Directory Entry Format
 */
typedef union
{
    struct
    {
        uint64_t p :1;          // 0 Present
        uint64_t fpd :1;        // 1 Fault Processing Disable
        uint64_t rsvd :10;       // 11:2 Reserved
        uint64_t smptblptr :52; // 63:12 Scalable Mode PASID Table Pointer
    };

    struct
    {
        uint64_t :8;           // 7:0
        uint64_t inv_state :2; // 9:8 SW managed field for storing the entry invalidation state
        uint64_t blocked :1;   // 10 blocked state - SW managed field for storing the entry state
        uint64_t locked :1;    // 11 lock bit
    };

    uint64_t raw;
} dmar_pde_t;
tdx_static_assert(sizeof(dmar_pde_t) == 8, dmar_pde_t);

typedef enum
{
    DMAR_PDE_FREE           = 0x000,
    DMAR_PDE_PRESENT        = 0x001,
    DMAR_PDE_BLOCKED        = 0x401,
    DMAR_PDE_STATE_BIT_MASK = 0x401,
    DMAR_PDE_RESET_STATE_BIT_MASK = 0x701
} dmar_pde_state_e;

/**
 * @struct dmar_pasidte_t
 *
 * @brief Scalable-Mode PASID Table Entry Format Format
 */
typedef union
{
    struct
    {
        uint64_t p :1;        // 0 Present
        uint64_t fpd :1;      // 1 Fault Processing Disable
        uint64_t aw :3;       // 4:2 Address Width
        uint64_t slee :1;     // 5 Second-Level Execute Enable
        uint64_t pgtt :3;     // 8:6 PASID Granular Translation Type
        uint64_t slade :1;    // 9 Second Level Access/Dirty bit Enable
        uint64_t rsvd1 :2;    // 11:10 Reserved1
        uint64_t slptptr :52; // 63:12 Second Level Page Table Pointer

        uint64_t did :16;  // 79:64 Domain Identifier
        uint64_t rsvd2 :7; // 86:80 Reserved2
        uint64_t pwsnp :1; // 87 Page-walk Snoop
        uint64_t pgsnp :1; // 88 Page Snoop
        uint64_t cd :1;    // 89 Cache Disable
        uint64_t emte :1;  // 90 Extended Memory Type Enable
        uint64_t emt :3;   // 93:91 Extended Memory Type
        uint64_t pwt :1;   // 94
        uint64_t pcd :1;   // 95
        uint64_t pat :32;  // 127:96 Page Attribute Table

        uint64_t sre :1;      // 128 Supervisor Request Enable
        uint64_t ere :1;      // 129 Execute Requests Enable
        uint64_t flpm :2;     // 131:130 First Level Paging Mode
        uint64_t wpe :1;      // 132 Write Protect Enable
        uint64_t nxe :1;      // 133 No Execute Enable
        uint64_t smep :1;     // 134 Supervisor Mode Execute Prevention
        uint64_t eafe :1;     // 135 Extended Accessed Flag Enable
        uint64_t rsvd3 :4;    // 139:136 Reserved3
        uint64_t flptptr :52; // 191:140 First Level Page Translation Pointer

        uint64_t rsvd4; // 255:192 Full reserved4 bit-field
        uint64_t rsvd5; // 319:256 Full reserved5 bit-field
        uint64_t rsvd6; // 383:320 Full reserved6 bit-field
        uint64_t rsvd7; // 447:384 Full reserved7 bit-field
        uint64_t rsvd8; // 511:448 Full reserved8 bit-field
    };

    struct
    {
        uint64_t :10;        // 9:0
        uint64_t blocked :1; // 10 blocked state - SW managed field for storing the entry state
        uint64_t locked :1;  // 11 lock bit
        uint64_t :51;        // 62:10
        uint64_t pending :1; // 63
    };

    struct
    {
        uint64_t :64;          // 63:0
        uint64_t :16;          // 79:64
        uint64_t inv_state :2; // 81:80 SW managed field for storing the entry invalidation state
    };

    uint512_t raw;
} dmar_pasidte_t;
tdx_static_assert(sizeof(dmar_pasidte_t) == 64, dmar_pasidte_t);

typedef enum
{
    DMAR_PASIDTE_FREE            = 0x000,
    DMAR_PASIDTE_PRESENT         = 0x001,
    DMAR_PASIDTE_BLOCKED         = 0x400,
    DMAR_PASIDTE_PENDING         = 0x8000000000000000, // = 2^63
    DMAR_PASIDTE_STATE_BIT_MASK  = 0x8000000000000401
} dmar_pasidte_state_e;

#pragma pack(pop)

typedef union
{
    dmar_rte_t rte;
    dmar_cte_t cte;
    dmar_pde_t pde;
    dmar_pasidte_t pasidte;
    uint512_t raw;
} dmar_entry_t;
tdx_static_assert(sizeof(dmar_entry_t) == 64, dmar_entry_t);

typedef struct
{
    dmar_lvl_t dmar_level; // Lowest DMAR level visited by the DMAR walk function

    // Flag indicating the DMAR walk was successful and the entry
    // lock of the last reached level(i.e.DMAR_LEVEL) was acquired
    bool_t entry_locked;

    dmar_rte_t *rte_ptr;
    pamt_entry_t *rt_pamt_ptr;
    pa_t rte_pa;

    dmar_cte_t *cte_ptr;
    pamt_entry_t *ct_pamt_ptr;
    pa_t cte_pa;

    dmar_pde_t *pde_ptr;
    pamt_entry_t *pd_pamt_ptr;
    pa_t pde_pa;

    dmar_pasidte_t *pasidte_ptr;
    pamt_entry_t *pasidt_pamt_ptr;
    pa_t pasidte_pa;
} dmar_walk_res_t;

typedef union
{
    struct
    {
        uint64_t vm_idx : 8; // Bits [7:0]: VM_IDX, 0:L1 SEPT, 1-3:L2 VM 1-3 SEPT
        uint64_t pasid : 20; // Bits [27:8]: Reserved for Gen2. Must be 0.
        uint64_t rsrvd : 36; // Bits [28:63]: Reserved for Gen2. Must be 0
    };
    uint64_t raw;
} dmar_target_t;
tdx_static_assert(sizeof(dmar_target_t) == 8, dmar_target_t);


#endif /* SRC_COMMON_DATA_STRUCTURES_TDXIO_DMAR_DEFS_H_ */
