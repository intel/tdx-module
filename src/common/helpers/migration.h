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
/*
 * migration.h
 *
 *  Created on: 8 Mar 2021
 *      Author: pstedev
 */

#ifndef SRC_COMMON_HELPERS_MIGRATION_H_
#define SRC_COMMON_HELPERS_MIGRATION_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "tdx_api_defs.h"
#include "accessors/ia32_accessors.h"
#include "debug/tdx_debug.h"
#include "helpers/error_reporting.h"
#include "crypto/aes_gcm.h"
#include "data_structures/tdx_tdvps.h"


/*********************************************
* MIGRATION BUNDLE HEADER
*********************************************/
#define SIZE_FIELDS_INCLUDED_IN_MBMD_HEADER_MAC 24
#define SIZE_OF_MBMD_STATE 8
#define MAC256_LEN 16
#define TOTAL_MDMD_SIZE ((SIZE_FIELDS_INCLUDED_IN_MBMD_HEADER_MAC) + (SIZE_OF_MBMD_STATE) + (MAC256_LEN))

#define NUM_SYS_STATE_EXPORT_PAGES           1   // Num pages used by TDH.EXPORT.STATE.IMMUTABLE for the SYS MD list

#define MIN_TD_IMMUTABLE_STATE_EXPORT_PAGES  4
#define MIN_TD_STATE_EXPORT_PAGES            2
#define MIN_VP_STATE_EXPORT_PAGES            5

#define MIN_TD_IMMUTABLE_STATE_IMPORT_PAGES  2   // Not including the pages for SYS metadata
#define MIN_TD_STATE_IMPORT_PAGES            1
#define MIN_VP_STATE_IMPORT_PAGES            4

// One page for SYS MD list + 1 page for TD Metadata (-1 for the last page number)
#define MIN_IMPORT_STATE_IMMUTABLE_LAST_ENTRY ((NUM_SYS_STATE_EXPORT_PAGES) + (MIN_TD_IMMUTABLE_STATE_IMPORT_PAGES) -1)

/*********************************************
* MIGRATION EPOCH
*********************************************/
#define MIG_EPOCH_OUT_OF_ORDER    0xFFFFFFFFUL // Special value of MIG_EPOCH to indicate out-of-order phase
#define MAX_EXPORT_COUNT          0x7FFFFFFFUL // Maximum allowed value of TDCS.EXPORT_COUNT (bit 31 must be 0)

typedef enum mb_type_e
{
    MB_TYPE_IMMUTABLE_TD_STATE = 0,
    MB_TYPE_MUTABLE_TD_STATE   = 1,
    MB_TYPE_MUTABLE_VCPU_STATE = 2,
    MB_TYPE_MEM                = 16,
    MB_TYPE_EPOCH_TOKEN        = 32,
    MB_TYPE_ABORT_TOKEN        = 33,
    MB_TYPE_MAX_MB_TYPE        = 33
} mb_type_t;

typedef struct PACKED mbmd_header_s
{
    union {
        struct {
            uint16_t  size;          // Offset 0
            uint16_t  mig_version;   // Offset 2
            uint16_t  migs_index;    // Offset 4
            uint8_t   mb_type;       // Offset 6
            uint8_t   reserved_1;    // Offset 7
            uint32_t  mb_counter;    // Offset 8
            uint32_t  mig_epoch;     // Offset 12
            uint64_t  iv_counter;    // Offset 16
        };
        uint8_t   fields_included_in_mac[SIZE_FIELDS_INCLUDED_IN_MBMD_HEADER_MAC];
    };
} mbmd_header_t;
tdx_static_assert(sizeof(mbmd_header_t) == SIZE_FIELDS_INCLUDED_IN_MBMD_HEADER_MAC, mbmd_header_t);

/*********************************************
* MIGRATION BUNDLE
*********************************************/

#define MBMD_ALIGN 128
#define MIN_MIGRATION_EXPORT_VERSION 0
#define MAX_MIGRATION_EXPORT_VERSION 0
#define MIN_MIGRATION_IMPORT_VERSION 0
#define MAX_MIGRATION_IMPORT_VERSION 0

// Values of MIG_TYPE
typedef enum mbmd_mig_type_e
{
    PAGE         = 0,
    PAGE_ALIAS   = 1,
    SEPT_ALIAS   = 2,
    MAX_MIG_TYPE = 2
} mbmd_mig_type_t;

// Values of STATE
typedef enum mbmd_mig_state_e
{
    MAPPED       = 0,
    PENDING      = 1,
    MAX_STATE    = 1
} mbmd_mig_state_t;

// Values of OPERATION
typedef enum mbmd_mig_operation_e
{
    MIGRATE      = 0,
    CANCEL       = 1
} mbmd_mig_operation_t;

// Values of COMMAND
typedef enum migs_index_and_command_e
{
    MIGS_INDEX_COMMAND_NEW          = 0,
    MIGS_INDEX_COMMAND_RESUME       = 1,
    MIGS_INDEX_COMMAND_INORDER_DONE = 1  // Used by TDH.EXPORT.TRACK
} migs_index_and_command_t;

typedef struct PACKED mbmd_mem_s
{
    mbmd_header_t     header;
    uint64_t          num_gpas    : 16; // uint16_t
    uint64_t          reserved    : 48;
    uint8_t           mac[MAC256_LEN];
} mbmd_mem_t;
tdx_static_assert(sizeof(mbmd_mem_t) == TOTAL_MDMD_SIZE, mbmd_mem_t);

typedef struct PACKED mbmd_immutable_td_state_s
{
    mbmd_header_t     header;
    uint16_t          num_f_migs;
    uint16_t          reserved_0;
    uint32_t          num_sys_md_pages : 8;
    uint32_t          reserved_1 : 24;
    uint8_t           mac[MAC256_LEN];
} mbmd_immutable_td_state_t;
tdx_static_assert(sizeof(mbmd_immutable_td_state_t) == TOTAL_MDMD_SIZE, mbmd_immutable_td_state_t);

typedef struct PACKED mbmd_td_state_s
{
    mbmd_header_t     header;
    uint64_t          reserved;
    uint8_t           mac[MAC256_LEN];
} mbmd_td_state_t;
tdx_static_assert(sizeof(mbmd_td_state_t) == TOTAL_MDMD_SIZE, mbmd_td_state_t);

typedef struct PACKED mbmd_vp_state_s
{
    mbmd_header_t     header;
    uint64_t          vp_index    : 16; // uint16_t
    uint64_t          reserved    : 48;
    uint8_t           mac[MAC256_LEN];
} mbmd_vp_state_t;
tdx_static_assert(sizeof(mbmd_vp_state_t) == TOTAL_MDMD_SIZE, mbmd_vp_state_t);

typedef struct PACKED mbmd_epoch_token_s
{
    mbmd_header_t     header;
    uint64_t          total_mb;
    uint8_t           mac[MAC256_LEN];
} mbmd_epoch_token_t;
tdx_static_assert(sizeof(mbmd_epoch_token_t) == TOTAL_MDMD_SIZE, mbmd_epoch_token_t);

typedef struct PACKED mbmd_abort_token_s
{
    mbmd_header_t     header;
    uint64_t          reserved;
    uint8_t           mac[MAC256_LEN];
} mbmd_abort_token_t;
tdx_static_assert(sizeof(mbmd_abort_token_t) == TOTAL_MDMD_SIZE, mbmd_abort_token_t);

typedef struct PACKED mbmd_s
{
    union {
        mbmd_header_t              header;
        mbmd_mem_t                 mem;                 // 13.3.1.2
        mbmd_immutable_td_state_t  immutable_td_state;  // 13.3.1.3
        mbmd_td_state_t            td_state;            // 13.3.1.2
        mbmd_vp_state_t            vp_state;            // 13.3.1.2
        mbmd_epoch_token_t         epoch_token;
        mbmd_abort_token_t         abort_token;
    };
} mbmd_t;
tdx_static_assert(sizeof(mbmd_t) <= MBMD_ALIGN , mbmd_t); // MBMD_ALIGN is too small

/*
 * Total size of mbmd header and type specific fields
 * Used when checking for sufficient buffer size allocated by the VMM
 * when receiving command that require sending or receiving migration bundles
 */
#define MBMD_SIZE_NO_MAC(mbmd_type)  (sizeof(mbmd_type) - MAC256_LEN)

/*********************************************
* MIGRATION STREAM CTX
*********************************************/
typedef struct page_list_info_s
{
    union
    {
        struct
        {
            uint64_t reserved_1      : 12;
            uint64_t hpa             : 40;
            uint64_t reserved_2      : 3;
            uint64_t last_entry      : 9;
        };
        uint64_t raw;
    };
} page_list_info_t;
tdx_static_assert(sizeof(page_list_info_t) == 8, page_list_info_t);

typedef struct PACKED migsc_s {
    uint16_t       migsc_i;              // Migration stream index
    uint8_t        reserved_0[6];
    uint64_t       iv_counter;           // Monotonously incrementing counter, used as a component in the AES-GCM IV
    uint32_t       next_mb_counter;      // Transmitted migration bundle counter
    uint32_t       expected_mb_counter;  // Expected received migration bundle counter

    struct {/* Interrupted State */
        tdx_leaf_and_version_t func;
        bool_t                 valid;
        bool_t                 sys_migrated;   // Used by TDH.*PORT.STATE.IMMUTABLE
        uint8_t                reserved_1[2];
        uint32_t               num_processed;
        page_list_info_t       page_list_info;
        md_field_id_t          field_id;

        pa_t                   tdvpr_pa;       // Used by TDH.*PORT.STATE.VP

        gpa_list_info_t        gpa_list_info;      // used by tdh.*port.mem

        pa_t                   mig_buff_list_pa;   // used by tdh.*port.mem
        pa_t                   mac_list_pa[2];     // used by tdh.*port.mem
        pa_t                   new_page_list_pa;   // used by tdh.import.mem

        /* Sticky error indications, used by TDH.IMPORT.STATE.*
           These fields hold error information for decrypted buffer parsing, until the MAC is checked.  The error
           is sticky (can be set once during a certain import function) and is reported to the caller only if the
           MAC check passed. */
        api_error_type         status;
        uint64_t               extended_err_info[2];

        uint8_t                reserved_2[24];
    } interrupted_state;

    mbmd_t         mbmd;
    uint8_t        reserved_3[56];
    ALIGN(256) aes_gcm_ctx_t  aes_gcm_context;      // Implementation dependent AES-GCM context
} migsc_t;
tdx_static_assert(offsetof(migsc_t, aes_gcm_context) == (256), migsc_t);
tdx_static_assert(sizeof(migsc_t) <= (_4KB), migsc_t);


/*
 * Migration stream index and command
 * R10 input operand
 */
typedef union migs_index_and_cmd_u
{
    struct
    {
        uint16_t    migs_index;
        union
        {
            uint16_t reserved_31_16;
        };
        struct
        {
            uint32_t reserved_62_32 : 31;
            uint32_t command        : 1;
        };
    };
    uint64_t    raw;
} migs_index_and_cmd_t;
tdx_static_assert(sizeof(migs_index_and_cmd_t) == 8, migs_index_and_cmd_t);

/**
 * HPA and memory size used for MBMD (Migration Bundle MetaData)
 */
typedef union hpa_and_size_u
{
    struct
    {
        uint64_t  hpa : 52;  // bits 0:51
        uint64_t  size : 12; // bits 52:63 - size of memory buffer for MBMD
    };
    uint64_t  raw;
} hpa_and_size_t;
tdx_static_assert(sizeof(hpa_and_size_t) == 8, hpa_and_size_t);

/**
 * HPA and last byte index
 */
typedef union hpa_and_last_u
{
    struct
    {
        uint64_t  last     : 12; // bits 0:11 - index of the last byte in the buffer
        uint64_t  hpa      : 40;  // bits 12:51
        uint64_t  reserved : 12; // bits 52:63
    };
    uint64_t  raw;
} hpa_and_last_t;
tdx_static_assert(sizeof(hpa_and_last_t) == 8, hpa_and_last_t);

typedef union migsc_link_u
{
    struct
    {
        uint64_t lock           : 1;   // Bit 0
        uint64_t initialized    : 1;   // Bit 1
        uint64_t reserved_0     : 10;   // Bits 11:2
        uint64_t migsc_hpa      : 40;  // Bits 51:12
        uint64_t reserved_1     : 12;  // Bits 63:52
    };
    uint64_t raw;
} migsc_link_t;
tdx_static_assert(sizeof(migsc_link_t) == 8, migsc_link_t);

// Maximum number of service TDs per TD
#define MAX_SERV_TDS          1
#define MIGSC_LINK_LOCK_BIT   0


typedef union page_list_entry_u
{
    struct
    {
        uint64_t reserved_11_0  : 12;  // Bits 11:0
        uint64_t hpa            : 40;  // Bits 51:12
        uint64_t reserved_62_52 : 11;  // Bits 62:52
        uint64_t invalid        : 1;   // Bit 63
    };
    uint64_t raw;
} page_list_entry_t;
tdx_static_assert(sizeof(page_list_entry_t) == 8, page_list_entry_t);

#define MAC_LIST_ENTRIES_IN_PAGE        256

/** Initialize a MIGSC:  must be done once per migration session before the MIGSC is used
    Caller needs to use aes_gcm_reset() to set the IV as required. */
void migsc_init(migsc_t *migsc, const key256_t *key);

// Lock the MIGSC
_STATIC_INLINE_ bool_t migsc_lock(migsc_link_t *mgsc_link)
{
    return _lock_bts_64b(&mgsc_link->raw, MIGSC_LINK_LOCK_BIT) == 0;
}

// Unlock the MIGSC
_STATIC_INLINE_ void migsc_unlock(migsc_link_t *mgsc_link)
{
    bool_t old;

    old = _lock_btr_64b(&mgsc_link->raw, MIGSC_LINK_LOCK_BIT);
    tdx_sanity_check(old, SCEC_LOCK_SOURCE, 9);
}

_STATIC_INLINE_ bool_t is_gpa_list_entry_op_cancel_or_nop(gpa_list_entry_t gpa_list_entry)
{
    return ((gpa_list_entry.operation & GPA_ENTRY_OP_EXPORT_NOP_MASK) == GPA_ENTRY_OP_NOP);
}

_STATIC_INLINE_ bool_t gpa_list_entry_is_valid(gpa_list_entry_t gpa_list_entry)
{
    if (gpa_list_entry.reserved_0 || gpa_list_entry.reserved_1 || gpa_list_entry.reserved_2 ||
        (gpa_list_entry.level != 0))
    {
        return false;
    }

    return true;
}

/**
 * @brief Check the GPA list info structure for validness, and return a mapped linear pointer to the
 *        actual list page. Pointer should be freed after usage.
 *
 * @param gpa_list_info - GPA list info structure
 * @param gpa_list_p - Output pointer to the GPA list page - should be freed after usage
 *
 * @return Error or success
 */
api_error_type check_and_map_gpa_list(gpa_list_info_t gpa_list_info, gpa_list_entry_t** gpa_list_p);

/**
 * @brief Check the GPA list entry for validness (reserved fields check and GPA valid check),
 *        and return the guest physical address from the entry.
 *
 * @param gpa_entry - GPA list entry
 * @param gpaw - GPAW from the TDCS
 * @param output_gpa - Output GPA from the list entry
 *
 * @return Validness check result
 */
bool_t check_and_get_gpa_from_entry(gpa_list_entry_t gpa_entry, bool_t gpaw, pa_t* output_gpa);

/**
 * copy MBMD
 */
void copy_mbmd(mbmd_t* mbmd_dst, mbmd_t* mbmd_src);


#endif /* SRC_COMMON_HELPERS_MIGRATION_H_ */
