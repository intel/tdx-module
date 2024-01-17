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
 * @file metadata_generic.h
 * @brief Generic metadata handler
 */

#ifndef SRC_COMMON_METADATA_HANDLERS_METADATA_GENERIC_H_
#define SRC_COMMON_METADATA_HANDLERS_METADATA_GENERIC_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/td_control_structures.h"
#include "data_structures/tdx_tdvps.h"

typedef enum
{
    MD_WRITE_ACCESS         = 0x1,

    MD_HOST_RD              = 0x10,
    MD_HOST_WR              = MD_HOST_RD | MD_WRITE_ACCESS,
    MD_GUEST_RD             = 0x20,
    MD_GUEST_WR             = MD_GUEST_RD | MD_WRITE_ACCESS,
    MD_SERV_TD_RD           = 0x30,
    MD_SERV_TD_WR           = MD_SERV_TD_RD | MD_WRITE_ACCESS,

    MD_EXPORT_IMMUTABLE     = 0x40,
    MD_EXPORT_MUTABLE       = 0x50,
    MD_IMPORT_IMMUTABLE     = MD_EXPORT_IMMUTABLE | MD_WRITE_ACCESS,
    MD_IMPORT_MUTABLE       = MD_EXPORT_MUTABLE   | MD_WRITE_ACCESS
} md_access_t;

typedef enum mig_type_e
{
    MIG_NONE,
    MIG_ME,
    MIG_MEO,
    MIG_MEC,
    MIG_MB,
    MIG_MBO,
    MIG_MBCO,
    MIG_IE,
    MIG_IES,
    MIG_IEME,
    MIG_IESME,
    MIG_IB,
    MIG_IBS,
    MIG_CB,
    MIG_CBO,
    MIG_CE,
    MIG_CEO
} mig_type_t;

/* For HOST_*, contains ATTRIBUTES.DEBUG value
   For GUEST_*, this field is N/A
   For SERV_TD_*, contains the service TD type */
typedef union md_access_qualifier_u
{
    struct
    {
        bool_t     debug;  // Copy of ATTRIBUTES.DEBUG
    } host_qualifier;

    struct
    {
        uint16_t service_td_type;
    } serv_td_qualifier;

    uint64_t raw;
} md_access_qualifier_t;
tdx_static_assert(sizeof(md_access_qualifier_t) == 8, md_access_qualifier_t);

typedef enum
{
    MD_CTX_SYS = 0,   // TDX Module global (Global sys fields)
    MD_CTX_TD  = 1,   // TD scope (TDR and TDCS)
    MD_CTX_VP  = 2,   // VCPU scope (TDVPS and TD-VMCS)

    MD_CTX_MAX = MD_CTX_VP
} md_context_code_e;

#define MAX_ELEMENTS_IN_FIELD           16
#define MAX_FIELDS_IN_SEQUENCE          512

#define CONTEXT_CODE_MASK       BITS(54,52) //0x0070000000000000
#define MD_NO_ENTRY_IDX         ((uint32_t)(-1))
#define MD_FIELD_ID_NA          ((uint64_t)(-1ULL))

typedef struct md_sequence_s
{
    md_field_id_t sequence_header;
    uint64_t      element[MAX_FIELDS_IN_SEQUENCE * MAX_ELEMENTS_IN_FIELD + 1];
} md_sequence_t;

typedef union md_list_header_u
{
    struct
    {
        uint16_t list_buff_size;
        uint16_t num_sequences;
        uint32_t reserved;
    };
    uint64_t raw;
} md_list_header_t;
tdx_static_assert(sizeof(md_list_header_t) == 8, md_list_header_t);

typedef union md_field_attributes_u
{
    struct
    {
        uint8_t hpa       : 1;
        uint8_t gpa       : 1;
        uint8_t prvate    : 1;
        uint8_t shared    : 1;
        uint8_t vm_app_l1 : 1;
        uint8_t vm_app_l2 : 1;
    };

    uint8_t raw;
} md_field_attributes_t;
tdx_static_assert(sizeof(md_field_attributes_t) == 1, md_field_attributes_t);

typedef struct md_lookup_s
{
    md_field_id_t field_id;
    uint16_t num_of_fields;
    uint16_t num_of_elem;
    uint32_t offset;

    union // Global fields table don't have neither Prod Mask nor Debug Mask
    {
        uint64_t prod_rd_mask;
        uint64_t vmm_rd_mask; // Used by global fields table
    };

    union // Global fields table don't have neither Prod Mask nor Debug Mask
    {
        uint64_t prod_wr_mask;
        uint64_t vmm_wr_mask; // Used by global fields table
    };

    uint64_t dbg_rd_mask;
    uint64_t dbg_wr_mask;

    union // L2 VMCS don't have Guest RD/WR mask
    {
        uint64_t guest_rd_mask;
        uint64_t l1_vmm_rd_mask;
    };

    union // L2 VMCS don't have Guest RD/WR mask
    {
        uint64_t guest_wr_mask;
        uint64_t l1_vmm_wr_mask;
    };

    uint64_t migtd_rd_mask;
    uint64_t migtd_wr_mask;

    uint64_t export_mask;
    uint64_t import_mask;

    mig_type_t mig_export;
    mig_type_t mig_import;

    md_field_attributes_t attributes;
    bool_t special_rd_handling;
    bool_t special_wr_handling;

} md_lookup_t;

typedef struct md_context_ptrs_s
{
    tdr_t* tdr_ptr;
    tdcs_t* tdcs_ptr;
    tdvps_t* tdvps_ptr;
} md_context_ptrs_t;

typedef union md_list_u
{
    struct
    {
        md_list_header_t hdr;
        uint8_t body[_4KB - sizeof(md_list_header_t)];
    };
    uint8_t raw[_4KB];
} md_list_t;

// Metadata common functions

const md_lookup_t* md_get_lookup_table(md_context_code_e ctx_code, md_field_id_t field_id,
                                       md_context_ptrs_t md_ctx, uint32_t* num_of_entries);

uint32_t md_find_entry_idx(const md_lookup_t* lookup_table, uint32_t num_of_entries, md_field_id_t field_id);

void md_get_rd_wr_mask(const md_lookup_t* entry, md_access_t access_type, md_access_qualifier_t access_qual,
        uint64_t* out_rd_mask, uint64_t* out_wr_mask);

void md_cpuid_field_id_get_leaf_subleaf(md_field_id_t field_id, uint32_t* leaf, uint32_t* subleaf);

_STATIC_INLINE_ bool_t is_null_field_id(md_field_id_t field_id)
{
    return ((field_id.raw | CONTEXT_CODE_MASK) == MD_FIELD_ID_NA);
}

/**
 * @brief  Get a bit mask based on the element size:
 *   element size 0 ==> 0xFF
 *   element size 1 ==> 0xFFFF
 *   element size 2 ==> 0xFFFFFFFF
 *   element size 3 ==> 0xFFFFFFFFFFFFFFFF
 */
_STATIC_INLINE_ uint64_t md_get_element_size_mask(uint64_t size_code)
{
    uint64_t mask = 0;
    tdx_debug_assert(size_code < 4);

    if (size_code < 3)
    {
        mask = BIT(8ULL * BIT(size_code)) - 1ULL;
    }
    else
    {
        mask = BIT_MASK_64BITS;
    }

    return mask;
}

_STATIC_INLINE_ bool_t md_check_forbidden_bits_unchanged(uint64_t original_value, uint64_t wr_value,
                                                         uint64_t wr_request_mask, uint64_t entry_wr_mask)
{
    // The caller must not attempt to modify any non-writable bit.
    // Calculate the forbidden bit mask as follows:
    // forbidden_mask[N] is 1 if and only if both conditions are met:
    //    - Non-writable:  element_wr_mask[N] == 0
    //    - Write attempt: wr_mask[N] == 1
    // Then check if any of the forbidden bits is being modified.

    uint64_t forbidden_mask = wr_request_mask & ~entry_wr_mask;

    return ((original_value & forbidden_mask) == (wr_value & forbidden_mask));
}

////////////////////////////// Common metadata handling interface /////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Check a field id that is used for a single element access (not as a sequence header).
 */
api_error_code_e md_check_as_single_element_id(md_field_id_t field_id);

/**
 * @brief Check a field id that is used as a sequence header
 */
api_error_code_e md_check_as_sequence_header(md_context_code_e ctx_code, md_field_id_t field_id,
        md_access_t access_type);

/**
 * @brief Get the next FIELD_ID in the current context, given the required access.
 *
 * @return Always returns the base FIELD_ID of a field (i.e., the FIELD_ID of the first element within a field).
 *         The meaning of "next" is as follows:
 *         - FIELD_IDs are ordered by:
 *           1. CONTEXT_CODE
 *           2. CLASS_CODE
 *           3. FIELD_CODE
 *         - The next FIELD_ID matched the given access and access_qualifier, i.e.:
 *           - For read, the applicable read mask is non-0
 *           - For write, the applicable write mask is non-0
 *         - If no next FIELD_ID exists, return 0
 */
md_field_id_t md_get_next_element_in_context(md_context_code_e ctx_code, md_field_id_t field_id,
                                             md_context_ptrs_t md_ctx,
                                             md_access_t access_type, md_access_qualifier_t access_qual);

/**
 * @brief Read the value of a single metadata element, given the required access.
 *
 * If the FIELD_ID is not found, return a TDX_METADATA_FIELD_ID_INCORRECT status.
 * Checks the actual element size vs. the size provided in the FIELD_ID,
 * returns a TDX_METADATA_FIELD_ID_INCORRECT status on error.
 * Derives a read mask based on the read mask provided in the spreadsheet, but adjusted to the element size.
 * If the resulting read mask is 0 returns a TDX_FIELD_NOT_READABLE status.
 * Masks the returned value with the derived read mask.
 */
api_error_code_e md_read_element(md_context_code_e ctx_code, md_field_id_t field_id,
        md_access_t access_type, md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t* value);

/** @brief Write the value of a single metadata element, given the required access.
 *
 * If the FIELD_ID is not found, return a TDX_METADATA_FIELD_ID_INCORRECT status.
 * Checks the actual element size vs. the size provided in the FIELD_ID,
 * returns a TDX_METADATA_FIELD_ID_INCORRECT status on error.
 * If the resulting write mask is 0 return a TDX_FIELD_NOT_WRITABLE status.
 * Mask the written value with the derived write mask.
 */
api_error_code_e md_write_element(md_context_code_e ctx_code, md_field_id_t field_id,
         md_access_t access_type, md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx,
         uint64_t value, uint64_t wr_mask, uint64_t* old_value);

/**
 * @brief Dump a metadata list, containing a header and multiple metadata sequences, into a buffer.
 *
 * All fields are of the same context.
 * Only fields that match the requested access attribute (e.g., immutable export) are dumped.
 * Start with the current field id, and dump field values as long as there a matching fields
 * and there is enough available space.
 * Dump only whole fields, i.e., if there are fields that are composed of multiple elements,
 * then all elements must be read.
 *
 * @param ctx_code - Context code
 * @param field_id - Field ID of the start field
 * @param md_ctx - Context of current TDR/TDCS/TDVPS pointers
 * @param list_header_ptr - List header. Size is set to the actual size of the list.
 * @param buff_size - Available memory buffer size, must be >= 24 to hold at least the list header and one sequence.
 * @param access_type - Requested access:  Only HOST_RD, GUEST_RD and EXPORT_* are supported.
 * @param access_qual - Requested access qualifier
 * @param next_field_id - Next field to be dumped, -1 if none
 *
 * @return Status code, one of the following:
 *         TDX_SUCCESS:  All available fields were dumped
 *         TDX_METADATA_LIST_OVERFLOW:  More available fields remain
 */
api_error_code_e md_dump_list(md_context_code_e ctx_code, md_field_id_t field_id, md_context_ptrs_t md_ctx,
        md_list_header_t* list_header_ptr, uint32_t buff_size,
        md_access_t access_type, md_access_qualifier_t access_qual, md_field_id_t* next_field_id);

/**
 * @brief Import the metadata list:
          - Import fields marked as "MB" and "MBO" in the TDR/TDCS spreadsheet
          - Check fields marked as "CB" and "CBO" in the TDR/TDCS spreadsheet
 *
 * @param ctx_code - Context code
 * @param expected_field - Field id of that we expecting to find on the first sequence header in the list
 *                         Should be -1 if the first field id of the context expected
 * @param check_missing - If true, check for missing required fields
 * @param skip_non_writable - Skip non-writable elements instead of terminating with an error.
 * @param is_last - If check_missing is true, then this flag indicates that this is the
 *                  last MD list to be processed. In this case, check that there is no
 *                  missing required field after the end of the list.
 * @param md_ctx - Context of current TDR/TDCS/TDVPS pointers
 * @param list_header_ptr - List header.
 * @param access_type - Requested access:  Only HOST_WR, GUEST_WR and IMPORT_* are supported.
 * @param access_qual - Requested access qualifier
 * @param next_field_id - Returns next field that is expected to be imported first on next call with new list.
 *                        Will be -1 if none - context finished.
 * @param ext_err_info - Will contain a field id of a field that failed write in the first array index.
 * @param is_import specifies whether the functions was called during import flow
 *
 * @return Status code, one of the following:
 *         TDX_SUCCESS:  All available fields were dumped
 *         TDX_METADATA_LIST_OVERFLOW:  More available fields remain
 *         TDX_REQUIRED_METADATA_FIELD_MISSING: Expected field is missing in the list
 *         TDX_INVALID_METADATA_LIST_HEADER: List header is incorrect
 *         TDX_METADATA_FIELD_NOT_WRITABLE: Wrong access type or non writable field in the list
 */
api_error_code_e md_write_list(md_context_code_e ctx_code, md_field_id_t expected_field, uint16_t buff_size,
                               bool_t check_missing, bool_t skip_non_writable, bool_t is_last,
                               md_context_ptrs_t md_ctx, md_list_header_t* list_header_ptr,
                               md_access_t access_type, md_access_qualifier_t access_qual,
                               md_field_id_t* next_field_id, uint64_t ext_err_info[2], bool_t is_import);

#endif /* SRC_COMMON_METADATA_HANDLERS_METADATA_GENERIC_H_ */
