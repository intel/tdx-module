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
 * @file metadata_generic.c
 * @brief Generic metadata handler
 */

#include "metadata_generic.h"
#include "auto_gen/global_sys_fields_lookup.h"
#include "auto_gen/tdr_tdcs_fields_lookup.h"
#include "auto_gen/td_vmcs_fields_lookup.h"
#include "auto_gen/td_l2_vmcs_fields_lookup.h"
#include "auto_gen/tdvps_fields_lookup.h"
#include "auto_gen/cpuid_configurations.h"
#include "helpers/error_reporting.h"
#include "helpers/helpers.h"
#include "metadata_sys.h"
#include "metadata_td.h"
#include "metadata_vp.h"

_STATIC_INLINE_ bool_t is_write_access_type(md_access_t access_type)
{
    return ((access_type & MD_WRITE_ACCESS) == MD_WRITE_ACCESS);
}

_STATIC_INLINE_ bool_t is_special_cpuid_field_id(md_field_id_t field_id)
{
    IF_RARE ((field_id.context_code == MD_CTX_TD) && (field_id.class_code == MD_TDCS_CPUID_CLASS_CODE))
    {
        return true;
    }

    return false;
}

_STATIC_INLINE_ bool_t is_special_l2_vmcs_field_id(md_field_id_t field_id)
{
    IF_RARE ((field_id.context_code == MD_CTX_VP) &&
             ((field_id.class_code == MD_TDVPS_VMCS_1_CLASS_CODE) ||
              (field_id.class_code == MD_TDVPS_VMCS_2_CLASS_CODE) ||
              (field_id.class_code == MD_TDVPS_VMCS_3_CLASS_CODE)))
    {
        return true;
    }

    return false;
}
#if 0 // TODO future use
_STATIC_INLINE_ bool_t is_l2_vm_field_id(md_field_id_t field_id, uint16_t* vm_id)
{
    if (field_id.context_code == MD_CTX_VP)
    {
        if ((field_id.class_code >= MD_TDVPS_VMCS_1_CLASS_CODE) &&
            (field_id.class_code < (MD_TDVPS_VMCS_1_CLASS_CODE + (L2_VP_CLASS_CODE_INC * MAX_L2_VMS))))
        {
            *vm_id = md_vp_get_l2_vm_index(field_id.class_code);
            return true;
        }
    }
    else if (field_id.context_code == MD_CTX_TD)
    {
        if ((field_id.class_code >= MD_TDCS_L2_SECURE_EPT_ROOT__1_CLASS_CODE) &&
            (field_id.class_code < (MD_TDCS_L2_SECURE_EPT_ROOT__1_CLASS_CODE + (L2_TD_CLASS_CODE_INC * MAX_L2_VMS))))
        {
            *vm_id = md_td_get_l2_vm_index(field_id.class_code);
            return true;
        }
    }

    *vm_id = 0;
    return false;
}
#endif
_STATIC_INLINE_ bool_t is_equal_field_id(md_field_id_t field_id1, md_field_id_t field_id2)
{
    return ((field_id1.field_code == field_id2.field_code) &&
            (field_id1.class_code == field_id2.class_code) &&
            (field_id1.context_code == field_id2.context_code));
}

api_error_code_e md_check_as_single_element_id(md_field_id_t field_id)
{
    // - RESERVED_* fields must be 0.
    // - LAST_ELEMENTS_IN_FIELD must be 0.
    // - LAST_FIELD_IN_SEQUENCE must by 0.
    // - WRITE_MASK_VALID is ignored.
    // - FIELD_SIZE is ignored.
    // - INC_SIZE is ignored.
    // - CONTEXT_CODE is ignored.
    IF_RARE (field_id.reserved_0 != 0 || field_id.reserved_1 != 0 ||
             field_id.reserved_2 != 0 || field_id.reserved_3 != 0 ||
             field_id.last_element_in_field != 0 || field_id.last_field_in_sequence != 0)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    return TDX_SUCCESS;
}

api_error_code_e md_check_as_sequence_header(md_context_code_e ctx_code, md_field_id_t field_id,
        md_access_t access_type)
{
    // - RESERVED_* fields must be 0.
    // - WRITE_MASK_VALID must be 0 if this is a read operation.
    IF_RARE (field_id.context_code != ctx_code ||
             field_id.reserved_0 != 0 || field_id.reserved_1 != 0 ||
             field_id.reserved_2 != 0 || field_id.reserved_3 != 0 ||
        ((access_type & MD_WRITE_ACCESS) == 0 && field_id.write_mask_valid != 0))
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ uint32_t md_get_num_of_td_vp_ctx_unused_entries(md_context_code_e ctx_code, md_context_ptrs_t md_ctx)
{
    uint32_t unused_vms = MAX_L2_VMS;
    uint32_t unused_entries = 0;

    if (md_ctx.tdcs_ptr != NULL)
    {
        unused_vms = MAX_L2_VMS - md_ctx.tdcs_ptr->management_fields.num_l2_vms;
    }

    switch (ctx_code)
    {
        case MD_CTX_TD:
            unused_entries = TDCS_PAGES_PER_L2_VM * unused_vms;
            break;
        case MD_CTX_VP:
            unused_entries = TDVPS_PAGES_PER_L2_VM * unused_vms;
            break;
        case MD_CTX_SYS:
            unused_entries = 0;
            break;
        default:
            FATAL_ERROR();
            break;
    }

    return unused_entries;
}

const md_lookup_t* md_get_lookup_table(md_context_code_e ctx_code, md_field_id_t field_id,
                                       md_context_ptrs_t md_ctx, uint32_t* num_of_entries)
{
    const md_lookup_t* lookup_table;

    uint32_t unused_entries = md_get_num_of_td_vp_ctx_unused_entries(ctx_code, md_ctx);

    switch (ctx_code)
    {
        case MD_CTX_SYS:
            lookup_table = global_sys_lookup;
            *num_of_entries = MAX_NUM_GLOBAL_SYS_LOOKUP;
            break;
        case MD_CTX_TD:
            lookup_table = tdr_tdcs_lookup;
            *num_of_entries = MAX_NUM_TDR_TDCS_LOOKUP - unused_entries;
            break;
        case MD_CTX_VP:
            // In VP context, if the FIELD ID in NA - means a first entry in first table
            // meaning a TD VMCS table, which comes first to the actual TDVPS table
            if (is_null_field_id(field_id) || (field_id.class_code == MD_TDVPS_VMCS_CLASS_CODE))
            {
                lookup_table = td_vmcs_lookup;
                *num_of_entries = MAX_NUM_TD_VMCS_LOOKUP;
            }
            else if ((field_id.class_code == MD_TDVPS_VMCS_1_CLASS_CODE) ||
                     (field_id.class_code == MD_TDVPS_VMCS_2_CLASS_CODE) ||
                     (field_id.class_code == MD_TDVPS_VMCS_3_CLASS_CODE))
            {
                lookup_table = td_l2_vmcs_lookup;
                *num_of_entries = MAX_NUM_TD_L2_VMCS_LOOKUP;
            }
            else
            {
                lookup_table = tdvps_lookup;
                *num_of_entries = MAX_NUM_TDVPS_LOOKUP - unused_entries;
            }
            break;
        default:
            FATAL_ERROR();
            break;
    }

    return lookup_table;
}

uint32_t md_find_entry_idx(const md_lookup_t* lookup_table, uint32_t num_of_entries, md_field_id_t field_id)
{
    uint32_t i;

    IF_RARE (is_special_cpuid_field_id(field_id))
    {
        // TD context CPUID VALUES field id have different format
        // Zero out everything except the element number
        field_id.field_code = field_id.cpuid_field_code.element;
    }

    if (is_special_l2_vmcs_field_id(field_id))
    {
        field_id.class_code = 0;
    }

    for (i = 0; i < num_of_entries; i++)
    {
        // Search is done by Context, Class and Field
        // Since we already know the context, we just need to check it with debug assert
        tdx_debug_assert(field_id.context_code == lookup_table[i].field_id.context_code);

        uint16_t element_stride = (uint16_t)lookup_table[i].field_id.inc_size + 1;

        uint64_t first_element_id_in_range = lookup_table[i].field_id.field_code;
        uint64_t last_element_id_in_range = lookup_table[i].field_id.field_code +
                (lookup_table[i].num_of_elem * element_stride * lookup_table[i].num_of_fields);

        if ((field_id.class_code == lookup_table[i].field_id.class_code) &&
            ((uint64_t)field_id.field_code >= first_element_id_in_range) &&
            ((uint64_t)field_id.field_code < last_element_id_in_range))
        {
            break;
        }
    }

    // If entry not found
    if (i == num_of_entries)
    {
        return MD_NO_ENTRY_IDX;
    }

    return i;
}

_STATIC_INLINE_ void md_cpuid_field_id_set_leaf_subleaf(md_field_id_t* field_id, uint32_t leaf, uint32_t subleaf)
{
    field_id->cpuid_field_code.leaf = (uint16_t)(leaf & ~BIT(31));
    field_id->cpuid_field_code.leaf_bit31 = (leaf & (uint32_t)BIT(31)) >> 31;
    field_id->cpuid_field_code.subleaf = (uint16_t)subleaf;
    field_id->cpuid_field_code.subleaf_na = (subleaf == CPUID_SUBLEAF_NA) ? 1 : 0;
}

void md_cpuid_field_id_get_leaf_subleaf(md_field_id_t field_id, uint32_t* leaf, uint32_t* subleaf)
{
    *leaf = field_id.cpuid_field_code.leaf | (((uint32_t)field_id.cpuid_field_code.leaf_bit31) << 31);
    *subleaf = field_id.cpuid_field_code.subleaf_na ? CPUID_SUBLEAF_NA : field_id.cpuid_field_code.subleaf;
}

static md_field_id_t md_get_next_cpuid_value_entry(md_field_id_t field_id, bool_t element)
{
    // Inc size of CPUID field codes should be 0
    tdx_debug_assert(field_id.inc_size == 0);

    if (element && (field_id.cpuid_field_code.element == 0))
    {
        // There are only two elements in CPUID_VALUE field
        // If we are on the first element, just return the next element of the same field id
        field_id.field_code++;
        return field_id;
    }

    // Else in any other case - we need to return the next field
    // First find on what index we are already located
    uint32_t leaf, subleaf;
    md_cpuid_field_id_get_leaf_subleaf(field_id, &leaf, &subleaf);
    uint32_t index = get_cpuid_lookup_entry(leaf, subleaf);

    tdx_sanity_check(index != CPUID_LOOKUP_IDX_NA, SCEC_METADATA_HANDLER_SOURCE, 0);

    do
    {
        index = index + 1;
    } while (!cpuid_lookup[index].valid_entry);

    IF_RARE (index >= MAX_NUM_CPUID_LOOKUP)
    {
        // we finished the cpuid lookup array, return -1 to indicate that
        return (md_field_id_t)MD_FIELD_ID_NA;
    }

    // Get the leaf and subleaf of next entry in cpuid lookup
    leaf = cpuid_lookup[index].leaf_subleaf.leaf;
    subleaf = cpuid_lookup[index].leaf_subleaf.subleaf;

    // Set it into the field code value
    md_cpuid_field_id_set_leaf_subleaf(&field_id, leaf, subleaf);

    // Set to the first element
    field_id.cpuid_field_code.element = 0;

    return field_id;
}

typedef struct lookup_iterator_s
{
    const md_lookup_t* lookup_table;
    uint32_t num_of_entries_in_table;
    uint32_t table_idx;
    uint32_t parent_table_idx; // Used for L2 VMCS parent table entry idx (TDVPS table)
    md_field_id_t field_id;
} lookup_iterator_t;

_STATIC_INLINE_ uint32_t get_tdvps_table_idx_from_l2_vmcs_field_id(md_field_id_t field_id)
{
    tdx_debug_assert((field_id.class_code == MD_TDVPS_VMCS_1_CLASS_CODE) ||
                     (field_id.class_code == MD_TDVPS_VMCS_2_CLASS_CODE) ||
                     (field_id.class_code == MD_TDVPS_VMCS_3_CLASS_CODE));

    uint32_t l2_vm_id = md_vp_get_l2_vm_index(field_id.class_code);
    return (((l2_vm_id - 1) * L2_VMCS_INDEX_STRIDE) + L2_VMCS_1_ENTRY_INDEX);
}

static void ____md_fetch_next_of_last_table_entry(lookup_iterator_t* lookup_context, md_context_ptrs_t md_ctx)
{
    // Special case if we finished VMCS table - next is the first from TDVPS table
    // That's because VMCS table has class 0, and it basically precedes the TDVPS table
    IF_RARE ((lookup_context->lookup_table == td_vmcs_lookup) ||
             (lookup_context->lookup_table == td_l2_vmcs_lookup))
    {
        // Lookup table and table index CHANGE here
        if (lookup_context->lookup_table == td_l2_vmcs_lookup)
        {
            lookup_context->table_idx =
                    get_tdvps_table_idx_from_l2_vmcs_field_id(lookup_context->field_id) + 1;
        }
        else
        {
            lookup_context->table_idx = 0;
        }

        uint32_t unused_entries = md_get_num_of_td_vp_ctx_unused_entries(MD_CTX_VP, md_ctx);

        lookup_context->lookup_table = tdvps_lookup;
        lookup_context->num_of_entries_in_table = MAX_NUM_TDVPS_LOOKUP - unused_entries;

        lookup_context->field_id = tdvps_lookup[lookup_context->table_idx].field_id;
        return;
    }

    // Other case - we finished our context completely and there's no more fields in it
    lookup_context->lookup_table = NULL;
    lookup_context->num_of_entries_in_table = 0;
    lookup_context->table_idx = 0;
    lookup_context->field_id.raw = MD_FIELD_ID_NA;
    return;
}

// This internal function not only returns the field_id of the next field, but also returns
// the next index in the table to which the field_id belongs, and also returns a different
// lookup table ptr in case when we switched to different lookup table under the same context
// (currently happens only with TD-VMCS table in TDVPS context)
static void md_get_next_item_with_iterator(lookup_iterator_t* lookup_context, md_context_ptrs_t md_ctx, bool_t is_element)
{
    md_field_id_t tmp_field_id;
    uint32_t class_code = lookup_context->field_id.class_code;

    // In case when input field id is -1, we just want the very first entry from the relevant table
    // And return the id of the first element of the first field, so all the calculations below are
    // not relevant.
    IF_RARE (is_null_field_id(lookup_context->field_id))
    {
        // Lookup table here stays the same, but we just make the idx is 0
        lookup_context->table_idx = 0;
        lookup_context->field_id = lookup_context->lookup_table[0].field_id;
        goto EXIT;
    }

    tdx_sanity_check(lookup_context->table_idx != MD_NO_ENTRY_IDX, SCEC_METADATA_HANDLER_SOURCE, 1);

    IF_RARE (is_special_cpuid_field_id(lookup_context->field_id))
    {
        // Very special case of "CPUID_VALUES" field in TDCS, should be handled differently
        tmp_field_id = md_get_next_cpuid_value_entry(lookup_context->field_id, is_element);

        // If there's no more CPUID_VALUES entries, fetch the next field
        if (is_null_field_id(tmp_field_id))
        {
            goto EXIT_FETCH_NEXT;
        }

        // Lookup table and table index stays the same here
        lookup_context->field_id = tmp_field_id;
        return;
    }

    // Every entry in the lookup table can contain multiple fields,
    // and every field can contain multiple elements.
    // The below if-else case handling is correct for regular field id's only, and not for CPUID_VALUES
    // which we handle in md_td_get_next_cpuid_value_item above.
    const md_lookup_t* entry = &lookup_context->lookup_table[lookup_context->table_idx];
    uint16_t element_stride = (uint16_t)entry->field_id.inc_size + 1;

    tdx_debug_assert(lookup_context->field_id.field_code >= entry->field_id.field_code);

    IF_RARE (is_element)
    {
        // In this case we return the next element within a field, or a first element of next field
        uint32_t elem_num = (lookup_context->field_id.field_code - entry->field_id.field_code) /
                             element_stride;

        // If we still have elements in the current table entry
        if (elem_num < ((entry->num_of_fields * entry->num_of_elem) - 1))
        {
            lookup_context->field_id.field_code += element_stride;
            // Lookup table and table index stays the same here
            return;
        }
    }
    else
    {
        // In this case we return the next field, with a field_id of the first element
        uint32_t field_num = (lookup_context->field_id.field_code - entry->field_id.field_code) /
                             (entry->num_of_elem * element_stride);

        // If we still have fields in the current table entry
        if (field_num < (entry->num_of_fields - 1))
        {
            lookup_context->field_id.field_code += (entry->num_of_elem * element_stride);
            // Lookup table and table index stays the same here
            return;
        }
    }

EXIT_FETCH_NEXT:

    // If we don't have elements or fields in the current table entry, we go to the next one
    IF_RARE (lookup_context->table_idx == (lookup_context->num_of_entries_in_table - 1)) // Last entry in table
    {
        ____md_fetch_next_of_last_table_entry(lookup_context, md_ctx);
    }
    else
    {
        // Else - return next entry in the table (first field, first element)
        // Lookup table stays the same here, but the index changes
        lookup_context->table_idx++;
        // Remember the class code - needed to apply to L2 VMCS fields
        class_code = lookup_context->field_id.class_code;
        lookup_context->field_id = lookup_context->lookup_table[lookup_context->table_idx].field_id;
    }

EXIT:

    // In case when we fetched a first field of CPUID_VALUE array as the next field
    IF_RARE (is_special_cpuid_field_id(lookup_context->field_id))
    {
        // Insert the leaf/subleaf of the first CPUID entry to the field id
        md_cpuid_field_id_set_leaf_subleaf(&lookup_context->field_id, cpuid_lookup[0].leaf_subleaf.leaf,
                                           cpuid_lookup[0].leaf_subleaf.subleaf);
    }

    // In case when we fetched a L2 VMCS 1/2/3 "parent" field in TDVPS table
    IF_RARE ((lookup_context->field_id.raw == MD_TDVPS_L2_VMCS_1_FIELD_ID) ||
             (lookup_context->field_id.raw == MD_TDVPS_L2_VMCS_2_FIELD_ID) ||
             (lookup_context->field_id.raw == MD_TDVPS_L2_VMCS_3_FIELD_ID))
    {
        // Switch to L2 VMCS table instead
        // Lookup table and table index CHANGE here
        lookup_context->lookup_table = td_l2_vmcs_lookup;
        lookup_context->num_of_entries_in_table = MAX_NUM_TD_L2_VMCS_LOOKUP;
        lookup_context->table_idx = 0;
        // Remember the class code - needed to apply to L2 VMCS fields
        class_code = lookup_context->field_id.class_code;
        lookup_context->field_id = td_l2_vmcs_lookup[0].field_id;
    }

    // In case we fetched L2 VMCS field in L2 VMCS table
    if (lookup_context->lookup_table == td_l2_vmcs_lookup)
    {
        // Apply the class code
        // Remembered either from a previous field in L2 VMCS table (and contained correct code)
        // Or remembered from the "parent" field in TDVPS table
        lookup_context->field_id.class_code = class_code;
    }

    return;
}

static void md_get_next_accessible_item(lookup_iterator_t* lookup_context, bool_t is_element,
                            md_context_ptrs_t md_ctx, md_access_t access_type, md_access_qualifier_t access_qual)
{
    uint64_t rd_mask = 0;
    uint64_t wr_mask = 0;
    bool_t accessible_item = false;

    do
    {
        md_get_next_item_with_iterator(lookup_context, md_ctx, is_element);

        if (is_null_field_id(lookup_context->field_id))
        {
            break;
        }

        const md_lookup_t* entry = &lookup_context->lookup_table[lookup_context->table_idx];

        md_get_rd_wr_mask(entry, access_type, access_qual, &rd_mask, &wr_mask);

        accessible_item = ((!is_write_access_type(access_type) && rd_mask) ||
                           (is_write_access_type(access_type) && wr_mask));

    } while (!accessible_item);

    return;
}

static md_field_id_t md_get_next_item_in_context(md_context_code_e ctx_code, md_field_id_t field_id,
                                                 md_context_ptrs_t md_ctx, bool_t element,
                                                 md_access_t access_type, md_access_qualifier_t access_qual)
{
    lookup_iterator_t lookup_context;

    // TD-VMCS lookup table is accessed by class code 0. If we are on field_id==0 then we will get it
    // From this function below automatically.
    lookup_context.lookup_table = md_get_lookup_table(ctx_code, field_id, md_ctx,
                                                      &lookup_context.num_of_entries_in_table);
    lookup_context.field_id.raw = field_id.raw;

    // In case when input field id is -1, we just want the very first entry from the relevant table
    // And return the id of the first element of the first field, so the table search is not needed
    IF_RARE (is_null_field_id(field_id))
    {
        lookup_context.table_idx = 0;
    }
    else
    {
        lookup_context.table_idx = md_find_entry_idx(lookup_context.lookup_table,
                                                lookup_context.num_of_entries_in_table, field_id);
    }

    md_get_next_accessible_item(&lookup_context, element, md_ctx, access_type, access_qual);

    return lookup_context.field_id;
}

static md_field_id_t md_get_next_field_in_context(md_context_code_e ctx_code, md_field_id_t field_id,
                                                  md_context_ptrs_t md_ctx,
                                                  md_access_t access_type, md_access_qualifier_t access_qual)
{
    return md_get_next_item_in_context(ctx_code, field_id, md_ctx, false, access_type, access_qual);
}

md_field_id_t md_get_next_element_in_context(md_context_code_e ctx_code, md_field_id_t field_id,
                                             md_context_ptrs_t md_ctx,
                                             md_access_t access_type, md_access_qualifier_t access_qual)
{
    return md_get_next_item_in_context(ctx_code, field_id, md_ctx, true, access_type, access_qual);
}

static bool_t md_is_id_start_of_field(md_field_id_t field_id, const md_lookup_t* lookup_entry)
{
    uint32_t elem_num = field_id.field_code - lookup_entry->field_id.field_code;

    if (lookup_entry->field_id.inc_size)
    {
        IF_RARE ((elem_num % 2) != 0)
        {
            return false;
        }

        elem_num = elem_num / 2;
    }

    IF_RARE ((elem_num % lookup_entry->num_of_elem) != 0)
    {
        return false;
    }

    return true;
}

void md_get_rd_wr_mask(const md_lookup_t* entry, md_access_t access_type, md_access_qualifier_t access_qual,
        uint64_t* out_rd_mask, uint64_t* out_wr_mask)
{
    switch (access_type)
    {
        case MD_HOST_WR:
            *out_wr_mask = access_qual.host_qualifier.debug ? entry->dbg_wr_mask : entry->prod_wr_mask;
            *out_rd_mask = access_qual.host_qualifier.debug ? entry->dbg_rd_mask : entry->prod_rd_mask;
            break;
        case MD_HOST_RD:
            *out_wr_mask = 0;
            *out_rd_mask = access_qual.host_qualifier.debug ? entry->dbg_rd_mask : entry->prod_rd_mask;
            break;
        case MD_GUEST_WR:
            *out_wr_mask = entry->guest_wr_mask;
            *out_rd_mask = entry->guest_rd_mask;
            break;
        case MD_GUEST_RD:
            *out_wr_mask = 0;
            *out_rd_mask = entry->guest_rd_mask;
            break;
        case MD_SERV_TD_WR:
            *out_wr_mask = entry->migtd_wr_mask;
            *out_rd_mask = entry->migtd_rd_mask;
            break;
        case MD_SERV_TD_RD:
            *out_wr_mask = 0;
            *out_rd_mask = entry->migtd_rd_mask;
            break;
        case MD_EXPORT_IMMUTABLE:
            *out_wr_mask = 0;
            *out_rd_mask = (entry->mig_export == MIG_MB) ? entry->export_mask : 0;
            break;
        case MD_EXPORT_MUTABLE:
            *out_wr_mask = 0;
            *out_rd_mask = (entry->mig_export == MIG_ME) ? entry->export_mask : 0;
            break;
        case MD_IMPORT_IMMUTABLE:
            *out_wr_mask = (entry->mig_import == MIG_MB  || entry->mig_import == MIG_CB ||
                            entry->mig_import == MIG_MBO || entry->mig_import == MIG_CBO ||
                            entry->mig_import == MIG_IB  || entry->mig_import == MIG_IBS)
                                    ? entry->import_mask : 0;
            *out_rd_mask = ~(0ULL);
            break;
        case MD_IMPORT_MUTABLE:
            *out_wr_mask = (entry->mig_import == MIG_ME   || entry->mig_import == MIG_CE ||
                            entry->mig_import == MIG_MEO  || entry->mig_import == MIG_CEO ||
                            entry->mig_import == MIG_IE   || entry->mig_import == MIG_IES ||
                            entry->mig_import == MIG_IEME || entry->mig_import == MIG_IESME)
                                    ? entry->import_mask : 0;
            *out_rd_mask = ~(0ULL);
            break;
        default:
            TDX_ERROR("Incorrect access type : 0x%x\n", access_type);
            FATAL_ERROR();
            break;
    }

    return;
}

static const md_lookup_t* md_check_element_and_get_entry(md_context_code_e ctx_code, md_field_id_t field_id,
                                                         md_context_ptrs_t md_ctx)
{
    const md_lookup_t* lookup_table;
    uint32_t curr_idx, num_of_entries;

    lookup_table = md_get_lookup_table(ctx_code, field_id, md_ctx, &num_of_entries);

    curr_idx = md_find_entry_idx(lookup_table, num_of_entries, field_id);

    IF_RARE (curr_idx == MD_NO_ENTRY_IDX)
    {
        return NULL;
    }

    return &lookup_table[curr_idx];
}

api_error_code_e md_read_element(md_context_code_e ctx_code, md_field_id_t field_id,
        md_access_t access_type, md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t* value)
{
    api_error_code_e retval;
    const md_lookup_t* entry = md_check_element_and_get_entry(ctx_code, field_id, md_ctx);

    IF_RARE (entry == NULL)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    switch (ctx_code)
    {
        case MD_CTX_SYS:
            retval = md_sys_read_element(field_id, entry, access_type, access_qual, value);
            break;
        case MD_CTX_TD:
            retval = md_td_read_element(field_id, entry, access_type, access_qual, md_ctx, value);
            break;
        case MD_CTX_VP:
            retval = md_vp_read_element(field_id, entry, access_type, access_qual, md_ctx, value);
            break;
        default:
            FATAL_ERROR();
            break;
    }

    return retval;
}

api_error_code_e md_write_element(md_context_code_e ctx_code, md_field_id_t field_id,
         md_access_t access_type, md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx,
         uint64_t value, uint64_t wr_mask, uint64_t* old_value)
{
    api_error_code_e retval;
    const md_lookup_t* entry = md_check_element_and_get_entry(ctx_code, field_id, md_ctx);

    IF_RARE (entry == NULL)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    switch (ctx_code)
    {
        case MD_CTX_SYS:
            retval = md_sys_write_element(field_id, entry, access_type, access_qual,
                                         value, wr_mask, old_value);
            break;
        case MD_CTX_TD:
            retval = md_td_write_element(field_id, entry, access_type, access_qual, md_ctx,
                                         value, wr_mask, old_value);
            break;
        case MD_CTX_VP:
            retval = md_vp_write_element(field_id, entry, access_type, access_qual, md_ctx,
                                         value, wr_mask, old_value, true);
            break;
        default:
            FATAL_ERROR();
            break;
    }

    return retval;
}

static const md_lookup_t* md_check_field_and_get_entry(md_context_code_e ctx_code, md_field_id_t field_id,
                        md_context_ptrs_t md_ctx, lookup_iterator_t* lookup_context)
{
    const md_lookup_t* lookup_table;
    uint32_t curr_idx, num_of_entries;

    lookup_table = md_get_lookup_table(ctx_code, field_id, md_ctx, &num_of_entries);

    curr_idx = md_find_entry_idx(lookup_table, num_of_entries, field_id);

    const md_lookup_t* entry = &lookup_table[curr_idx];

    if ((curr_idx == MD_NO_ENTRY_IDX) || !md_is_id_start_of_field(field_id, entry) ||
        (field_id.element_size_code != entry->field_id.element_size_code))
    {
        return NULL;
    }

    tdx_sanity_check(entry->num_of_elem <= MAX_ELEMENTS_IN_FIELD, SCEC_METADATA_HANDLER_SOURCE, 2);

    if (lookup_context != NULL)
    {
        lookup_context->lookup_table = lookup_table;
        lookup_context->num_of_entries_in_table = num_of_entries;
        lookup_context->table_idx = curr_idx;
        lookup_context->field_id = entry->field_id;
        // Set up the exact input field code
        lookup_context->field_id.field_code = field_id.field_code;
    }

    return entry;
}

static api_error_code_e md_read_field_with_entry(md_context_code_e ctx_code, md_field_id_t field_id,
        md_access_t access_type, md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx,
        uint64_t value[MAX_ELEMENTS_IN_FIELD], const md_lookup_t* entry)
{
    api_error_code_e retval;

    IF_RARE (entry == NULL)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    switch (ctx_code)
    {
        case MD_CTX_SYS:
            retval = md_sys_read_field(field_id, entry, access_type, access_qual, value);
            break;
        case MD_CTX_TD:
            retval = md_td_read_field(field_id, entry, access_type, access_qual, md_ctx, value);
            break;
        case MD_CTX_VP:
            retval = md_vp_read_field(field_id, entry, access_type, access_qual, md_ctx, value);
            break;
        default:
            FATAL_ERROR();
            break;
    }

    return retval;
}

static api_error_code_e md_write_field_with_entry(md_context_code_e ctx_code, md_field_id_t field_id,
        md_access_t access_type, md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx,
        uint64_t value[MAX_ELEMENTS_IN_FIELD], uint64_t wr_mask, const md_lookup_t* entry, bool_t is_import)
{
    api_error_code_e retval;

    IF_RARE (entry == NULL)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    switch (ctx_code)
    {
        case MD_CTX_SYS:
            retval = md_sys_write_field(field_id, entry, access_type, access_qual, value, wr_mask);
            break;
        case MD_CTX_TD:
            retval = md_td_write_field(field_id, entry, access_type, access_qual, md_ctx, value, wr_mask, is_import);
            break;
        case MD_CTX_VP:
            retval = md_vp_write_field(field_id, entry, access_type, access_qual, md_ctx, value, wr_mask);
            break;
        default:
            FATAL_ERROR();
            break;
    }

    return retval;
}

_STATIC_INLINE_ void md_set_sequence_header(md_sequence_t* sequence_ptr, md_context_code_e ctx_code,
                                            md_field_id_t field_id, uint16_t num_of_elem, bool_t write_access)
{
    sequence_ptr->sequence_header.raw = field_id.raw;
    sequence_ptr->sequence_header.context_code = ctx_code;
    sequence_ptr->sequence_header.reserved_0 = 0;
    sequence_ptr->sequence_header.reserved_1 = 0;
    sequence_ptr->sequence_header.reserved_2 = 0;
    sequence_ptr->sequence_header.reserved_3 = 0;
    sequence_ptr->sequence_header.write_mask_valid = write_access;
    sequence_ptr->sequence_header.last_element_in_field = num_of_elem - 1;

#define MINUS_ONE_IN_9_BITS  (0x1FF)
    // Set it to -1, so that on first increment it will become 0
    sequence_ptr->sequence_header.last_field_in_sequence = MINUS_ONE_IN_9_BITS;
}

// Should be used only when next_field_id was created by calling md_get_next_item_in_context
// on the prev_field_id
_STATIC_INLINE_ bool_t is_sequential_field_id(md_field_id_t prev_field_id, uint32_t num_of_elem,
                                              md_field_id_t next_field_id)
{
    IF_RARE (is_special_cpuid_field_id(prev_field_id) &&
             is_special_cpuid_field_id(next_field_id))
    {
        // CPUID fields are never sequential
        return false;
    }

    uint16_t element_stride = (uint16_t)prev_field_id.inc_size + 1;

    return (prev_field_id.class_code == next_field_id.class_code) &&
           ((prev_field_id.field_code + (num_of_elem * element_stride)) == next_field_id.field_code);
}

typedef enum
{
    DUMP_SEQUENCE_DONE,
    DUMP_SEQUENCE_EMPTY,
    DUMP_SEQUENCE_NO_SPACE
} dump_seq_status_e;

// Can be invoked only after sequence header is set in sequence ptr
// Returns true if it completed the full the sequence dump
static dump_seq_status_e md_dump_sequence(md_sequence_t* sequence_ptr, md_context_code_e ctx_code,
                               md_context_ptrs_t md_ctx, uint32_t buff_size, md_access_t access_type,
                               md_access_qualifier_t access_qual,
                               uint32_t* elements_written, lookup_iterator_t* lkp_ctx)
{
    uint32_t sequence_idx = 0;
    dump_seq_status_e sequence_done = DUMP_SEQUENCE_NO_SPACE;
    const md_lookup_t* entry = NULL;
    api_error_code_e retval = TDX_SUCCESS;

    entry = &lkp_ctx->lookup_table[lkp_ctx->table_idx];

    bool_t sequence_header_set = false;

    // Decrement the sequence header size from the remaining buffer
    buff_size -= sizeof(md_field_id_t);
    *elements_written = 0;

    // Read the sequence, as long as there's space in the buffer for a whole field
    while ((uint64_t)buff_size >= ((uint64_t)entry->num_of_elem * sizeof(uint64_t)))
    {
        // Only fields that match the requested access attribute (e.g., immutable export) are dumped
        retval = md_read_field_with_entry(ctx_code, lkp_ctx->field_id,
                                          access_type, access_qual, md_ctx, &sequence_ptr->element[sequence_idx],
                                          entry);
        // If field was readable
        IF_COMMON (retval == TDX_SUCCESS)
        {
            if (!sequence_header_set)
            {
                // Set sequence header
                md_set_sequence_header(sequence_ptr, ctx_code, lkp_ctx->field_id, entry->num_of_elem, false);
                sequence_header_set = true;
            }

            // Update the remaining output buffer size, and advance the sequence buffer index
            buff_size -= (entry->num_of_elem * sizeof(uint64_t));
            sequence_idx += entry->num_of_elem;
            sequence_ptr->sequence_header.last_field_in_sequence++;
        }
        else if ((retval != TDX_METADATA_FIELD_NOT_READABLE) && (retval != TDX_METADATA_FIELD_SKIP))
        {
            TDX_ERROR("Unexpected error during sequence dump - 0x%llx, field_id = 0x%llx\n",
                    retval, lkp_ctx->field_id.raw);
            FATAL_ERROR();
        }

        // Fetch next field in context and class
        md_field_id_t last_field_id = lkp_ctx->field_id;
        md_get_next_accessible_item(lkp_ctx, false, md_ctx, access_type, access_qual);
        // If sequence is done (stopped on non-readable field), or no next field in table (current context),
        // or no next field in class, or two fields are not consequent,
        // or different number of elements between the fields
        // or different size of elements between the fields
        if ((retval == TDX_METADATA_FIELD_NOT_READABLE) ||
            (is_null_field_id(lkp_ctx->field_id)) ||
            !is_sequential_field_id(last_field_id, entry->num_of_elem, lkp_ctx->field_id) ||
            (entry->num_of_elem != lkp_ctx->lookup_table[lkp_ctx->table_idx].num_of_elem) ||
            (entry->field_id.element_size_code != lkp_ctx->field_id.element_size_code))
        {
            if (sequence_idx == 0)
            {
                sequence_done = DUMP_SEQUENCE_EMPTY;
            }
            else
            {
                sequence_done = DUMP_SEQUENCE_DONE;
            }
            break;
        }

        entry = &lkp_ctx->lookup_table[lkp_ctx->table_idx];
    }

    *elements_written = sequence_idx;

    return sequence_done;
}

api_error_code_e md_dump_list(md_context_code_e ctx_code, md_field_id_t field_id, md_context_ptrs_t md_ctx,
        md_list_header_t* list_header_ptr, uint32_t buff_size, md_access_t access_type,
        md_access_qualifier_t access_qual, md_field_id_t* next_field_id)
{
    lookup_iterator_t lookup_context;
    api_error_code_e retval;
    uint8_t* sequence_buffer_ptr;
    md_sequence_t* sequence_ptr;
    uint32_t elements_written = 0;
    dump_seq_status_e sequence_done = DUMP_SEQUENCE_NO_SPACE;

    next_field_id->raw = MD_FIELD_ID_NA;

    // Only HOST_RD, GUEST_RD and EXPORT_* are supported.
    IF_RARE ((access_type != MD_HOST_RD) && (access_type != MD_GUEST_RD) &&
        (access_type != MD_EXPORT_IMMUTABLE) && (access_type != MD_EXPORT_MUTABLE))
    {
        return TDX_METADATA_FIELD_NOT_READABLE;
    }

    // Buffer size, must be >= 24 to hold at least the list header and one sequence
    IF_RARE (buff_size < (sizeof(md_list_header_t) + sizeof(md_field_id_t) + MAX_ELEMENTS_IN_FIELD))
    {
        next_field_id->raw = field_id.raw;
        return TDX_METADATA_LIST_OVERFLOW;
    }

    // -1 as input means to expect a first field id from the lookup table
    if (is_null_field_id(field_id))
    {
        field_id = md_get_next_field_in_context(ctx_code, field_id, md_ctx, access_type, access_qual);

        // If we still got NULL_ID field, there's nothing to dump for given access type/qual
        if (is_null_field_id(field_id))
        {
            return TDX_SUCCESS;
        }
    }

    const md_lookup_t* entry = md_check_field_and_get_entry(ctx_code, field_id, md_ctx, &lookup_context);
    IF_RARE (entry == NULL)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    // Decrement the list header size
    buff_size -= sizeof(md_list_header_t);

    retval = TDX_METADATA_LIST_OVERFLOW;

    // Initialize the list header
    list_header_ptr->raw = 0;
    list_header_ptr->list_buff_size = sizeof(md_list_header_t);

    // Set up the first sequence header, which begins right after the list header
    sequence_buffer_ptr = (uint8_t*)(list_header_ptr) + sizeof(md_list_header_t);

    TDX_LOG("========================DUMP LIST========================\n");
    // Loop on sequences until we can't squeeze a sequence header + at least one complete field
    while (buff_size >= (sizeof(md_field_id_t) + entry->num_of_elem * sizeof(uint64_t)))
    {
        sequence_ptr = (md_sequence_t*)sequence_buffer_ptr;
        // Dump the sequence
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
        uint64_t prev_field_id = lookup_context.field_id.raw;
#endif

        sequence_done = md_dump_sequence(sequence_ptr, ctx_code, md_ctx, buff_size, access_type, access_qual,
                                         &elements_written, &lookup_context);

        // Check that it's not an empty sequence
        IF_COMMON (sequence_done != DUMP_SEQUENCE_EMPTY)
        {
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
            TDX_LOG("Sequence written from field 0x%llx, to field (which is next) 0x%llx\n",
                    prev_field_id, lookup_context.field_id.raw);
#endif

            // Update the list header
            list_header_ptr->num_sequences++;
            list_header_ptr->list_buff_size += (sizeof(md_field_id_t) + (elements_written * sizeof(uint64_t)));
            // Decrement the written element size and sequence header size from the buffer
            buff_size -= (sizeof(md_field_id_t) + (elements_written * sizeof(uint64_t)));
            // Advance the buffer pointer by the size of the sequence header + written elements
            sequence_buffer_ptr += (sizeof(md_field_id_t) + (elements_written * sizeof(uint64_t)));
        }

        // If sequence not finished (no more space left), or the context is done - no point to continue anymore
        IF_RARE ((sequence_done == DUMP_SEQUENCE_NO_SPACE) || is_null_field_id(lookup_context.field_id))
        {
            break;
        }

        // Fetch next field table entry, to see the number of elements in the loop condition
        entry = &lookup_context.lookup_table[lookup_context.table_idx];
    }

    // Next field id will either get -1 if we finished the context, or the next field id to be written
    // in case of unfinished sequence, or unfinished context
    next_field_id->raw = lookup_context.field_id.raw;

    if (is_null_field_id(*next_field_id))
    {
        retval = TDX_SUCCESS;
    }

    return retval;
}

_STATIC_INLINE_ bool_t is_required_entry(const md_lookup_t* entry, md_access_t access_type)
{
    if (access_type == MD_IMPORT_MUTABLE)
    {
        if (entry->mig_import == MIG_ME || entry->mig_import == MIG_CE || entry->mig_import == MIG_IESME)
        {
            return true;
        }
    }
    else if (access_type == MD_IMPORT_IMMUTABLE)
    {
        if (entry->mig_import == MIG_MB || entry->mig_import == MIG_CB)
        {
            return true;
        }
    }

    return false;
}

_STATIC_INLINE_ bool_t is_required_or_optional_entry(const md_lookup_t* entry, md_access_t access_type)
{
    if (access_type == MD_IMPORT_MUTABLE)
    {
        if (entry->mig_import == MIG_ME || entry->mig_import == MIG_CE || entry->mig_import == MIG_IESME ||
            entry->mig_import == MIG_MEO || entry->mig_import == MIG_CEO)
        {
            return true;
        }
    }
    else if (access_type == MD_IMPORT_IMMUTABLE)
    {
        if (entry->mig_import == MIG_MB || entry->mig_import == MIG_CB ||
            entry->mig_import == MIG_MBO || entry->mig_import == MIG_CBO)
        {
            return true;
        }
    }

    return false;
}

static api_error_code_e md_write_sequence(md_sequence_t* sequence_ptr, md_context_ptrs_t md_ctx,
                                uint32_t buff_size, md_access_t access_type, md_access_qualifier_t access_qual,
                                uint32_t* elements_read, lookup_iterator_t* lkp_iter, bool_t skip_non_writable,
                                uint64_t ext_err_info[2], bool_t is_import)
{
    md_context_code_e ctx_code = sequence_ptr->sequence_header.context_code;
    uint32_t sequence_idx = 0;
    const md_lookup_t* entry = NULL;
    uint64_t wr_mask;
    api_error_code_e retval;

    ext_err_info[0] = 0;
    ext_err_info[1] = 0;

    // Check that there's enough remaining size for the minimal sequence (header + 1 field)
    IF_RARE (buff_size < (sizeof(md_field_id_t) + sizeof(uint64_t)))
    {
        ext_err_info[0] = lkp_iter->field_id.raw;
        return api_error_with_l2_details(TDX_METADATA_LIST_OVERFLOW, 0xFFFF, 0);
    }
    // Check the sequence header
    retval = md_check_as_sequence_header(ctx_code, sequence_ptr->sequence_header, access_type);
    IF_RARE (retval != TDX_SUCCESS)
    {
        ext_err_info[0] = sequence_ptr->sequence_header.raw;
        return api_error_with_l2_details(retval, 0xFFFF, 0);
    }

    // Check the element size
    IF_RARE (sequence_ptr->sequence_header.element_size_code != lkp_iter->field_id.element_size_code)
    {
        ext_err_info[0] = sequence_ptr->sequence_header.raw;
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    *elements_read = 0;
    uint32_t num_fields = sequence_ptr->sequence_header.last_field_in_sequence + 1;

    // Subtract the sequence header size from remaining buffer
    buff_size -= sizeof(md_field_id_t);

    for (uint32_t i = 0; i < num_fields; i++)
    {
        entry = &lkp_iter->lookup_table[lkp_iter->table_idx];

        if (sequence_ptr->sequence_header.write_mask_valid)
        {
            // First element after the header will be the write mask, if write mask is valid
            wr_mask = sequence_ptr->element[0];
            sequence_idx++;
            buff_size -= sizeof(uint64_t);
        }
        else
        {
            wr_mask = (uint64_t)-1;
        }

        // Check that there's enough remaining size for the minimal sequence (1 field)
        if ((uint64_t)buff_size < ((uint64_t)entry->num_of_elem * sizeof(uint64_t)))
        {
            ext_err_info[0] = lkp_iter->field_id.raw;
            return api_error_with_l2_details(TDX_METADATA_LIST_OVERFLOW, 0xFFFF, 0);
        }

        if (!skip_non_writable || is_required_or_optional_entry(entry, access_type))
        {
            retval = md_write_field_with_entry(ctx_code, lkp_iter->field_id,
                                               access_type, access_qual, md_ctx, &sequence_ptr->element[sequence_idx],
                                               wr_mask, entry, is_import);

            if (retval != TDX_SUCCESS)
            {
                if (!((retval == TDX_METADATA_FIELD_NOT_WRITABLE) && skip_non_writable))
                {
                    ext_err_info[0] = lkp_iter->field_id.raw;
                    return retval;
                }
            }
        }

        // Update the remaining output buffer size, and advance the sequence buffer index
        buff_size -= (entry->num_of_elem * sizeof(uint64_t));
        sequence_idx += entry->num_of_elem;
        // Fetch next field in context and class
        md_get_next_item_with_iterator(lkp_iter, md_ctx, false);
        // If no next field in table (current context), or no next field in class, and apparently we still
        // have fields left...
        if ((i < (num_fields - 1)) &&
            (is_null_field_id(lkp_iter->field_id) ||
            (lkp_iter->field_id.class_code != entry->field_id.class_code)))
        {
            ext_err_info[0] = sequence_ptr->sequence_header.raw;
            return TDX_METADATA_FIELD_ID_INCORRECT;
        }
    }

    *elements_read = sequence_idx;

    return TDX_SUCCESS;
}

api_error_code_e md_write_list(md_context_code_e ctx_code, md_field_id_t expected_field, uint16_t buff_size,
                               bool_t check_missing, bool_t skip_non_writable, bool_t is_last,
                               md_context_ptrs_t md_ctx, md_list_header_t* list_header_ptr,
                               md_access_t access_type, md_access_qualifier_t access_qual,
                               md_field_id_t* next_field_id, uint64_t ext_err_info[2], bool_t is_import)
{
    lookup_iterator_t lkp_iter;
    uint16_t remaining_buff_size;
    api_error_code_e retval;
    uint8_t* sequence_buffer_ptr;
    md_sequence_t* sequence_ptr;
    uint32_t elements_read;

    // Default return values for extended error information
    ext_err_info[0] = ext_err_info[1] = 0;

    // Only HOST_WR, GUEST_WR and IMPORT_* are supported.
    tdx_debug_assert(!((access_type != MD_HOST_WR) && (access_type != MD_GUEST_WR) &&
        (access_type != MD_IMPORT_IMMUTABLE) && (access_type != MD_IMPORT_MUTABLE)));

    next_field_id->raw = MD_FIELD_ID_NA;

    // Check the list header
    if ((list_header_ptr->num_sequences == 0) || (list_header_ptr->reserved != 0))
    {
        return api_error_with_operand_id(TDX_INVALID_METADATA_LIST_HEADER, 0xFFFF);
    }

    if (list_header_ptr->list_buff_size > buff_size)
    {
        return api_error_with_operand_id(TDX_METADATA_LIST_OVERFLOW, 0xFFFF);
    }

    // -1 as input means to expect a first field id from the lookup table
    if (is_null_field_id(expected_field))
    {
        expected_field = md_get_next_field_in_context(ctx_code, expected_field, md_ctx, access_type, access_qual);

        // If we still got NULL_ID field, there's nothing to write for given access type/qual
        if (is_null_field_id(expected_field))
        {
            return TDX_METADATA_FIELD_ID_INCORRECT;
        }
    }

    if (check_missing)
    {
        // When ordered write list is done, we need to set up the iterator to the expected field
        if (md_check_field_and_get_entry(ctx_code, expected_field, md_ctx, &lkp_iter) == NULL)
        {
            return TDX_METADATA_FIELD_ID_INCORRECT;
        }
    }

    // Set up the first sequence header, which begins right after the list header
    remaining_buff_size = list_header_ptr->list_buff_size - sizeof(md_list_header_t);
    sequence_buffer_ptr = (uint8_t*)(list_header_ptr) + sizeof(md_list_header_t);

    // Read all sequences
    for (uint32_t i = 0; i < list_header_ptr->num_sequences; i++)
    {
        sequence_ptr = (md_sequence_t*)sequence_buffer_ptr;

        // Check that there's enough remaining size to actually access the sequence header,
        // and at least one element
        if (remaining_buff_size < (sizeof(sequence_ptr->sequence_header) + sizeof(uint64_t)))
        {
            return api_error_with_l2_details(TDX_METADATA_LIST_OVERFLOW, 0xFFFF, (uint16_t)i);
        }

        // Check context code
        if (sequence_ptr->sequence_header.context_code != expected_field.context_code)
        {
            ext_err_info[0] = sequence_ptr->sequence_header.raw;
            return api_error_with_l2_details(TDX_METADATA_FIELD_ID_INCORRECT, 0xFFFF, (uint16_t)i);
        }

        // When unordered write list is done, we need to set up the iterator for every new sequence
        if (!check_missing)
        {
            if (md_check_field_and_get_entry(ctx_code, sequence_ptr->sequence_header, md_ctx, &lkp_iter) == NULL)
            {
                ext_err_info[0] = sequence_ptr->sequence_header.raw;
                return api_error_with_l2_details(TDX_METADATA_FIELD_ID_INCORRECT, 0xFFFF, (uint16_t)i);
            }
        }

        // Check the sequence header if required
        if (check_missing && !is_equal_field_id(sequence_ptr->sequence_header, expected_field))
        {
            // The sequence header that we are looking at might skip some optional field in the context
            // We need to scroll forward the iterator until we find an entry with a field matching the sequence header
            // or until we hit the first required entry.
            while (!is_null_field_id(lkp_iter.field_id) &&
                   !is_equal_field_id(sequence_ptr->sequence_header, lkp_iter.field_id) &&
                   !is_required_entry(&lkp_iter.lookup_table[lkp_iter.table_idx], access_type))
            {
                md_get_next_item_with_iterator(&lkp_iter, md_ctx, false);
            }
            // If we didn't find any match, then a required field is missing
            if (!is_equal_field_id(sequence_ptr->sequence_header, lkp_iter.field_id))
            {
                ext_err_info[0] = lkp_iter.field_id.raw;
                return TDX_REQUIRED_METADATA_FIELD_MISSING;
            }
        }
        retval = md_write_sequence(sequence_ptr, md_ctx, (uint32_t)remaining_buff_size, access_type, access_qual,
                                   &elements_read, &lkp_iter, skip_non_writable, ext_err_info, is_import);
        if (retval != TDX_SUCCESS)
        {
            return api_error_with_operand_id(retval, i);
        }

        // Decrement the written element size and sequence header size from the buffer
        remaining_buff_size -= (sizeof(md_field_id_t) + (elements_read * sizeof(uint64_t)));
        // Advance the buffer pointer by the size of the sequence header + written elements
        sequence_buffer_ptr += (sizeof(md_field_id_t) + (elements_read * sizeof(uint64_t)));
        // Update the expected field id
        expected_field.raw = lkp_iter.field_id.raw;
    }

    if (check_missing)
    {
        if (is_last)
        {
            while (!is_null_field_id(lkp_iter.field_id))
            {
                if (is_required_entry(&lkp_iter.lookup_table[lkp_iter.table_idx], access_type))
                {
                    break;
                }
                md_get_next_item_with_iterator(&lkp_iter, md_ctx, false);
            }

            // This was the last metadata list, check that there are no required fields after the list
            if (!is_null_field_id(lkp_iter.field_id) &&
                 is_required_entry(&lkp_iter.lookup_table[lkp_iter.table_idx], access_type))
            {
                // There is a required field after this list
                ext_err_info[0] = lkp_iter.field_id.raw;
                ext_err_info[1] = 0;
                return TDX_REQUIRED_METADATA_FIELD_MISSING;
            }
        }
        else
        {
            // This was not the last metadata list page
            if (is_null_field_id(lkp_iter.field_id))
            {
                // We have more metadata lists to process, but there should be no more fields
                ext_err_info[0] = MD_FIELD_ID_NA;
                ext_err_info[1] = 0;
                return TDX_REQUIRED_METADATA_FIELD_MISSING;
            }
        }
    }

    // Return the next expected field id
    next_field_id->raw = lkp_iter.field_id.raw;

    return TDX_SUCCESS;
}
