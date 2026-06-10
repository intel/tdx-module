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
 * @file metadata_td.h
 * @brief TD-context (TDR and TDCS) metadata handler
 */

#ifndef SRC_COMMON_METADATA_HANDLERS_METADATA_TD_H_
#define SRC_COMMON_METADATA_HANDLERS_METADATA_TD_H_

#include "metadata_generic.h"
#include "auto_gen/tdr_tdcs_fields_lookup.h"
#include "helpers/error_reporting.h"

api_error_code_e md_td_read_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t* out_rd_value);

api_error_code_e md_td_read_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t value[MAX_ELEMENTS_IN_FIELD]);

api_error_code_e md_td_write_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t wr_value, uint64_t wr_request_mask,
        uint64_t* old_value);

api_error_code_e md_td_write_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t value[MAX_ELEMENTS_IN_FIELD],
        uint64_t wr_mask, bool_t is_import);

/**
 * @brief Private helper function to get the L2 VM index
 * Assumes that the current CLASS_CODE is one of the L2 class codes - no sanity checks are done
 *
 * @return VM index:  0 if n/a
 */

#define L2_TD_CLASS_CODE_INC 4   // Increment of CLASS_CODE per VM

_STATIC_INLINE_ uint16_t md_td_get_l2_vm_index(uint16_t class_code)
{
    tdx_debug_assert(class_code >= MD_TDCS_L2_SECURE_EPT_ROOT__1_CLASS_CODE);

    return ((class_code - MD_TDCS_L2_SECURE_EPT_ROOT__1_CLASS_CODE) / L2_TD_CLASS_CODE_INC) + 1;
};


#endif /* SRC_COMMON_METADATA_HANDLERS_METADATA_TD_H_ */
