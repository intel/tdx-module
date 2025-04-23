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
 * @file tdg_vm_rd_wr.c
 * @brief TDGVMRDWR API handler
 */

#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "x86_defs/x86_defs.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "auto_gen/tdr_tdcs_fields_lookup.h"

static api_error_type tdg_vm_rd_wr(md_field_id_t field_id, uint64_t vm_id, tdx_module_local_t * local_data_ptr,
                                   bool_t write, uint64_t wr_value, uint64_t wr_request_mask, uint64_t version)
{
    // Temporary Variables
    uint64_t              rd_value;           // Data read from field

    md_context_ptrs_t     md_ctx;
    md_access_qualifier_t access_qual = { .raw = 0 };

    api_error_type        return_val = TDX_SUCCESS;

    // Default output register operands
    if (!write && (version > 0))
    {
        local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx = MD_FIELD_ID_NA;
    }
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = 0;

    // TDG.VM.RD supports version 1.  Other version checks are done by the TDCALL dispatcher.
    if ((!write) && (version > 1))
    {
        TDX_ERROR("Unsupported version = %llx\n", version);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        goto EXIT;
    }

    if (vm_id != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    md_ctx.tdr_ptr = local_data_ptr->vp_ctx.tdr;
    md_ctx.tdcs_ptr = local_data_ptr->vp_ctx.tdcs;
    md_ctx.tdvps_ptr = NULL;

    // Set the proper context code
    field_id.context_code = MD_CTX_TD;    // CONTEXT_CODE is ignored on input

    if (!write && (version > 0))
    {
        // For read, a null field ID means return the first field ID in context
        if (is_null_field_id(field_id))
        {
            local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx =
                    (md_get_next_element_in_context(MD_CTX_TD, field_id, md_ctx, MD_GUEST_RD, access_qual)).raw;

            return_val = TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT;
            goto EXIT;
        }
    }

    return_val = md_check_as_single_element_id(field_id);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Request field id doesn't match single element = %llx\n", field_id.raw);
        goto EXIT;
    }

    if (write)
    {
        return_val = md_write_element(MD_CTX_TD, field_id, MD_GUEST_WR, access_qual,
                                      md_ctx, wr_value, wr_request_mask, &rd_value);
    }
    else
    {
        return_val = md_read_element(MD_CTX_TD, field_id, MD_GUEST_RD, access_qual,
                                     md_ctx, &rd_value);

        if ((version > 0) && (return_val == TDX_SUCCESS))
        {
            local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx =
                    md_get_next_element_in_context(MD_CTX_TD, field_id, md_ctx, MD_GUEST_RD, access_qual).raw;
        }
    }

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to Read or Write data to a TDR/TDCS field - error = %llx\n", return_val);
        goto EXIT;
    }

    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = rd_value;

    return_val = TDX_SUCCESS;

EXIT:

    return return_val;
}

api_error_type tdg_vm_wr(uint64_t requested_field_code,
        uint64_t vm_id,
        uint64_t wr_data,
        uint64_t wr_mask,
        uint64_t version)
{
    tdx_module_local_t * local_data_ptr = get_local_data();
    md_field_id_t    field_code = { .raw = requested_field_code };

    return tdg_vm_rd_wr(field_code, vm_id, local_data_ptr, true, wr_data, wr_mask, version);
}

api_error_type tdg_vm_rd(uint64_t requested_field_code, uint64_t vm_id, uint64_t version)
{
    tdx_module_local_t * local_data_ptr = get_local_data();
    md_field_id_t    field_code = { .raw = requested_field_code };

    return tdg_vm_rd_wr(field_code, vm_id, local_data_ptr, false, 0, 0, version);
}


