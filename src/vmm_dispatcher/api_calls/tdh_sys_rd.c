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
 * @file tdh_sys_rd
 * @brief TDH_SYS_RD API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "memory_handlers/keyhole_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "auto_gen/global_sys_fields_lookup.h"
#include "metadata_handlers/metadata_generic.h"

api_error_type tdh_sys_rd(md_field_id_t field_id)
{
    tdx_module_local_t*     local_data_ptr = get_local_data();
    uint64_t                rd_value = 0;           // Data read from field

    md_access_qualifier_t   access_qual = { .raw = 0 };
    md_context_ptrs_t       md_ctx;
    api_error_type          retval = TDX_SUCCESS;

    // Default output register operands
    local_data_ptr->vmm_regs.rdx = MD_FIELD_ID_NA;
    local_data_ptr->vmm_regs.r8  = 0;

    // Check that LP-scope initialization has been done.
    // This also implies that TDH_SYS_INIT has been done.
    if (!local_data_ptr->lp_is_init)
    {
        retval = TDX_SYS_LP_INIT_NOT_DONE;
        TDX_ERROR("TDSYSINITLP not done!\n");
        goto EXIT;
    }

    // Set the proper context code
    field_id.context_code = MD_CTX_SYS;

    md_ctx.tdr_ptr = NULL;
    md_ctx.tdcs_ptr = NULL;
    md_ctx.tdvps_ptr = NULL;

    // For read, a null field ID means return the first field ID in context
    if (is_null_field_id(field_id))
    {
        local_data_ptr->vmm_regs.rdx =
                (md_get_next_element_in_context(MD_CTX_SYS, field_id, md_ctx, MD_HOST_RD, access_qual)).raw;

        retval = TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT;
        goto EXIT;
    }

    retval = md_check_as_single_element_id(field_id);
    if (retval != TDX_SUCCESS)
    {
        TDX_ERROR("Request field id doesn't match single element = %llx\n", field_id.raw);
        goto EXIT;
    }

    retval = md_read_element(MD_CTX_SYS, field_id, MD_HOST_RD, access_qual, md_ctx, &rd_value);

    local_data_ptr->vmm_regs.r8 = rd_value;

    if (retval == TDX_SUCCESS)
    {
        local_data_ptr->vmm_regs.rdx =
                (md_get_next_element_in_context(MD_CTX_SYS, field_id, md_ctx, MD_HOST_RD, access_qual)).raw;
    }

EXIT:

    return retval;
}
