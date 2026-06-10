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
 * @file tdh_sys_rdall
 * @brief TDH_SYS_RDALL API handler
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

api_error_type tdh_sys_rdall(uint64_t md_list_hpa, md_field_id_t field_id)
{
    tdx_module_local_t*     local_data_ptr = get_local_data();
    md_field_id_t           next_field_id;

    md_access_qualifier_t   access_qual = { .raw = 0 };
    md_context_ptrs_t       md_ctx;

    md_list_header_t        *md_list_hdr_p = NULL;
    api_error_type          retval = TDX_SUCCESS;

    // Default output register operands
    local_data_ptr->vmm_regs.r8 = MD_FIELD_ID_NA;

    // Check that LP-scope initialization has been done.
    // This also implies that TDH_SYS_INIT has been done.
    if (!local_data_ptr->lp_is_init)
    {
        retval = TDX_SYS_LP_INIT_NOT_DONE;
        TDX_ERROR("TDSYSINITLP not done!\n");
        goto EXIT;
    }

    // Verify the source physical address is canonical, shared, and aligned to 4KB page
    retval = shared_hpa_check_with_pwr_2_alignment((pa_t)md_list_hpa, _4KB);
    if (retval != TDX_SUCCESS)
    {
        retval = api_error_with_operand_id(retval, OPERAND_ID_RDX);
        TDX_ERROR("TD_SYS_RDALL output PA is not a valid shared HPA pa=0x%llx, error=0x%llx\n",
                  md_list_hpa, retval);
        goto EXIT;
    }

    md_list_hdr_p = (md_list_header_t*)map_pa((void*)md_list_hpa, TDX_RANGE_RW);

    // CONTEXT_CODE is implicit
    field_id.context_code = MD_CTX_SYS;

    md_ctx.tdr_ptr = NULL;
    md_ctx.tdcs_ptr = NULL;
    md_ctx.tdvps_ptr = NULL;

    retval = md_dump_list(MD_CTX_SYS, field_id, md_ctx, md_list_hdr_p, _4KB,
                          MD_HOST_RD, access_qual, &next_field_id);

    local_data_ptr->vmm_regs.r8 = next_field_id.raw;

EXIT:

    if (md_list_hdr_p != NULL)
    {
        free_la(md_list_hdr_p);
    }

    return retval;
}
