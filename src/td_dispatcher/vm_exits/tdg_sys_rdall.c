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
#include "tdx_td_api_handlers.h"
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

api_error_type tdg_sys_rdall(uint64_t md_list_gpa, md_field_id_t field_id)
{
    tdx_module_local_t*     local_data_ptr = get_local_data();
    md_field_id_t           next_field_id;

    md_access_qualifier_t   access_qual = { .raw = 0 };
    md_context_ptrs_t       md_ctx;

    md_list_header_t        *md_list_hdr_p = NULL;
    api_error_type          retval = TDX_SUCCESS;

    tdr_t* tdr_p     = local_data_ptr->vp_ctx.tdr;
    tdcs_t* tdcs_p   = local_data_ptr->vp_ctx.tdcs;
    tdvps_t* tdvps_p = local_data_ptr->vp_ctx.tdvps;

    tdx_sanity_check(tdr_p != NULL, SCEC_TDCALL_SOURCE(TDG_SYS_RDALL_LEAF), 0);
    tdx_sanity_check(tdcs_p != NULL, SCEC_TDCALL_SOURCE(TDG_SYS_RDALL_LEAF), 1);
    tdx_sanity_check(tdvps_p != NULL, SCEC_TDCALL_SOURCE(TDG_SYS_RDALL_LEAF), 2);

    // Default output register operands
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = MD_FIELD_ID_NA;

    if (!is_addr_aligned_pwr_of_2(md_list_gpa, _4KB))
    {
        TDX_ERROR("MD_LIST GPA (%llx) is not aligned to 4KB\n", md_list_gpa);
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    retval = check_walk_and_map_guest_side_gpa(tdcs_p,
                                               tdvps_p,
                                               (pa_t)md_list_gpa,
                                               tdr_p->key_management_fields.hkid,
                                               TDX_RANGE_RW,
                                               PRIVATE_ONLY,
                                               (void **)&md_list_hdr_p);
    if (retval != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on checking GPA (=%llx) error = %llx\n", md_list_gpa, retval);
        retval = api_error_with_operand_id(retval, OPERAND_ID_RDX);
        goto EXIT;
    }

    // CONTEXT_CODE is implicit
    field_id.context_code = MD_CTX_SYS;

    md_ctx.tdr_ptr = NULL;
    md_ctx.tdcs_ptr = NULL;
    md_ctx.tdvps_ptr = NULL;

    retval = md_dump_list(MD_CTX_SYS, field_id, md_ctx, md_list_hdr_p, _4KB,
                          MD_GUEST_RD, access_qual, &next_field_id);

    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = next_field_id.raw;

EXIT:

    if (md_list_hdr_p != NULL)
    {
        free_la(md_list_hdr_p);
    }

    return retval;
}
