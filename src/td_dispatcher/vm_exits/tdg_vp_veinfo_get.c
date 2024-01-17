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
 * @file tdg_vp_veinfo_get.c
 * @brief TDGVPVEINFOGET API handler
 */
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "tdx_td_api_handlers.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/data_accessors.h"

api_error_type tdg_vp_veinfo_get(void)
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Initialize output registers to default values
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rcx = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r9 = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r10 = 0;

    // Check that VE_INFO has valid contents
    if (local_data_ptr->vp_ctx.tdvps->ve_info.valid == 0)
    {
        TDX_ERROR("VE_INFO has no valid contents\n");
        return_val = TDX_NO_VALID_VE_INFO;
        goto EXIT;
    }
    
    // Retrieve the data from the VE_INFO and put into output registers
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rcx = (uint64_t)local_data_ptr->vp_ctx.tdvps->ve_info.exit_reason;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx = local_data_ptr->vp_ctx.tdvps->ve_info.exit_qualification;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = local_data_ptr->vp_ctx.tdvps->ve_info.gla;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r9 = local_data_ptr->vp_ctx.tdvps->ve_info.gpa;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r10 = local_data_ptr->vp_ctx.tdvps->ve_info.inst_len_and_info;

    // Mark VE info as free
    local_data_ptr->vp_ctx.tdvps->ve_info.valid = 0ULL;

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}
