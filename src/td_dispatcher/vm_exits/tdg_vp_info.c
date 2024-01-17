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
 * @file tdg_vp_info.c
 * @brief TDGVPINFO API handler
 */
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/tdx_tdvps.h"
#include "data_structures/td_control_structures.h"
#include "accessors/data_accessors.h"
#include "tdx_td_api_handlers.h"


api_error_type tdg_vp_info(void)
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    td_num_of_vcpus_t vcpus_info = {.raw = 0};
    tdg_commands_available_t commands_available = {.raw = 0};

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Check GPA width
    if (local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.gpaw)
    {
        local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rcx = MAX_PA_FOR_GPAW;
    }
    else
    {
        local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rcx = MAX_PA_FOR_GPA_NOT_WIDE;
    }

    // Get attributes
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx =
            local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.raw;

    // Get VCPUs info
    vcpus_info.max_vcpus = local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.max_vcpus;
    vcpus_info.num_vcpus = local_data_ptr->vp_ctx.tdcs->management_fields.num_vcpus;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = vcpus_info.raw;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r9 = local_data_ptr->vp_ctx.tdvps->management.vcpu_index;

    commands_available.tdg_sys_rd_available = 1;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r10 = commands_available.raw;

    // Reserved for future use
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r11 = 0ULL;

    return_val = TDX_SUCCESS;

    return return_val;
}
