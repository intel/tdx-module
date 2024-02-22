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
 * @file tdg_vp_cpuidve_set.c
 * @brief TDGVPCPUIDVE API handler
 */


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"

#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "accessors/data_accessors.h"
#include "tdx_td_api_handlers.h"


api_error_type tdg_vp_cpuidve_set(uint64_t control)
{
    api_error_type retval = UNINITIALIZE_ERROR;
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    union
    {
        struct
        {
            uint64_t supervisor : 1;
            uint64_t user       : 1;
            uint64_t reserved   : 62;
        };
        uint64_t raw;
    } cpuid_ve;

    cpuid_ve.raw = control;

    if (cpuid_ve.reserved != 0)
    {
        TDX_ERROR("Reserved field is not 0\n");
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    tdx_local_data_ptr->vp_ctx.tdvps->management.cpuid_supervisor_ve = cpuid_ve.supervisor;
    tdx_local_data_ptr->vp_ctx.tdvps->management.cpuid_user_ve = cpuid_ve.user;

    retval = TDX_SUCCESS;

EXIT:

    return retval;
}
