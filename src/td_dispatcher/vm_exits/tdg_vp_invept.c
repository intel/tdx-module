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
 * @file tdg_vp_invept.c
 * @brief TDGVPINVEPT API handler
 */
#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "helpers/helpers.h"

api_error_type tdg_vp_invept(uint64_t vm_mask)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    /* Bit 0 must be 0, INVEPT of L1 VMM is not supported.
       Bits for non - existing L2 VMs must be. 0 */
    if ((vm_mask & BIT(0)) != 0 || ((vm_mask >> (tdx_local_data_ptr->vp_ctx.tdcs->management_fields.num_l2_vms + 1)) != 0))
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
    }

    for (uint16_t vm_id = 1; vm_id <= tdx_local_data_ptr->vp_ctx.tdcs->management_fields.num_l2_vms; vm_id++)
    {
        if (vm_mask & BIT(vm_id))
        {
            // Flush the TLB context and extended paging structure (EPxE) caches associated
            // with the VM, using INVEPT single-context invalidation (type 1).
            flush_td_asid(tdx_local_data_ptr->vp_ctx.tdr, tdx_local_data_ptr->vp_ctx.tdcs, vm_id);

            // Currently there is no need to invalidate soft-translated GPAs, they are all in the L1 context
            vm_mask &= ~BIT(vm_id);
        }
    }

    return TDX_SUCCESS;
}
