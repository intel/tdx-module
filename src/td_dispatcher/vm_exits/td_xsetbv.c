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
 * @file td_xsetbv.c
 * @brief VM Exit handler for XSETBV instruction handler
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "helpers/helpers.h"

void td_xsetbv_instruction_exit(void)
{
    // On XSETBV, which attempts to write to XCR0, and on WRMSR of IA32_XSS, the guest TD exits to TDX-SEAM.
    // - If the new value is not natively legal for XCR0 (sets reserved bits,
    //   sets bits for features not supported by the CPU, sets bits for features
    //   not recognized by TDX-SEAM, or uses illegal bit combinations), TDX-SEAM injects a #GP(0) to the guest TD.
    // - Else, if the new value has any bits set which are not allowed by XFAM,
    //   TDX-SEAM injects a #GP(0) to the guest TD.

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvps_t* tdvps_ptr = tdx_local_data_ptr->vp_ctx.tdvps;

    // XCR index must be 0
    if ((uint32_t)tdvps_ptr->guest_state.gpr_state.rcx != 0)
    {
        inject_gp(0);
        return;
    }

    ia32_xcr0_t xcr0;
    xcr0.raw = (tdx_local_data_ptr->td_regs.rdx << 32) | (tdx_local_data_ptr->td_regs.rax & BITS(31,0));

    if (!check_guest_xcr0_value(xcr0, tdx_local_data_ptr->vp_ctx.xfam))
    {
        inject_gp(0);
        return;
    }

    /*-----------------------------------------------------
       All checks passed, emulate the XSETBV instruction
    -----------------------------------------------------*/

    ia32_xsetbv(0, xcr0.raw);
}

