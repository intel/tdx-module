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
 * @file tdg_vp_vmcall.c
 * @brief TDGVPVMCALL API handler
 */

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "tdx_td_api_handlers.h"
#include "debug/tdx_debug.h"

#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "accessors/data_accessors.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "x86_defs/x86_defs.h"

#include "td_transitions/td_exit.h"

static void copy_gprs_data_from_td_to_vmm(tdx_module_local_t* tdx_local_data_ptr,
                                          tdvmcall_control_t control)
{
    // Copy guest TD's GPRs, selected by the input parameter, to the host VMM GPRs image.
    // Clear other non-selected GPRs.
    td_exit_qualification_t td_exit_qual = { .raw = 0 };
    td_exit_qual.vm = tdx_local_data_ptr->vp_ctx.tdvps->management.curr_vm;
    td_exit_qual.gpr_select = control.gpr_select;
    td_exit_qual.xmm_select = control.xmm_select;

    tdx_local_data_ptr->vmm_regs.rcx = td_exit_qual.raw;

    // RAX is not copied, RCX filled above, start from RDX
    for (uint32_t i = 2; i < 16; i++)
    {
        if ((control.gpr_select & BIT(i)) != 0)
        {
            tdx_local_data_ptr->vmm_regs.gprs[i] = tdx_local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.gprs[i];
        }
        else
        {
            // Avoid modifying RBP
            if (!tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.config_flags.no_rbp_mod ||
                    (i != 5))
            {
                tdx_local_data_ptr->vmm_regs.gprs[i] = 0ULL;
            }
        }
    }
}

api_error_type tdg_vp_vmcall(uint64_t controller_value)
{
    api_error_type retval = TDX_OPERAND_INVALID;
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvmcall_control_t control = { .raw = controller_value };

    uint16_t gpr_check_mask = (uint16_t)(BIT(0) | BIT(1) | BIT(4));

    if (tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.config_flags.no_rbp_mod)
    {
        gpr_check_mask |= (uint16_t)BIT(5);
    }

    // Bits 0, 1 and 4 and 63:32 of RCX must be 0
    if (((control.gpr_select & gpr_check_mask) != 0) ||
         (control.reserved != 0))
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Unsupported bits in GPR_SELECT field = 0x%x\n", control.gpr_select)
        goto EXIT_FAILURE;
    }

    // TDX-SEAM loads the host VMM GPRs (in its LP-scope state save area), except RAX,
    // with the guest TD GPR (from TDVPS).
    copy_gprs_data_from_td_to_vmm(tdx_local_data_ptr, control);


    // Set the exit reason in RAX
    // Check the sticky BUS_LOCK_PREEMPTED flag, report and clear if true.
    vm_vmexit_exit_reason_t vm_exit_reason = { .raw = VMEXIT_REASON_TDCALL};
    if (tdx_local_data_ptr->vp_ctx.bus_lock_preempted)
    {
        vm_exit_reason.bus_lock_preempted = true;
        tdx_local_data_ptr->vp_ctx.bus_lock_preempted = false;
    }
    tdx_local_data_ptr->vmm_regs.rax = vm_exit_reason.raw;

    ia32_xcr0_t xcr0 = { .raw = tdx_local_data_ptr->vp_ctx.xfam };
    xcr0.sse = 1;
    uint64_t scrub_mask = xcr0.raw;

    // TDGVPVMCALL behaves as a trap-like TD exit.
    // TDX-SEAM advances the guest TD RIP (in TD VMCS) to the instruction following TDCALL.
    td_vmexit_to_vmm(VCPU_READY, LAST_EXIT_TDVMCALL, scrub_mask, control.xmm_select, false, true);
    
    EXIT_FAILURE:

    return retval;
}
