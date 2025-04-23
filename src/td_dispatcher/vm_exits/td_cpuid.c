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
 * @file td_vmexit.c
 * @brief CPUID VMexit handler
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"
#include "auto_gen/cpuid_configurations.h"

void td_cpuid_exit(void)
{
    uint32_t       leaf;
    uint32_t       subleaf;
    uint32_t       index;
    uint32_t       cpl;
    cpuid_config_return_values_t return_values;
    cpuid_01_ebx_t cpuid_01_ebx;
    cpuid_01_ecx_t cpuid_01_ecx;
    cpuid_07_00_ecx_t cpuid_07_00_ecx;
    cpuid_80000001_edx_t cpuid_80000001_edx;
    ia32_cr4_t     cr4;

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    vp_ctx_t* vp_ctx = &tdx_local_data_ptr->vp_ctx;

    leaf = (uint32_t)vp_ctx->tdvps->guest_state.gpr_state.rax;
    subleaf = (uint32_t)vp_ctx->tdvps->guest_state.gpr_state.rcx;

    /* CPUID leaf number that is higher than the maximum for its range is treated as if it were
       the maximum in the base range. */
    if (((leaf < CPUID_RESERVED_START) || (leaf > CPUID_RESERVED_END)) &&
        ((leaf > tdx_global_data_ptr->cpuid_last_extended_leaf) ||
         ((leaf > tdx_global_data_ptr->cpuid_last_base_leaf) && (leaf < CPUID_MAX_EXTENDED_VAL_LEAF))))
    {
        leaf = tdx_global_data_ptr->cpuid_last_base_leaf;
    }


    // Get an index to the CPUID tables
    index = get_cpuid_lookup_entry(leaf, subleaf);

    // Check if this is a faulting leaf/sub-leaf, either implicitly (if not in the tables)
    // or explicitly.  If so, inject a #VE.
    if ((index == CPUID_LOOKUP_IDX_NA) || cpuid_lookup[index].faulting)
    {
        tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, vp_ctx->tdvps, 0, 0);
        return;
    }

    // Check if the guest TD elected to unconditionally inject a #VE for the guest CPL
    cpl = get_guest_td_cpl();

    if ( ((cpl == 0) && (vp_ctx->tdvps->management.cpuid_supervisor_ve ||
                         vp_ctx->tdvps->cpuid_control[index].supervisor_ve))
         ||
         ((cpl > 0) && (vp_ctx->tdvps->management.cpuid_user_ve ||
                        vp_ctx->tdvps->cpuid_control[index].user_ve))
       )
    {
        tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, vp_ctx->tdvps, 0, 0);
        return;
    }

    // Get the CPUID value calculated by TDH_MNG_INIT from TDCS
    return_values = vp_ctx->tdcs->cpuid_config_vals[index];

    // Special CPUID Leaves/Sub-Leaves Handling
    //  - XFAM-allowed
    //  - KeyLocker-allowed
    //  - Perfmon-allowed
    //  - Dynamic

    switch (leaf)
    {
    case 0x1:
        // INITIAL_APIC_ID dynamically reflects VCPU_INDEX
        cpuid_01_ebx.raw = return_values.ebx;
        cpuid_01_ebx.initial_apic_id = vp_ctx->tdvps->management.vcpu_index;
        return_values.ebx = cpuid_01_ebx.raw;

        // OSXSAVE dynamically reflects guest CR4.OSXSAVE
        cpuid_01_ecx.raw = return_values.ecx;
        ia32_vmread(VMX_GUEST_CR4_ENCODE, &cr4.raw);
        cpuid_01_ecx.osxsave = cr4.osxsave;
        return_values.ecx = cpuid_01_ecx.raw;

        break;

    case 0x7:
        if (subleaf == 0)
        {
            cpuid_07_00_ebx_t cpuid_07_00_ebx;

            if (vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.tsx_supported)
            {
                // TSX is supported for the TD.  Emulate the effect of IA32_TSX_CTRL; if the TSX_CPUID_CLEAR
                // bit is 1, then clear the TSX CPUID bits in the virtual value that is returned to the guest.
                ia32_tsx_ctrl_t tsx_ctrl = { .raw = ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR) };
                if (tsx_ctrl.tsx_cpuid_clear)
                {
                    cpuid_07_00_ebx.raw = return_values.ebx;
                    cpuid_07_00_ebx.hle = 0;
                    cpuid_07_00_ebx.rtm = 0;
                    return_values.ebx = cpuid_07_00_ebx.raw;
                }
            }

            cpuid_07_00_ecx.raw = return_values.ecx;

            // CPUID(0x7, 0x0).ECX.OSPKE reflects guest CR4.PKE
            ia32_vmread(VMX_GUEST_CR4_ENCODE, &cr4.raw);
            cpuid_07_00_ecx.ospke = cr4.pke;

            return_values.ecx = cpuid_07_00_ecx.raw;
        }

        break;

    case 0xD:
        if (subleaf <= 1)
        {
            // EBX value, the maximum size of the XSAVE/XRSTOR save area required
            // by enabled features in XCR0 (sub-leaf 0) or XCR0 || IA32_XSS
            // (sub-leaf 1) is dynamically retrieved from the CPU.
            // This assumes that the TDX-SEAM module has not changed XCR0 or
            // IA32_XSS since VM exit from the guest TD.
            uint32_t eax, ecx, edx;
            ia32_cpuid(leaf, subleaf, &eax, &return_values.ebx, &ecx, &edx);
        }

        break;

    case 0x80000001:
        // If the guest is running in 64=bit mode, bit SYSCALL_SYSRET is returned as 1.  Otherwise, it's returned as 0
        cpuid_80000001_edx.raw = return_values.edx;
        cpuid_80000001_edx.syscall_sysret = is_td_guest_in_64b_mode();
        return_values.edx = cpuid_80000001_edx.raw;
        break;

    // Other leaves have no XFAM-related configuration
    default:
        break;
    }

    // Write the CPUID return values into the guest TD's GPR image
    vp_ctx->tdvps->guest_state.gpr_state.rax = return_values.eax;
    vp_ctx->tdvps->guest_state.gpr_state.rbx = return_values.ebx;
    vp_ctx->tdvps->guest_state.gpr_state.rcx = return_values.ecx;
    vp_ctx->tdvps->guest_state.gpr_state.rdx = return_values.edx;
}
