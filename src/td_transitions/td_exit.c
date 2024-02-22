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
 * @file td_async_exit.c
 * @brief All the ways to transition from TD(VM) to VMM
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "td_transitions/td_exit.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "helpers/virt_msr_helpers.h"

static void load_xmms_by_mask(tdvps_t* tdvps_ptr, uint16_t xmm_select)
{
    uint128_t xmms[16];

    basic_memset_to_zero(xmms, sizeof(xmms));

    // Copy the guest TD XMM's that should be passed to the VMM, otherwise they will be zeroed
    for (uint32_t i = 0; i < 16; i++)
    {
        if (xmm_select & (uint16_t)BIT(i))
        {
            xmms[i] = tdvps_ptr->guest_extension_state.xbuf.legacy_region.xmm[i];
        }
    }

    load_xmms_from_buffer(xmms);
    basic_memset_to_zero(xmms, sizeof(xmms));
}

// Clear DR if 'cur_value' != 0
static void init_all_dr_opt(tdvps_t* tdvps_ptr)
{
   if (tdvps_ptr->guest_state.dr0 != DR0_RESET_STATE)
   {
       ia32_load_dr0(DR0_RESET_STATE);
   }

   if (tdvps_ptr->guest_state.dr1 != DR1_RESET_STATE)
   {
       ia32_load_dr1(DR1_RESET_STATE);
   }

   if (tdvps_ptr->guest_state.dr2 != DR2_RESET_STATE)
   {
       ia32_load_dr2(DR2_RESET_STATE);
   }

   if (tdvps_ptr->guest_state.dr3 != DR3_RESET_STATE)
   {
       ia32_load_dr3(DR3_RESET_STATE);
   }

   if (tdvps_ptr->guest_state.dr6 != DR6_RESET_STATE)
   {
       ia32_load_dr6(DR6_RESET_STATE);
   }
}

// Clear MSR 'index' if 'cur_value' != 0
static void init_msr_opt(uint64_t addr, uint64_t cur_value)
{
    if (addr == IA32_FMASK_MSR_ADDR)
    {
        if (cur_value != IA32_FMASK_MSR_RESET_STATE)
        {
            ia32_wrmsr(IA32_FMASK_MSR_ADDR, IA32_FMASK_MSR_RESET_STATE);
        }
    }
    else if (addr == IA32_LBR_DEPTH_MSR_ADDR)
    {
        if (cur_value != IA32_LBR_DEPTH_MSR_RESET_STATE)
        {
            ia32_wrmsr(IA32_LBR_DEPTH_MSR_ADDR, IA32_LBR_DEPTH_MSR_RESET_STATE);
        }
    }
    else // All other MSR's are reset to 0
    {
        if (cur_value != 0)
        {
            ia32_wrmsr(addr, 0);
        }
    }
}

/*
 * Scrub CPU state that is not restored from TD VMCS host state by VM exit
 */
static void load_vmm_state_before_td_exit(tdx_module_local_t* local_data_ptr)
{
    tdx_module_global_t* global_data = get_global_data();

    // Clear CR2 to its INIT value
    ia32_load_cr2(CR2_RESET_STATE);

    // Debug state restoration
    init_all_dr_opt(local_data_ptr->vp_ctx.tdvps);

    wrmsr_opt(IA32_DS_AREA_MSR_ADDR, local_data_ptr->vmm_non_extended_state.ia32_ds_area, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_ds_area);

    if (local_data_ptr->vp_ctx.xfd_supported)
    {
        init_msr_opt(IA32_XFD_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_xfd);
        init_msr_opt(IA32_XFD_ERROR_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_xfd_err);
    }

    // Perfmon State
    if (local_data_ptr->vp_ctx.attributes.perfmon)
    {
        for (uint8_t i = 0; i < global_data->num_fixed_ctrs; i++)
        {
            if ((global_data->fc_bitmap & BIT(i)) != 0)
            {
                init_msr_opt(IA32_FIXED_CTR0_MSR_ADDR + i, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_fixed_ctr[i]);
            }
        }

        for (uint32_t i = 0; i < NUM_PMC; i++)
        {
            {
                init_msr_opt(IA32_A_PMC0_MSR_ADDR + i, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_a_pmc[i]);
            }
        }

        for (uint32_t i = 0; i < 2; i++)
        {
            init_msr_opt(IA32_OFFCORE_RSPx_MSR_ADDR + i, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_offcore_rsp[i]);
        }

        ia32_wrmsr(IA32_PERF_GLOBAL_STATUS_RESET_MSR_ADDR, ia32_rdmsr(IA32_PERF_GLOBAL_STATUS_MSR_ADDR));
        if (1 == global_data->plt_common_config.ia32_perf_capabilities.perf_metrics_available)
        {
            init_msr_opt(IA32_PERF_METRICS_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_perf_metrics);
        }
    }

    init_msr_opt(IA32_UARCH_MISC_CTL_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_uarch_misc_ctl);

    /*
     * Initialize the following MSRs:
     * IA32_STAR, IA32_LSTAR, IA32_FMASK, IA32_TSC_AUX,  & IA32_KERNEL_GS_BASE
     */

    init_msr_opt(IA32_TSC_AUX_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_tsc_aux);
    init_msr_opt(IA32_STAR_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_star);
    init_msr_opt(IA32_LSTAR_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_lstar);
    init_msr_opt(IA32_FMASK_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_fmask);
    init_msr_opt(IA32_KERNEL_GS_BASE_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_kernel_gs_base);

    if (local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.cpuid_flags.tsx_supported)
    {
        ia32_wrmsr(IA32_TSX_CTRL_MSR_ADDR, 0);
    }
    else
    {
        wrmsr_opt(IA32_TSX_CTRL_MSR_ADDR, local_data_ptr->vmm_non_extended_state.ia32_tsx_ctrl, IA32_TSX_CTRL_DISABLE_VALUE);
    }

    /*
     *  Use vmwrite to update the following SEAM-VMCS guest fields
     *  IA32_DEBUGCTL, IA32_PERF_GLOBAL_CTRL, IA32_RTIT_CTL, IA32_LBR_CTL and DR7
     */
    uint64_t debugctl_msr_value;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &debugctl_msr_value);
    debugctl_msr_value = debugctl_msr_value & IA32_DEBUGCTLMSR_MASK_BITS_PRESERVED;
    ia32_vmwrite(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, debugctl_msr_value);
    if (local_data_ptr->vp_ctx.attributes.perfmon)
    {
        ia32_vmwrite(VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE, VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_INIT_VALUE);
    }
    if (((ia32_xcr0_t)local_data_ptr->vp_ctx.xfam).pt)
    {
        ia32_vmwrite(VMX_GUEST_RTIT_CTL_FULL_ENCODE, VMX_GUEST_RTIT_CTL_INIT_VALUE);
    }
    if (((ia32_xcr0_t)local_data_ptr->vp_ctx.xfam).lbr)
    {
        ia32_vmwrite(VMX_GUEST_LBR_CTL_FULL_ENCODE, VMX_GUEST_LBR_CTL_INIT_VALUE);
    }
    ia32_vmwrite(VMX_GUEST_DR7_ENCODE, VMX_GUEST_DR7_INIT_VALUE);

}

static void save_guest_td_state_before_td_exit(tdcs_t* tdcs_ptr, tdx_module_local_t* local_data_ptr)
{
    tdx_module_global_t* global_data = get_global_data();

    tdvps_t* tdvps_ptr = local_data_ptr->vp_ctx.tdvps;

    // Extended state control

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported)
    {
        tdvps_ptr->guest_msr_state.ia32_xfd = ia32_rdmsr(IA32_XFD_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_xfd_err = ia32_rdmsr(IA32_XFD_ERROR_MSR_ADDR);
    }

    // CR2 state
    tdvps_ptr->guest_state.cr2 = ia32_store_cr2();

    // XCR0 state
    tdvps_ptr->guest_state.xcr0 = ia32_xgetbv(0);

    // Debug state
    tdvps_ptr->guest_state.dr0 = ia32_store_dr0();
    tdvps_ptr->guest_state.dr1 = ia32_store_dr1();
    tdvps_ptr->guest_state.dr2 = ia32_store_dr2();
    tdvps_ptr->guest_state.dr3 = ia32_store_dr3();
    tdvps_ptr->guest_state.dr6 = ia32_store_dr6();

    tdvps_ptr->guest_msr_state.ia32_ds_area = ia32_rdmsr(IA32_DS_AREA_MSR_ADDR);
    if (((ia32_xcr0_t)tdvps_ptr->management.xfam).lbr)
    {
        tdvps_ptr->guest_msr_state.ia32_lbr_depth = ia32_rdmsr(IA32_LBR_DEPTH_MSR_ADDR);
    }

    // Perfmon State
    if (tdcs_ptr->executions_ctl_fields.attributes.perfmon)
    {
        tdvps_ptr->guest_msr_state.ia32_fixed_ctr_ctrl = ia32_rdmsr(IA32_FIXED_CTR_CTRL_MSR_ADDR);
        for (uint8_t i = 0; i < global_data->num_fixed_ctrs; i++)
        {
            if ((global_data->fc_bitmap & BIT(i)) != 0)
            {
                tdvps_ptr->guest_msr_state.ia32_fixed_ctr[i] = ia32_rdmsr(IA32_FIXED_CTR0_MSR_ADDR + i);
            }
        }

        for (uint32_t i = 0; i < NUM_PMC; i++)
        {
            {
                tdvps_ptr->guest_msr_state.ia32_a_pmc[i] = ia32_rdmsr(IA32_A_PMC0_MSR_ADDR + i);
                tdvps_ptr->guest_msr_state.ia32_perfevtsel[i] = ia32_rdmsr(IA32_PERFEVTSEL0_MSR_ADDR + i);
            }
        }

        for (uint32_t i = 0; i < 2; i++)
        {
            tdvps_ptr->guest_msr_state.ia32_offcore_rsp[i] = ia32_rdmsr(IA32_OFFCORE_RSPx_MSR_ADDR + i);
        }

        tdvps_ptr->guest_msr_state.ia32_perf_global_status = ia32_rdmsr(IA32_PERF_GLOBAL_STATUS_MSR_ADDR);
        if (1 == global_data->plt_common_config.ia32_perf_capabilities.perf_metrics_available)
        {
            tdvps_ptr->guest_msr_state.ia32_perf_metrics = ia32_rdmsr(IA32_PERF_METRICS_MSR_ADDR);
        }
        tdvps_ptr->guest_msr_state.ia32_pebs_enable = ia32_rdmsr(IA32_PEBS_ENABLE_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_pebs_data_cfg = ia32_rdmsr(IA32_PEBS_DATA_CFG_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_pebs_ld_lat = ia32_rdmsr(IA32_PEBS_LD_LAT_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_pebs_frontend = ia32_rdmsr(IA32_PEBS_FRONTEND_MSR_ADDR);
    }
    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported)
    {
        tdvps_ptr->guest_msr_state.ia32_umwait_control= ia32_rdmsr(IA32_UMWAIT_CONTROL);
    }

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.tsx_supported)
    {
        tdvps_ptr->guest_msr_state.ia32_tsx_ctrl = ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR);
    }

    tdvps_ptr->guest_msr_state.ia32_uarch_misc_ctl = ia32_rdmsr(IA32_UARCH_MISC_CTL_MSR_ADDR);

    // Save the following MSRs:
    // IA32_STAR, IA32_LSTAR,
    // IA32_FMASK, IA32_KERNEL_GS_BASE, IA32_TSC_AUX
    tdvps_ptr->guest_msr_state.ia32_star            = ia32_rdmsr(IA32_STAR_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_lstar           = ia32_rdmsr(IA32_LSTAR_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_fmask           = ia32_rdmsr(IA32_FMASK_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_kernel_gs_base  = ia32_rdmsr(IA32_KERNEL_GS_BASE_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_tsc_aux         = ia32_rdmsr(IA32_TSC_AUX_MSR_ADDR);
}

static void async_tdexit_internal(api_error_code_e tdexit_case,
                                  vm_vmexit_exit_reason_t vm_exit_reason,
                                  uint64_t exit_qualification,
                                  uint64_t extended_exit_qualification,
                                  uint64_t gpa,
                                  uint64_t vm_exit_interruption_information,
                                  bool_t check_bus_lock_preempted)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvps_t* tdvps_ptr = tdx_local_data_ptr->vp_ctx.tdvps;
    tdr_t* tdr_ptr = tdx_local_data_ptr->vp_ctx.tdr;
    uint8_t vcpu_state = tdvps_ptr->management.state;
    uint8_t last_td_exit = tdvps_ptr->management.last_td_exit;
    api_error_code_t error_code;

    error_code.raw = tdexit_case;

    if (check_bus_lock_preempted)
    {
        // Check the sticky BUS_LOCK_PREEMPTED flag, report and clear if true
        if (tdx_local_data_ptr->vp_ctx.bus_lock_preempted)
        {
            vm_exit_reason.bus_lock_preempted = true;
        }
    }

    tdx_local_data_ptr->vp_ctx.bus_lock_preempted = false;

    switch (tdexit_case)
    {
    case TDX_SUCCESS:
    case TDX_CROSS_TD_FAULT:
    case TDX_TD_EXIT_BEFORE_L2_ENTRY:
    case TDX_TD_EXIT_ON_L2_TO_L1:
    case TDX_TD_EXIT_ON_L2_VM_EXIT:
        // Update the VCPU state for the next TDHVPENTER
        vcpu_state = VCPU_READY;
        last_td_exit = LAST_EXIT_ASYNC_FAULT;
        break;

    case TDX_CROSS_TD_TRAP:
    case TDX_HOST_PRIORITY_BUSY_TIMEOUT:
        // Update the VCPU state for the next TDH_VP_ENTER
        vcpu_state = VCPU_READY;
        last_td_exit = LAST_EXIT_ASYNC_TRAP;
        break;

    case TDX_NON_RECOVERABLE_VCPU:
        // Mark the VCPU so it can't be re-entered
        vcpu_state = VCPU_DISABLED;
        break;

        // Fatal cases
    case TDX_NON_RECOVERABLE_TD:
    case TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE:
    case TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE:
    case TDX_NON_RECOVERABLE_TD_CORRUPTED_MD:
        // VCPU state and last TD-exit doesn't change - we will pass to td_vmexit_to_vmm
        // the current value written in the TDVPS
        tdr_ptr->management_fields.fatal = true;
        error_code.fatal = 1;
        break;
    default:
        FATAL_ERROR();
    }

    // Set TD exit information
    error_code.details_l2 = vm_exit_reason.raw & BIT_MASK_32BITS;
    tdx_local_data_ptr->vmm_regs.rax = error_code.raw;

    td_exit_qualification_t td_exit_qual = { .raw = exit_qualification };
    td_exit_qual.vm = tdvps_ptr->management.curr_vm;

    tdx_local_data_ptr->vmm_regs.rcx = td_exit_qual.raw;
    tdx_local_data_ptr->vmm_regs.rdx = extended_exit_qualification;
    tdx_local_data_ptr->vmm_regs.r8  = gpa;
    tdx_local_data_ptr->vmm_regs.r9  = vm_exit_interruption_information;
    tdx_local_data_ptr->vmm_regs.r10 = 0ULL;
    tdx_local_data_ptr->vmm_regs.r11 = 0ULL;
    tdx_local_data_ptr->vmm_regs.r12 = 0ULL;
    tdx_local_data_ptr->vmm_regs.r13 = 0ULL;
    tdx_local_data_ptr->vmm_regs.r14 = 0ULL;

    tdx_local_data_ptr->vmm_regs.r15 = 0ULL;
    tdx_local_data_ptr->vmm_regs.rbx = 0ULL;
    tdx_local_data_ptr->vmm_regs.rbp = 0ULL;
    tdx_local_data_ptr->vmm_regs.rsi = 0ULL;
    tdx_local_data_ptr->vmm_regs.rdi = 0ULL;

    ia32_xcr0_t xcr0 = { .raw = tdx_local_data_ptr->vp_ctx.xfam };
    xcr0.sse = 1;
    uint64_t scrub_mask = xcr0.raw;

    if (error_code.host_recoverability_hint)
    {
        tdx_debug_assert(tdvps_ptr->management.curr_vm == 0);
    }

    td_vmexit_to_vmm(vcpu_state, last_td_exit, scrub_mask,
                     0, (tdexit_case == TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE),
                     error_code.host_recoverability_hint);
}

void write_l2_enter_outputs(tdvps_t* tdvps_ptr, uint16_t vm_id)
{
    // HPA assumed to be correct since it is checked before L2 VM entry
    l2_enter_guest_state_t* guest_state = map_pa((void*)tdvps_ptr->management.l2_enter_guest_state_hpa[vm_id], TDX_RANGE_RW);

    tdx_memcpy(&guest_state->gpr_state, sizeof(guest_state->gpr_state),
               &tdvps_ptr->guest_state.gpr_state, sizeof(tdvps_ptr->guest_state.gpr_state));

    // Read RSP, RFLAGS, RIP and SSP from their respective L2 VMCS fields
    ia32_vmread(VMX_GUEST_RSP_ENCODE, &guest_state->gpr_state.rsp);
    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &guest_state->rflags);
    ia32_vmread(VMX_GUEST_RIP_ENCODE, &guest_state->rip);
    ia32_vmread(VMX_GUEST_SSP_ENCODE, &guest_state->ssp);

    uint64_t val = 0;
    ia32_vmread(VMX_GUEST_INTERRUPT_STATUS_ENCODE, &val);
    guest_state->interrupt_status = (uint16_t)val;

    free_la(guest_state);
}

void async_tdexit_to_vmm(api_error_code_e tdexit_case,
                         vm_vmexit_exit_reason_t vm_exit_reason,
                         uint64_t exit_qualification,
                         uint64_t extended_exit_qualification,
                         uint64_t gpa,
                         uint64_t vm_exit_interruption_information)
{
    async_tdexit_internal(tdexit_case, vm_exit_reason, exit_qualification,
                          extended_exit_qualification, gpa, vm_exit_interruption_information, true);
}

void async_tdexit_cross_td(api_error_code_e tdexit_case,
                           api_error_code_e cross_td_status,
                           pa_t target_td)
{
    get_local_data()->vp_ctx.tdvps->guest_state.gpr_state.rax = cross_td_status;
    vm_vmexit_exit_reason_t empty_reason = { .raw = 0 };

    async_tdexit_internal(tdexit_case, empty_reason, 0, cross_td_status, target_td.raw, 0, false);
}

void async_tdexit_empty_reason(api_error_code_e tdexit_case)
{
    vm_vmexit_exit_reason_t empty_reason = { .raw = 0 };

    async_tdexit_internal(tdexit_case, empty_reason, 0, 0, 0, 0, false);
}

void td_vmexit_to_vmm(uint8_t vcpu_state, uint8_t last_td_exit, uint64_t scrub_mask,
                      uint16_t xmm_select, bool_t is_td_dead, bool_t is_trap_exit)
{
    // Local data
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    vp_ctx_t* vp_ctx = &tdx_local_data_ptr->vp_ctx;
    tdvps_t* tdvps_ptr = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_ptr = tdx_local_data_ptr->vp_ctx.tdcs;

    // Avoid accessing TD private memory and control structures (except TDR).
    // The TD is dead, no need so save its state.
    if (!is_td_dead)
    {
        // 1.  Save any guest state that it has not saved as part of the common guest-side operation, e.g.,
        //     the extended state per TDCS.XFAM
        save_guest_td_state_before_td_exit(tdcs_ptr, tdx_local_data_ptr);

        // 2.  Set TDVPS.STATE to one of the VCPU_READY sub states, as an indication to the next TD entry.
        tdvps_ptr->management.state = vcpu_state;
        tdvps_ptr->management.last_td_exit = last_td_exit;
        // At this point the VCPU state will no longer be accessed

        if ((tdvps_ptr->management.curr_vm != 0) && !is_trap_exit)
        {
            // On TD exit from L2 VM, write the output memory operands of TDG.VP.ENTER to memory.
            // This is done at this point, before the TLB tracking counter is decremented,
            // because after that the memory is not protected by TLB tracking and may not
            // be valid for writing anymore.
            write_l2_enter_outputs(tdvps_ptr, tdvps_ptr->management.curr_vm);
        }

        // Save Guest-TD XCR0 and XSS
        save_guest_td_extended_state(tdvps_ptr, tdx_local_data_ptr->vp_ctx.xfam);

        if (is_trap_exit)
        {
            // TDGVPVMCALL behaves as a trap-like TD exit.
            // TDX-SEAM advances the guest TD RIP (in TD VMCS) to the instruction following TDCALL.
            advance_guest_rip();
        }

        // 3.  Execute the TD exit TLB tracking sequence, adjusting the TDCS tracking counters.
        tdcs_epoch_tracking_fields_t* epoch_tracking = &tdcs_ptr->epoch_tracking;
        (void)_lock_xadd_16b(&epoch_tracking->epoch_and_refcount.refcount[tdvps_ptr->management.vcpu_epoch & 1], (uint16_t)-1);
    }

    // 4.  At this point TDR, TDCS and TDVPS will no longer be used during the flow.
    //     Release the shared lock on those control structures, which was acquired by TDHVPENTER.
    pamt_implicit_release_lock(vp_ctx->tdr_pamt_entry, TDX_LOCK_SHARED);
    pamt_unwalk(vp_ctx->tdvpr_pa, vp_ctx->tdvpr_pamt_block, vp_ctx->tdvpr_pamt_entry, TDX_LOCK_SHARED, PT_4KB);

    // Load host VMM state:
    set_seam_vmcs_as_active();

    // 5.  Load any host VMM state, which is not part of the output of TDHVPENTER, and that
    //     might have been modified by TDX-SEAM itself and by the guest TD, with synthetic INIT values.
    //
    // This is done before loading VMM state - to save additional XCR0/XSS save-restore
    initialize_extended_state(scrub_mask);

    // 6.  Restore host VMM CPU state from the TDX-SEAM LP-scope state save area.
    //     At this point, any flow that needed to update the host VMM state, e.g.,
    //     write to RDX as an output operand, has done so by updating the state save area.
    load_vmm_state_before_td_exit(tdx_local_data_ptr);

    // In case of TDGVPVMCALL, Guest XMM's will be passed down to VMM, based on XFAM.SSE bit
    // If the bit is 0 then they won't be zeroed by initialization
    // In case of Async TDEXIT, set XMM0-15 of the VMM to 0.
    if (last_td_exit == LAST_EXIT_TDVMCALL)
    {
        load_xmms_by_mask(tdvps_ptr, xmm_select);
    }

    // 7.   Run the common SEAMRET routine.
    tdx_vmm_post_dispatching();

    //unreachable Code. Panic
    tdx_sanity_check(0, SCEC_TDEXIT_SOURCE, 0);
}

static void td_l2_to_l1_exit_internal(api_error_code_e tdexit_case, vm_vmexit_exit_reason_t vm_exit_reason,
                      vmx_exit_qualification_t vm_exit_qualification, uint64_t extended_exit_qualification,
                      vmx_exit_inter_info_t vm_exit_inter_info,
                      uint32_t inter_error, uint64_t gla, uint64_t gpa, uint32_t idt_vectoring_info,
                      uint32_t idt_vectoring_err, uint32_t instr_info, uint32_t instr_length)
{
    tdx_module_local_t* ld_p = get_local_data();

    tdvps_t* tdvps_ptr = ld_p->vp_ctx.tdvps;
    uint16_t curr_vm = tdvps_ptr->management.curr_vm;
    api_error_code_t error_code;

    // If the TD is debuggable, the host VMM can request all L2->L1 exits to be converted to TD exits.
    if (tdvps_ptr->management.l2_debug_ctls[curr_vm].td_exit_on_l2_to_l1)
    {
        tdx_sanity_check(ld_p->vp_ctx.tdcs->executions_ctl_fields.attributes.debug, SCEC_TDEXIT_SOURCE, 1);
        async_tdexit_to_vmm(TDX_TD_EXIT_ON_L2_TO_L1, vm_exit_reason, vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }

    write_l2_enter_outputs(tdvps_ptr, tdvps_ptr->management.curr_vm);

    error_code.raw = tdexit_case;
    error_code.details_l2 = vm_exit_reason.raw & BIT_MASK_32BITS;

    tdvps_ptr->guest_state.gpr_state.rax = error_code.raw;
    tdvps_ptr->guest_state.gpr_state.rbx = 0;
    tdvps_ptr->guest_state.gpr_state.rcx = vm_exit_qualification.raw;
    tdvps_ptr->guest_state.gpr_state.rdx = gla;

    l2_enter_seg_details_t cs_seg_details = { .raw = 0 };
    uint64_t val, cs_base;
    cs_seg_details.selector = (uint16_t)(ia32_vmread(VMX_GUEST_CS_SELECTOR_ENCODE, &val), val);
    cs_seg_details.ar = (uint16_t)(ia32_vmread(VMX_GUEST_CS_ARBYTE_ENCODE, &val), val);
    cs_seg_details.limit = (uint32_t)(ia32_vmread(VMX_GUEST_CS_LIMIT_ENCODE, &val), val);

    ia32_vmread(VMX_GUEST_CS_BASE_ENCODE, &cs_base);

    tdvps_ptr->guest_state.gpr_state.rsi = cs_seg_details.raw;
    tdvps_ptr->guest_state.gpr_state.rdi = cs_base;

    tdvps_ptr->guest_state.gpr_state.r8  = gpa;
    tdvps_ptr->guest_state.gpr_state.r9  = ((uint64_t)inter_error << 32) | vm_exit_inter_info.raw;
    tdvps_ptr->guest_state.gpr_state.r10 = ((uint64_t)idt_vectoring_err << 32) | idt_vectoring_info;
    tdvps_ptr->guest_state.gpr_state.r11 = ((uint64_t)instr_length << 32) + instr_info;

    l2_enter_additional_exit_info_t exit_info = { .raw = 0 };
    exit_info.cpl = get_guest_td_cpl();

    tdvps_ptr->guest_state.gpr_state.r12 = exit_info.raw;
    tdvps_ptr->guest_state.gpr_state.r13 = extended_exit_qualification;
    tdvps_ptr->guest_state.gpr_state.r14 = 0;
    tdvps_ptr->guest_state.gpr_state.r15 = 0;

    // Make L1 the current VM
    tdvps_ptr->management.curr_vm = 0;
    set_vm_vmcs_as_active(tdvps_ptr, tdvps_ptr->management.curr_vm);

    // Set VMCS.IA32_SPEC_CTRL_SHADOW to the virtual value of IA32_SPEC_CTRL as seen by L1
    ia32_vmwrite(VMX_IA32_SPEC_CTRL_SHADOW,
            calculate_virt_ia32_spec_ctrl(ld_p->vp_ctx.tdcs, tdvps_ptr->guest_msr_state.ia32_spec_ctrl));

    // Update L1's host state fields before entry
    update_host_state_in_td_vmcs(ld_p, tdvps_ptr, tdvps_ptr->management.curr_vm);

    // Advance L1 guest RIP to the next instruction, following the TDCALL(TDG.VP.VMCALL) which entered L2
    advance_guest_rip();

    // Restore IA32_SPEC_CTR, restore the guest GPRs and enter the guest TD
    if (tdvps_ptr->management.vm_launched[tdvps_ptr->management.curr_vm])
    {
        tdx_return_to_td(true, false, &tdvps_ptr->guest_state.gpr_state);
    }
    else
    {
        tdx_return_to_td(false, false, &tdvps_ptr->guest_state.gpr_state);
    }

    // Flow should never reach here
    tdx_sanity_check(0, SCEC_TDEXIT_SOURCE, 2);
}

void td_l2_to_l1_exit_with_exit_case(api_error_code_e tdexit_case, vm_vmexit_exit_reason_t vm_exit_reason,
                                     vmx_exit_qualification_t vm_exit_qualification, uint64_t extended_exit_qualification,
                                     vmx_exit_inter_info_t vm_exit_inter_info)
{
    uint64_t inter_error, gla, gpa, idt_vectoring_info, idt_vectoring_err, instr_info, instr_length;

    ia32_vmread(VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE, &inter_error);
    ia32_vmread(VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE, &gla);
    ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &gpa);
    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vectoring_info);
    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE, &idt_vectoring_err);
    ia32_vmread(VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE, &instr_info);
    ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &instr_length);

    td_l2_to_l1_exit_internal(tdexit_case, vm_exit_reason, vm_exit_qualification, extended_exit_qualification,
                              vm_exit_inter_info, (uint32_t)inter_error, gla, gpa, (uint32_t)idt_vectoring_info,
                              (uint32_t)idt_vectoring_err, (uint32_t)instr_info, (uint32_t)instr_length);
}

void td_l2_to_l1_exit(vm_vmexit_exit_reason_t vm_exit_reason, vmx_exit_qualification_t vm_exit_qualification,
                      uint64_t extended_exit_qualification, vmx_exit_inter_info_t vm_exit_inter_info)
{
    td_l2_to_l1_exit_with_exit_case(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification,
                                    extended_exit_qualification, vm_exit_inter_info);
}
