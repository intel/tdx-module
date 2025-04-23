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
 * @file tdh_vp_enter
 * @brief TDHVPENTER API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "td_dispatcher/tdx_td_dispatcher.h"
#include "td_transitions/td_exit_stepping.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"
#include "helpers/virt_msr_helpers.h"


_STATIC_INLINE_ void guest_ext_state_load_failure()
{
    vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };
    vm_exit_reason.basic_reason = VMEXIT_REASON_FAILED_VMENTER_GS;

    vmx_ext_exit_qual_t eeq = { .raw = 0 };
    eeq.type = VMX_EEQ_TD_ENTRY_XSTATE_LOAD_FAILURE;

    async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE,
            vm_exit_reason, 0, eeq.raw, 0, 0);
}

// Before using the first safe_wrmsr - save MSR(NON_FAULTING_MSR_ADDR) - 0x8b in the local data
// and it will be restored in case of #GP.
static __attribute__((noinline)) void safe_wrmsr(uint64_t addr, uint64_t value)
{
    IF_RARE (!ia32_safe_wrmsr(addr, value))
    {
        TDX_ERROR("WRMSR(0x%llx) with value 0x%llx caused #GP\n", addr, value);

        vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };
        vm_exit_reason.basic_reason = VMEXIT_REASON_FAILED_VMENTER_MSR;

        vmx_ext_exit_qual_t eeq = { .raw = 0 };
        eeq.type = VMX_EEQ_TD_ENTRY_MSR_LOAD_FAILURE;
        eeq.info = addr;

        ia32_wrmsr(NON_FAULTING_MSR_ADDR, get_local_data()->non_faulting_msr_value);

        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE,
                vm_exit_reason, 0, eeq.raw, 0, 0);
    }
}

static __attribute__((noinline)) void safe_xrstors(const void* xsave_area, uint64_t xfam)
{
    IF_RARE (!ia32_safe_xrstors(xsave_area, xfam))
    {
        TDX_ERROR("XRSTORS with XFAM 0x%llx caused #GP\n", xfam);
        guest_ext_state_load_failure();
    }
}

_STATIC_INLINE_ void ia32_perf_global_status_write(uint64_t reset_command, uint64_t set_command)
{
    // IA32_PERF_GLOBAL_STATUS is written in a special way, using the RESET and SET command MSRs
    safe_wrmsr(IA32_PERF_GLOBAL_STATUS_RESET_MSR_ADDR, reset_command);
    safe_wrmsr(IA32_PERF_GLOBAL_STATUS_SET_MSR_ADDR, set_command);
}

_STATIC_INLINE_ void restore_guest_td_extended_state(tdvps_t* tdvps_ptr)
{
    uint64_t xstate_bv = tdvps_ptr->guest_extension_state.xbuf.xsave_header.xstate_bv;
    uint64_t xcomp_bv = tdvps_ptr->guest_extension_state.xbuf.xsave_header.xcomp_bv;

    // Check for XBUFF header corruption before trying to use SAFE_XRSTORS
    // Checks are done according to SDM Volume 1, Chapter 13.12
    // A #GP occurs in the following cases:
    //  - XCOMP_BV[63] = 0.
    //  - XCOMP_BV sets a bit in the range 62:0 that is not set in XCR0 | IA32_XSS
    //    (in our case XCR0 | IA32_XSS is just the XFAM)
    //  - XSTATE_BV sets a bit(including bit 63) that is not set in XCOMP_BV.
    //  - Bytes 63 : 16 of the XSAVE header are not all 0.

    if (((xcomp_bv & BIT(63)) == 0) ||
        ((xcomp_bv & ~BIT(63) & ~(tdvps_ptr->management.xfam)) != 0) ||
        ((xstate_bv & ~xcomp_bv) != 0) ||
        (!tdx_memcmp_to_zero(tdvps_ptr->guest_extension_state.xbuf.xsave_header.reserved,
                             sizeof(tdvps_ptr->guest_extension_state.xbuf.xsave_header.reserved))))
    {
        TDX_ERROR("Failed checks on XBUFF header. xcomp_bv = 0x%llx, xstate_bv = 0x%llx, xfam = 0x%llx\n",
                xcomp_bv, xstate_bv, tdvps_ptr->management.xfam);
        guest_ext_state_load_failure();
    }

    // Set Guest XCR0 and XSS context for restoring the state
    ia32_xsetbv(0, tdvps_ptr->management.xfam & XCR0_USER_BIT_MASK);
    ia32_wrmsr(IA32_XSS_MSR_ADDR, tdvps_ptr->management.xfam & XCR0_SUPERVISOR_BIT_MASK);

    safe_xrstors(&tdvps_ptr->guest_extension_state.xbuf, tdvps_ptr->management.xfam);
}

static void emulate_ept_violation_td_exit(tdx_module_local_t* local_data_ptr, pa_t faulting_gpa,
                                          tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr, uint16_t vm_id)
{
    faulting_gpa.low_12_bits = 0;

    // VMX qualification = write access (bit 1 set)
    vmx_exit_qualification_t qualification;
    qualification.raw = 0;
    qualification.ept_violation.data_write = 1;

    td_exit_qualification_t exit_qualification;
    exit_qualification.raw = qualification.raw;
    exit_qualification.vm = vm_id;

    // Emulate an Async TDEXIT
    initialize_extended_state(local_data_ptr->vp_ctx.xfam);

    tdvps_ptr->management.state = VCPU_READY;
    tdvps_ptr->management.last_td_exit = LAST_EXIT_ASYNC_FAULT;

    // Set TD exit information
    local_data_ptr->vmm_regs.rcx = exit_qualification.raw;
    local_data_ptr->vmm_regs.rdx = 0; // No TDX extended qualification
    local_data_ptr->vmm_regs.r8 = faulting_gpa.raw;
    local_data_ptr->vmm_regs.r9 = 0; // No VMX interruption information

    // Other GPRs return 0
    local_data_ptr->vmm_regs.rbx = 0;
    if (!tdcs_ptr->executions_ctl_fields.config_flags.no_rbp_mod)
    {
        local_data_ptr->vmm_regs.rbp = 0;
    }
    local_data_ptr->vmm_regs.rsi = 0;
    local_data_ptr->vmm_regs.rdi = 0;
    local_data_ptr->vmm_regs.r10 = 0;
    local_data_ptr->vmm_regs.r11 = 0;
    local_data_ptr->vmm_regs.r12 = 0;
    local_data_ptr->vmm_regs.r13 = 0;
    local_data_ptr->vmm_regs.r14 = 0;
    local_data_ptr->vmm_regs.r15 = 0;
}

static void save_xmms_by_mask(tdvps_t* tdvps_ptr, uint16_t xmm_select)
{
    uint128_t xmms[16];

    store_xmms_in_buffer(xmms);

    // Copy the required VMM XMM's to the guest XMM's
    for (uint32_t i = 0; i < 16; i++)
    {
        if (xmm_select & (uint16_t)BIT(i))
        {
            tdvps_ptr->guest_extension_state.xbuf.legacy_region.xmm[i] = xmms[i];

        }
    }

    basic_memset_to_zero(xmms, sizeof(xmms));

    if (xmm_select != 0)
    {
        tdvps_ptr->guest_extension_state.xbuf.xsave_header.xstate_bv |= BIT(1);
    }

}

static void save_regs_after_tdvmcall(tdvps_t* tdvps_ptr, tdvmcall_control_t control, 
                    uint64_t gprs[16])
{
    uint64_t mask;
    uint32_t i;

    /* Save XMM registers selected by guest RCX to TDVPS.
     * Later on the whole state of XMMs, MXCSR and optionally YMMs and ZMMs is
     * restored from TDVPS.
     */
    save_xmms_by_mask(tdvps_ptr, control.xmm_select);

    /* Save VMM GPRs selected by guest RCX to TDVPS.
     * RAX and RCX are not copied, start from RDX.
     */
    mask = 0x0004;
    for (i = 2; i < 16; i++)
    {
        if ((control.gpr_select & mask) != 0)
        {
            gprs[i] = get_local_data()->vmm_regs.gprs[i];
        }       
        mask <<= 1;
    }

    gprs[0] = TDX_SUCCESS;   // RAX
    gprs[1] = control.raw;   // RCX
}

static void set_l2_exit_host_routing(tdvps_t* tdvps_ptr)
{
    if (tdvps_ptr->management.l2_exit_host_routed == HOST_ROUTED_NONE)
    {
        if (tdvps_ptr->management.last_td_exit == LAST_EXIT_TDVMCALL)
        {
            tdvps_ptr->management.l2_exit_host_routed = HOST_ROUTED_TDVMCALL;
        }
        else
        {
            tdvps_ptr->management.l2_exit_host_routed = HOST_ROUTED_ASYNC;
        }
    }
}

static void restore_guest_td_state_before_td_entry(tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr)
{
    tdx_module_global_t* global_data = get_global_data();
    tdx_module_local_t* local_data_ptr = get_local_data();
    // Save MSR (NON_FAULTING_MSR_ADDR) value before the first usage of safe_wrmsr
    local_data_ptr->non_faulting_msr_value = ia32_rdmsr(NON_FAULTING_MSR_ADDR);

    // CR2 state restoration
    ia32_load_cr2(tdvps_ptr->guest_state.cr2);

    // Debug state restoration
    ia32_load_dr0(tdvps_ptr->guest_state.dr0);
    ia32_load_dr1(tdvps_ptr->guest_state.dr1);
    ia32_load_dr2(tdvps_ptr->guest_state.dr2);
    ia32_load_dr3(tdvps_ptr->guest_state.dr3);
    ia32_load_dr6(tdvps_ptr->guest_state.dr6);

    safe_wrmsr(IA32_DS_AREA_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_ds_area);

    //  Restore IA32_LBR_DEPTH from TDVPS.IA32_LBR_DEPTH. This MSR is not restored by XRSTORS
    //  like other LBR MSRs. On XRSTORS, if the saved value matches current value, then
    //  only LBRs 0..DEPTH-1 are restored, otherwise all IA32_LBR_TOS, IA32_LBR_x_*
    //  MSRs, and IA32_LER_* MSRs are cleared.
    if (((ia32_xcr0_t)tdvps_ptr->management.xfam).lbr)
    {
        safe_wrmsr(IA32_LBR_DEPTH_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_lbr_depth);
    }

    // Perfmon State
    if (tdcs_ptr->executions_ctl_fields.attributes.perfmon)
    {
        safe_wrmsr(IA32_FIXED_CTR_CTRL_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_fixed_ctr_ctrl);
        for (uint8_t i = 0; i < global_data->num_fixed_ctrs; i++)
        {
            if ((global_data->fc_bitmap & BIT(i)) != 0)
            {
                safe_wrmsr(IA32_FIXED_CTR0_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_fixed_ctr[i]);
            }
        }

        for (uint32_t i = 0; i < NUM_PMC; i++)
        {
            safe_wrmsr(IA32_A_PMC0_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_a_pmc[i]);
            safe_wrmsr(IA32_PERFEVTSEL0_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_perfevtsel[i]);
        }

        for (uint32_t i = 0; i < 2; i++)
        {
            safe_wrmsr(IA32_OFFCORE_RSPx_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_offcore_rsp[i]);
        }

        ia32_perf_global_status_write(ia32_rdmsr(IA32_PERF_GLOBAL_STATUS_MSR_ADDR),
                tdvps_ptr->guest_msr_state.ia32_perf_global_status);
        safe_wrmsr(IA32_PEBS_ENABLE_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_enable);
        if (global_data->plt_common_config.ia32_perf_capabilities.perf_metrics_available)
        {
            safe_wrmsr(IA32_PERF_METRICS_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_perf_metrics);
        }
        safe_wrmsr(IA32_PEBS_DATA_CFG_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_data_cfg);
        safe_wrmsr(IA32_PEBS_LD_LAT_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_ld_lat);
        // MSR_PEBS_FRONTEND exists only in big cores
        if (global_data->native_model_info.core_type == CORE_TYPE_BIGCORE)
        {
            safe_wrmsr(IA32_PEBS_FRONTEND_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_frontend);
        }
    }
    else
    {
        // save VMM's Fixed Counter Controls (FCC) MSR
        local_data_ptr->vmm_ia32_fixed_ctr_ctrl = ia32_rdmsr(IA32_FIXED_CTR_CTRL_MSR_ADDR);
        
        if (TDX_MODULE_IA32_FIXED_CTR_CTRL != local_data_ptr->vmm_ia32_fixed_ctr_ctrl)
        {
            // load TD's FCC with FC0 enabled in all rings, no PMI on overflow
            safe_wrmsr(IA32_FIXED_CTR_CTRL_MSR_ADDR, TDX_MODULE_IA32_FIXED_CTR_CTRL);
        }

        // save VMM's FC0 value
        local_data_ptr->vmm_ia32_fixed_ctr0 = ia32_rdmsr(IA32_FIXED_CTR0_MSR_ADDR);

        if (0x0 != local_data_ptr->vmm_ia32_fixed_ctr0)
        {
            // clear FC0
            safe_wrmsr(IA32_FIXED_CTR0_MSR_ADDR, 0x0);
        }

        uint64_t perf_global_status_mask = (BIT(32) | BIT(59));
        // save VMM's Perf Global Status (PGS) counter freezing and FC0 
        local_data_ptr->vmm_ia32_perf_global_status = ia32_rdmsr(IA32_PERF_GLOBAL_STATUS_MSR_ADDR) & perf_global_status_mask;

        if (0x0 != local_data_ptr->vmm_ia32_perf_global_status)
        {
            // unfreeze counters and/or clear FC0 
            safe_wrmsr(IA32_PERF_GLOBAL_STATUS_RESET_MSR_ADDR, perf_global_status_mask);
        }

        local_data_ptr->guest_rcx_on_td_entry = tdvps_ptr->guest_state.gpr_state.rcx;
    }

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported)
    {
        safe_wrmsr(IA32_UMWAIT_CONTROL, tdvps_ptr->guest_msr_state.ia32_umwait_control);
    }

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.tsx_supported)
    {
        safe_wrmsr(IA32_TSX_CTRL_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_tsx_ctrl);
    }
    else if (get_global_data()->plt_common_config.ia32_arch_capabilities.tsx_ctrl)
    {
        // Read the host VMM value of IA32_TSX_CTRL
        ia32_tsx_ctrl_t tsx_ctrl = { .raw = ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR) };
        local_data_ptr->vmm_non_extended_state.ia32_tsx_ctrl = tsx_ctrl.raw; // Will be used on TD exit

        // Optimize by disabling TSX only if not disabled by the host VMM
        if (!tsx_ctrl.rtm_disable || tsx_ctrl.rsvd)
        {
            safe_wrmsr(IA32_TSX_CTRL_MSR_ADDR, IA32_TSX_CTRL_DISABLE_VALUE);
        }
    }

    safe_wrmsr(IA32_UARCH_MISC_CTL_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_uarch_misc_ctl);

    // Unconditionally restore the following MSRs from TDVP:
    // IA32_STAR, IA32_SPEC_CTRL, IA32_LSTAR, IA32_FMASK, IA32_KERNEL_GS_BASE, IA32_TSC_AUX
    safe_wrmsr(IA32_TSC_AUX_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_tsc_aux);
    safe_wrmsr(IA32_STAR_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_star);
    safe_wrmsr(IA32_LSTAR_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_lstar);
    safe_wrmsr(IA32_FMASK_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_fmask);
    safe_wrmsr(IA32_KERNEL_GS_BASE_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_kernel_gs_base);

    // Restore CPU extended state, based on XFAM
    restore_guest_td_extended_state(tdvps_ptr);

    // Extended state control
    ia32_xsetbv(0, tdvps_ptr->guest_state.xcr0);
    safe_wrmsr(IA32_XSS_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_xss);
    local_data_ptr->vp_ctx.td_xcr0_state_modified = false;

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported)
    {
        safe_wrmsr(IA32_XFD_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_xfd);
        safe_wrmsr(IA32_XFD_ERROR_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_xfd_err);
    }

    // Restore IA32_SPEC_CTRL - safely, instead of restoring it as usual in tdx_return_to_td
    if (tdvps_ptr->guest_msr_state.ia32_spec_ctrl != TDX_MODULE_IA32_SPEC_CTRL)
    {
        safe_wrmsr(IA32_SPEC_CTRL_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_spec_ctrl);
    }
}

static api_error_type handle_stepping_filter(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr,
                                             vm_vmexit_exit_reason_t exit_reason, pa_t* gpa,
                                             bool_t* is_sept_locked, stepping_filter_e* filter_result)
{
    // if too many EPFs on private GPAs have already detected on current instruction, fake TDEXIT due to EPF
    *filter_result = td_entry_stepping_filter(gpa, tdvps_ptr, tdr_ptr, tdcs_ptr, is_sept_locked);

    if (*filter_result == FILTER_FAIL_SEPT_TREE_BUSY)
    {
        // The filter could not acquire the SEPT tree lock, raise "busy" error

        tdx_debug_assert(*is_sept_locked == false);

        // decrement the TLB tracker that was incremented at the beginning of TDENTER
        revert_tlb_tracking_state(tdcs_ptr, tdvps_ptr);

        TDX_WARN("Failed to acquire SEPT lock during TD Entry stepping filter\n");
        return api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT_TREE);
    }
    else if (*filter_result == FILTER_OK_NOTIFY_EPS_FAULT)
    {
        // We need to notify the TD by injecting a #VE. (if coming from L1) or L2->L1 exit (if coming from L2).
        // Read the current VM's VMCS
        bool_t shared_bit = get_gpa_shared_bit(gpa->raw, tdcs_ptr->executions_ctl_fields.gpaw);

        if ((exit_reason.basic_reason == VMEXIT_REASON_EPT_VIOLATION) && !shared_bit)
        {
            if (tdvps_ptr->management.curr_vm != 0)
            {
                // If last TD exit was from L2, we do an L2->L1 exit.
                // Tag this as L2_EXIT_HOST_ROUTED_*, which is handled below.
                // This flag remains sticky until actual L1 entry.
                // If the last TD exit was from L1, we inject a #VE below.
                set_l2_exit_host_routing(tdvps_ptr);
            }
        }
        else // TD notification (#VE or L2->L1 exit) should not be delivered
        {
            *filter_result = FILTER_OK_CONTINUE;
        }
    }

    // This is the only path on which SEPT lock will remain locked.
    // On the two possible errors above it will be unlocked

    return FILTER_OK_CONTINUE;
}

_STATIC_INLINE_ void set_l2_to_l1_async_exit_gprs(tdvps_t* tdvps_p, vm_vmexit_exit_reason_t exit_reason,
        vmx_exit_qualification_t exit_qualification, pa_t faulting_gpa)
{
    api_error_code_t error_code;

    tdx_debug_assert(tdvps_p->management.l2_exit_host_routed != HOST_ROUTED_NONE);
    error_code.raw = tdvps_p->management.l2_exit_host_routed == HOST_ROUTED_ASYNC ? TDX_L2_EXIT_HOST_ROUTED_ASYNC : TDX_L2_EXIT_HOST_ROUTED_TDVMCALL;
    error_code.details_l2 = (uint32_t)exit_reason.raw;

    tdvps_p->guest_state.gpr_state.rax = error_code.raw;
    tdvps_p->guest_state.gpr_state.rbx = 0;
    tdvps_p->guest_state.gpr_state.rcx = exit_qualification.raw;

    uint64_t guest_la;
    ia32_vmread(VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE, &guest_la);

    tdvps_p->guest_state.gpr_state.rdx = guest_la;

    l2_enter_seg_details_t cs_seg_details = { .raw = 0 };
    uint64_t val, cs_base;
    cs_seg_details.selector = (uint16_t)(ia32_vmread(VMX_GUEST_CS_SELECTOR_ENCODE, &val), val);
    cs_seg_details.ar = (uint16_t)(ia32_vmread(VMX_GUEST_CS_ARBYTE_ENCODE, &val), val);
    cs_seg_details.limit = (uint32_t)(ia32_vmread(VMX_GUEST_CS_LIMIT_ENCODE, &val), val);

    ia32_vmread(VMX_GUEST_CS_BASE_ENCODE, &cs_base);

    tdvps_p->guest_state.gpr_state.rsi = cs_seg_details.raw;
    tdvps_p->guest_state.gpr_state.rdi = cs_base;
    tdvps_p->guest_state.gpr_state.r8  = faulting_gpa.raw;

    uint64_t inter_error = 0, inter_info = 0;
    ia32_vmread(VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE, &inter_info);
    ia32_vmread(VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE, &inter_error);
    tdvps_p->guest_state.gpr_state.r9  = (inter_error << 32) | inter_info;

    uint64_t idt_vec_error = 0, idt_vec_info = 0;
    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vec_info);
    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE, &idt_vec_error);
    tdvps_p->guest_state.gpr_state.r10 = (idt_vec_error << 32) | idt_vec_info;

    uint64_t instr_len = 0, instr_info = 0;
    ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &instr_len);
    ia32_vmread(VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE, &instr_info);
    tdvps_p->guest_state.gpr_state.r11 = (instr_len << 32) | instr_info;

    l2_enter_additional_exit_info_t exit_info = { .raw = 0 };
    exit_info.cpl = get_guest_td_cpl();

    tdvps_p->guest_state.gpr_state.r12 = exit_info.raw;
    tdvps_p->guest_state.gpr_state.r13 = 0;
    tdvps_p->guest_state.gpr_state.r14 = 0;
    tdvps_p->guest_state.gpr_state.r15 = 0;
}

static api_error_type handle_l2_entry(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr,
        vm_vmexit_exit_reason_t* exit_reason, vmx_exit_qualification_t* exit_qualification, pa_t* faulting_gpa)
{
    if (tdvps_ptr->management.l2_exit_host_routed == HOST_ROUTED_NONE)
    {
        // We're reentering into L2.
        // If the L2 was in the middle of IDT vectoring when the VM exit happened, re-inject it as VOE.
        // Don't do this if resuming L1 - in that case it's the L1 VMM's responsibility.
        (void)reinject_idt_vectoring_event_if_any();
    }

    // Check if a Vector-On-Entry (VOE) is being injected.
    // This includes VOE set by the above IDT vectoring re-injections.
    // If so, check if it matches the VMCS' exception bitmap and #PF filtering set by the L1 VMM.
    if (is_voe_in_exception_bitmap())
    {
        // Convert the VOE fields in the L2 VMCS to exit information fields and mark this as an L2->L1 exit
        convert_l2_voe_to_l1_exit();
        // Update the VMCS fields that we already read, but changed in convert_l2_voe_to_l1_exit
        exit_reason->raw = VMEXIT_REASON_EXCEPTION_OR_NMI;
        exit_qualification->raw = 0;

        set_l2_exit_host_routing(tdvps_ptr);
    }

    // Emulate Virtual L2->L1 Exit
    if (tdvps_ptr->management.l2_exit_host_routed != HOST_ROUTED_NONE)
    {
        // There's a sticky indication of host routing.
        // This means we have a TD entry to L1 after a TD exit from L2, which hasn't been
        // completed yet (there might have been previous attempts which failed).

        if (tdvps_ptr->management.last_td_exit == LAST_EXIT_TDVMCALL)
        {
            /*
             *  Last TD exit was a TDG.VP.VMCALL done by L2.  GPR and XMM state passed from the host
             *  VMM to the guest TD are selected by guest RCX, saved by TDG.VP.VMCALL.
             *  We're resuming L1.  From L1's perspective, it should look as if TDG.VP.VMCALL has terminated
             *  successfully in L2, and then an asynchronous exit happened from L2.  Therefore, do the following:
             *
             *    1.  Save the L2 GPR and XMM image to TDPVS
             *    2.  Do an EPT walk to make sure the TDG.VP.VMCALL guest state output buffer in memory is accessible
             *       2.1.  If failed, emulate an EPT violation from L2
             *    3.  Save the TDG.VP.VMCALL guest state output buffer (same as how it's done on TD exit from L2)
             */

            // Save the GPR and XMM from the host VMM into TDVPS.  This is the output state of TDG.VP.VMCALL.
            tdvmcall_control_t control;

            control.raw = tdvps_ptr->guest_state.gpr_state.rcx;
            save_regs_after_tdvmcall(tdvps_ptr, control, tdvps_ptr->guest_state.gpr_state.gprs);

            // At this point the VCPU state is as if L2's TDG.VP.VMCALL was completed and an asynchronous exit happened
            tdvps_ptr->management.last_td_exit = LAST_EXIT_ASYNC_FAULT;
        }

        if (tdvps_ptr->management.l2_exit_host_routed == HOST_ROUTED_TDVMCALL)
        {
            // There's a sticky indication of host routing of TDG.VP.VMCALL results.
            // This means we have a TD entry to L1 after a synchronous TD exit from L2, which hasn't been
            // completed yet (previous might have been previous attempts which failed).

            // Translate soft-translated GPAs, if required
            if (!translate_l2_enter_guest_state_gpa(tdr_ptr, tdcs_ptr, tdvps_ptr,
                                tdvps_ptr->management.curr_vm, &faulting_gpa->raw))
            {
                // Address translation failed.  Emulate an EPT violation TD exit from L2
                // decrement the TLB tracker that was incremented at the beginning of TDENTER
                revert_tlb_tracking_state(tdcs_ptr, tdvps_ptr);

                // Emulate a TD exit.
                // Note that the sticky host routing indication remains.
                // It will be handled on the next TD entry.
                emulate_ept_violation_td_exit(get_local_data(), *faulting_gpa, tdcs_ptr, tdvps_ptr, tdvps_ptr->management.curr_vm);

                TDX_ERROR("Failed to translate L2 GPA - 0x%llx\n", faulting_gpa->raw);
                return VMEXIT_REASON_EPT_VIOLATION;
            }

            // Address translation succeeded.  Write the output of TDG.VP.VMCALL
            write_l2_enter_outputs(tdvps_ptr, tdvps_ptr->management.curr_vm);
        }

        // Update the GPR image in TDVPS to emulate TDG.VP.ENTER output on L2->L1 exit
        set_l2_to_l1_async_exit_gprs(tdvps_ptr, *exit_reason, *exit_qualification, *faulting_gpa);

        // At this point we can clear the sticky flag, since the saved L1 state indicates the proper exit from L2
        tdvps_ptr->management.l2_exit_host_routed = HOST_ROUTED_NONE;

        // Make L1 (VM #0) the current VM
        set_vm_vmcs_as_active(tdvps_ptr, 0);

        // Advance L1 guest RIP to the next instruction, following the TDCALL(TDG.VP.VMCALL) which entered L2
        advance_guest_rip();

        tdvps_ptr->management.curr_vm = 0;
    }

    return TDX_SUCCESS;
}

api_error_type tdh_vp_enter(uint64_t vcpu_handle_and_flags)
{
    // Local data for return values and global data
    tdx_module_local_t  * local_data_ptr = get_local_data();
    tdx_module_global_t * global_data_ptr = get_global_data();

    // TDVPR related variables
    pa_t                  tdvpr_pa;                    // TDVPR physical address
    tdvps_t             * tdvps_ptr = NULL;            // Pointer to the TDVPS (multi-page linear address)
    pamt_block_t          tdvpr_pamt_block;            // TDVPR PAMT block
    pamt_entry_t        * tdvpr_pamt_entry_ptr;        // Pointer to the TDVPR PAMT entry
    bool_t                tdvpr_locked_flag = false;   // Indicate TDVPR is locked

    // TDR related variables
    pa_t                  tdr_pa;                      // TDR physical address
    tdr_t               * tdr_ptr;                     // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr;          // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;     // Indicate TDVPR is locked

    tdcs_t              * tdcs_ptr = NULL;             // Pointer to the TDCS page (linear address)
    bool_t                op_state_locked_flag = false;

    uint16_t              td_hkid;
    tdvmcall_control_t    control;
    bool_t                td_vmcs_loaded = false;      // Indicates whether TD VMCS was loaded
    vcpu_and_flags_t      vcpu_and_flags = { .raw = vcpu_handle_and_flags };
    bool_t                is_sept_locked = false;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    ia32_misc_enable_t misc_enable = { .raw = ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) };

    // Boot NT4 bit should not be set
    if (misc_enable.limit_cpuid_maxval)
    {
        return_val = TDX_LIMIT_CPUID_MAXVAL_SET;
        goto EXIT_FAILURE;
    }

    if (vcpu_and_flags.reserved_0 || vcpu_and_flags.reserved_1)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Input VCPU handle and flags has reserved bits sets - 0x%llx\n", vcpu_and_flags.raw);
        goto EXIT_FAILURE;
    }

    tdvpr_pa.raw = 0;
    tdvpr_pa.page_4k_num = vcpu_and_flags.tdvpra_hpa_51_12;

    // Check and lock the TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RCX,
                                                         TDX_LOCK_SHARED,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_block,
                                                         &tdvpr_pamt_entry_ptr,
                                                         &tdvpr_locked_flag);

    IF_RARE (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock a TDVPR (0x%llx) - error = %llx\n", tdvpr_pa.raw, return_val);
        goto EXIT_FAILURE;
    }

    // Get and lock the owner TDR page
    // TDR is mapped in static keyhole range, and thus doesn't need to be freed
    tdr_pa = get_pamt_entry_owner(tdvpr_pamt_entry_ptr);
    return_val = lock_and_map_implicit_tdr(tdr_pa,
                                           OPERAND_ID_TDR,
                                           TDX_RANGE_RW,
                                           TDX_LOCK_SHARED,
                                           &tdr_pamt_entry_ptr,
                                           &tdr_locked_flag,
                                           &tdr_ptr);

    IF_RARE (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR - error = %lld\n", return_val);
        goto EXIT_FAILURE;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_VP_ENTER_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT_FAILURE;
    }
    op_state_locked_flag = true;

    // Get the TD's ephemeral HKID
    td_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the TDVPS structure
    // TDVPS is mapped in static keyhole range, and thus doesn't need to be freed
    tdvps_ptr = map_tdvps(tdvpr_pa, td_hkid, tdcs_ptr->management_fields.num_l2_vms, TDX_RANGE_RW);

    if (tdvps_ptr == NULL)
    {
        TDX_ERROR("TDVPS mapping failed\n");
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT_FAILURE;
    }

    // Associate the VCPU
    bool_t new_associate_flag = false;
    return_val = check_and_associate_vcpu(tdvps_ptr, tdcs_ptr, &new_associate_flag, false);

    IF_RARE (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to associate VCPU - error = %llx\n", return_val);
        goto EXIT_FAILURE;
    }

    set_vm_vmcs_as_active(tdvps_ptr, tdvps_ptr->management.curr_vm);
    td_vmcs_loaded = true;

    if ((vcpu_and_flags.host_recoverability_hint) && (tdvps_ptr->management.last_td_exit != LAST_EXIT_ASYNC_TRAP))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Host recoverability is set, but last exit wasn't ASYNC_TRAP - %d\n", tdvps_ptr->management.last_td_exit);
        goto EXIT_FAILURE;
    }

    if (vcpu_and_flags.resume_l1)
    {
        // Resume to L1 is only supported on exit from L2
        if (tdvps_ptr->management.curr_vm == 0)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
            TDX_ERROR("Resume to L1 is only supported on exit from L2\n");
            goto EXIT_FAILURE;
        }

        // RESUME_L1 is sticky; the internal flag is cleared later, only if actual L1 entry happens
        set_l2_exit_host_routing(tdvps_ptr);
    }

    // We read TSC below.  Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    // to make sure the host VMM doesn't play any trick on us.
    IF_RARE (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != global_data_ptr->plt_common_config.ia32_tsc_adjust)
    {
        return_val = api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
        TDX_ERROR("Inconsistent IA32_TSC_ADJUST MSR!\n");
        goto EXIT_FAILURE;
    }

    // Read TSC and verify that it is higher than LAST_EXIT_TSC.
    // Do the calculation as signed 64b, works even if TSC rolls over.
    IF_RARE (((int64_t)(ia32_rdtsc() - tdvps_ptr->management.last_exit_tsc)) < 0)
    {
        return_val = TDX_TSC_ROLLBACK;
        TDX_ERROR("TSC is lower than LAST_EXIT_TSC!\n");
        goto EXIT_FAILURE;
    }

    // If MONITOR/MWAIT support is enabled, then MONITOR_FSM must be enabled
    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.monitor_mwait_supported &&
        !misc_enable.enable_monitor_fsm)
    {
        return_val = api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_MISC_ENABLES_MSR_ADDR);
        TDX_ERROR("If MONITOR/MWAIT support is enabled, then MONITOR_FSM must be enabled\n");
        goto EXIT_FAILURE;
    }

    // Save the VMM value of IA32_DS_AREA
    local_data_ptr->vmm_non_extended_state.ia32_ds_area = ia32_rdmsr(IA32_DS_AREA_MSR_ADDR);

    // Update the TLB tracking state. This is done as a critical section,
    // allowing concurrent TDHVPENTERs, but no concurrent TDHMEMTRACK
    IF_RARE (!adjust_tlb_tracking_state(tdr_ptr, tdcs_ptr, tdvps_ptr, new_associate_flag))
    {
        TDX_ERROR("Failed to acquire global lock for TD epoch\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);
        goto EXIT_FAILURE;
    }

    stepping_filter_e filter_result = FILTER_OK_CONTINUE;

    // Sample current VMCS state for handling stepping filter FILTER_OK_NOTIFY_EPS_FAULT case
    vm_vmexit_exit_reason_t exit_reason;
    vmx_exit_qualification_t exit_qualification;
    pa_t faulting_gpa;

    ia32_vmread(VMX_VM_EXIT_REASON_ENCODE, &exit_reason.raw);
    ia32_vmread(VMX_VM_EXIT_QUALIFICATION_ENCODE, &exit_qualification.raw);
    ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &faulting_gpa.raw);

    IF_RARE ((return_val = handle_stepping_filter(tdr_ptr, tdcs_ptr, tdvps_ptr, exit_reason, &faulting_gpa,
                                                  &is_sept_locked, &filter_result)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed handling stepping filter - error = %llx\n", return_val);
        goto EXIT_FAILURE;
    }

    if (tdvps_ptr->management.curr_vm != 0)
    {
        return_val = handle_l2_entry(tdr_ptr, tdcs_ptr, tdvps_ptr,
                                           &exit_reason, &exit_qualification, &faulting_gpa);

        IF_RARE (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to handle L2 entry\n");
            goto EXIT_FAILURE;
        }
    }
    // If the stepping filter above indicated a #VE injection, inject it now to the L1 VMM
    // being entered, with the values sampled above from the VMCS of the VM that previously exited.
    else if ((filter_result == FILTER_OK_NOTIFY_EPS_FAULT) && can_inject_epf_ve(exit_qualification, tdvps_ptr))
    {
        tdx_debug_assert(tdvps_ptr->management.curr_vm == 0);
        tdx_inject_ve((uint32_t)exit_reason.raw, exit_qualification.raw, tdvps_ptr, faulting_gpa.raw, 0);
    }
    
    /*-------------------------------------------------------------------------------------
    At this point we're at the VM to be entered - if there was an L2->L1 virtual exit
    then the state of L1 is after the L2->L1 exit.
    If the stepping filter above indicated too many EPT violations on private GPA,
    emulate an EPT violation TD exit; do not do an actual VM entry so the VM is not
    exposed to the 0-step attack.
    -------------------------------------------------------------------------------------*/

    if (filter_result == FILTER_FAIL_TDENTER_EPFS)
    {
        tdx_debug_assert(is_sept_locked == false);

        // decrement the TLB tracker that was incremented at the beginning of TDENTER
        revert_tlb_tracking_state(tdcs_ptr, tdvps_ptr);

        emulate_ept_violation_td_exit(get_local_data(), faulting_gpa, tdcs_ptr, tdvps_ptr, tdvps_ptr->management.curr_vm);

        TDX_ERROR("Too many EPT violation on private GPA - 0x%llx\n", faulting_gpa.raw);
        return_val = VMEXIT_REASON_EPT_VIOLATION;
        goto EXIT_FAILURE;
    }

    // Translate soft-translated GPAs, if required
    if ((tdvps_ptr->management.curr_vm != 0) &&
        !translate_gpas(tdr_ptr, tdcs_ptr, tdvps_ptr, tdvps_ptr->management.curr_vm, &faulting_gpa.raw))
    {
        // decrement the TLB tracker that was incremented at the beginning of TDENTER
        revert_tlb_tracking_state(tdcs_ptr, tdvps_ptr);

        emulate_ept_violation_td_exit(get_local_data(), faulting_gpa, tdcs_ptr, tdvps_ptr, tdvps_ptr->management.curr_vm);
        TDX_ERROR("EPT violation due GPA (0x%llx) translation\n", faulting_gpa.raw);

        return_val = VMEXIT_REASON_EPT_VIOLATION;
        goto EXIT_FAILURE;
    }

    // ALL CHECKS PASSED:

    /* OP_STATE has been locked in a temporary mode; it is released before
       entering non-root mode. */
    tdx_debug_assert(op_state_locked_flag);
    release_sharex_lock_hp_sh(&(tdcs_ptr->management_fields.op_state_lock));
    op_state_locked_flag = false;

    // If the current VCPU to be executed on this LP is not the same as the last one,
    // issue an indirect branch prediction barrier (IBPB) command
    if (tdvpr_pa.raw != local_data_ptr->vp_ctx.last_tdvpr_pa.raw)
    {
        // The TD ASID (Address Space Identifier) does not distinguish between different VCPUs of the same TD.
        // Therefore, when switching VCPU of the same TD on the same LP we should invalidate EPT.
        // Practically, we do this on every VCPU switch (even not of the same TD).
        // This is because it is difficult to track the history of TD execution on an LP
        // (i.e., we should check for every TD/VCPU combination in the past).
        flush_all_td_asids(tdr_ptr, tdcs_ptr);

        // Issue an indirect branch prediction barrier (IBPB) command, since the CPU does not
        // distinguish between VCPUs for its branch prediction.
        ia32_pred_cmd_t pred_cmd = { .raw = 0 };
        pred_cmd.ibpb = 1;
        ia32_wrmsr(IA32_PRED_CMD_MSR_ADDR, pred_cmd.raw);
        local_data_ptr->vp_ctx.last_tdvpr_pa.raw = tdvpr_pa.raw;
    }

    // Save the TDR, TDCS and TDVPS linear pointers for use after every VM exit
    local_data_ptr->vp_ctx.tdr               = tdr_ptr;
    local_data_ptr->vp_ctx.tdr_pamt_entry    = tdr_pamt_entry_ptr;
    local_data_ptr->vp_ctx.tdr_pa            = tdr_pa;

    local_data_ptr->vp_ctx.tdvps             = tdvps_ptr;
    local_data_ptr->vp_ctx.tdvpr_pamt_entry  = tdvpr_pamt_entry_ptr;
    local_data_ptr->vp_ctx.tdvpr_pamt_block  = tdvpr_pamt_block;
    local_data_ptr->vp_ctx.tdvpr_pa          = tdvpr_pa;

    local_data_ptr->vp_ctx.tdcs              = tdcs_ptr;

    // Save some other TD state to avoid accessing TDCS and TDVPS in case of a
    // memory integrity error
    local_data_ptr->vp_ctx.attributes = tdcs_ptr->executions_ctl_fields.attributes;
    local_data_ptr->vp_ctx.xfam = tdvps_ptr->management.xfam;
    local_data_ptr->vp_ctx.xfd_supported = tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported;
    local_data_ptr->vp_ctx.ia32_perf_global_status = tdvps_ptr->guest_msr_state.ia32_perf_global_status;

    // Restore Guest Extended State
    if (tdvps_ptr->management.last_td_exit == LAST_EXIT_TDVMCALL)
    {
        // Last TD exit was a TDGVPVMCALL. GPR and XMM state passed from the host
        // VMM to the guest TD are selected by guest RCX, saved by TDGVPVMCALL.
        control.raw = tdvps_ptr->guest_state.gpr_state.rcx;

        save_regs_after_tdvmcall(tdvps_ptr, control, tdvps_ptr->guest_state.gpr_state.gprs);
    }
    else if (tdvps_ptr->management.last_td_exit == LAST_EXIT_ASYNC_TRAP)
    {
        // Following a trap-like TD exit, update the guest's TDCALL completion status with
        // the host hint bit.
        api_error_code_t guest_tdcall_status;
        guest_tdcall_status.raw = tdvps_ptr->guest_state.gpr_state.rax;
        guest_tdcall_status.host_recoverability_hint = vcpu_and_flags.host_recoverability_hint;
        tdvps_ptr->guest_state.gpr_state.rax = guest_tdcall_status.raw;
    }

    if (tdvps_ptr->management.curr_vm == 0)
    {
        vmx_procbased_ctls_t vm_procbased_ctls;
        /* If PEND_NMI was requested, and there's no pending #VE (which should be handled
           by the guest TD before NMI), set NMI Window Exiting execution control so NMI
           can be injected at the proper time. */
        if (tdvps_ptr->management.pend_nmi && (tdvps_ptr->ve_info.valid == 0))
        {
            ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &vm_procbased_ctls.raw);
            vm_procbased_ctls.nmi_window_exiting = 1;
            ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, vm_procbased_ctls.raw);
        }
    }
    else // Reentering into L2
    {
        // If NMI unblocking by IRET was indicated during VM exit, re-block NMI
        if (tdvps_ptr->management.nmi_unblocking_due_to_iret)
        {
            set_guest_inter_blocking_by_nmi();
        }
    }

    // Set the guest TD's IA32_DEBUGCTL.ENABLE_UNCORE_PMI to the VMM's value.
    ia32_debugctl_t debugctl;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &debugctl.raw);
    debugctl.en_uncore_pmi = local_data_ptr->ia32_debugctl_value.en_uncore_pmi;
    ia32_vmwrite(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, debugctl.raw);

    if (tdvps_ptr->management.curr_vm != 0)
    {
        // Set the VMX preemption timer, if TSC deadline is enabled
        set_vmx_preemption_timer(tdvps_ptr, tdvps_ptr->management.curr_vm);
    }

    // If the SEPT lock was acquired by the TDENTER stepping filter, release it now
    // SEPT lock will be acquired by TDENTER stepping filter only if it didn't return
    // FILTER_FAIL_TDENTER_SEPT_BUSY or FILTER_FAIL_TDENTER_EPFS
    if (is_sept_locked)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
    }

    // If IA32_SPEC_CTRL is virtualized, write the VMCS' IA32_SPEC_CTRL shadow
    conditionally_write_vmcs_ia32_spec_ctrl_shadow(tdcs_ptr, tdvps_ptr->guest_msr_state.ia32_spec_ctrl);

    // Restore other Guest state (GPRs, DRs, MSRs) in TDVPS
    restore_guest_td_state_before_td_entry(tdcs_ptr, tdvps_ptr);

    update_host_state_in_td_vmcs(local_data_ptr, tdvps_ptr, tdvps_ptr->management.curr_vm);

    local_data_ptr->single_step_def_state.last_entry_tsc = ia32_rdtsc();

    tdvps_ptr->management.state = VCPU_ACTIVE;

    if (tdvps_ptr->management.vm_launched[tdvps_ptr->management.curr_vm])
    {
        tdx_return_to_td(true, true, &tdvps_ptr->guest_state.gpr_state);
    }
    else
    {
        tdx_return_to_td(false, true, &tdvps_ptr->guest_state.gpr_state);
    }

    // Flow should never reach here
    tdx_sanity_check(0, SCEC_SEAMCALL_SOURCE(TDH_VP_ENTER_LEAF), 0);

EXIT_FAILURE:

    if (is_sept_locked)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
    }

    // Check if we need to load the SEAM VMCS
    IF_COMMON (td_vmcs_loaded)
    {
        set_seam_vmcs_as_active();
    }

    // Release all acquired locks and free keyhole mappings
    IF_COMMON (tdcs_ptr != NULL)
    {
        IF_COMMON (op_state_locked_flag)
        {
            release_sharex_lock_hp_sh(&(tdcs_ptr->management_fields.op_state_lock));
        }
        free_la(tdcs_ptr);
    }

    IF_COMMON (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
        free_la(tdr_ptr);
    }

    IF_COMMON (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }

    return return_val;
}
