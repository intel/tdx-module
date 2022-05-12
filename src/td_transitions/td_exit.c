// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_async_exit.c
 * @brief All the ways to transition from TD(VM) to VMM
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
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "td_transitions/td_exit.h"

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

    if (((ia32_xcr0_t)local_data_ptr->vp_ctx.xfam).lbr)
    {
        init_msr_opt(IA32_LBR_DEPTH_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_lbr_depth);
    }

    // Perfmon State
    if (local_data_ptr->vp_ctx.attributes.perfmon)
    {
        init_msr_opt(IA32_FIXED_CTR_CTRL_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_fixed_ctr_ctrl);
        for (uint32_t i = 0; i < NUM_FIXED_CTR; i++)
        {
            init_msr_opt(IA32_FIXED_CTR0_MSR_ADDR + i, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_fixed_ctr[i]);
        }

        for (uint32_t i = 0; i < NUM_PMC; i++)
        {
            init_msr_opt(IA32_A_PMC0_MSR_ADDR + i, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_a_pmc[i]);
            init_msr_opt(IA32_PERFEVTSEL0_MSR_ADDR + i, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_perfevtsel[i]);
        }

        for (uint32_t i = 0; i < 2; i++)
        {
            init_msr_opt(IA32_OFFCORE_RSPx_MSR_ADDR + i, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_offcore_rsp[i]);
        }

        ia32_wrmsr(IA32_PERF_GLOBAL_STATUS_RESET_MSR_ADDR, ia32_rdmsr(IA32_PERF_GLOBAL_STATUS_MSR_ADDR));
        init_msr_opt(IA32_PEBS_ENABLE_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_pebs_enable);
        init_msr_opt(IA32_PERF_METRICS_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_perf_metrics);
        init_msr_opt(IA32_PEBS_DATA_CFG_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_pebs_data_cfg);
        init_msr_opt(IA32_PEBS_LD_LAT_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_pebs_ld_lat);
        init_msr_opt(IA32_PEBS_FRONTEND_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_pebs_frontend);
    }


    /*
     * Initialize the following MSRs:
     * IA32_STAR, IA32_LSTAR, IA32_FMASK, IA32_TSC_AUX,  & IA32_KERNEL_GS_BASE
     */

    init_msr_opt(IA32_TSC_AUX_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_tsc_aux);
    init_msr_opt(IA32_STAR_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_star);
    init_msr_opt(IA32_LSTAR_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_lstar);
    init_msr_opt(IA32_FMASK_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_fmask);
    init_msr_opt(IA32_KERNEL_GS_BASE_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_kernel_gs_base);

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
    tdvps_t* tdvps_ptr = local_data_ptr->vp_ctx.tdvps;

    // Extended state control

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported)
    {
        tdvps_ptr->guest_msr_state.ia32_xfd = ia32_rdmsr(IA32_XFD_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_xfd_err = ia32_rdmsr(IA32_XFD_ERROR_MSR_ADDR);
    }

    // CR2 state
    tdvps_ptr->guest_state.cr2 = ia32_store_cr2();

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
        for (uint32_t i = 0; i < NUM_FIXED_CTR; i++)
        {
            tdvps_ptr->guest_msr_state.ia32_fixed_ctr[i] = ia32_rdmsr(IA32_FIXED_CTR0_MSR_ADDR + i);
        }

        for (uint32_t i = 0; i < NUM_PMC; i++)
        {
            tdvps_ptr->guest_msr_state.ia32_a_pmc[i] = ia32_rdmsr(IA32_A_PMC0_MSR_ADDR + i);
            tdvps_ptr->guest_msr_state.ia32_perfevtsel[i] = ia32_rdmsr(IA32_PERFEVTSEL0_MSR_ADDR + i);
        }

        for (uint32_t i = 0; i < 2; i++)
        {
            tdvps_ptr->guest_msr_state.ia32_offcore_rsp[i] = ia32_rdmsr(IA32_OFFCORE_RSPx_MSR_ADDR + i);
        }

        tdvps_ptr->guest_msr_state.ia32_perf_global_status = ia32_rdmsr(IA32_PERF_GLOBAL_STATUS_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_perf_metrics = ia32_rdmsr(IA32_PERF_METRICS_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_pebs_enable = ia32_rdmsr(IA32_PEBS_ENABLE_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_pebs_data_cfg = ia32_rdmsr(IA32_PEBS_DATA_CFG_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_pebs_ld_lat = ia32_rdmsr(IA32_PEBS_LD_LAT_MSR_ADDR);
        tdvps_ptr->guest_msr_state.ia32_pebs_frontend = ia32_rdmsr(IA32_PEBS_FRONTEND_MSR_ADDR);
    }
    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported)
    {
        tdvps_ptr->guest_msr_state.ia32_umwait_control= ia32_rdmsr(IA32_UMWAIT_CONTROL);
    }

    // Save the following MSRs:
    // IA32_STAR, IA32_LSTAR,
    // IA32_FMASK, IA32_KERNEL_GS_BASE, IA32_TSC_AUX
    tdvps_ptr->guest_msr_state.ia32_star            = ia32_rdmsr(IA32_STAR_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_lstar           = ia32_rdmsr(IA32_LSTAR_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_fmask           = ia32_rdmsr(IA32_FMASK_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_kernel_gs_base  = ia32_rdmsr(IA32_KERNEL_GS_BASE_MSR_ADDR);
    tdvps_ptr->guest_msr_state.ia32_tsc_aux         = ia32_rdmsr(IA32_TSC_AUX_MSR_ADDR);
}

void async_tdexit_to_vmm(api_error_code_e tdexit_case,
                         vm_vmexit_exit_reason_t vm_exit_reason,
                         uint64_t exit_qualification,
                         uint64_t extended_exit_qualification,
                         uint64_t gpa,
                         uint64_t vm_exit_interruption_information)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdcs_t* tdcs_ptr = tdx_local_data_ptr->vp_ctx.tdcs;
    tdvps_t* tdvps_ptr = tdx_local_data_ptr->vp_ctx.tdvps;
    tdr_t* tdr_ptr = tdx_local_data_ptr->vp_ctx.tdr;
    uint8_t vcpu_state = tdvps_ptr->management.state;

    // Check the sticky BUS_LOCK_PREEMPTED flag, report and clear if true
    if (tdx_local_data_ptr->vp_ctx.bus_lock_preempted)
    {
        vm_exit_reason.bus_lock_preempted = true;
        tdx_local_data_ptr->vp_ctx.bus_lock_preempted = false;
    }


    switch (tdexit_case)
    {
    case TDX_SUCCESS:
        // Update the VCPU state for the next TDHVPENTER
        vcpu_state = VCPU_READY_ASYNC;
        break;

    case TDX_NON_RECOVERABLE_VCPU:
        // Mark the VCPU so it can't be re-entered
        vcpu_state = (uint8_t)VCPU_DISABLED;
        _lock_xadd_32b(&tdcs_ptr->management_fields.num_vcpus, (uint32_t)-1);
        break;

    case TDX_NON_RECOVERABLE_TD:
    case TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE:
    case TDX_NON_RECOVERABLE_TD_FATAL:
        // VCPU state doesn't change
        tdr_ptr->management_fields.fatal = true;
        break;
    default:
        FATAL_ERROR();
    }

    // Set TD exit information
    tdx_local_data_ptr->vmm_regs.rax = (uint64_t)tdexit_case + (vm_exit_reason.raw & BIT_MASK_32BITS);
    tdx_local_data_ptr->vmm_regs.rcx = exit_qualification;
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
    tdx_local_data_ptr->vmm_regs.rsi = 0ULL;
    tdx_local_data_ptr->vmm_regs.rdi = 0ULL;

    ia32_xcr0_t xcr0 = { .raw = tdx_local_data_ptr->vp_ctx.xfam };
    xcr0.sse = 1;
    uint64_t scrub_mask = xcr0.raw;

    td_vmexit_to_vmm(vcpu_state, scrub_mask, 0, (tdexit_case == TDX_NON_RECOVERABLE_TD_FATAL));

}

void td_vmexit_to_vmm(uint8_t vcpu_state, uint64_t scrub_mask, uint16_t xmm_select, bool_t is_td_dead)
{
    // Local data
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    vp_ctx_t* vp_ctx = &tdx_local_data_ptr->vp_ctx;
    tdvps_t* tdvps_ptr = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_ptr = tdx_local_data_ptr->vp_ctx.tdcs;

    if (!is_td_dead)
    {
        /**
         * Avoid accessing TD private memory and control structures (except TDR).
         * The TD is dead, no need so save its state.
         */

        // 1.  Save any guest state that it has not saved as part of the common guest-side operation, e.g.,
        //     the extended state per TDCS.XFAM
        save_guest_td_state_before_td_exit(tdcs_ptr, tdx_local_data_ptr);

        // 2.  Set TDVPS.STATE to one of the VCPU_READY sub states, as an indication to the next TD entry.
        tdvps_ptr->management.state = vcpu_state;
        // At this point the VCPU state will no longer be accessed

        // 3.  Execute the TD exit TLB tracking sequence, adjusting the TDCS tracking counters.
        tdcs_epoch_tracking_fields_t* epoch_tracking = &tdcs_ptr->epoch_tracking;
        _lock_xadd_16b(&epoch_tracking->epoch_and_refcount.refcount[tdvps_ptr->management.vcpu_epoch & 1], (uint16_t)-1);

        // Save Guest-TD XCR0 and XSS
        save_guest_td_extended_state(tdvps_ptr, tdx_local_data_ptr->vp_ctx.xfam);
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
    if (vcpu_state == (uint8_t)VCPU_READY_TDVMCALL)
    {
        load_xmms_by_mask(tdvps_ptr, xmm_select);
    }

    // 7.   Run the common SEAMRET routine.
    tdx_vmm_post_dispatching();

    //unreachable Code. Panic
    tdx_sanity_check(0, SCEC_TDEXIT_SOURCE, 0);
}
