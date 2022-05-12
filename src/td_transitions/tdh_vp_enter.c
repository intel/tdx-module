// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

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

static void emulate_td_exit(tdx_module_local_t* local_data_ptr, pa_t faulting_gpa, tdvps_t* tdvps_ptr)
{
    faulting_gpa.low_12_bits = 0;

    // VMX qualification = write access (bit 1 set)
    vmx_exit_qualification_t qualification;
    qualification.raw = 0;
    qualification.ept_violation.data_write = 1;

    // Emulate an Async TDEXIT
    initialize_extended_state(local_data_ptr->vp_ctx.xfam);
    tdvps_ptr->management.state = VCPU_READY_ASYNC;

    // Set TD exit information
    local_data_ptr->vmm_regs.rcx = qualification.raw;
    local_data_ptr->vmm_regs.rdx = 0; // No TDX extended qualification
    local_data_ptr->vmm_regs.r8 = faulting_gpa.raw;
    local_data_ptr->vmm_regs.r9 = 0; // No VMX interruption information

    // Other GPRs return 0
    local_data_ptr->vmm_regs.rbx = 0;
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
    if (xmm_select != 0)
    {
        tdvps_ptr->guest_extension_state.xbuf.xsave_header.xstate_bv |= BIT(1);
    }

}

static void restore_guest_td_state_before_td_entry(tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr)
{
    // CR2 state restoration
    ia32_load_cr2(tdvps_ptr->guest_state.cr2);

    // Debug state restoration
    ia32_load_dr0(tdvps_ptr->guest_state.dr0);
    ia32_load_dr1(tdvps_ptr->guest_state.dr1);
    ia32_load_dr2(tdvps_ptr->guest_state.dr2);
    ia32_load_dr3(tdvps_ptr->guest_state.dr3);
    ia32_load_dr6(tdvps_ptr->guest_state.dr6);

    ia32_wrmsr(IA32_DS_AREA_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_ds_area);

    //  Restore IA32_LBR_DEPTH from TDVPS.IA32_LBR_DEPTH. This MSR is not restored by XRSTORS
    //  like other LBR MSRs. On XRSTORS, if the saved value matches current value, then
    //  only LBRs 0..DEPTH-1 are restored, otherwise all IA32_LBR_TOS, IA32_LBR_x_*
    //  MSRs, and IA32_LER_* MSRs are cleared.
    if (((ia32_xcr0_t)tdvps_ptr->management.xfam).lbr)
    {
        ia32_wrmsr(IA32_LBR_DEPTH_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_lbr_depth);
    }

    // Perfmon State
    if (tdcs_ptr->executions_ctl_fields.attributes.perfmon)
    {
        ia32_wrmsr(IA32_FIXED_CTR_CTRL_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_fixed_ctr_ctrl);
        for (uint32_t i = 0; i < NUM_FIXED_CTR; i++)
        {
            ia32_wrmsr(IA32_FIXED_CTR0_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_fixed_ctr[i]);
        }

        for (uint32_t i = 0; i < NUM_PMC; i++)
        {
            ia32_wrmsr(IA32_A_PMC0_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_a_pmc[i]);
            ia32_wrmsr(IA32_PERFEVTSEL0_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_perfevtsel[i]);
        }

        for (uint32_t i = 0; i < 2; i++)
        {
            ia32_wrmsr(IA32_OFFCORE_RSPx_MSR_ADDR + i, tdvps_ptr->guest_msr_state.ia32_offcore_rsp[i]);
        }

        ia32_perf_global_status_write(ia32_rdmsr(IA32_PERF_GLOBAL_STATUS_MSR_ADDR), tdvps_ptr->guest_msr_state.ia32_perf_global_status);
        ia32_wrmsr(IA32_PEBS_ENABLE_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_enable);
        ia32_wrmsr(IA32_PERF_METRICS_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_perf_metrics);
        ia32_wrmsr(IA32_PEBS_DATA_CFG_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_data_cfg);
        ia32_wrmsr(IA32_PEBS_LD_LAT_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_ld_lat);
        ia32_wrmsr(IA32_PEBS_FRONTEND_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_pebs_frontend);
    }

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported)
    {
        ia32_wrmsr(IA32_UMWAIT_CONTROL, tdvps_ptr->guest_msr_state.ia32_umwait_control);
    }


    // Unconditionally restore the following MSRs from TDVP:
    // IA32_STAR, IA32_SPEC_CTRL, IA32_LSTAR, IA32_FMASK, IA32_KERNEL_GS_BASE, IA32_TSC_AUX
    ia32_wrmsr(IA32_TSC_AUX_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_tsc_aux);
    ia32_wrmsr(IA32_STAR_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_star);
    ia32_wrmsr(IA32_LSTAR_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_lstar);
    ia32_wrmsr(IA32_FMASK_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_fmask);
    ia32_wrmsr(IA32_KERNEL_GS_BASE_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_kernel_gs_base);

    // Restore CPU extended state, based on XFAM
    restore_guest_td_extended_state(tdvps_ptr);

    // Extended state control
    ia32_xsetbv(0, tdvps_ptr->guest_state.xcr0);
    ia32_wrmsr(IA32_XSS_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_xss);

    if (tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported)
    {
        ia32_wrmsr(IA32_XFD_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_xfd);
        ia32_wrmsr(IA32_XFD_ERROR_MSR_ADDR, tdvps_ptr->guest_msr_state.ia32_xfd_err);
    }
}

static api_error_type handle_stepping_filter(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr,
                                             bool_t* is_sept_locked)
{
    // if too many EPFs on private GPAs have already detected on current instruction, fake TDEXIT due to EPF
    pa_t faulting_gpa = { .raw = 0 };

    stepping_filter_e td_entry_stepping_result =
            td_entry_stepping_filter(&faulting_gpa, tdvps_ptr, tdr_ptr, tdcs_ptr, is_sept_locked);

    if (td_entry_stepping_result != FILTER_OK_CONTINUE)
    {
        tdx_debug_assert(*is_sept_locked == false);
        // TDCALLs are not expected to cause TDENTER stepping filter failure
        tdx_debug_assert(tdvps_ptr->management.state == VCPU_READY_ASYNC);

        // decrement the TLB tracker that was incremented at the beginning of TDENTER
        revert_tlb_tracking_state(tdcs_ptr, tdvps_ptr);
     
        // if the filter could not take SEPT lock, raise "busy" error
        if (td_entry_stepping_result == FILTER_FAIL_TDENTER_SEPT_BUSY)
        {
            TDX_ERROR("Failed to acquire SEPT lock during TD Entry stepping filter\n");
            return api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT);
        }
        else if (td_entry_stepping_result == FILTER_FAIL_TDENTER_EPFS)
        {
            // if too many EPFs on private GPAs already detected on current instruction, fake TDEXIT due to EPF
            emulate_td_exit(get_local_data(), faulting_gpa, tdvps_ptr);

            return VMEXIT_REASON_EPT_VIOLATION;
        }
        else
        {
            tdx_debug_assert(0);
        }
    }

    // This is the only path on which SEPT lock will remain locked.
    // On the two possible errors above it will be unlocked

    return TDX_SUCCESS;
}

api_error_type tdh_vp_enter(uint64_t target_tdvpr_pa)
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

    uint16_t              td_hkid;
    tdvmcall_control_t    control;
    page_size_t           page_leaf_size = PT_4KB;
    bool_t                td_vmcs_loaded = false;      // Indicates whether TD VMCS was loaded
    bool_t                is_sept_locked = false;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdvpr_pa.raw = target_tdvpr_pa;

    // Boot NT4 bit should not be set
    if ((ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) & MISC_EN_BOOT_NT4_BIT ) != 0)
    {
        return_val = TDX_BOOT_NT4_SET;
        goto EXIT_FAILURE;
    }

    // Check and lock the TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RCX,
                                                         TDX_LOCK_SHARED,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_block,
                                                         &tdvpr_pamt_entry_ptr,
                                                         &page_leaf_size,
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

    // Check the TD state
    IF_RARE ((return_val = check_td_in_correct_build_state(tdr_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("TD is not in correct - error = %lld\n", return_val);
        goto EXIT_FAILURE;
    }

    // Map the TDCS structure and check the state.  No need to lock
    // TDCS is mapped in static keyhole range, and thus doesn't need to be freed
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);
    IF_RARE (!tdcs_ptr->management_fields.finalized)
    {
        TDX_ERROR("TD is not finalized\n");
        return_val = TDX_TD_NOT_FINALIZED;
        goto EXIT_FAILURE;
    }

    // Get the TD's ephemeral HKID
    td_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the TDVPS structure
    // TDVPS is mapped in static keyhole range, and thus doesn't need to be freed
    tdvps_ptr = map_tdvps(tdvpr_pa, td_hkid, TDX_RANGE_RW);

    if (tdvps_ptr == NULL)
    {
        TDX_ERROR("TDVPS mapping failed\n");
        return_val = TDX_TDVPX_NUM_INCORRECT;
        goto EXIT_FAILURE;
    }

    // Associate the VCPU
    bool_t new_associate_flag = false;
    IF_RARE ((return_val = associate_vcpu(tdvps_ptr, tdcs_ptr, tdr_ptr, false, &new_associate_flag)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to associate VCPU - error = %llx\n", return_val);
        goto EXIT_FAILURE;
    }
    td_vmcs_loaded = true;


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
    IF_RARE (((int64_t)((int64_t)ia32_rdtsc() - (int64_t)tdvps_ptr->management.last_exit_tsc)) < 0)
    {
        return_val = TDX_TSC_ROLLBACK;
        TDX_ERROR("TSC is lower than LAST_EXIT_TSC!\n");
        goto EXIT_FAILURE;
    }

    // If IA32_TSX_CTRL MSR exists, we require its value to be the same as sampled on TDHSYSINIT
    if (global_data_ptr->plt_common_config.ia32_arch_capabilities.tsx_ctrl)
    {
        if (ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR) != global_data_ptr->plt_common_config.ia32_tsx_ctrl.raw)
        {
            return_val = api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSX_CTRL_MSR_ADDR);
            TDX_ERROR("IA32_TSX_CTRL MSR exists, but its value does not match to the value sampled on tdh_sys_init\n");
            goto EXIT_FAILURE;
        }
    }

    // Save the VMM value of IA32_DS_AREA
    local_data_ptr->vmm_non_extended_state.ia32_ds_area = ia32_rdmsr(IA32_DS_AREA_MSR_ADDR);

    // Update the TLB tracking state. This is done as a critical section,
    // allowing concurrent TDHVPENTERs, but no concurrent TDHMEMTRACK
    IF_RARE (!adjust_tlb_tracking_state(tdcs_ptr, tdvps_ptr, new_associate_flag))
    {
        TDX_ERROR("Failed to acquire global lock for TD epoch\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);
        goto EXIT_FAILURE;
    }

    IF_RARE ((return_val = handle_stepping_filter(tdr_ptr, tdcs_ptr,tdvps_ptr, &is_sept_locked)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed handling stepping filter - error = %llx\n", return_val);
        goto EXIT_FAILURE;
    }

    // ALL CHECKS PASSED:

    // If the current VCPU to be executed on this LP is not the same as the last one,
    // issue an indirect branch prediction barrier (IBPB) command
    if (tdvpr_pa.raw != local_data_ptr->vp_ctx.last_tdvpr_pa.raw)
    {
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
    if (tdvps_ptr->management.state == VCPU_READY_TDVMCALL)
    {
        // Last TD exit was a TDGVPVMCALL. GPR and XMM state passed from the host
        // VMM to the guest TD are selected by guest RCX, saved by TDGVPVMCALL.
        control.raw = tdvps_ptr->guest_state.rcx;

        // Save XMM registers selected by guest RCX to TDVPS.
        // Later on the whole state of XMMs, MXCSR and optionally YMMs and ZMMs is
        // restored from TDVPS.
        if (control.xmm_select != 0)
        {
            save_xmms_by_mask(tdvps_ptr, control.xmm_select);
        }

        // Copy VMM GPRs selected by guest RCX to TDVPS.  Later on all GPRs will be
        // restored from TDVPS before entering the guest TD.
        // RAX and RCX are not copied, start from RDX.

        for (uint32_t i = 2; i < 16; i++)
        {
            if ((control.gpr_select & (uint16_t)BIT(i)) != 0)
            {
                tdvps_ptr->guest_state.gprs[i] = local_data_ptr->vmm_regs.gprs[i];
            }
        }

        tdvps_ptr->guest_state.rax = TDX_SUCCESS;
    }

    vmcs_procbased_ctls_t vm_procbased_ctls;
    /* If PEND_NMI was requested, and there's no pending #VE (which should be handled
       by the guest TD before NMI), set NMI Window Exiting execution control so NMI
       can be injected at the proper time. */
    if (tdvps_ptr->management.pend_nmi && (tdvps_ptr->ve_info.valid == 0))
    {
        ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &vm_procbased_ctls.raw);
        vm_procbased_ctls.nmi_window_exiting = 1;
        ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, vm_procbased_ctls.raw);
    };

    tdvps_ptr->management.state = VCPU_ACTIVE;

    // Set the guest TD's IA32_DEBUGCTL.ENABLE_UNCORE_PMI to the VMM's value.
    ia32_debugctl_t debugctl;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &debugctl.raw);
    debugctl.en_uncore_pmi = local_data_ptr->ia32_debugctl_value.en_uncore_pmi;
    ia32_vmwrite(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, debugctl.raw);

    // If the SEPT lock was acquired by the TDENTER stepping filter, release it now
    // SEPT lock will be acquired by TDENTER stepping filter only if it didn't return
    // FILTER_FAIL_TDENTER_SEPT_BUSY or FILTER_FAIL_TDENTER_EPFS
    if (is_sept_locked)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
    }

    // Restore other Guest state (GPRs, DRs, MSRs) in TDVPS
    restore_guest_td_state_before_td_entry(tdcs_ptr, tdvps_ptr);

    local_data_ptr->single_step_def_state.last_entry_tsc = ia32_rdtsc();

    if (tdvps_ptr->management.launched)
    {
        tdx_return_to_td(true);
    }
    else
    {
        tdvps_ptr->management.launched = true;
        tdx_return_to_td(false);
    }

    // Flow should never reach here
    tdx_sanity_check(0, SCEC_SEAMCALL_SOURCE(TDH_VP_ENTER_LEAF), 0);

EXIT_FAILURE:
    // Check if we need to load the SEAM VMCS
    IF_COMMON (td_vmcs_loaded)
    {
        set_seam_vmcs_as_active();
    }

    // Release all acquired locks and free keyhole mappings
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

    IF_COMMON (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    return return_val;
}
