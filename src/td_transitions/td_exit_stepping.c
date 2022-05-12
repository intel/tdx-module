// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_exit_stepping.c
 * @brief All the ways to transition from TD(VM) to VMM
 */


#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "memory_handlers/sept_manager.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit_stepping.h"

#define ENABLE 1
#define DISABLE 0
#define BLOCK_EXTERNAL_INTERRUPTS 15

// returns true if a data breakpoint or single-step or RTM debug is pending
static bool_t is_pending_debug_exception()
{
    pending_debug_exception_t pde;

    ia32_vmread(VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE, &pde.raw);

    return (pde.enable != 0 || pde.bs != 0 || pde.rtm != 0);
}

static bool_t is_guest_blocked_by_sti(vmx_guest_inter_state_t guest_inter_state)
{
    return (bool_t)guest_inter_state.blocking_by_sti;
}

static bool_t is_code_breakpoint_on_next_rip(uint64_t guest_rip)
{
    dr7_t dr7;

   ia32_vmread(VMX_GUEST_DR7_ENCODE, &dr7.raw);

    // check if any breakpoint could is enabled
    if ((dr7.raw & 0xFF) == 0)
    {
        return false;
    }

    // check if DRi (i = 0..3) is enabled as code breakpoint and matches guest RIP
    if (   ((dr7.l0 || dr7.g0) && (dr7.ln0 == 0) && (dr7.rw0 == 0) && (ia32_store_dr0() == guest_rip))
        || ((dr7.l1 || dr7.g1) && (dr7.ln1 == 0) && (dr7.rw1 == 0) && (ia32_store_dr1() == guest_rip))
        || ((dr7.l2 || dr7.g2) && (dr7.ln2 == 0) && (dr7.rw2 == 0) && (ia32_store_dr2() == guest_rip))
        || ((dr7.l3 || dr7.g3) && (dr7.ln3 == 0) && (dr7.rw3 == 0) && (ia32_store_dr3() == guest_rip)))
    {
        return true;
    }

    return false;
}

static bool_t is_epf_exiting(vm_vmexit_exit_reason_t vm_exit_reason)
{
    return vm_exit_reason.basic_reason == VMEXIT_REASON_EPT_VIOLATION;
}

static bool_t is_nmi_exiting(vm_vmexit_exit_reason_t vm_exit_reason, vmx_exit_inter_info_t vm_exit_inter_info)
{
    return ((vm_exit_reason.basic_reason == VMEXIT_REASON_EXCEPTION_OR_NMI) &&
            (vm_exit_inter_info.vector == E_NMI));
}

static bool_t is_intr_exiting(vm_vmexit_exit_reason_t vm_exit_reason)
{
    return vm_exit_reason.basic_reason == VMEXIT_REASON_INTERRUPT;
}

static bool_t is_mtf_exiting(vm_vmexit_exit_reason_t vm_exit_reason)
{
    return vm_exit_reason.basic_reason == VMEXIT_REASON_MTF;
}

static bool_t is_init_exiting(vm_vmexit_exit_reason_t vm_exit_reason)
{
    return vm_exit_reason.basic_reason == VMEXIT_REASON_INIT_EVENT ;
}

static bool_t is_smi_not_msmi_exiting(vm_vmexit_exit_reason_t vm_exit_reason,
                                      vmx_exit_qualification_t vm_exit_qualification)
{
    return ((vm_exit_reason.basic_reason == VMEXIT_REASON_SMI_OTHER_EVENT) &&
            (vm_exit_qualification.smi.msmi == 0));
}

static void set_mtf(uint32_t enable)
{
    vmcs_procbased_ctls_t vm_procbased_ctls;
    ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &vm_procbased_ctls.raw);
    vm_procbased_ctls.monitor_trap_flag = enable;
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, vm_procbased_ctls.raw);
}

static void set_movss_blocking(vmx_guest_inter_state_t guest_inter_state, uint32_t enable)
{
    if (enable)
    {
        set_guest_pde_bs();
    }

    guest_inter_state.blocking_by_mov_ss = enable;
    ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
}

static uint64_t vcpu_rip_delta(tdx_module_local_t* local_data_p, uint64_t guest_rip)
{
    return (guest_rip > local_data_p->single_step_def_state.last_epf_guest_rip)?
        guest_rip - local_data_p->single_step_def_state.last_epf_guest_rip:
        local_data_p->single_step_def_state.last_epf_guest_rip - guest_rip;
}

static uint64_t vcpu_tsc_delta(tdx_module_local_t* local_data_p)
{
    return local_data_p->vp_ctx.tdvps->management.last_exit_tsc -
            local_data_p->single_step_def_state.last_entry_tsc;
}

static bool_t is_epf_expected(tdr_t* tdr_p, tdcs_t* tdcs_p, pa_t gpa)
{
    ept_walk_result_t walk_result;
    ia32e_eptp_t eptp = {.raw = tdcs_p->executions_ctl_fields.eptp.raw};
    uint16_t hkid = tdr_p->key_management_fields.hkid;
    access_rights_t access_rights = { .raw = 0x7 };

    pa_t page_hpa;
    ia32e_ept_t ept_entry_copy = {.raw = 0};
    access_rights_t accumulated_rwx;

    walk_result = gpa_translate(eptp, gpa, true, hkid, access_rights,
                                    &page_hpa, &ept_entry_copy, &accumulated_rwx);

    return ((walk_result != EPT_WALK_SUCCESS) && (walk_result != EPT_WALK_CONVERTIBLE_VIOLATION));
}


static bool_t can_inject_epf_ve(vmx_exit_qualification_t last_exit_qualification, tdvps_t* tdvps_p)
{
    vmx_guest_inter_state_t last_guest_inter_state;
    vmx_idt_vectoring_info_t last_idt_vec_info;

    ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &last_guest_inter_state.raw);
    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &last_idt_vec_info.raw);

    return ((last_guest_inter_state.blocking_by_nmi == 0)
        && (last_exit_qualification.ept_violation.nmi_unblocking_due_to_iret == 0)
        && (last_idt_vec_info.valid == 0)
        && (tdvps_p->ve_info.valid == 0));
}


stepping_filter_e vmexit_stepping_filter(
        vm_vmexit_exit_reason_t vm_exit_reason,
        vmx_exit_qualification_t vm_exit_qualification,
        vmx_exit_inter_info_t vm_exit_inter_info)
{
    tdx_module_local_t* ld_p = get_local_data();
    tdcs_t* tdcs_p = ld_p->vp_ctx.tdcs;

    // stop and reset EPF tracking if forward progress occurred
    uint64_t guest_rip;
    ia32_vmread(VMX_GUEST_RIP_ENCODE, &guest_rip);
    uint64_t rip_delta = vcpu_rip_delta(ld_p, guest_rip); //


    if (rip_delta != 0)
    {
        ld_p->vp_ctx.tdvps->management.last_epf_gpa_list_idx = 0;
        ld_p->vp_ctx.tdvps->management.possibly_epf_stepping = 0;
    }

    // track EPT violation faults
    if (is_epf_exiting(vm_exit_reason))
    {
        if (ld_p->vp_ctx.tdvps->management.possibly_epf_stepping < STEPPING_EPF_THRESHOLD)
        {
            ld_p->vp_ctx.tdvps->management.possibly_epf_stepping++;
        }
        else
        {
            uint64_t gpa;
            ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &gpa);

            bool_t shared_bit = get_gpa_shared_bit(gpa, tdcs_p->executions_ctl_fields.gpaw);
            uint8_t last_epf_gpa_list_idx = ld_p->vp_ctx.tdvps->management.last_epf_gpa_list_idx;
            if (!shared_bit && (last_epf_gpa_list_idx < EPF_GPA_LIST_SIZE))
            {
                uint8_t i;

                // lookup for this private GPA
                for (i = 0; i < last_epf_gpa_list_idx; i++)
                {
                    // GPA is already in list
                    if (ld_p->vp_ctx.tdvps->management.last_epf_gpa_list[i] == gpa)
                    {
                        break;
                    }
                }

                if (i == last_epf_gpa_list_idx) // this is a new GPA - add to list
                {
                    ld_p->vp_ctx.tdvps->management.last_epf_gpa_list[last_epf_gpa_list_idx] = gpa;
                    ld_p->vp_ctx.tdvps->management.last_epf_gpa_list_idx = last_epf_gpa_list_idx + 1;
                }
            }
        }
    }

    // If interruption type exiting happened, check if single stepping may be in progress
    if (is_intr_exiting(vm_exit_reason)
        || is_mtf_exiting(vm_exit_reason)
        || is_smi_not_msmi_exiting(vm_exit_reason, vm_exit_qualification)
        || is_nmi_exiting(vm_exit_reason, vm_exit_inter_info)
        || is_init_exiting(vm_exit_reason))
    {

        if (!ld_p->single_step_def_state.in_inst_step_mode)
        {
            if ((rip_delta > INTEL64_MAX_INST_LEN * 2) || (vcpu_tsc_delta(ld_p) > STEPPING_TSC_THRESHOLD))
            {
                return FILTER_OK_CONTINUE;
            }

            /*
             * Read APIC base.  Check that the local APIC mode is correct for later IPI injection.
             * If not, kill the TD.
             */
            ld_p->single_step_def_state.apic_base.raw = ia32_rdmsr(IA32_APIC_BASE_MSR_ADDR);
            if ((ld_p->single_step_def_state.apic_base.enable == 0) ||
                ((ld_p->single_step_def_state.apic_base.extd == 0) && (get_global_data()->max_x2apic_id > 255)))
            {
                return FILTER_FAIL_TDEXIT_WRONG_APIC_MODE;
            }

            // start stepping mode
            ld_p->single_step_def_state.num_inst_step = (lfsr_get_random() & 0x1F) + 1;
            ld_p->single_step_def_state.in_inst_step_mode = true;

            // Block external interrupts during stepping by raising TPR to 15
            ld_p->single_step_def_state.saved_cr8 = ia32_store_cr8();
            ia32_load_cr8(BLOCK_EXTERNAL_INTERRUPTS);

            // if stepping started due to interrupt, push it back to APIC as self-IPI
            if (is_intr_exiting(vm_exit_reason))
            {
                send_self_ipi(ld_p->single_step_def_state.apic_base,
                              APIC_DELIVERY_FIXED, vm_exit_inter_info.vector);
            }

            // enable MTF to start single stepping
            set_mtf(ENABLE);
        }

        // At this point, we are in stepping mode and interrupts are blocked

        // If NMI or INIT started the stepping, remember that
        // Note: no need to remember SMI (and PREQ) exiting because
        // uCode keeps it pending when delivering SMI exiting
        ld_p->single_step_def_state.nmi_exit_occured |= is_nmi_exiting(vm_exit_reason, vm_exit_inter_info);
        ld_p->single_step_def_state.init_exit_occured |= is_init_exiting(vm_exit_reason);

        // If stepping mode not done yet, resume the TD to execute next step
        if (ld_p->single_step_def_state.num_inst_step > 0)
        {
            vmx_guest_inter_state_t guest_inter_state;
            ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);

            // Set MOVSS blocking to block external signals from causing TD VM exit
            // before the next TD instruction is executed, unless debug events are
            // pending to be delivered, or a code breakpoint is set on the next vCPU instruction
            if (!is_pending_debug_exception() && !is_code_breakpoint_on_next_rip(guest_rip) &&
                !is_guest_blocked_by_sti(guest_inter_state))
            {
                set_movss_blocking(guest_inter_state, 1);
            }

            ld_p->single_step_def_state.num_inst_step -= 1;
            return FILTER_OK_RESUME_TD;
        }
    }

    // At this point, a non-interruption type exiting happened (including EPF), or stepping is over

    // End stepping mode if needed
    if (ld_p->single_step_def_state.in_inst_step_mode)
    {
        // If NMI started the stepping, and current exiting is not NMI,
        // push a new NMI into local APIC
        if (ld_p->single_step_def_state.nmi_exit_occured &&
                !is_nmi_exiting(vm_exit_reason, vm_exit_inter_info))
        {
            send_self_ipi(ld_p->single_step_def_state.apic_base, APIC_DELIVERY_NMI, 0);
        }

        // If INIT started the stepping, and current exiting is not INIT,
        // push a new INIT into local APIC
        if (ld_p->single_step_def_state.init_exit_occured && !is_init_exiting(vm_exit_reason))
        {
            send_self_ipi(ld_p->single_step_def_state.apic_base, APIC_DELIVERY_INIT, 0);
        }

        // Restore TPR to unblock external interrupts
        ia32_load_cr8(ld_p->single_step_def_state.saved_cr8);

        // Clear MTF to stop single stepping
        set_mtf(DISABLE);

        // Reset stepping mode variables
        ld_p->single_step_def_state.in_inst_step_mode = false;
        ld_p->single_step_def_state.num_inst_step = 0;
        ld_p->single_step_def_state.nmi_exit_occured = false;
        ld_p->single_step_def_state.init_exit_occured = false;
        ld_p->single_step_def_state.saved_cr8 = 0;

        // If the exit reason was MTF, re-enter the TD to consume pending interrupts
        // OPEN: in tight loops and rep string instructions,
        // this may lead to indefinite delay in interruption delivery
        if (is_mtf_exiting(vm_exit_reason))
        {
            // reset time stamp to avoid restarting stepping mode when
            // the pending interruption is consumed
            ld_p->single_step_def_state.last_entry_tsc = 0;
            return FILTER_OK_RESUME_TD;
        }
    }

    return FILTER_OK_CONTINUE;
}


stepping_filter_e td_entry_stepping_filter(pa_t* faulting_gpa, tdvps_t* tdvps_p, tdr_t* tdr_p, tdcs_t* tdcs_p,
                                           bool_t* is_sept_locked)
{
    // capture guest RIP, to be checked at next TD exiting
    uint64_t last_epf_guest_rip;
    ia32_vmread(VMX_GUEST_RIP_ENCODE,&last_epf_guest_rip);
    get_local_data()->single_step_def_state.last_epf_guest_rip = last_epf_guest_rip;

    // if LAST_EPF_GPA_LIST is empty, everything is OK, otherwise a zero-step attack is suspected
    if (tdvps_p->management.last_epf_gpa_list_idx == 0)
    {
        return FILTER_OK_CONTINUE;
    }

    // Acquire Secure-EPT lock as exclusive
    if (acquire_sharex_lock_ex(&tdcs_p->executions_ctl_fields.secure_ept_lock) != LOCK_RET_SUCCESS)
    {
        return FILTER_FAIL_TDENTER_SEPT_BUSY;
    }

    *is_sept_locked = true;

    // if another EPF on private GPA is pending to happen, fail TD entry
    for (uint32_t i = 0; i < tdvps_p->management.last_epf_gpa_list_idx; i++)
    {
        pa_t last_epf_gpa = {.raw = tdvps_p->management.last_epf_gpa_list[i]};
        if (is_epf_expected(tdr_p, tdcs_p, last_epf_gpa))
        {
            *faulting_gpa = last_epf_gpa;
            release_sharex_lock_ex(&tdcs_p->executions_ctl_fields.secure_ept_lock);
            *is_sept_locked = false;
            return FILTER_FAIL_TDENTER_EPFS;
        }
    }

    // notify the TD about the suspected zero-step attack using #VE
    // if the TD has asked for notification, and the last TD VM exit was due to EPF on a private GPA,
    // and #VE can be injected at this time
    if ((tdcs_p->notify_enables & BIT(0)) == 1) // Bit 0 - notify when zero-step attack is suspected
    {

        vm_vmexit_exit_reason_t last_exit_reason;
        vmx_exit_qualification_t last_exit_qualification;
        uint64_t last_faulting_gpa;

        ia32_vmread(VMX_VM_EXIT_REASON_ENCODE, &last_exit_reason.raw);
        ia32_vmread(VMX_VM_EXIT_QUALIFICATION_ENCODE, &last_exit_qualification.raw);
        ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &last_faulting_gpa);

        bool_t shared_bit = get_gpa_shared_bit(last_faulting_gpa, tdcs_p->executions_ctl_fields.gpaw);

        if (is_epf_exiting(last_exit_reason)
            && (!shared_bit )
            && can_inject_epf_ve(last_exit_qualification, tdvps_p))
        {
            // The VE object injects #VE into TD VMCS
            tdx_inject_ve((uint32_t)last_exit_reason.raw,
                    last_exit_qualification.raw, tdvps_p, last_faulting_gpa ,0);
        }
    }

    return FILTER_OK_CONTINUE;
}
