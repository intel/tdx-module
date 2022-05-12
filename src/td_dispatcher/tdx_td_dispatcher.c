// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_td_dispatcher.c
 * @brief VM Exit from TD entry point and API dispatcher
 */

#include "tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"
#include "td_transitions/td_exit_stepping.h"

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
void tdx_failed_vmentry(void)
{
    uint64_t error_code = 0;

    ia32_vmread(VMX_VM_INSTRUCTION_ERRORCODE_ENCODE, &error_code);

    TDX_ERROR("VMENTRY failed - error code - %d\n", error_code);

    uint64_t val;
    platform_common_config_t* msrs = &get_global_data()->plt_common_config;

    ia32_vmread(VMX_VM_EXIT_CONTROL_ENCODE, &val);
    TDX_ERROR("VM_EXIT_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_exit_ctls.raw);

    ia32_vmread(VMX_VM_ENTRY_CONTROL_ENCODE, &val);
    TDX_ERROR("VM_ENTRY_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_entry_ctls.raw);

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE, &val);
    TDX_ERROR("VM_PIN_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_pinbased_ctls.raw);

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &val);
    TDX_ERROR("VM_PROC_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_true_procbased_ctls.raw);

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE, &val);
    TDX_ERROR("VM_SEC_PROC_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_procbased_ctls2.raw);

    ia32_vmread(VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE, &val);
    TDX_ERROR("VM_TERT_PROC_BASED_CONTROL = 0x%llx, VMX_MSR = 0x%llx\n",
            val, msrs->ia32_vmx_procbased_ctls3);

    tdx_arch_fatal_error();
}
#endif

void tdx_return_to_td(bool_t launch_state)
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    // Restore IA32_SPEC_CTRL
    ia32_spec_ctrl_t spec_ctrl = { .raw = 0 };
    spec_ctrl.ssbd = 1;
    wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR, local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_spec_ctrl, spec_ctrl.raw);

    // Exit to TD
    tdx_tdentry_to_td(launch_state, &local_data_ptr->vp_ctx.tdvps->guest_state);
}

void bus_lock_exit ( void )
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    if (local_data_ptr->vp_ctx.bus_lock_preempted)
    {
        /*
         * If we got here and BUS_LOCK_PREEMPTED is still set, it means that a bus lock preemption
         * has been indicated on VM exit (bit 26 of the exit reason) but the VM exit handler decided
         * not to do a TD exit.
         * In this case, we do an asynchronous TD exit here with a synthetic BUS_LOCK (74) exit reason.
         **/
        vm_vmexit_exit_reason_t vm_exit_reason = {.raw = 0};
        vm_exit_reason.basic_reason = VMEXIT_REASON_BUS_LOCK;
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, 0, 0);
    }
}

void check_hw_exception( void )
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();
    vm_vmexit_exit_reason_t vm_exit_reason;
    vmx_exit_inter_info_t vm_exit_inter_info;
    vmx_entry_inter_info_t entry_intr_info;

    ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &(entry_intr_info.raw));
    ia32_vmread(VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE, &vm_exit_inter_info.raw);

    if (entry_intr_info.valid && entry_intr_info.interruption_type == HW_EXCEPTION)
    {
        /* We get here if the VM exit handler decided to inject an exception into the TD.
         * If the TD is debuggable and execption bitmap bit v is set, then TD Exit with a
         * synthetic EXCEPTION_OR_NMI exit reason.
         * The exception will be injected to the TD on the following TD entry.
         **/

        uint64_t error_code = 0;
        uint64_t error_info = 0;
        ia32_vmread(VMX_EXCEPTION_BITMAP_ENCODE, &error_code);
        ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &error_info);

        if (local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.debug &&
            ((error_code & (1ULL << (error_info &0xFF))) != 0))
        {
            vm_exit_reason.raw = 0;
            vm_exit_reason.basic_reason = VMEXIT_REASON_EXCEPTION_OR_NMI;
            ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &vm_exit_inter_info.raw);
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, 0, vm_exit_inter_info.raw);
        }
    }
}


static void save_guest_td_gpr_state_on_td_vmexit(void)
{
    tdx_module_local_t* local_data_ptr = get_local_data();
    tdvps_t* tdvps_ptr = local_data_ptr->vp_ctx.tdvps;

    // GPR's saving: move them from local data area (already saved there by assembly prologue) to current TDVPS
    tdvps_ptr->guest_state.rax = local_data_ptr->td_regs.rax;
    tdvps_ptr->guest_state.rcx = local_data_ptr->td_regs.rcx;
    tdvps_ptr->guest_state.rdx = local_data_ptr->td_regs.rdx;
    tdvps_ptr->guest_state.rbx = local_data_ptr->td_regs.rbx;
    tdvps_ptr->guest_state.rbp = local_data_ptr->td_regs.rbp;
    tdvps_ptr->guest_state.rsi = local_data_ptr->td_regs.rsi;
    tdvps_ptr->guest_state.rdi = local_data_ptr->td_regs.rdi;
    tdvps_ptr->guest_state.r8  = local_data_ptr->td_regs.r8;
    tdvps_ptr->guest_state.r9  = local_data_ptr->td_regs.r9;
    tdvps_ptr->guest_state.r10 = local_data_ptr->td_regs.r10;
    tdvps_ptr->guest_state.r11 = local_data_ptr->td_regs.r11;
    tdvps_ptr->guest_state.r12 = local_data_ptr->td_regs.r12;
    tdvps_ptr->guest_state.r13 = local_data_ptr->td_regs.r13;
    tdvps_ptr->guest_state.r14 = local_data_ptr->td_regs.r14;
    tdvps_ptr->guest_state.r15 = local_data_ptr->td_regs.r15;
}


static void td_generic_ve_exit(vm_vmexit_exit_reason_t vm_exit_reason, uint64_t exit_qualification)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;

    tdx_inject_ve((uint32_t)vm_exit_reason.raw, exit_qualification, tdvps_p, 0, 0);
}


static void td_call(tdx_module_local_t* tdx_local_data_ptr, bool_t* interrupt_occurred)
{
    api_error_type retval = UNINITIALIZE_ERROR;
    /**
     * Check CPU mode is 64b
     */
    ia32_efer_t ia32_efer;
    uint64_t cs_ar_vmread;
    seg_arbyte_t cs_ar;

    TDX_LOG("TDCALL exit reason\n");
    ia32_vmread(VMX_GUEST_IA32_EFER_FULL_ENCODE, &ia32_efer.raw);
    ia32_vmread(VMX_GUEST_CS_ARBYTE_ENCODE, &cs_ar_vmread);
    cs_ar.raw = (uint32_t)cs_ar_vmread;

    if ((ia32_efer.lma != 1) || (cs_ar.l != 1))
    {
        //Not in CPU 64b mode
        TDX_ERROR("Not in CPU mode 64bit. inject GP\n");
        inject_gp(0);
        return;
    }

    switch (tdx_local_data_ptr->td_regs.rax)
    {
        case TDG_MEM_PAGE_ACCEPT_LEAF:
        {
            retval = tdg_mem_page_accept(tdx_local_data_ptr->td_regs.rcx, interrupt_occurred);
            break;
        }
        case TDG_MR_RTMR_EXTEND_LEAF:
        {
            retval = tdg_mr_rtmr_extend(tdx_local_data_ptr->td_regs.rcx, tdx_local_data_ptr->td_regs.rdx);
            break;
        }
        case TDG_VP_VEINFO_GET_LEAF:
        {
            retval = tdg_vp_veinfo_get();
            break;
        }
        case TDG_VP_INFO_LEAF:
        {
            retval = tdg_vp_info();
            break;
        }
        case TDG_MR_REPORT_LEAF:
        {
            retval = tdg_mr_report(tdx_local_data_ptr->td_regs.rcx,
                               tdx_local_data_ptr->td_regs.rdx,
                               tdx_local_data_ptr->td_regs.r8);
            break;
        }
        case TDG_VP_CPUIDVE_SET_LEAF:
        {
            retval = tdg_vp_cpuidve_set(tdx_local_data_ptr->td_regs.rcx);
            break;
        }
        case TDG_VP_VMCALL_LEAF:
        {
            //Special case.  will (or may) not return to the TD but to go to VMM.
            retval = tdg_vp_vmcall(tdx_local_data_ptr->td_regs.rcx);
            break;
        }
        case TDG_VM_RD:
        {
            retval = tdg_vm_rd(tdx_local_data_ptr->td_regs.rcx, tdx_local_data_ptr->td_regs.rdx);
            break;
        }
        case TDG_VM_WR:
        {
            retval = tdg_vm_wr(tdx_local_data_ptr->td_regs.rcx,
                           tdx_local_data_ptr->td_regs.rdx,
                           tdx_local_data_ptr->td_regs.r8,
                           tdx_local_data_ptr->td_regs.r9);
            break;
        }
        default:
        {
            TDX_ERROR("Invalid leaf number for TDCALL\n");
            retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
            break;
        }
    }

    tdx_sanity_check(retval != UNINITIALIZE_ERROR, SCEC_TD_DISPATCHER_SOURCE, 1);

    if (*interrupt_occurred == false)
    {
        tdx_local_data_ptr->vp_ctx.tdvps->guest_state.rax = retval;
    }

}

/**
 * @brief Handle VM entry failures per basic exit reason
 **/
static void handle_vm_entry_failures(tdx_module_local_t* tdx_local_data_ptr,
        vm_vmexit_exit_reason_t vm_exit_reason, vmx_exit_qualification_t vm_exit_qualification)
{
    if (vm_exit_reason.vmenter_fail != 0)
    {
        switch (vm_exit_reason.basic_reason)
        {
            case VMEXIT_REASON_FAILED_VMENTER_GS:
            case VMEXIT_REASON_FAILED_VMENTER_MSR:
                if (tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.debug)
                {
                    async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason,
                                       vm_exit_qualification.raw, 0, 0, 0);
                }
                else
                {
                    FATAL_ERROR();
                }
                break;
            case VMEXIT_REASON_FAILED_VMENTER_MC:
                // This VM entry failure was due to a #MC, disable the TD
                    async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_FATAL, vm_exit_reason,
                                       vm_exit_qualification.raw, 0, 0, 0);
                break;
                // No other exit reasons should happen on VM entry failure
            default:
                FATAL_ERROR();
                break;
        }
        // Flow should never reach here
        tdx_sanity_check(0, SCEC_TD_DISPATCHER_SOURCE, 2);
    }
}


static void handle_idt_vectoring(tdx_module_local_t* tdx_local_data_ptr, vm_vmexit_exit_reason_t vm_exit_reason,
        vmx_exit_qualification_t vm_exit_qualification, vmx_idt_vectoring_info_t idt_vectoring_info)
{
    vmx_entry_inter_info_t vm_entry_inter_info;

    // Sanity check: only cases in TDX are task switch, EPT violation and
    //   EPT misconfiguration
    if ((vm_exit_reason.basic_reason != VMEXIT_REASON_TASK_SWITCH) &&
        (vm_exit_reason.basic_reason != VMEXIT_REASON_EPT_VIOLATION) &&
        (vm_exit_reason.basic_reason != VMEXIT_REASON_EPT_MISCONFIGURATION))
    {
        if (tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.debug)
        {
            // if the TD is debuggable, other exit reasons can happen during IDT vectoring
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason,
                           vm_exit_qualification.raw, 0, 0, 0);
        }
        else
        {
            // otherwise, only the above exit reasons are expected to happen during IDT vectoring
            TDX_ERROR("Fatal error, IDT vectoring corrupted\n");
            FATAL_ERROR();
        }

    }

    // if a virtual NMI was re-injected, clear virtual NMI blocking
    if (idt_vectoring_info.interruption_type == VMEXIT_INTER_INFO_TYPE_NMI)
    {
        vmx_guest_inter_state_t guest_inter_state;
        ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);
        guest_inter_state.blocking_by_nmi = 0;
        ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
    }

    // Copy IDT vectoring fields to VM entry exception fields. On the next
    // VM entry, the CPU will inject a VOE.

    vm_entry_inter_info.raw = idt_vectoring_info.raw;
    vm_entry_inter_info.reserved = (uint32_t)0;
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, vm_entry_inter_info.raw);

    if (idt_vectoring_info.error_code_valid)
    {
        uint64_t idt_vectoring_error_code;
        ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE, &idt_vectoring_error_code);
        ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, idt_vectoring_error_code);
    }

    uint64_t vm_exit_instruction_length;
    ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &vm_exit_instruction_length);
    ia32_vmwrite(VMX_VM_ENTRY_INSTRUCTION_LENGTH_ENCODE, vm_exit_instruction_length);
}


void tdx_td_dispatcher(void)
{
    // Must be first thing to do before accessing local/global data or sysinfo table
    tdx_module_local_t* tdx_local_data_ptr = init_data_fast_ref_ptrs();
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    vm_vmexit_exit_reason_t vm_exit_reason;
    vmx_exit_qualification_t vm_exit_qualification;
    vmx_exit_inter_info_t vm_exit_inter_info;
    vmx_idt_vectoring_info_t idt_vectoring_info;

    vmcs_procbased_ctls_t vm_procbased_ctls;
    vmx_guest_inter_state_t guest_inter_state;

    bool_t interrupt_occurred = false;

    TDX_LOG("TD Dispatcher Entry\n");
    
    // Execute the BHB defense sequence
    if (tdx_global_data_ptr->rtm_supported)
    {
        tsx_abort_sequence();             
    }
    else
    {
        // BHB draining sequence
        // There are 6 taken branches in each iteration (one CALL, four JMPs, and one JNZ), 
        // so for GLC (194 branch stews in BHB), NUM_ITERS = round-up(194 / 6) = 32.
        uint64_t num_iters = NUM_OF_BHB_CLEARING_ITERATIONS;
        uint64_t num_iters_multi_8 = 8*num_iters;

        _ASM_VOLATILE_ (
            "movq %0, %%rcx\n"
            "1:  call 2f\n"
            "lfence\n" 
            "2:  jmp 3f\n"
            "nop\n"
            "3:  jmp 4f\n"
            "nop\n"
            "4:  jmp 5f\n"
            "nop\n"
            "5:  jmp 6f\n"
            "nop\n"
            "6:  dec %%rcx\n"
            "jnz 1b\n"
            "add %1, %%rsp\n"
            "lfence\n"
            : : "a"(num_iters), "b"(num_iters_multi_8) : "memory", "rcx");
    }

    // Save current time to verify on next TD entry and for TDEXIT filter checks
    tdx_local_data_ptr->vp_ctx.tdvps->management.last_exit_tsc = ia32_rdtsc();

    // Save TD GPR state to TDVPS.
    // DR's, XSTATE and XCR's, MSR's will be saved if exit to TD will be required later
    // In case of need of performance improvement - should be done only when actual vmexit to VMM happens
    save_guest_td_gpr_state_on_td_vmexit();

    tdx_local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_spec_ctrl = ia32_rdmsr(IA32_SPEC_CTRL_MSR_ADDR);
    ia32_spec_ctrl_t spec_ctrl = { .raw = 0 };
    spec_ctrl.ssbd = 1;
    wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR, spec_ctrl.raw, tdx_local_data_ptr->vp_ctx.tdvps->guest_msr_state.ia32_spec_ctrl);

    // Get exit information
    ia32_vmread(VMX_VM_EXIT_REASON_ENCODE, &vm_exit_reason.raw);

    ia32_vmread(VMX_VM_EXIT_QUALIFICATION_ENCODE, &vm_exit_qualification.raw);
    ia32_vmread(VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE, &vm_exit_inter_info.raw);

    /*
     * If a preempted bus lock has been reported in the exit reason, set the local data bus lock flag.
     * This flag is sticky bit; it gets reset only when reported on TD exit.
     **/
    if (vm_exit_reason.bus_lock_preempted)
    {
        tdx_local_data_ptr->vp_ctx.bus_lock_preempted = true;
    }


    /*------------------------------
       Single/Zero Step Filtering
    ------------------------------*/
    stepping_filter_e vmexit_stepping_result = vmexit_stepping_filter(vm_exit_reason,
                                                    vm_exit_qualification, vm_exit_inter_info);
    // if stepping cannot be done safely, kill the TD and exit
    if (vmexit_stepping_result == FILTER_FAIL_TDEXIT_WRONG_APIC_MODE)
    {
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE, vm_exit_reason,
                vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }

    if(vmexit_stepping_result != FILTER_OK_CONTINUE)
    {
        goto EXIT;
    }

    if (!tdx_local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.debug &&
        ((vm_exit_reason.reserved_0           != 0) ||
        (vm_exit_reason.pending_mtf          != 0) ||
        (vm_exit_reason.parallel             != 0) ||
        (vm_exit_reason.reserved_1           != 0)))
    {
        TDX_ERROR("Fatal error, exit reason corrupted - 0x%llx\n", vm_exit_reason.raw);
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
        uint64_t idt_vectoring, activity, interruptibility, entry_int;

        ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vectoring);
        ia32_vmread(VMX_GUEST_SLEEP_STATE_ENCODE, &activity);
        ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &interruptibility);
        ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &entry_int);

        TDX_ERROR("IDT vectoring = 0x%llx, activity state = 0x%llx\n",
                idt_vectoring, activity);
        TDX_ERROR("Interruptibility state = 0x%llx, Entry intr info = 0x%llx\n",
                interruptibility, entry_int);
#endif
        FATAL_ERROR();
    }

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    uint64_t guest_rip = 0, guest_cs_base = 0;

    ia32_vmread(VMX_GUEST_RIP_ENCODE, &guest_rip);
    ia32_vmread(VMX_GUEST_CS_BASE_ENCODE, &guest_cs_base);
    TDX_LOG("Exit reason = %d, Guest RIP = 0x%llx, CS Base = 0x%llx\n",
            vm_exit_reason.basic_reason, guest_rip, guest_cs_base);
    TDX_LOG("RAX = 0x%llx, RBX = 0x%llx, RCX = 0x%llx, RDX = 0x%llx\n",
            tdx_local_data_ptr->vp_ctx.tdvps->guest_state.rax,
            tdx_local_data_ptr->vp_ctx.tdvps->guest_state.rbx,
            tdx_local_data_ptr->vp_ctx.tdvps->guest_state.rcx,
            tdx_local_data_ptr->vp_ctx.tdvps->guest_state.rdx);
#endif

    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vectoring_info.raw);

    // VM Exits during Event Delivery via IDT in the Guest TD
    // If the VM exit happened while the CPU attempted to deliver a vectored
    // event via the guest's IDT, collect the information and set up for a
    // Vector-On-Entry (VOE) on the following VM entry.
    // Note that the VOE information may later be changed, e.g., if the flow needs to inject a #PF.

    if (idt_vectoring_info.valid == 1)
    {
        handle_idt_vectoring(tdx_local_data_ptr, vm_exit_reason, vm_exit_qualification,
                            idt_vectoring_info);
    }

    ia32_vmread(VMX_VM_EXIT_QUALIFICATION_ENCODE, &vm_exit_qualification.raw);

    ia32_vmread(VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE, &vm_exit_inter_info.raw);

    if (tdx_local_data_ptr->vp_ctx.tdr->management_fields.fatal)
    {
        /*
         * A #MC VM exit has occurred on another LP, indicating memory integrity error.
         * Do an async TD exit without accessing TD memory.
        */
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_FATAL, vm_exit_reason,
                                       vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }

    handle_vm_entry_failures(tdx_local_data_ptr, vm_exit_reason, vm_exit_qualification);

    switch (vm_exit_reason.basic_reason)
    {
        case VMEXIT_REASON_IO_INSTRUCTION:
        case VMEXIT_REASON_HLT_INSTRUCTION:
        case VMEXIT_REASON_INVD_INSTRUCTION:
        case VMEXIT_REASON_VMCALL_INSTRUCTION:
        case VMEXIT_REASON_WBINVD_INSTRUCTION:
        case VMEXIT_REASON_MWAIT_INSTRUCTION:
        case VMEXIT_REASON_MONITOR_INSTRUCTION:
        case VMEXIT_REASON_PCONFIG:
        case VMEXIT_REASON_APIC_WRITE:
            td_generic_ve_exit(vm_exit_reason, vm_exit_qualification.raw);
            break;

        case VMEXIT_REASON_GETSEC_INSTRUCTION:
        case VMEXIT_REASON_RSM_INSTRUCTION:
        case VMEXIT_REASON_VMCLEAR_INSTRUCTION:
        case VMEXIT_REASON_VMLAUNCH_INSTRUCTION:
        case VMEXIT_REASON_VMPTRLD_INSTRUCTION:
        case VMEXIT_REASON_VMPTRST_INSTRUCTION:
        case VMEXIT_REASON_VMREAD_INSTRUCTION:
        case VMEXIT_REASON_VMRESUME_INSTRUCTION:
        case VMEXIT_REASON_VMWRITE_INSTRUCTION:
        case VMEXIT_REASON_VMXOFF_INSTRUCTION:
        case VMEXIT_REASON_VMXON_INSTRUCTION:
        case VMEXIT_REASON_INVLEPT:
        case VMEXIT_REASON_INVLVPID:
        case VMEXIT_REASON_VMFUNC_INSTRUCTION:
        case VMEXIT_REASON_ENCLS_INSTRUCTION:
        case VMEXIT_REASON_ENCLV_INSTRUCTION:
        case VMEXIT_REASON_ENQCMD_PASID_TRANSLATION_FAILURE:
        case VMEXIT_REASON_ENQCMDS_PASID_TRANSLATION_FAILURE:
        case VMEXIT_REASON_SEAMCALL:
            inject_ud();
            break;

        case VMEXIT_REASON_TASK_SWITCH:
        case VMEXIT_REASON_BUS_LOCK:
        case VMEXIT_REASON_INIT_EVENT:
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason,
                    vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_NOTIFICATION:
            if (vm_exit_qualification.notification.nmi_unblocking_due_to_iret)
            {
                ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);
                guest_inter_state.blocking_by_nmi = 1;
                ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
            }
            async_tdexit_to_vmm((vm_exit_qualification.notification.vm_context_invalid) ?
                                 TDX_NON_RECOVERABLE_TD : TDX_SUCCESS,
                                 vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_TRIPLE_FAULT:
            async_tdexit_to_vmm(TDX_NON_RECOVERABLE_VCPU,
                    vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            break;
        case VMEXIT_REASON_SMI_OTHER_EVENT:
            // If this exit was due to an MSMI, disable the TD.  Else, do a normal async TD exit.
            async_tdexit_to_vmm((vm_exit_qualification.smi.msmi) ? TDX_NON_RECOVERABLE_TD_FATAL  : TDX_SUCCESS,
                    vm_exit_reason, vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
            break;
        case VMEXIT_REASON_INTERRUPT:
        case VMEXIT_REASON_C_STATE_SMI:
            async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
            break;
        case VMEXIT_REASON_RDPMC_INSTRUCTION:
            td_rdpmc_exit(vm_exit_reason, vm_exit_qualification.raw);
            break;
        case VMEXIT_REASON_EPT_MISCONFIGURATION:
            td_ept_misconfiguration_exit(vm_exit_reason);
            break;
        case VMEXIT_REASON_CPUID_INSTRUCTION:
            td_cpuid_exit();
            break;
        case VMEXIT_REASON_EPT_VIOLATION:
            td_ept_violation_exit(vm_exit_qualification, vm_exit_reason);
            break;
        case VMEXIT_REASON_XSETBV_INSTRUCTION:
            td_xsetbv_instruction_exit();
            break;
        case VMEXIT_REASON_CR_ACCESS:
            td_cr_access_exit(vm_exit_qualification);
            break;
        case VMEXIT_REASON_EXCEPTION_OR_NMI:
            td_exception_or_nmi_exit(vm_exit_reason, vm_exit_qualification, vm_exit_inter_info);
            break;
        case VMEXIT_REASON_MSR_READ:
            td_rdmsr_exit();
            break;
        case VMEXIT_REASON_MSR_WRITE:
            td_wrmsr_exit();
            break;
        case VMEXIT_REASON_TDCALL:
            td_call(tdx_local_data_ptr, &interrupt_occurred);
            break;
        case VMEXIT_REASON_NMI_WINDOW:
            // NMI Window is open.  Inject an NMI if applicable
            td_nmi_exit(tdx_local_data_ptr);
            break;
        case VMEXIT_REASON_LOADIWK_INSTRUCTION:
        case VMEXIT_REASON_RDTSC_INSTRUCTION:
        case VMEXIT_REASON_DR_ACCESS:
        case VMEXIT_REASON_PAUSE_INSTRUCTION:
        case VMEXIT_REASON_VIRTUALIZED_EOI:
        case VMEXIT_REASON_GDTR_IDTR_ACCESS:
        case VMEXIT_REASON_LDTR_TR_ACCESS:
        case VMEXIT_REASON_RDTSCP:
        case VMEXIT_REASON_FAILED_VMENTER_GS:
        case VMEXIT_REASON_FAILED_VMENTER_MSR:
        case VMEXIT_REASON_FAILED_VMENTER_MC:
        case VMEXIT_REASON_TPR_BELOW_THRESHOLD:
        case VMEXIT_REASON_SIPI_EVENT:
        case VMEXIT_REASON_SMI_IO_EVENT:
        case VMEXIT_REASON_INTERRUPT_WINDOW:
        case VMEXIT_REASON_INVLPG_INSTRUCTION:
        case VMEXIT_REASON_RDRAND_INSTRUCTION:
        case VMEXIT_REASON_INVPCID_INSTRUCTION:
            // Fatal error
        default:
            // if TD is debuggable then TDEXIT
            if (tdx_local_data_ptr->vp_ctx.attributes.debug)
            {
                async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification.raw, 0, 0, 0);
            }
            else
            {
                // If ATTRIBUTES.PERFMON is set, there shouldn't be a VM exit
                TDX_ERROR("Fatal/unknown exit reason %d \n", vm_exit_reason.basic_reason);
                FATAL_ERROR();
            }
            break;
    }

    /* If PEND_NMI was requested, and there's no pending #VE (which should be handled
       by the guest TD before NMI), set NMI Window Exiting execution control so NMI
       can be injected at the proper time. */
    if (tdx_local_data_ptr->vp_ctx.tdvps->management.pend_nmi &&
            (tdx_local_data_ptr->vp_ctx.tdvps->ve_info.valid == 0)  && !interrupt_occurred)
    {
        ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &vm_procbased_ctls.raw);
        vm_procbased_ctls.nmi_window_exiting = 1;
        ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, vm_procbased_ctls.raw);
    }

    // Check if we need to advance guest rip (only if no exception was injected)
    // Entry Interrupt Info valid bit is cleared automatically on every VMEXIT
    vmx_entry_inter_info_t entry_intr_info;
    ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &(entry_intr_info.raw));
    if (!entry_intr_info.valid && !interrupt_occurred)
    {
        advance_guest_rip();
    }

    check_hw_exception();
    bus_lock_exit();

EXIT:
    //Return to TD
    tdx_return_to_td(true);

    //Unreachable code. panic
    tdx_sanity_check(0, SCEC_TD_DISPATCHER_SOURCE, 0);
}
