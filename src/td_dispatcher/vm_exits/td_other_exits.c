// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_other_exits.c
 * @brief VM Exit handlers for various other small reasons
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
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"

void td_rdpmc_exit(vm_vmexit_exit_reason_t vm_exit_reason, uint64_t  vm_exit_qualification)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    if (tdcs_p->executions_ctl_fields.attributes.perfmon == 0)
    {
        TDX_LOG("RDPMC exit - causes #GP");
        inject_gp(0);
        return;
    }
    // if TD is debuggable then TDEXIT
    if (tdx_local_data_ptr->vp_ctx.attributes.debug)
    {
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, vm_exit_qualification, 0, 0, 0);
    }
    else
    {
        // If ATTRIBUTES.PERFMON is set, there shouldn't be a VM exit
        FATAL_ERROR();
    }

}

void td_ept_misconfiguration_exit(vm_vmexit_exit_reason_t vm_exit_reason)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    bool_t gpaw = tdcs_p->executions_ctl_fields.gpaw;
    pa_t gpa;

    ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &gpa.raw);

    bool_t shared_bit = get_gpa_shared_bit(gpa.raw, gpaw);

    if (shared_bit)
    {
        // Clear page offset
        gpa.low_12_bits = 0;
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, gpa.raw, 0);
    }
    else
    {
        // Fatal error - EPT misconfiguration is not expected for private GPA
        FATAL_ERROR();
    }
}

void td_cr_access_exit(vmx_exit_qualification_t vm_exit_qualification)
{
    uint64_t   value;
    ia32_cr0_t cr0;
    ia32_cr4_t cr4;

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;
    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;

    switch (vm_exit_qualification.cr_access.access_type)
    {
        case VMEXIT_CR_ACCESS_MOV_TO_CR:
            if (vm_exit_qualification.cr_access.mov_cr_gpr == GPR_RSP_IDX)
            {
                ia32_vmread(VMX_GUEST_RSP_ENCODE, &value);
            }
            else
            {
                value = tdvps_p->guest_state.gprs[vm_exit_qualification.cr_access.mov_cr_gpr];
            }


            switch (vm_exit_qualification.cr_access.cr_num)
            {
                case 0:
                    // MOV to CR0
                    // All valid cases of accessing CR0 are controlled by the CR0 guest/host mask
                    // and CR0 read shadow fields of the TD VMCS, and do not cause a VM exit.

                    cr0.raw = value;

                    // If the guest attempted to write natively invalid values, inject a #GP(0)
                    ia32_cr0_t cr0_fixed0;
                    cr0_fixed0.raw = msr_values_ptr->ia32_vmx_cr0_fixed0.raw;
                    cr0_fixed0.pe = 0;
                    cr0_fixed0.pg = 0;

                    if ((~cr0.raw & cr0_fixed0.raw) ||
                        (cr0.raw & ~msr_values_ptr->ia32_vmx_cr0_fixed1.raw))
                    {
                        TDX_LOG("MOV to CR0 - attempt to write invalid values (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    // The combination CR0.PE == 0 and CR0.PG == 1 is architecturally illegal
                    if ((cr0.pe == 0) && (cr0.pg == 1))
                    {
                        TDX_LOG("MOV to CR0 - use illegal combination (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    // If the guest attempted to clear CR0.WP while CR4.CET is 1, throw a #GP(0)
                    ia32_vmread(VMX_GUEST_CR4_ENCODE, &(cr4.raw));
                    if ((cr4.cet == 1) && (cr0.wp == 0))
                    {
                        TDX_LOG("MOV to CR0 - illegal attempt to clear bit (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    //  If the guest attempted to change any CR0 bit that is owned by TDX-SEAM
                    if ((cr0.pe == 0) ||
                        (cr0.ne == 0) ||
                        (cr0.nw == 1) ||
                        (cr0.cd == 1) ||
                        (cr0.reserved_3 != 0))
                    {
                        TDX_LOG("MOV to CR0 - other case (0x%lx) - #VE", value);
                        tdx_inject_ve(VMEXIT_REASON_CR_ACCESS, vm_exit_qualification.raw, tdvps_p, 0, 0);
                        return;
                    }

                    /* Update the value of guest CR0.
                     * Values of bits 28-19, 17 and 15-6 left as they were before.
                     */
                    cr0.raw &= ~(uint64_t)CR0_IGNORED_MASK;
                    uint64_t guest_cr0;
                    ia32_vmread(VMX_GUEST_CR0_ENCODE, &guest_cr0);
                    cr0.raw |= guest_cr0 & (uint64_t)CR0_IGNORED_MASK;
                    ia32_vmwrite(VMX_GUEST_CR0_ENCODE, cr0.raw);


                    break;

                case 4:
                    // MOV to CR4
                    // All valid cases of accessing CR4 are controlled by the CR4 guest/host mask
                    // and CR4 read shadow fields of the TD VMCS, and do not cause a VM exit.

                    cr4.raw = value;

                    // If the guest attempted to write natively invalid values, inject a #GP(0)
                    ia32_cr4_t cr4_fixed0;
                    cr4_fixed0.raw = msr_values_ptr->ia32_vmx_cr4_fixed0.raw;
                    cr4_fixed0.vmxe = 0;
                    if ((~cr4.raw & cr4_fixed0.raw) ||
                        (cr4.raw & ~msr_values_ptr->ia32_vmx_cr4_fixed1.raw))
                    {
                        TDX_LOG("MOV to CR4 - attempt to write invalid values (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    // If the guest attempted to set bits for features that are not enabled by XFAM,
                    //   inject a #GP(0)
                    ia32_xcr0_t cur_xfam;
                    cur_xfam.raw = tdvps_p->management.xfam;
                    if (((cur_xfam.pk == 0) && (cr4.pke == 1)) ||
                        (((cur_xfam.cet_s == 0) || (cur_xfam.cet_u == 0)) && (cr4.cet == 1)) ||
                        ((cur_xfam.uli == 0) && (cr4.uie == 1)))
                    {
                        TDX_LOG("MOV to CR4 - attempt to write features not enabled by XFAM (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    // If the guest attempted to set bits for features that are not enabled by ATTRIBUTES,
                    // inject a #GP(0)
                    if (cr4.keylocker == 1)
                    {
                        TDX_LOG("MOV to CR4 - keylocker not supported (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    if ((tdcs_p->executions_ctl_fields.attributes.pks == 0) && (cr4.pks == 1))
                    {
                        TDX_LOG("MOV to CR4 - PKS not supported (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    // If the guest attempted to set CR4.CET while CR0.WP is 0, throw a #GP(0)
                    ia32_vmread(VMX_GUEST_CR0_ENCODE, &(cr0.raw));
                    if ((cr4.cet == 1) && (cr0.wp == 0))
                    {
                        TDX_LOG("MOV to CR4 - illegal attempt to clear bit (0x%lx) - #GP", value);
                        inject_gp(0);
                        return;
                    }

                    // In all other cases, inject a #VE
                    TDX_LOG("MOV to CR4 - other case (0x%lx) - #VE", value);
                    tdx_inject_ve(VMEXIT_REASON_CR_ACCESS, vm_exit_qualification.raw, tdvps_p, 0, 0);

                    break;

                default:
                    // VM exits due to other CR accesses are not expected
                    // Fatal error:
                    FATAL_ERROR();
            }

            break;

        case VMEXIT_CR_ACCESS_LMSW:

            // Architecturally, LMSW can only write CR0[3:1] (TS, EM, MP); write to CR0[0] (PE)
            // is ignored in protected mode.
            // Because of the setting of TD VMCS CR0 guest/host mask, guest TD attempts to
            // clear CR0.NE or CR0.PE to 0, or set CR0.CD, CR0.NW or any of the CR0 reserved bits
            // to 1 cause a VM exit.

            value = vm_exit_qualification.cr_access.lmsw_src_data;
            ia32_vmread(VMX_GUEST_CR0_ENCODE, &cr0.raw);

            ia32_vmwrite(VMX_GUEST_CR0_ENCODE, (value & 0xEULL) | (cr0.raw & ~0xEULL));

            break;

        default:
            // VM exits due to other access types (MOV from CR, CLTS) are not expected
            // Fatal error

            FATAL_ERROR();
    }

}

void td_exception_or_nmi_exit(vm_vmexit_exit_reason_t vm_exit_reason,
                              vmx_exit_qualification_t vm_exit_qualification,
                              vmx_exit_inter_info_t vm_exit_inter_info)
{
    if (vm_exit_inter_info.interruption_type == VMEXIT_INTER_INFO_TYPE_NMI)
    {
        // This exit was due to an NMI
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason,
                            vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }
    else if (vm_exit_inter_info.vector == E_MC)
    {
        // This exit was due to a #MC, disable the TD
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_FATAL, vm_exit_reason,
                            vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }
    else if (get_local_data()->vp_ctx.tdcs->executions_ctl_fields.attributes.debug)
    {
        // If the TD is debuggable, it may exit due to any exception
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason,
                            vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }
    else
    {
        // Currently we don't expect exits due to other exceptions
        // Fatal error
        FATAL_ERROR();
    }

}

void tdx_ept_violation_exit_to_vmm(pa_t gpa, vm_vmexit_exit_reason_t vm_exit_reason, uint64_t exit_qual, uint64_t ext_exit_qual)
{
    vmx_exit_qualification_t exit_qualification;
    exit_qualification.raw = exit_qual;

    // When exit is due to EPT violation, bits 12-7 of the exit qualification are cleared to 0.
    exit_qualification.ept_violation.gla_valid = 0;
    exit_qualification.ept_violation.page_walk_fault = 0;
    exit_qualification.ept_violation.user_mode_lin_addr = 0;
    exit_qualification.ept_violation.writable_lin_addr = 0;
    exit_qualification.ept_violation.execute_dis_lin_addr = 0;
    exit_qualification.ept_violation.nmi_unblocking_due_to_iret = 0;

    // When exit is due to EPT violation or EPT misconfiguration, format is similar to the
    // VMCS guest-physical address, except that bits 11:0 are cleared to 0.
    gpa.low_12_bits = 0;

    async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, exit_qualification.raw,
                        ext_exit_qual, gpa.raw, 0);
}

void tdx_ept_misconfig_exit_to_vmm(pa_t gpa)
{
    // When exit is due to EPT violation or EPT misconfiguration, format is similar to the
    // VMCS guest-physical address, except that bits 11:0 are cleared to 0.
    gpa.low_12_bits = 0;

    vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };
    vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_MISCONFIGURATION;

    async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, gpa.raw, 0);
}

void tdx_inject_ve(uint32_t vm_exit_reason, uint64_t exit_qualification, tdvps_t* tdvps_p,
        uint64_t gpa, uint64_t gla)
{
    // TDX-SEAM first checks VE_INFO.VALID to make sure VE_INFO does not contain information that
    // hasn’t been read yet using TDGVPVEINFOGET.
    // - If VE_INFO.VALID is 0, it copies the exit reason and exit qualification from the
    //   TD VMCS to VE_INFO, and injects a #VE to the guest TD, as described in ‎16.4.2.4.
    // - If VE_INFO.VALID is not 0, it injects a #GP(0) to the guest TD.

    if (tdvps_p->ve_info.valid == 0)
    {
        uint64_t eptp_index;
        uint64_t length, info;

        ia32_vmread(VMX_EPTP_INDEX_ENCODE, &eptp_index);
        ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &length);
        ia32_vmread(VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE, &info);

        tdvps_p->ve_info.exit_reason = vm_exit_reason;
        tdvps_p->ve_info.exit_qualification = exit_qualification;
        tdvps_p->ve_info.gla = gla;
        tdvps_p->ve_info.gpa = gpa;
        tdvps_p->ve_info.eptp_index = (uint16_t)eptp_index;
        tdvps_p->ve_info.instruction_length = (uint32_t)length;
        tdvps_p->ve_info.instruction_info = (uint32_t)info;

        tdvps_p->ve_info.valid = (uint32_t)VE_INFO_CONTENTS_VALID;

        inject_ve();
    }
    else
    {
        inject_df();
    }

    ia32_rflags_t rflags;

    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);
    rflags.rf = 1;
    ia32_vmwrite(VMX_GUEST_RFLAGS_ENCODE, rflags.raw);
}

void td_nmi_exit(tdx_module_local_t* tdx_local_data_ptr)
{
    vmx_entry_inter_info_t vm_entry_inter_info;
    vmcs_procbased_ctls_t vm_procbased_ctls;

    if (tdx_local_data_ptr->vp_ctx.tdvps->management.pend_nmi &&
            tdx_local_data_ptr->vp_ctx.tdvps->ve_info.valid == 0)
    {
        /**
         * PEND_NMI was requested, and there's no pending #VE (which should be handled
         * by the guest TD before NMI).  Inject an NMI.
         */
        vm_entry_inter_info.raw = 0ULL;
        vm_entry_inter_info.vector = E_NMI;
        vm_entry_inter_info.interruption_type = VMEXIT_INTER_INFO_TYPE_NMI;
        vm_entry_inter_info.deliver_error_code = 0;
        vm_entry_inter_info.valid = 1;
        ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, vm_entry_inter_info.raw);

        tdx_local_data_ptr->vp_ctx.tdvps->management.pend_nmi = false;
    }

    // Clear the NMI Window Exiting VM execution control
    ia32_vmread(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, &vm_procbased_ctls.raw);
    vm_procbased_ctls.nmi_window_exiting = 0;
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, vm_procbased_ctls.raw);
}

