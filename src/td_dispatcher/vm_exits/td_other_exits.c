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

// CR0 bits that can be modified by LMSW
// For L2, only PE, MP, EM and TD bits can be modified
#define CR0_L1_LMSW_MASK 0xEULL

bool_t td_cr_access_exit(vmx_exit_qualification_t vm_exit_qualification)
{
    uint64_t   value;
    ia32_cr0_t cr0;
    cr_write_status_e status = CR_ACCESS_SUCCESS;

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    switch (vm_exit_qualification.cr_access.access_type)
    {
        case VMEXIT_CR_ACCESS_MOV_TO_CR:
            if (vm_exit_qualification.cr_access.mov_cr_gpr == GPR_RSP_IDX)
            {
                ia32_vmread(VMX_GUEST_RSP_ENCODE, &value);
            }
            else
            {
                value = tdvps_p->guest_state.gpr_state.gprs[vm_exit_qualification.cr_access.mov_cr_gpr];
            }

            switch (vm_exit_qualification.cr_access.cr_num)
            {
                case 0:
                    // MOV to CR0
                    // All valid cases of accessing CR0 are controlled by the CR0 guest/host mask
                    // and CR0 read shadow fields of the TD VMCS, and do not cause a VM exit.
                    status = write_guest_cr0(value, false);
                    break;

                case 4:
                    // MOV to CR4
                    // All valid cases of accessing CR4 are controlled by the CR4 guest/host mask
                    // and CR4 read shadow fields of the TD VMCS, and do not cause a VM exit.
                    status = write_guest_cr4(value, tdcs_p, tdvps_p);
                    break;

                default:
                    // VM exits due to other CR accesses are not expected
                    return false;
            }

            if (status == CR_ACCESS_GP)
            {
                inject_gp(0);
                return true;
            }
            else if (status == CR_ACCESS_NON_ARCH)
            {
                tdx_inject_ve(VMEXIT_REASON_CR_ACCESS, vm_exit_qualification.raw, tdvps_p, 0, 0);
                return true;
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

            // L1 is assumed to never run in real mode
            tdx_sanity_check(cr0.pe == 1, SCEC_TDEXIT_SOURCE, 3);

            ia32_vmwrite(VMX_GUEST_CR0_ENCODE, (value & CR0_L1_LMSW_MASK) | (cr0.raw & ~CR0_L1_LMSW_MASK));

            break;

        default:
            // VM exits due to other access types (MOV from CR, CLTS) are not expected
            return false;
    }

    return true;
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
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE, vm_exit_reason,
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

void tdx_inject_ve(uint64_t vm_exit_reason, uint64_t exit_qualification, tdvps_t* tdvps_p,
        uint64_t gpa, uint64_t gla)
{
    bool_t ve_info_mapped = false;
    tdvps_ve_info_t* ve_info_p;

    // Before we inject a #VE, reinject IDT vectoring events that happened during VM exit, if any

    tdx_debug_assert(tdvps_p->management.curr_vm == 0);
    {
        ve_info_p = &tdvps_p->ve_info;
    }

    // TDX-SEAM first checks VE_INFO.VALID to make sure VE_INFO does not contain information that
    // hasn’t been read yet using TDGVPVEINFOGET.
    // - If VE_INFO.VALID is 0, it copies the exit reason and exit qualification from the
    //   TD VMCS to VE_INFO, and injects a #VE to the guest TD, as described in ‎16.4.2.4.
    // - If VE_INFO.VALID is not 0, it injects a #GP(0) to the guest TD.

    if (ve_info_p->valid == 0)
    {
        uint64_t eptp_index;
        uint64_t length, info;

        ia32_vmread(VMX_EPTP_INDEX_ENCODE, &eptp_index);
        ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &length);
        ia32_vmread(VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE, &info);

        ve_info_p->exit_reason = (uint32_t)vm_exit_reason;
        ve_info_p->exit_qualification = exit_qualification;
        ve_info_p->gla = gla;
        ve_info_p->gpa = gpa;
        ve_info_p->eptp_index = (uint16_t)eptp_index;
        ve_info_p->instruction_length = (uint32_t)length;
        ve_info_p->instruction_info = (uint32_t)info;

        ve_info_p->valid = (uint32_t)VE_INFO_CONTENTS_VALID;

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

    if (ve_info_mapped)
    {
        free_la(ve_info_p);
    }
}

void td_nmi_exit(tdx_module_local_t* tdx_local_data_ptr)
{
    vmx_entry_inter_info_t vm_entry_inter_info;
    vmx_procbased_ctls_t vm_procbased_ctls;

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

void async_tdexit_ept_violation(pa_t gpa, ept_level_t req_level, ia32e_sept_t sept_entry,
                                ept_level_t ept_level, ia32e_sept_t* sept_entry_ptr, vmx_eeq_type_t eeq_type)
{
    vmx_ext_exit_qual_t eeq = {.raw = 0};
    tdaccept_vmx_eeq_info_t eeq_info = {.raw = 0};

    vmx_exit_qualification_t exit_qual = { .raw = 0 };

    // TDG.MEM.PAGE.ACCEPT and TDG.MEM.PAGE.ATTR.WR are both write operations
    exit_qual.ept_violation.data_write             = 1;
    exit_qual.ept_violation.gpa_readable           = sept_entry.r;
    exit_qual.ept_violation.gpa_writeable          = sept_entry.w;
    exit_qual.ept_violation.gpa_executable         = sept_entry.x;
    exit_qual.ept_violation.gpa_exec_for_ring3_lin = 0; // MBEC is not enabled for L1

    eeq_info.req_sept_level = req_level;
    eeq_info.err_sept_level = ept_level;
    eeq_info.err_sept_state = sept_get_arch_state(sept_entry);
    eeq_info.err_sept_is_leaf = is_secure_ept_leaf_entry(&sept_entry);

    eeq.type = eeq_type;
    eeq.info = eeq_info.raw;

    if (sept_entry_ptr != NULL)
    {
        free_la(sept_entry_ptr);
    }

    vm_vmexit_exit_reason_t vm_exit_reason = {.raw = 0};
    vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;

    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qual.raw, eeq.raw);
}
