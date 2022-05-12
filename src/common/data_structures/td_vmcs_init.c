// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_vmcs_init.c
 * @brief Predefined init fields for TD's VMCS
 */
#include "x86_defs/vmcs_defs.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "data_structures/td_vmcs_init.h"
#include "td_dispatcher/tdx_td_dispatcher.h"
#include "helpers/helpers.h"


const vmcs_fields_info_t vmcs_init_map[] = {
        // Guest Register State
        {.encoding = VMX_GUEST_CR0_ENCODE, .value = 0x0021ULL},
        {.encoding = VMX_GUEST_CR4_ENCODE, .value = 0x2040ULL},
        {.encoding = VMX_GUEST_DR7_ENCODE, .value = 0x00000400ULL},
        {.encoding = VMX_GUEST_RIP_ENCODE, .value = 0xFFFFFFF0ULL},
        {.encoding = VMX_GUEST_RFLAGS_ENCODE, .value = 0x00000002ULL},
        {.encoding = VMX_GUEST_CS_LIMIT_ENCODE, .value = 0xFFFFFFFFULL},
        {.encoding = VMX_GUEST_CS_ARBYTE_ENCODE, .value = 0x0000C09BULL},
        {.encoding = VMX_GUEST_DS_LIMIT_ENCODE, .value = 0xFFFFFFFFULL},
        {.encoding = VMX_GUEST_DS_ARBYTE_ENCODE, .value = 0x0000C093ULL},
        {.encoding = VMX_GUEST_ES_LIMIT_ENCODE, .value = 0xFFFFFFFFULL},
        {.encoding = VMX_GUEST_ES_ARBYTE_ENCODE, .value = 0x0000C093ULL},
        {.encoding = VMX_GUEST_FS_LIMIT_ENCODE, .value = 0xFFFFFFFFULL},
        {.encoding = VMX_GUEST_FS_ARBYTE_ENCODE, .value = 0x0000C093ULL},
        {.encoding = VMX_GUEST_GS_LIMIT_ENCODE, .value = 0xFFFFFFFFULL},
        {.encoding = VMX_GUEST_GS_ARBYTE_ENCODE, .value = 0x0000C093ULL},
        {.encoding = VMX_GUEST_SS_LIMIT_ENCODE, .value = 0xFFFFFFFFULL},
        {.encoding = VMX_GUEST_SS_ARBYTE_ENCODE, .value = 0x0000C093ULL},
        {.encoding = VMX_GUEST_LDTR_LIMIT_ENCODE, .value = 0x0000FFFFULL},
        {.encoding = VMX_GUEST_LDTR_ARBYTE_ENCODE, .value = 0x00010082ULL},
        {.encoding = VMX_GUEST_TR_LIMIT_ENCODE, .value = 0x0000FFFFULL},
        {.encoding = VMX_GUEST_TR_ARBYTE_ENCODE, .value = 0x0000008BULL},
        {.encoding = VMX_GUEST_GDTR_LIMIT_ENCODE, .value = 0x0000FFFFULL},

        // Guest MSR
        {.encoding = VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE, .value = 0xFFULL},
        {.encoding = VMX_GUEST_IA32_PAT_FULL_ENCODE, .value = 0x0007040600070406ULL},
        {.encoding = VMX_GUEST_IA32_EFER_FULL_ENCODE, .value = 0x901ULL},

        // Guest Non-Register State
        {.encoding = VMX_GUEST_SAVED_WORKING_VMCS_POINTER_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR0_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR1_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR2_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR3_FULL_ENCODE, .value = (uint64_t)-1},

        // Controls for APIC Virtualization
        {.encoding = VMX_VIRTUAL_APIC_ACCESS_PAGE_ADDRESS_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE, .value = 0xFFFFULL},
        {.encoding = VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE, .value = (uint64_t)-1},



        // VM-Execution Control
        {.encoding = VMX_EXCEPTION_BITMAP_ENCODE, .value = BIT(18)}, // Bit 18 (MCE) is set to 1
        {.encoding = VMX_IO_BITMAP_A_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_IO_BITMAP_B_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},

        {.encoding = VMX_EPTP_LIST_ADDRESS_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_VMREAD_BITMAP_ADDRESS_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_VMWRITE_BITMAP_ADDRESS_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_ENCLS_EXIT_CONTROL_FULL_ENCODE, .value = (BIT(63) - BIT(0) + BIT(63))},
        {.encoding = VMX_ENCLV_EXIT_CONTROL_FULL_ENCODE, .value = (BIT(63) - BIT(0) + BIT(63))},

        {.encoding = VMX_PML_LOG_ADDRESS_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_PCONFIG_EXITING_FULL_ENCODE, .value = (BIT(63) - BIT(0) + BIT(63))},

        // VM-Exit Controls
        {.encoding = VMX_VM_EXIT_CONTROL_ENCODE, .value = VM_EXIT_CONTROL_FIXED_VALUES},

        // VM-Exit Controls for MSRs
        {.encoding = VMX_EXIT_MSR_STORE_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_EXIT_MSR_LOAD_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},

        // VM-Entry Controls
        {.encoding = VMX_ENTRY_MSR_LOAD_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},

        {.encoding = (uint64_t)-1, .value = 0} // indicates last index
};


_STATIC_INLINE_ void read_vmcs_field_info(uint64_t encoding, vmcs_fields_info_t *fields_info)
{
    fields_info->encoding = encoding;
    ia32_vmread(fields_info->encoding, &fields_info->value);
}


void save_vmcs_host_fields(vmcs_host_values_t* host_fields_ptr)
{
    read_vmcs_field_info(VMX_HOST_CR0_ENCODE, &host_fields_ptr->CR0);
    read_vmcs_field_info(VMX_HOST_CR3_ENCODE, &host_fields_ptr->CR3);
    read_vmcs_field_info(VMX_HOST_CR4_ENCODE, &host_fields_ptr->CR4);
    read_vmcs_field_info(VMX_HOST_CS_SELECTOR_ENCODE, &host_fields_ptr->CS);
    read_vmcs_field_info(VMX_HOST_SS_SELECTOR_ENCODE, &host_fields_ptr->SS);
    read_vmcs_field_info(VMX_HOST_FS_SELECTOR_ENCODE, &host_fields_ptr->FS);
    read_vmcs_field_info(VMX_HOST_GS_SELECTOR_ENCODE, &host_fields_ptr->GS);
    read_vmcs_field_info(VMX_HOST_TR_SELECTOR_ENCODE, &host_fields_ptr->TR);
    read_vmcs_field_info(VMX_HOST_IA32_S_CET_ENCODE, &host_fields_ptr->IA32_S_CET);
    read_vmcs_field_info(VMX_HOST_SSP_ENCODE, &host_fields_ptr->SSP);
    read_vmcs_field_info(VMX_HOST_IA32_PAT_FULL_ENCODE, &host_fields_ptr->IA32_PAT);
    read_vmcs_field_info(VMX_HOST_IA32_EFER_FULL_ENCODE, &host_fields_ptr->IA32_EFER);
    read_vmcs_field_info(VMX_HOST_FS_BASE_ENCODE, &host_fields_ptr->FS_BASE);
    read_vmcs_field_info(VMX_HOST_RSP_ENCODE, &host_fields_ptr->RSP);
    read_vmcs_field_info(VMX_HOST_GS_BASE_ENCODE, &host_fields_ptr->GS_BASE);
}


static void init_td_vmcs_host_fields(vmcs_host_values_t* host_fields_ptr)
{
    ia32_vmwrite(host_fields_ptr->CR0.encoding, host_fields_ptr->CR0.value);
    ia32_vmwrite(host_fields_ptr->CR3.encoding, host_fields_ptr->CR3.value);
    ia32_vmwrite(host_fields_ptr->CR4.encoding, host_fields_ptr->CR4.value);
    ia32_vmwrite(host_fields_ptr->CS.encoding, host_fields_ptr->CS.value);
    ia32_vmwrite(host_fields_ptr->SS.encoding, host_fields_ptr->SS.value);
    ia32_vmwrite(host_fields_ptr->FS.encoding, host_fields_ptr->FS.value);
    ia32_vmwrite(host_fields_ptr->GS.encoding, host_fields_ptr->GS.value);
    ia32_vmwrite(host_fields_ptr->TR.encoding, host_fields_ptr->TR.value);
    ia32_vmwrite(host_fields_ptr->IA32_S_CET.encoding, host_fields_ptr->IA32_S_CET.value);
    ia32_vmwrite(host_fields_ptr->SSP.encoding, host_fields_ptr->SSP.value);
    ia32_vmwrite(host_fields_ptr->IA32_PAT.encoding, host_fields_ptr->IA32_PAT.value);
    ia32_vmwrite(host_fields_ptr->IA32_EFER.encoding, host_fields_ptr->IA32_EFER.value);
    ia32_vmwrite(host_fields_ptr->FS_BASE.encoding, host_fields_ptr->FS_BASE.value);
    ia32_vmwrite(host_fields_ptr->RSP.encoding, host_fields_ptr->RSP.value);
    ia32_vmwrite(host_fields_ptr->GS_BASE.encoding, host_fields_ptr->GS_BASE.value);
}

void init_guest_td_address_fields(tdr_t* tdr_ptr, tdvps_t* tdvps_ptr, uint16_t curr_hkid)
{
    pa_t write_addr = set_hkid_to_pa((pa_t)tdvps_ptr->management.tdvps_pa[TDVPS_VAPIC_PAGE_INDEX], curr_hkid);
    ia32_vmwrite(VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE,
                 write_addr.raw);

    write_addr = set_hkid_to_pa((pa_t)tdr_ptr->management_fields.tdcx_pa[MSR_BITMAPS_PAGE_INDEX], curr_hkid);
    ia32_vmwrite(VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE,
                 write_addr.raw);

    write_addr = set_hkid_to_pa((pa_t)tdvps_ptr->management.tdvps_pa[TDVPS_VE_INFO_PAGE_INDEX], curr_hkid);
    ia32_vmwrite(VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE,
                 write_addr.raw);

    write_addr = set_hkid_to_pa((pa_t)tdr_ptr->management_fields.tdcx_pa[ZERO_PAGE_INDEX], curr_hkid);

    ia32_vmwrite(VMX_PASID_LOW_FULL_ENCODE, write_addr.raw);
    ia32_vmwrite(VMX_PASID_HIGH_FULL_ENCODE, write_addr.raw);

    // Shared EPTP is only updated if it's in its initial state.
    // Once written with a real Shared HPA value via TDHVPWR, there's no need to update
    if (!tdvps_ptr->management.is_shared_eptp_valid)
    {
        // Set to TDCS Zero Page too
        ia32_vmwrite(VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE, write_addr.raw);
    }

    ia32_vmwrite(VMX_HKID_ENCODE, curr_hkid);

    // set current hkid to VCPU
    tdvps_ptr->management.assoc_hkid = (uint32_t)curr_hkid;
}

static void init_td_vmcs_exec_control_field(tdcs_t * tdcs_ptr)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;

    uint32_t vmexit_controls_vector = tdx_global_data_ptr->td_vmcs_values.exit_ctls;
    uint32_t vmentry_controls_vector = tdx_global_data_ptr->td_vmcs_values.entry_ctls;
    uint32_t pin_based_execution_controls = tdx_global_data_ptr->td_vmcs_values.pinbased_ctls;
    vmcs_procbased_ctls_t processor_based_execution_controls = { .raw = tdx_global_data_ptr->td_vmcs_values.procbased_ctls };
    vmcs_procbased_ctls2_t sec_proc_based_execution_controls = { .raw = tdx_global_data_ptr->td_vmcs_values.procbased_ctls2 };
    vmcs_procbased_ctls3_t ter_proc_based_execution_controls = { .raw = tdx_global_data_ptr->td_vmcs_values.procbased_ctls3 };

    // Fixed bits:

    vmexit_controls_vector                 |= msr_values_ptr->ia32_vmx_true_exit_ctls.not_allowed0;
    vmentry_controls_vector                |= msr_values_ptr->ia32_vmx_true_entry_ctls.not_allowed0;
    pin_based_execution_controls           |= msr_values_ptr->ia32_vmx_true_pinbased_ctls.not_allowed0;
    processor_based_execution_controls.raw |= msr_values_ptr->ia32_vmx_true_procbased_ctls.not_allowed0;
    sec_proc_based_execution_controls.raw  |= msr_values_ptr->ia32_vmx_procbased_ctls2.not_allowed0;

    // Conditional bits:

    if (tdcs_ptr->executions_ctl_fields.attributes.perfmon || tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        // Set to one 
        vmexit_controls_vector  |= (uint32_t)1 << VMCS_EXIT_LOAD_PERF_GLBL_CTRL_BIT_LOCATION;
        vmexit_controls_vector  |= (uint32_t)1 << VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION;

        vmentry_controls_vector |= (uint32_t)1 << VMCS_ENTRY_LOAD_PERF_GLBL_CTRL_BIT_LOCATION;
    }
    else
    {
        // Set to zero 
        vmexit_controls_vector  &= ~((uint32_t)1 << VMCS_EXIT_LOAD_PERF_GLBL_CTRL_BIT_LOCATION);
        vmexit_controls_vector  &= ~((uint32_t)1 << VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION);

        vmentry_controls_vector &= ~((uint32_t)1 << VMCS_ENTRY_LOAD_PERF_GLBL_CTRL_BIT_LOCATION);
    }

    if (tdcs_ptr->executions_ctl_fields.attributes.pks || tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        // Set to one 
        vmentry_controls_vector |= (uint32_t) 1 << VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION;
    }
    else
    {
        // Set to zero 
        vmentry_controls_vector &= ~((uint32_t) 1 << VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION);
    }

    processor_based_execution_controls.rdpmc_exiting = ~tdcs_ptr->executions_ctl_fields.attributes.perfmon;
    
    sec_proc_based_execution_controls.en_guest_wait_pause = tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported; 
    sec_proc_based_execution_controls.en_pconfig = tdcs_ptr->executions_ctl_fields.cpuid_flags.mktme_supported;    

    ter_proc_based_execution_controls.gpaw = tdcs_ptr->executions_ctl_fields.gpaw;

    ia32_vmwrite(VMX_VM_EXIT_CONTROL_ENCODE, vmexit_controls_vector);
    ia32_vmwrite(VMX_VM_ENTRY_CONTROL_ENCODE, vmentry_controls_vector);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE, pin_based_execution_controls);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, processor_based_execution_controls.raw);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE, sec_proc_based_execution_controls.raw);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE, ter_proc_based_execution_controls.raw);
}


void init_td_vmcs(tdcs_t * tdcs_ptr, tdvps_t* tdvps_ptr, vmcs_host_values_t* host_fields_ptr)
{
    uint32_t index = 0;
    uint64_t bitmap = 0;
    void (*td_entry_func_ptr)(void) = tdx_tdexit_entry_point;
    vmcs_procbased_ctls2_t procbased_ctls2 = {.raw = get_global_data()->td_vmcs_values.procbased_ctls2};

    while (vmcs_init_map[index].encoding != (uint64_t)(-1))
    {
        if (vmcs_init_map[index].encoding != VMX_ENCLV_EXIT_CONTROL_FULL_ENCODE ||
            procbased_ctls2.en_enclv_exiting == 1)
        {
            ia32_vmwrite(vmcs_init_map[index].encoding, vmcs_init_map[index].value);
        }  
        index++;
    }

    /**
     *  Initialize TD VMCS host fields
     */
    init_td_vmcs_host_fields(host_fields_ptr);

    /**
     *  Initialize/Update fields which depend on TDCS/TDR values
     */
    // Host-State
    ia32_vmwrite(VMX_HOST_RIP_ENCODE, (uint64_t)td_entry_func_ptr);

    // Exec control fields
    init_td_vmcs_exec_control_field(tdcs_ptr);

    // Other exec-control fields:
    // TSC multiplier
    ia32_vmwrite(VMX_TSC_MULTIPLIER_FULL_ENCODE, tdcs_ptr->executions_ctl_fields.tsc_multiplier);

    // TSC offset
    ia32_vmwrite(VMX_TSC_OFFSET_FULL_ENCODE, tdcs_ptr->executions_ctl_fields.tsc_offset);

    // EPTP
    pa_t eptp_raw = set_hkid_to_pa((pa_t)tdcs_ptr->executions_ctl_fields.eptp.raw, 0);
    ia32_vmwrite(VMX_GUEST_EPT_POINTER_FULL_ENCODE, eptp_raw.raw);

    /** CR0 Guest/Host Mask
     * The following bits are set to 1 : PE (0), NE (5), NW (29), CD (30)
     * Any bit set to 1 in IA32_VMX_CR0_FIXED0 (i.e., bit whose value must be 1)), except for PG(31) which is set to 0, since the guest TD run as an unrestricted guest.
     * Any bit set to 0 in IA32_VMX_CR0_FIXED1 (i.e., bit whose value must be 0).
     * Bits known to TDX-SEAM as reserved (TDX1:  bits 63-32, 28-19, 17 and 15-6)
     * All other bits are cleared to 0
     */
    uint64_t ia32_vmx_cr0_fixed0 = ia32_rdmsr(IA32_VMX_CR0_FIXED0_MSR_ADDR) & (~BIT(31));
    bitmap = ia32_vmx_cr0_fixed0 | (BIT(0) | BIT(5) | BIT(29) | BIT(30) |
            BITS(63,32) | BITS(28,19) | BIT(17) | BITS(15,6));
    ia32_vmwrite(VMX_CR0_GUEST_HOST_MASK_ENCODE, bitmap);

    /** CR0 Read Shadow
     * The following bits are set to 1: PE (0), NE (5)
     * Any bit set to 1 in IA32_VMX_CR0_FIXED0 (i.e., bit whose value must be 1)
     * All other bits are cleared to 0
     */
    bitmap = ia32_vmx_cr0_fixed0 | (BIT(0) | BIT(5));
    ia32_vmwrite(VMX_CR0_READ_SHADOW_ENCODE, bitmap);

    /** CR4 Guest/Host Mask
     * Bits MCE (6), VMXE (13) and SMXE (14) are always set to 1
     * Bit PKE (22) is set to ~TDCS.XFAM[9]
     * bit CET (23) is cleared to 0 if TDCS.XFAM[12:11] is 11. Otherwise, bit CET (23) is set to 1
     * Bit UINT (25) is set ~TDCS.XFAM[14] if ULI is not enabled
     * Bit KL (19) is set to ~TDCS.ATTRIBUTES.KL if KeyLocker is not enabled.
     * Bit PKS (24) is set to ~TDCS.ATTRIBUTES.PKS if PKS is not enabled.
     * Any bit set to 1 in IA32_VMX_CR4_FIXED0 is set to 1
     * Any bit set to 0 in IA32_VMX_CR4_FIXED1 is set to 1
     * Reserved bits (15 and 63-26) are set to 1
     * All other bits are cleared to 0
     */
    uint64_t ia32_vmx_cr4_fixed0 = get_global_data()->plt_common_config.ia32_vmx_cr4_fixed0.raw;
    uint64_t ia32_vmx_cr4_fixed1 = get_global_data()->plt_common_config.ia32_vmx_cr4_fixed1.raw;
    bitmap = ia32_vmx_cr4_fixed0 | (~ia32_vmx_cr4_fixed1);
    bitmap = bitmap | (BIT(6) | BIT(13) | BIT(14) | BIT(15) | BITS(63,26));
    if ((tdcs_ptr->executions_ctl_fields.xfam & BIT(9)) == 0)
    {
        bitmap |= BIT(22);
    }
    if ((tdcs_ptr->executions_ctl_fields.xfam & BITS(12,11)) != BITS(12,11))
    {
        bitmap |= BIT(23);
    }
    if ((tdcs_ptr->executions_ctl_fields.xfam & BIT(14)) == 0)
    {
        bitmap |= BIT(25);
    }
    if (!tdcs_ptr->executions_ctl_fields.attributes.kl)
    {
        bitmap |= BIT(19);
    }
    if (!tdcs_ptr->executions_ctl_fields.attributes.pks)
    {
        bitmap |= BIT(24);
    }

    ia32_vmwrite(VMX_CR4_GUEST_HOST_MASK_ENCODE, bitmap);

    /** CR4 Read Shadow
         * Bit MCE (6) is set to 1.
         * Bit VMXE (13) is cleared to 0.
         * Any other bit whose value is set to 1 in IA32_VMX_CR4_FIXED0 (i.e., a bit whose value must be 1) is set to 1.
         * All other bits are cleared to 0
         */
    bitmap = (ia32_vmx_cr4_fixed0 & ~BIT(13)) | BIT(6);
    ia32_vmwrite(VMX_CR4_READ_SHADOW_ENCODE, bitmap);

    /**
     * VPID
     * Set by TDX-SEAM on TDHVPINIT to the sequential index of the VCPU
     */
    ia32_vmwrite(VMX_GUEST_VPID_ENCODE, tdvps_ptr->management.vcpu_index + 1);
}

