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
 * @file td_vmcs_init.c
 * @brief Predefined init fields for TD's VMCS
 */
#include "x86_defs/vmcs_defs.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "data_structures/td_vmcs_init.h"
#include "td_dispatcher/tdx_td_dispatcher.h"
#include "helpers/helpers.h"

const vmcs_fields_info_t td_vmcs_migrated_state_init_map[] = {

        // Guest Register State
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
        // init value when perfmon enabled 0xFFULL
        {.encoding = VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE, .value = 0xFFULL},
        {.encoding = VMX_GUEST_IA32_PAT_FULL_ENCODE, .value = 0x0007040600070406ULL},
        {.encoding = VMX_GUEST_IA32_EFER_FULL_ENCODE, .value = 0x901ULL},

        {.encoding = (uint64_t)-1, .value = 0} // indicates last index
};

const vmcs_fields_info_t td_vmcs_non_migrated_state_init_map[] = {

        // Guest Register State - these two needs to initialized on import
        {.encoding = VMX_GUEST_CR0_ENCODE, .value = 0x0021ULL},
        {.encoding = VMX_GUEST_CR4_ENCODE, .value = 0x2040ULL},

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
        {.encoding = VMX_OSV_CVP_FULL_ENCODE, .value = (uint64_t)-1},

        // VM-Exit Controls for MSRs
        {.encoding = VMX_EXIT_MSR_STORE_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_EXIT_MSR_LOAD_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},

        // VM-Entry Controls
        {.encoding = VMX_ENTRY_MSR_LOAD_PHYPTR_FULL_ENCODE, .value = (uint64_t)-1},

        // Guest Non-Register State
        {.encoding = VMX_GUEST_SAVED_WORKING_VMCS_POINTER_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR0_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR1_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR2_FULL_ENCODE, .value = (uint64_t)-1},
        {.encoding = VMX_GUEST_PDPTR3_FULL_ENCODE, .value = (uint64_t)-1},

        {.encoding = (uint64_t)-1, .value = 0} // indicates last index
};


_STATIC_INLINE_ void read_vmcs_field_info(uint64_t encoding, vmcs_fields_info_t *fields_info)
{
    fields_info->encoding = encoding;
    ia32_vmread(fields_info->encoding, &fields_info->value);
}

void save_vmcs_non_lp_host_fields(vmcs_host_values_t* host_fields_ptr)
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
    read_vmcs_field_info(VMX_HOST_IA32_PAT_FULL_ENCODE, &host_fields_ptr->IA32_PAT);
    read_vmcs_field_info(VMX_HOST_IA32_EFER_FULL_ENCODE, &host_fields_ptr->IA32_EFER);
    read_vmcs_field_info(VMX_HOST_FS_BASE_ENCODE, &host_fields_ptr->FS_BASE);
    read_vmcs_field_info(VMX_HOST_IDTR_BASE_ENCODE, &host_fields_ptr->IDTR_BASE);
    read_vmcs_field_info(VMX_HOST_GDTR_BASE_ENCODE, &host_fields_ptr->GDTR_BASE);
}

static void init_td_vmcs_non_lp_host_fields(vmcs_host_values_t* host_fields_ptr)
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
    ia32_vmwrite(host_fields_ptr->IA32_PAT.encoding, host_fields_ptr->IA32_PAT.value);
    ia32_vmwrite(host_fields_ptr->IA32_EFER.encoding, host_fields_ptr->IA32_EFER.value);
    ia32_vmwrite(host_fields_ptr->FS_BASE.encoding, host_fields_ptr->FS_BASE.value);
    ia32_vmwrite(host_fields_ptr->IDTR_BASE.encoding, host_fields_ptr->IDTR_BASE.value);
    ia32_vmwrite(host_fields_ptr->GDTR_BASE.encoding, host_fields_ptr->GDTR_BASE.value);
}

void init_guest_td_address_fields(tdr_t* tdr_ptr, tdvps_t* tdvps_ptr, uint16_t curr_hkid, uint16_t vm_id)
{
    // L2 VMCS init
    if (vm_id > 0)
    {
        ia32_vmwrite(VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE, NULL_PA);
        ia32_vmwrite(VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE, tdvps_ptr->management.tdvps_pa[get_tdvps_msr_bitmap_index(vm_id)]);
        ia32_vmwrite(VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE, NULL_PA);
    }
    else // L1 VMCS init
    {
        ia32_vmwrite(VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE, tdvps_ptr->management.tdvps_pa[TDVPS_VAPIC_PAGE_INDEX]);
        ia32_vmwrite(VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE, tdr_ptr->management_fields.tdcx_pa[MSR_BITMAPS_PAGE_INDEX]);
        ia32_vmwrite(VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE, tdvps_ptr->management.tdvps_pa[TDVPS_VE_INFO_PAGE_INDEX]);
    }

    // Set all to TDCS Zero Page
    ia32_vmwrite(VMX_PASID_LOW_FULL_ENCODE, tdr_ptr->management_fields.tdcx_pa[ZERO_PAGE_INDEX]);
    ia32_vmwrite(VMX_PASID_HIGH_FULL_ENCODE, tdr_ptr->management_fields.tdcx_pa[ZERO_PAGE_INDEX]);
    ia32_vmwrite(VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE, tdr_ptr->management_fields.tdcx_pa[ZERO_PAGE_INDEX]);

    ia32_vmwrite(VMX_HKID_ENCODE, curr_hkid);
}

static void init_td_vmcs_exec_control_field(tdcs_t * tdcs_ptr, uint16_t vm_id)
{
    td_vmcs_values_t* td_vmcs_values_ptr = vm_id ? &get_global_data()->l2_vmcs_values :
                                                   &get_global_data()->td_vmcs_values;

    uint32_t vmexit_controls_vector = td_vmcs_values_ptr->exit_ctls;
    uint32_t vmentry_controls_vector = td_vmcs_values_ptr->entry_ctls;
    uint32_t pin_based_execution_controls = td_vmcs_values_ptr->pinbased_ctls;
    vmx_procbased_ctls_t processor_based_execution_controls = { .raw = td_vmcs_values_ptr->procbased_ctls };
    vmx_procbased_ctls2_t sec_proc_based_execution_controls = { .raw = td_vmcs_values_ptr->procbased_ctls2 };
    vmx_procbased_ctls3_t ter_proc_based_execution_controls = { .raw = td_vmcs_values_ptr->procbased_ctls3 };

    // Fixed bits already set in tdh_sys_init
    // Conditional bits
    if (tdcs_ptr->executions_ctl_fields.attributes.perfmon || tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        vmexit_controls_vector |= (uint32_t)1 << VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION;
    }
    else
    {
        vmexit_controls_vector &= ~((uint32_t)1 << VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION);
    }

    if (tdcs_ptr->executions_ctl_fields.attributes.pks || tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        vmentry_controls_vector |= (uint32_t) 1 << VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION;
    }
    else
    {
        vmentry_controls_vector &= ~((uint32_t) 1 << VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION);
    }

    processor_based_execution_controls.mwait_exiting = ~tdcs_ptr->executions_ctl_fields.cpuid_flags.monitor_mwait_supported;
    processor_based_execution_controls.rdpmc_exiting = ~tdcs_ptr->executions_ctl_fields.attributes.perfmon;
    processor_based_execution_controls.monitor_exiting = ~tdcs_ptr->executions_ctl_fields.cpuid_flags.monitor_mwait_supported;

    sec_proc_based_execution_controls.en_guest_wait_pause = tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported;
    sec_proc_based_execution_controls.en_pconfig = tdcs_ptr->executions_ctl_fields.cpuid_flags.pconfig_supported;

    ter_proc_based_execution_controls.gpaw = tdcs_ptr->executions_ctl_fields.gpaw;

    if (get_global_data()->ddpd_supported != tdcs_ptr->executions_ctl_fields.cpuid_flags.ddpd_supported)
    {
        ter_proc_based_execution_controls.virt_ia32_spec_ctrl = 1;
    }

    ia32_vmwrite(VMX_VM_EXIT_CONTROL_ENCODE, vmexit_controls_vector);
    ia32_vmwrite(VMX_VM_ENTRY_CONTROL_ENCODE, vmentry_controls_vector);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE, pin_based_execution_controls);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE, processor_based_execution_controls.raw);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE, sec_proc_based_execution_controls.raw);
    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE, ter_proc_based_execution_controls.raw);
}

void init_module_lp_host_state_in_td_vmcs(tdx_module_local_t* ld_p)
{
    // Init LP-dependant state
    ia32_vmwrite(VMX_HOST_RSP_ENCODE, ld_p->host_rsp);
    ia32_vmwrite(VMX_HOST_SSP_ENCODE, ld_p->host_ssp);
    ia32_vmwrite(VMX_HOST_GS_BASE_ENCODE, ld_p->host_gs_base);
}

void init_module_host_state_in_td_vmcs(void)
{
    init_td_vmcs_non_lp_host_fields(&get_global_data()->seam_vmcs_host_values);

    init_module_lp_host_state_in_td_vmcs(get_local_data());

    void (*td_entry_func_ptr)(void) = tdx_tdexit_entry_point;
    ia32_vmwrite(VMX_HOST_RIP_ENCODE, (uint64_t)td_entry_func_ptr);
}

static void init_tdcs_dependent_fields_in_vmcs(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, uint16_t vm_id)
{
    uint64_t bitmap = 0;

    // Exec control fields
    init_td_vmcs_exec_control_field(tdcs_ptr, vm_id);

    // Other exec-control fields:
    // TSC multiplier
    ia32_vmwrite(VMX_TSC_MULTIPLIER_FULL_ENCODE, tdcs_ptr->executions_ctl_fields.tsc_multiplier);

    // TSC offset
    ia32_vmwrite(VMX_TSC_OFFSET_FULL_ENCODE, tdcs_ptr->executions_ctl_fields.tsc_offset);

    // EPTP
    if (vm_id == 0)
    {
        pa_t eptp_raw = set_hkid_to_pa((pa_t)tdcs_ptr->executions_ctl_fields.eptp.raw, 0);
        ia32_vmwrite(VMX_GUEST_EPT_POINTER_FULL_ENCODE, eptp_raw.raw);
    }
    else
    {
        ia32e_eptp_t l2_eptp = get_l2_septp(tdr_ptr, tdcs_ptr, vm_id);
        ia32_vmwrite(VMX_GUEST_EPT_POINTER_FULL_ENCODE, l2_eptp.raw);
    }

    /** L1 CR0 Guest/Host Mask
     * The following bits are set to 1 : PE (0), NE (5), NW (29), CD (30)
     * Any bit set to 1 in IA32_VMX_CR0_FIXED0 (i.e., bit whose value must be 1)), 
     * except for PG(31) which is set to 0, since the guest TD run as an unrestricted guest.
     * Any bit set to 0 in IA32_VMX_CR0_FIXED1 (i.e., bit whose value must be 0).
     * Bits known to TDX-SEAM as reserved (TDX1:  bits 63-32, 28-19, 17 and 15-6)
     * All other bits are cleared to 0
     */
    uint64_t ia32_vmx_cr0_fixed0 = get_global_data()->plt_common_config.ia32_vmx_cr0_fixed0.raw;
    uint64_t ia32_vmx_cr0_fixed1 = get_global_data()->plt_common_config.ia32_vmx_cr0_fixed1.raw;
    
    if (vm_id == 0)
    {
        bitmap = (ia32_vmx_cr0_fixed0 | (~ia32_vmx_cr0_fixed1)) & (~BIT(31));
        bitmap = bitmap | BIT(0) | (BIT(5) | BIT(29) | BIT(30) |
                 BITS(63,32) | BITS(28,19) | BIT(17) | BITS(15,6));

        ia32_vmwrite(VMX_CR0_GUEST_HOST_MASK_ENCODE, bitmap);
    }
    else
    {
        ia32_vmwrite(VMX_CR0_GUEST_HOST_MASK_ENCODE, ~(0ULL));
    }


    /** L1 CR0 Read Shadow
     * The following bits are set to 1: PE (0), NE (5)
     * Any bit set to 1 in IA32_VMX_CR0_FIXED0 (i.e., bit whose value must be 1)
     * All other bits are cleared to 0
     */
    if (vm_id == 0)
    {
        bitmap = ia32_vmx_cr0_fixed0 | (BIT(0) | BIT(5));
    }
    else
    {
        bitmap = BIT(0) | BIT(5);
    }

    ia32_vmwrite(VMX_CR0_READ_SHADOW_ENCODE, bitmap);

    /** L1 CR4 Guest/Host Mask
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

    if (vm_id == 0)
    {
        bitmap = ia32_vmx_cr4_fixed0 | (~ia32_vmx_cr4_fixed1);
        bitmap = bitmap | (BIT(6) | BIT(13) | BIT(14) | BIT(15) | BIT(26) | BITS(31,29) | BITS(63,33));
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
        if (!tdcs_ptr->executions_ctl_fields.attributes.lass)
        {
            bitmap |= BIT(27);
        }

        ia32_vmwrite(VMX_CR4_GUEST_HOST_MASK_ENCODE, bitmap);
    }
    else
    {
        ia32_vmwrite(VMX_CR4_GUEST_HOST_MASK_ENCODE, ~(0ULL));
    }

    /** L1 CR4 Read Shadow
         * Bit MCE (6) is set to 1.
         * Bit VMXE (13) is cleared to 0.
         * Any other bit whose value is set to 1 in IA32_VMX_CR4_FIXED0 (i.e., a bit whose value must be 1) is set to 1.
         * All other bits are cleared to 0
         */
    if (vm_id == 0)
    {
        bitmap = (ia32_vmx_cr4_fixed0 & ~BIT(13)) | BIT(6);
    }
    else
    {
        bitmap = BIT(6) | BIT(13);
    }
    
    ia32_vmwrite(VMX_CR4_READ_SHADOW_ENCODE, bitmap);

    if (get_global_data()->plt_common_config.ia32_vmx_procbased_ctls3.virt_ia32_spec_ctrl)
    {
        // Set IA32_SPEC_CTRL Mask to tdcs_p->IA32_SPEC_CTRL_MASK.
        ia32_vmwrite(VMX_IA32_SPEC_CTRL_MASK, tdcs_ptr->executions_ctl_fields.ia32_spec_ctrl_mask);
    }
}

static void init_tdvps_shadow_masks(tdvps_t* tdvps_ptr, uint16_t vm_id)
{
    if (vm_id == 0)
    {
        uint64_t val = 0;

        tdvps_ptr->management.shadow_cr0_guest_host_mask[0] = (ia32_vmread(VMX_CR0_GUEST_HOST_MASK_ENCODE, &val), val);
        tdvps_ptr->management.shadow_cr0_read_shadow[0] = (ia32_vmread(VMX_CR0_READ_SHADOW_ENCODE, &val), val);
        tdvps_ptr->management.shadow_cr4_guest_host_mask[0] = (ia32_vmread(VMX_CR4_GUEST_HOST_MASK_ENCODE, &val), val);
        tdvps_ptr->management.shadow_cr4_read_shadow[0] = (ia32_vmread(VMX_CR4_READ_SHADOW_ENCODE, &val), val);
    }
    else
    {
        tdvps_ptr->management.shadow_cr0_guest_host_mask[vm_id] = ~(0ULL);
        tdvps_ptr->management.shadow_cr0_read_shadow[vm_id] = 0;
        tdvps_ptr->management.shadow_cr4_guest_host_mask[vm_id] = ~(0ULL);
        tdvps_ptr->management.shadow_cr4_read_shadow[vm_id] = 0;
    }
}

void init_td_vmcs(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr, bool_t init_on_import, uint16_t vm_id)
{
    uint32_t index = 0;
    vmx_procbased_ctls2_t procbased_ctls2 = {.raw = get_global_data()->td_vmcs_values.procbased_ctls2};

    if (!init_on_import)
    {
        while (td_vmcs_migrated_state_init_map[index].encoding != (uint64_t)(-1))
        {
            if (td_vmcs_migrated_state_init_map[index].encoding == VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE && !tdcs_ptr->executions_ctl_fields.attributes.perfmon)
            {
                // init value when perfmon disabled 0x100000000ULL
                ia32_vmwrite(td_vmcs_migrated_state_init_map[index].encoding, 0x100000000ULL);
            }
            else
            {
                ia32_vmwrite(td_vmcs_migrated_state_init_map[index].encoding, td_vmcs_migrated_state_init_map[index].value);
            }
            index++;
        }

        index = 0;
    }

    while (td_vmcs_non_migrated_state_init_map[index].encoding != (uint64_t)(-1))
    {
        if (td_vmcs_non_migrated_state_init_map[index].encoding != VMX_ENCLV_EXIT_CONTROL_FULL_ENCODE ||
            procbased_ctls2.en_enclv_exiting == 1)
        {
            ia32_vmwrite(td_vmcs_non_migrated_state_init_map[index].encoding, td_vmcs_non_migrated_state_init_map[index].value);
        }
        index++;
    }

    /**
     *  Initialize TD VMCS host fields
     */
    init_module_host_state_in_td_vmcs();

    /**
     * Initialize TD address fields
     */
    init_guest_td_address_fields(tdr_ptr, tdvps_ptr, tdr_ptr->key_management_fields.hkid, vm_id);

    /**
     *  Initialize/Update fields which depend on TDCS/TDR values
     */
    init_tdcs_dependent_fields_in_vmcs(tdr_ptr, tdcs_ptr, vm_id);

    // Init shadow mask fields in TDVPS
    init_tdvps_shadow_masks(tdvps_ptr, vm_id);

    /**
     * VPID
     * Set by TDX-SEAM on TDHVPINIT to the sequential index of the VCPU
     */
    uint16_t vpid = compose_vpid(vm_id, tdr_ptr->key_management_fields.hkid);
    ia32_vmwrite(VMX_GUEST_VPID_ENCODE, vpid);
}
