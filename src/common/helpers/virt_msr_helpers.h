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
 * @file virt_msr_helpers.h
 * @brief Virtual VMX MSR helper functions
 */

#ifndef SRC_COMMON_HELPERS_VIRT_MSR_HELPERS_H_
#define SRC_COMMON_HELPERS_VIRT_MSR_HELPERS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"

#include "x86_defs/x86_defs.h"
#include "x86_defs/msr_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "accessors/data_accessors.h"
#include "data_structures/td_control_structures.h"
#include "error_reporting.h"
#include "helpers.h"

// Calculate the value of virtual IA32_VMX_BASIC
_STATIC_INLINE_ ia32_vmx_basic_t calc_virt_ia32_vmx_basic(void)
{
    ia32_vmx_basic_t msr;

    msr.raw = 0;
    msr.vmexit_info_on_ios = 1;
    msr.ia32_vmx_true_available = 1;
    msr.voe_without_err_code = 1;

    return msr;
}

// Calculate the value of virtual IA32_VMX_MISC
_STATIC_INLINE_ ia32_vmx_misc_t calc_virt_ia32_vmx_misc(void)
{
    ia32_vmx_misc_t msr;

    msr.raw = 0;
    msr.unrestricted_guest = 1;
    msr.activity_hlt = 1;
    msr.activity_shutdown = 1;
    msr.pt_in_vmx = 1;
    msr.max_cr3_targets = 4;
    msr.vmwrite_any_vmcs_field = 1;
    msr.voe_with_0_instr_length = 1;

    return msr;
}

_STATIC_INLINE_ ia32_vmx_allowed_bits_t calc_allowed32_vmx_ctls(uint32_t init, uint32_t variable_mask)
{
    ia32_vmx_allowed_bits_t allowed;

    // Set bits that are fixed-1 (bits that are 1 in NOT_ALLOWED0).
    // A Bit must be 1 if its init value is 1 and it's not variable.
    allowed.not_allowed0 = init & ~variable_mask;
    // Set bits that are fixed-0 (bits that are 0 in ALLOWED1).
    // A bit must be 0 if its init value is 0 and it's not variable.
    allowed.allowed1 = init | variable_mask;

    // Sanity check on the TDX-SEAM module's constants:
    // Any bit can't be both fixed-1 (bits that are 1 in NOT_ALLOWED0) and fixed-0 (bits that are 0 in ALLOWED1)
    tdx_sanity_check((allowed.not_allowed0 & ~allowed.allowed1) == 0, SCEC_HELPERS_SOURCE, 30);

    return allowed;
}

// Helper function for calculationg allowed-1 bits in 64-bit VMCS control fields.
_STATIC_INLINE_ uint64_t calc_allowed1_vmx_ctls(uint64_t init, uint64_t variable_mask)

{
    // Set bits that are fixed-0 (bits that are 0 in ALLOWED1).  A bit must be 0 if
    // its init value is 0 and it's not variable.
    return init | variable_mask;
}

// Helper function for calculationg allowed bits in 64-bit VMCS control fields.
// See the definitions in the Intel SDM, Vol.3 Appendix A.7, A.8
_STATIC_INLINE_ void calc_allowed64_vmx_ctls(uint64_t init, uint64_t variable_mask,
                                             uint64_t* not_allowed0, uint64_t* allowed1)
{
    // Set bits that are fixed-1 (bits that are 1 in NOT_ALLOWED0).
    // A Bit must be 1 if its init value is 1 and it's not variable.
    *not_allowed0 = init & ~variable_mask;

    // Set bits that are fixed-0 (bits that are 0 in ALLOWED1).
    // A bit must be 0 if its init value is 0 and it's not variable.
    *allowed1 = init | variable_mask;

    // Sanity check:
    // Any bit can't be both fixed-1 (bits that are 1 in not_allowed0) and
    // fixed-0 (bits that are 0 in allowed1)
    tdx_sanity_check((*not_allowed0 & ~(*allowed1)) == 0, SCEC_HELPERS_SOURCE, 31);
}

/* Calculate the initial value of L2 VMCS' pin-based controls field,
   using the base value calculated during TDH.SYS.INIT and the TD configuration.
   See the L2 VMCS' spreadsheet for the definition of initial values.
*/
_STATIC_INLINE_ uint32_t calc_l2_vmcs_pinbased_ctls_init(void)
{
    // There is no TD-specific configuration, just return the base value
    return get_global_data()->l2_vmcs_values.pinbased_ctls;
}

_STATIC_INLINE_ uint32_t calc_l2_vmcs_procbased_ctls_init(tdcs_t* tdcs_p)
{
    td_vmcs_values_t* td_vmcs_values_ptr = &get_global_data()->l2_vmcs_values;

    vmx_procbased_ctls_t ctls = { .raw = td_vmcs_values_ptr->procbased_ctls };

    // Set TD-specific configuration
    ctls.mwait_exiting = ~tdcs_p->executions_ctl_fields.cpuid_flags.monitor_mwait_supported;
    ctls.rdpmc_exiting = ~tdcs_p->executions_ctl_fields.attributes.perfmon;
    ctls.monitor_exiting = ~tdcs_p->executions_ctl_fields.cpuid_flags.monitor_mwait_supported;

    return (uint32_t)ctls.raw;
}

_STATIC_INLINE_ uint32_t calc_l2_vmcs_procbased_ctls2_init(tdcs_t* tdcs_p)
{
    td_vmcs_values_t* td_vmcs_values_ptr = &get_global_data()->l2_vmcs_values;

    vmx_procbased_ctls2_t ctls = { .raw = td_vmcs_values_ptr->procbased_ctls2 };

    // Set TD-specific configuration
    ctls.en_guest_wait_pause = tdcs_p->executions_ctl_fields.cpuid_flags.waitpkg_supported;
    ctls.en_pconfig = tdcs_p->executions_ctl_fields.cpuid_flags.mktme_supported;

    return (uint32_t)ctls.raw;
}

_STATIC_INLINE_ uint64_t calc_l2_vmcs_procbased_ctls3_init(void)
{
    td_vmcs_values_t* td_vmcs_values_ptr = &get_global_data()->l2_vmcs_values;

    vmx_procbased_ctls3_t ctls = { .raw = td_vmcs_values_ptr->procbased_ctls3 };

    return ctls.raw;
}

_STATIC_INLINE_ uint32_t calc_l2_vmcs_vm_exit_ctls_init(tdcs_t* tdcs_p)
{
    td_vmcs_values_t* td_vmcs_values_ptr = &get_global_data()->l2_vmcs_values;

    uint32_t ctls = td_vmcs_values_ptr->exit_ctls;

    // Set TD-specific configuration
    if (tdcs_p->executions_ctl_fields.attributes.perfmon || tdcs_p->executions_ctl_fields.attributes.debug)
    {
        ctls |= (uint32_t)BIT(VMCS_EXIT_LOAD_PERF_GLBL_CTRL_BIT_LOCATION);
        ctls |= (uint32_t)BIT(VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION);
    }
    else
    {
        ctls &= ~((uint32_t)BIT(VMCS_EXIT_LOAD_PERF_GLBL_CTRL_BIT_LOCATION));
        ctls &= ~((uint32_t)BIT(VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION));
    }

    return ctls;
}

_STATIC_INLINE_ uint32_t calc_l2_vmcs_vm_entry_ctls_init(tdcs_t* tdcs_p)
{
    td_vmcs_values_t* td_vmcs_values_ptr = &get_global_data()->l2_vmcs_values;

    uint32_t ctls = td_vmcs_values_ptr->entry_ctls;

    // Set TD-specific configuration
    if (tdcs_p->executions_ctl_fields.attributes.perfmon || tdcs_p->executions_ctl_fields.attributes.debug)
    {
        ctls |= (uint32_t)BIT(VMCS_ENTRY_LOAD_PERF_GLBL_CTRL_BIT_LOCATION);
    }
    else
    {
        ctls &= ~((uint32_t)BIT(VMCS_ENTRY_LOAD_PERF_GLBL_CTRL_BIT_LOCATION));
    }

    if (tdcs_p->executions_ctl_fields.attributes.pks || tdcs_p->executions_ctl_fields.attributes.debug)
    {
        ctls |= (uint32_t)BIT(VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION);
    }
    else
    {
        ctls &= ~((uint32_t)BIT(VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION));
    }

    return ctls;
}

_STATIC_INLINE_ ia32_vmx_allowed_bits_t calc_virt_ia32_vmx_true_pinbased_ctls(void)
{
    // calculate the msr value based on constants and cpu enumeration gathered by tdh.sys.init
    return calc_allowed32_vmx_ctls(calc_l2_vmcs_pinbased_ctls_init(), PINBASED_CTLS_L1_WR_MASK);
}

_STATIC_INLINE_ ia32_vmx_allowed_bits_t calc_virt_ia32_vmx_true_procbased_ctls(tdcs_t *tdcs_p)
{
    vmx_procbased_ctls_t wr_mask = {.raw = PROCBASED_CTLS_L1_WR_MASK};

    // clear bits that are not allowed to be 1, based on the td configuration
    wr_mask.rdpmc_exiting = tdcs_p->executions_ctl_fields.attributes.perfmon;

    // calculate the msr value based on constants and cpu enumeration gathered by tdh.sys.init
    return calc_allowed32_vmx_ctls(calc_l2_vmcs_procbased_ctls_init(tdcs_p), (uint32_t)wr_mask.raw);
}

_STATIC_INLINE_ ia32_vmx_allowed_bits_t calc_virt_ia32_vmx_procbased_ctls2(tdcs_t *tdcs_ptr)
{
    vmx_procbased_ctls2_t wr_mask =  {.raw = PROCBASED_CTLS2_L1_WR_MASK};

    // clear bits that are not allowed to be 1, based on the td configuration
    wr_mask.en_guest_wait_pause =  tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported;
    wr_mask.en_pconfig = tdcs_ptr->executions_ctl_fields.cpuid_flags.mktme_supported;

    // calculate the msr value based on constants and cpu enumeration gathered by tdh.sys.init
    return calc_allowed32_vmx_ctls(calc_l2_vmcs_procbased_ctls2_init(tdcs_ptr), (uint32_t)wr_mask.raw);
}

_STATIC_INLINE_ uint64_t calc_virt_ia32_vmx_procbased_ctls3(void)
{
    // calculate the msr value based on constants and cpu enumeration gathered by tdh.sys.init
    return calc_allowed1_vmx_ctls(calc_l2_vmcs_procbased_ctls3_init(), PROCBASED_CTLS3_L1_WR_MASK);
}

_STATIC_INLINE_ ia32_vmx_allowed_bits_t calc_virt_ia32_vmx_true_vmexit_ctls(tdcs_t* tdcs_p)
{
    return calc_allowed32_vmx_ctls(calc_l2_vmcs_vm_exit_ctls_init(tdcs_p), EXIT_CTLS_L1_WR_MASK);
}

_STATIC_INLINE_ ia32_vmx_allowed_bits_t calc_virt_ia32_vmx_true_vmentry_ctls(tdcs_t* tdcs_p)
{
    return calc_allowed32_vmx_ctls(calc_l2_vmcs_vm_entry_ctls_init(tdcs_p), ENTRY_CTLS_L1_WR_MASK);
}

_STATIC_INLINE_ ia32_vmx_ept_vpid_cap_t calc_virt_ia32_vmx_ept_vpid_cap(tdcs_t* tdcs_p)
{
    ia32_vmx_ept_vpid_cap_t msr, platform_msr;

    platform_msr.raw = get_global_data()->plt_common_config.ia32_vmx_ept_vpid_cap;

    msr.raw = 0;
    msr.exe_only_supported = 1;
    msr.ps_2m_supported = 1;
    msr.ps_1g_supported = 1;
    msr.advanced_vmexit_info_supported = 1;
    msr.sss_support = ((ia32_xcr0_t)tdcs_p->executions_ctl_fields.xfam).cet_s;
    msr.hlat_prefix_size = platform_msr.hlat_prefix_size;

    return msr;
}

_STATIC_INLINE_ uint64_t calc_virt_ia32_vmx_vmfunc(void)
{
    return 0;
}

_STATIC_INLINE_ void calc_virt_ia32_vmx_cr0_fixed(uint64_t* not_allowed0, uint64_t* allowed1)
{
    // Calculate based on L2 CR0 init value and variable mask, as defined in the L2 VMCS spreadsheet.
    // Note that the init and variable values were checked by TDH.SYS.INIT to be compatible with the platform.
    calc_allowed64_vmx_ctls(GUEST_CR0_L2_INIT, GUEST_CR0_L2_VARIABLE, not_allowed0, allowed1);
}

_STATIC_INLINE_ void calc_virt_ia32_vmx_cr4_fixed(tdcs_t* tdcs_p, uint64_t* not_allowed0, uint64_t* allowed1)
{
    ia32_cr4_t write_mask;

    // The writable bits of CR4 depend on the TD configuration
    write_mask = calc_base_l2_cr4_write_mask(tdcs_p->executions_ctl_fields.attributes,
                                             (ia32_xcr0_t)tdcs_p->executions_ctl_fields.xfam);

    // Calculate based on L2 CR4 init value, as defined in the L2 VMCS spreadsheet, and the write mask.
    // Note that the init value was checked by TDH.SYS.INIT to be compatible with the platform. */
    calc_allowed64_vmx_ctls(GUEST_CR4_L2_INIT, write_mask.raw, not_allowed0, allowed1);
}

/**
 * @brief Initialize the values of the virtual IA32_VMS_* MSRs,
 * which enumerate VMX capabilities to the L1 VMM.
 *
 * @param tdcs_ptr - linear pointer to TDCS
 */
void init_virt_ia32_vmx_msrs(tdcs_t* tdcs_ptr);

// Check the native value of IA32_ARCH_CAPABILITIES MSR
_STATIC_INLINE_ bool_t check_native_ia32_arch_capabilities(ia32_arch_capabilities_t arch_cap)
{
    return (arch_cap.rdcl_no == 1)           &&   // Bit 0
        (arch_cap.irbs_all == 1)             &&   // Bit 1
        (arch_cap.rsba == 0)                 &&   // Bit 2
        (arch_cap.skip_l1dfl_vmentry == 1)   &&   // Bit 3
        (arch_cap.mds_no == 1)               &&   // Bit 5
        (arch_cap.if_pschange_mc_no == 1)    &&   // Bit 6
        (arch_cap.taa_no == 1)               &&   // Bit 8
        (arch_cap.misc_package_ctls == 1)    &&   // Bit 10
        (arch_cap.energy_filtering_ctl == 1) &&   // Bit 11
        (arch_cap.doitm == 1)                &&   // Bit 12
        (arch_cap.sbdr_ssdp_no == 1)         &&   // Bit 13
        (arch_cap.fbsdp_no == 1)             &&   // Bit 14
        (arch_cap.psdp_no == 1)              &&   // Bit 15
        (arch_cap.xapic_disable_status == 1);     // Bit 21
}

/**
 * @brief Initialize the values of the virtual IA32_ARCH_CAPABILITIES MSR
 * @param tdcs_p
 * @param config_flag
 * @param config_val
 *
 * @return
 */
bool_t init_virt_ia32_arch_capabilities(tdcs_t* tdcs_p, bool_t config_flag, uint64_t config_val);

/**
 * @brief Check the value of the virtual IA32_ARCH_CAPABILITIES MSR on import
 *
 * @param tdcs_p
 * @param arch_cap
 *
 * @return
 */
bool_t check_virt_ia32_arch_capabilities(tdcs_t* tdcs_p, ia32_arch_capabilities_t arch_cap);

// Calculate the TDCS' IA32_SPEC_CTRL mask based on DDPD_U support
_STATIC_INLINE_ ia32_spec_ctrl_t calculate_ia32_spec_ctrl_mask(const tdcs_t* tdcs_p)
{
    ia32_spec_ctrl_t mask;

    // Set IA32_SPEC_CTRL_MASK to mask out DDPD_U if not supported
    mask.raw = 0;
    mask.ddpd_u = !tdcs_p->executions_ctl_fields.cpuid_flags.ddpd_supported;

    return mask;
}

// Calculate the virtual value of IA32_SPEC_CTRL MSR based on the real value
_STATIC_INLINE_ uint64_t calculate_virt_ia32_spec_ctrl(const tdcs_t* tdcs_p, uint64_t spec_ctrl)
{
    spec_ctrl &= ~tdcs_p->executions_ctl_fields.ia32_spec_ctrl_mask;
    return spec_ctrl;
}

// Calculate the real value of IA32_SPEC_CTRL MSR based on the virtual value
_STATIC_INLINE_ uint64_t calculate_real_ia32_spec_ctrl(const tdcs_t* tdcs_p, uint64_t value)
{
    ia32_spec_ctrl_t spec_ctrl = { .raw = value };

    if (get_global_data()->ddpd_supported)
    {
        // The CPU supports DDPD_U.  If the TD is not aware of this, force to 1
        if (!tdcs_p->executions_ctl_fields.cpuid_flags.ddpd_supported)
        {
            spec_ctrl.ddpd_u = 1;
        }
    }
    else
    {
        // The CPU does not support DDPD_U
        spec_ctrl.ddpd_u = 0;
    }

    return spec_ctrl.raw;
}

#endif /* SRC_COMMON_HELPERS_VIRT_MSR_HELPERS_H_ */
