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
 * @file virt_msr_helpers.c
 * @brief Virtual VMX MSR helper functions
 */

#include "virt_msr_helpers.h"
#include "auto_gen/tdr_tdcs_fields_lookup.h"
#include "x86_defs/vmcs_defs.h"

void init_virt_ia32_vmx_msrs(tdcs_t* tdcs_ptr)
{
    tdcs_ptr->virt_msrs.virt_ia32_vmx_basic               = calc_virt_ia32_vmx_basic();
    tdcs_ptr->virt_msrs.virt_ia32_vmx_misc                = calc_virt_ia32_vmx_misc();

    tdcs_ptr->virt_msrs.virt_ia32_vmx_true_pinbased_ctls  = calc_virt_ia32_vmx_true_pinbased_ctls();
    tdcs_ptr->virt_msrs.virt_ia32_vmx_true_procbased_ctls = calc_virt_ia32_vmx_true_procbased_ctls(tdcs_ptr);
    tdcs_ptr->virt_msrs.virt_ia32_vmx_procbased_ctls2     = calc_virt_ia32_vmx_procbased_ctls2(tdcs_ptr);
    tdcs_ptr->virt_msrs.virt_ia32_vmx_procbased_ctls3     = calc_virt_ia32_vmx_procbased_ctls3();
    tdcs_ptr->virt_msrs.virt_ia32_vmx_true_exit_ctls      = calc_virt_ia32_vmx_true_vmexit_ctls(tdcs_ptr);
    tdcs_ptr->virt_msrs.virt_ia32_vmx_true_entry_ctls     = calc_virt_ia32_vmx_true_vmentry_ctls(tdcs_ptr);

    tdcs_ptr->virt_msrs.virt_ia32_vmx_ept_vpid_cap        = calc_virt_ia32_vmx_ept_vpid_cap(tdcs_ptr);
    tdcs_ptr->virt_msrs.virt_ia32_vmx_vmfunc              = calc_virt_ia32_vmx_vmfunc();

    calc_virt_ia32_vmx_cr0_fixed(&tdcs_ptr->virt_msrs.virt_ia32_vmx_cr0_fixed0.raw,
                                 &tdcs_ptr->virt_msrs.virt_ia32_vmx_cr0_fixed1.raw);
    calc_virt_ia32_vmx_cr4_fixed(tdcs_ptr, &tdcs_ptr->virt_msrs.virt_ia32_vmx_cr4_fixed0.raw,
                                           &tdcs_ptr->virt_msrs.virt_ia32_vmx_cr4_fixed1.raw);
}

// Initialize the values of the virtual IA32_ARCH_CAPABILITIES MSR
bool_t init_virt_ia32_arch_capabilities(tdcs_t* tdcs_p, bool_t config_flag, uint64_t config_val)
{
    ia32_arch_capabilities_t config_value = { .raw = config_val };
    ia32_arch_capabilities_t arch_cap_value;

    if (!config_flag && (config_value.raw != 0))
    {
        return false;
    }

    // Get the value sampled during TDX module init
    arch_cap_value = get_global_data()->plt_common_config.ia32_arch_capabilities;

    // Bit 4 (SSB_NO) is defined as ALLOW_DIRECT.  If not configured as 1, force to 0
    if (!config_value.ssb_no)
    {
        arch_cap_value.ssb_no = 0;
    }
    else
    {
        config_value.ssb_no = 0;   // Clear for sanity check at the end
    }

    // Bit 7 (TSX_CTRL) is forced to 0 if TSX is not supported
    if (!tdcs_p->executions_ctl_fields.cpuid_flags.tsx_supported)
    {
        arch_cap_value.tsx_ctrl = 0;
    }

    // Fixed-0 bits
    arch_cap_value.mcu_ctls = 0;              // Bit 9
    arch_cap_value.misc_package_ctls = 0;     // Bit 10
    arch_cap_value.energy_filtering_ctl = 0;  // Bit 11
    arch_cap_value.reserved_1 = 0;            // Bit 16
    arch_cap_value.fb_clear = 0;              // Bit 17
    arch_cap_value.fb_clear_ctrl = 0;         // Bit 18

    // Bit 19 (RRSBA) is defined as FORCE_DIRECT.  If configured as 1, force to 1
    if (config_value.rrsba)
    {
        arch_cap_value.rrsba = 1;
        config_value.rrsba = 0;
    }

    // Bit 20 (BHI_NO) is defined as ALLOW_DIRECT.  If not configured as 1, force to 0
    if (!config_value.bhi_no)
    {
        arch_cap_value.bhi_no = 0;
    }
    else
    {
        config_value.bhi_no = 0;   // Clear for sanity check at the end
    }

    // Fixed-0 bits
    arch_cap_value.xapic_disable_status = 0;  // Bit 21
    arch_cap_value.reserved_2 = 0;            // Bit 22
    arch_cap_value.overclocking_status = 0;   // Bit 23

    // Bit 24 (PBRSB_NO) is defined as ALLOW_DIRECT.  If not configured as 1, force to 0
    if (!config_value.pbrsb_no)
    {
        arch_cap_value.pbrsb_no = 0;
    }
    else
    {
        config_value.pbrsb_no = 0;   // Clear for sanity check at the end
    }

    // Fixed-0 bits
    arch_cap_value.reserved_3 = 0;        // Bits 63:25

    // At this point there should not be any configurable bits left
    if (config_value.raw != 0)
    {
        return false;
    }

    tdcs_p->virt_msrs.virt_ia32_arch_capabilities = arch_cap_value.raw;

    return true;
}

// Check the value of the virtual IA32_ARCH_CAPABILITIES MSR on import
bool_t check_virt_ia32_arch_capabilities(tdcs_t* tdcs_p, ia32_arch_capabilities_t arch_cap)
{
    ia32_arch_capabilities_t  native_value;

    // Check the fixed bits
    if ((arch_cap.rdcl_no != 1)              ||   // Bit 0
        (arch_cap.irbs_all != 1)             ||   // Bit 1
        (arch_cap.rsba != 0)                 ||   // Bit 2
        (arch_cap.skip_l1dfl_vmentry != 1)   ||   // Bit 3
        (arch_cap.mds_no != 1)               ||   // Bit 5
        (arch_cap.if_pschange_mc_no != 1)    ||   // Bit 6
        (arch_cap.taa_no != 1)               ||   // Bit 8
        (arch_cap.mcu_ctls != 0)             ||   // Bit 9
        (arch_cap.misc_package_ctls != 0)    ||   // Bit 10
        (arch_cap.energy_filtering_ctl != 0) ||   // Bit 11
        (arch_cap.doitm != 1)                ||   // Bit 12
        (arch_cap.sbdr_ssdp_no != 1)         ||   // Bit 13
        (arch_cap.fbsdp_no != 1)             ||   // Bit 14
        (arch_cap.psdp_no != 1)              ||   // Bit 15
        (arch_cap.reserved_1 != 0)           ||   // Bit 16
        (arch_cap.fb_clear != 0)             ||   // Bit 17
        (arch_cap.fb_clear_ctrl != 0)        ||   // Bit 18
        (arch_cap.xapic_disable_status != 0) ||   // Bit 21
        (arch_cap.reserved_2 != 0)           ||   // Bit 22
        (arch_cap.overclocking_status != 0)  ||   // Bit 23
        (arch_cap.reserved_3 != 0))           // Bits 63:25
    {
        return false;
    }

    // Get the value sampled during TDX module init
    native_value = get_global_data()->plt_common_config.ia32_arch_capabilities;

    // Check directly configurable bits vs. CPU native values

    // Bit 4 (SSB_NO) is defined as ALLOW_DIRECT.  If value is 1, must be natively 1.
    if (arch_cap.ssb_no && !native_value.ssb_no)
    {
        return false;
    }

    // Bit 19 (RRSBA) is defined as FORCE_DIRECT.  If value is 0, must be natively 0.
    if (!arch_cap.rrsba && native_value.rrsba)
    {
        return false;
    }

    // Bit 20 (BHI_NO) is defined as ALLOW_DIRECT.  If value is 1, must be natively 1.
    if (arch_cap.bhi_no && !native_value.bhi_no)
    {
        return false;
    }

    // Bit 24 (PBRSB_NO) is defined as ALLOW_DIRECT.  If value is 1, must be natively 1.
    if (arch_cap.pbrsb_no && !native_value.pbrsb_no)
    {
        return false;
    }

    // TSX is supported, then Bit 7 (TSX_CTRL) must be 1.
    // The following assertion ensures that virtual CPUID values are imported before virtual IA32_ARCH_CAPABILITIES, thus
    // at this point CPUID_FLAGS.TSX_SUPPORT has been calculated.
    tdx_debug_assert(MD_TDCS_VIRT_MSR_VALUES_CLASS_CODE > MD_TDCS_CPUID_CLASS_CODE);

    if (!arch_cap.tsx_ctrl && tdcs_p->executions_ctl_fields.cpuid_flags.tsx_supported)
    {
        return false;
    }

    return true;
}

