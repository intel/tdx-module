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
 * @file td_vmexit.c
 * @brief CPUID VMexit handler
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"
#include CPUID_CONFIGURATIONS_HEADER

void td_cpuid_exit(void)
{
    uint32_t       leaf;
    uint32_t       subleaf;
    uint32_t       index;
    uint32_t       cpl;
    cpuid_config_return_values_t return_values;

    cpuid_01_ebx_t cpuid_01_ebx;
    cpuid_01_ecx_t cpuid_01_ecx;
    cpuid_01_edx_t cpuid_01_edx;

    cpuid_04_eax_t       cpuid_04_eax;
    cpuid_04_eax_t       cpuid_04_eax_configured;

    cpuid_07_00_ebx_t cpuid_07_00_ebx;
    cpuid_07_00_ecx_t    cpuid_07_00_ecx;
    cpuid_07_00_edx_t    cpuid_07_00_edx;

    cpuid_80000001_edx_t cpuid_80000001_edx;

    ia32_cr4_t     cr4;

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    vp_ctx_t* vp_ctx = &tdx_local_data_ptr->vp_ctx;

    td_ctls_t td_ctls = vp_ctx->tdcs->executions_ctl_fields.td_ctls;

    bool_t no_special_handling = false;

    leaf = (uint32_t)vp_ctx->tdvps->guest_state.gpr_state.rax;
    subleaf = (uint32_t)vp_ctx->tdvps->guest_state.gpr_state.rcx;

    // CPUID in the range 0x40000000 to 0x4FFFFFFF always inject a #VE
    if ((leaf >= CPUID_RESERVED_START) && (leaf <= CPUID_RESERVED_END))
    {
        tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_NON_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
        return;
    }

    // Check if the guest TD elected to unconditionally inject a #VE for the guest CPL, regardless of leaf/sub-leaf
    cpl = get_guest_td_cpl();
    if (((cpl == 0) && vp_ctx->tdvps->management.cpuid_supervisor_ve) ||
        ((cpl > 0) && vp_ctx->tdvps->management.cpuid_user_ve))
    {
        tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
        return;
    }

    // CPUID leaf number that is higher than the maximum for its range is treated as if it were
    // the maximum in the base range.
    if ((leaf > get_tdcs_cpuid_last_ext_leaf(vp_ctx->tdcs)) ||
        ((leaf > get_tdcs_cpuid_last_base_leaf(vp_ctx->tdcs)) && (leaf < CPUID_FIRST_EXTENDED_LEAF)))
    {
        leaf = get_tdcs_cpuid_last_base_leaf(vp_ctx->tdcs);
    }

    // Get an index to the CPUID tables
    index = get_cpuid_lookup_entry(leaf, subleaf);

    if (index == CPUID_LOOKUP_IDX_NA)
    {
        // CPUID leaf/subleaf was not found in the lookup tables
        if (is_cpuid_fixed0(vp_ctx->tdcs->executions_ctl2_fields.cpuid_fixed0_bitmap, leaf))
        {
            // CPUID leaf/subleaf has a fixed-0 virtual value
            return_values.low = 0;
            return_values.high = 0;
        }
        else if (td_ctls.reduce_ve)
        {
            // In this case, values are all-0
            return_values.low = 0;
            return_values.high = 0;

            // Special handling for leaves that don't exist in the lookup table, if returned values are not 0
            if (0xB == leaf || 0x1F == leaf)
            {
                cpuid_topology_level_t cpuid_1f_ecx;

                // ECX[7:0] reflects the sub-leaf number
                cpuid_1f_ecx.raw = 0;
                cpuid_1f_ecx.level_number = subleaf;
                return_values.ecx = cpuid_1f_ecx.raw;

                // EDX dynamically reflects x2APIC ID
                return_values.edx = vp_ctx->tdcs->x2apic_ids[vp_ctx->tdvps->management.vcpu_index];
            }

            // Don't do the regular special handling, since it relies on the lookup tables
            no_special_handling = true;
        }
        else
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }
    }
    else
    {
        // CPUID leaf/subleaf was found in the lookup tables

        /* The leaf/sub-leaf may not be valid because the TD was imported from a source platform where it was
           not defined.  In this case, the value is 0, however if REDUCE_VE is not set we inject a #VE. */
        if (!td_ctls.reduce_ve && !vp_ctx->tdcs->executions_ctl_fields.cpuid_valid[index])
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        /* Check if the guest TD elected to unconditionally inject a #VE for the guest CPL.
           This is done regardless of REDUCE_VE. */
        if (((cpl == 0) && vp_ctx->tdvps->cpuid_control[index].supervisor_ve) || ((cpl > 0) && vp_ctx->tdvps->cpuid_control[index].user_ve))
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        // Get the CPUID value calculated by TDH_MNG_INIT from TDCS
        return_values = vp_ctx->tdcs->cpuid_values[index];
    }

    if (no_special_handling)
    {
        goto EXIT;
    }

    switch (leaf)
    {
    /*----------------------------------------
       FAULTING_OR_FIXED_LEAF_SUBLEAF Cases
    -----------------------------------------*/

    // CPUID(2) is "FAULTING_OR_FIXED_LEAF_SUBLEAF" depending on VIRT_CPUID2 (and implicitly on REDUCE_VE)
    case 0x2:
        if (!td_ctls.virt_cpuid2)
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        break;

    // CPUID leaves that are "FAULTING_OR_FIXED*_LEAF_SUBLEAF" depending on REDUCE_VE
    case 0x6:
    case 0xC:
    case 0x16:
    case 0x17:
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
    case 0x80000005:
        if (!td_ctls.reduce_ve)
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        break;

     // CPUID(9) is "FAULTING_OR_FIXED*_LEAF_SUBLEAF" depending on REDUCE_VE and DCA
    case 0x9:
        if (!td_ctls.reduce_ve || vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.dca_supported)
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }
        break;

    // CPUID(0xF) is "FAULTING_OR_FIXED*_LEAF_SUBLEAF" depending on REDUCE_VE and RDT_M
    case 0xF:
        if (!td_ctls.reduce_ve || vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.rdt_m_supported)
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        break;

    // CPUID(0x10) is "FAULTING_OR_FIXED*_LEAF_SUBLEAF" depending on REDUCE_VE and RDT_A
    case 0x10:
        if (!td_ctls.reduce_ve || vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.rdt_a_supported)
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        break;

    // CPUID(0x1B) is "FAULTING_OR_FIXED*_LEAF_SUBLEAF" depending on REDUCE_VE and PCONFIG
    case 0x1B:
        if (!td_ctls.reduce_ve || vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.pconfig_supported)
        {
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        break;

    case 0x1:
        cpuid_01_ebx.raw = return_values.ebx;
        cpuid_01_ecx.raw = return_values.ecx;
        cpuid_01_edx.raw = return_values.edx;

        /* Mutable Cases:  Field that depend on controls set by the TD using TDCS.FEATURE_PARAVIRT_CTLS.
           Those cases are reflected by the value of TDCS.CPUID_FLAGS. */

        cpuid_01_ecx.dca            = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.dca_supported;
        cpuid_01_ecx.tsc_deadline   = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.tsc_deadline_supported;
        cpuid_01_ecx.est            = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.est_supported;
        cpuid_01_ecx.tm2            = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.tm2_supported;

        cpuid_01_edx.mce            = !vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.mce_not_supported;
        cpuid_01_edx.mca            = !vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.mca_not_supported;
        cpuid_01_edx.mtrr           = !vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.mtrr_not_supported;
        cpuid_01_edx.acpi             = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.acpi_supported;

        // Dynamic Cases:  Fields marked as STATUS in the CPUID spreadsheet
        if (td_ctls.enum_topology)
        {
            // INITIAL_APIC_ID dynamically reflects x2APIC ID, but is limited to 8 bits
            cpuid_01_ebx.initial_apic_id = (uint8_t)vp_ctx->tdcs->x2apic_ids[vp_ctx->tdvps->management.vcpu_index];
        }
        else
        {
            // INITIAL_APIC_ID dynamically reflects VCPU_INDEX, but is limited to 8 bits
            cpuid_01_ebx.initial_apic_id = vp_ctx->tdvps->management.vcpu_index;
        }

        // OSXSAVE dynamically reflects guest CR4.OSXSAVE
        ia32_vmread(VMX_GUEST_CR4_ENCODE, &cr4.raw);
        cpuid_01_ecx.osxsave = cr4.osxsave;

        return_values.ebx = cpuid_01_ebx.raw;
        return_values.ecx = cpuid_01_ecx.raw;
        return_values.edx = cpuid_01_edx.raw;

        break;

    case 0x4:
        if ((td_ctls.reduce_ve) && (subleaf < NUM_CPUID4_NATIVE))
        {
            /* Use the native CPUID(0x4, *) values sampled at TD initialization time (TDH.MNG.INIT) with
               exception of the following bit ranges:
               - CPUID(0x4, *).EAX[25:14]
               - CPUID(0x4, *).EAX[31:26]
               For those range, use the values configured by the host VMM.

               Note:  For backward-compatibility reasons, the lookup table may contain additional entries that are
                          fixed-0.  Those entries are not configurable and are virtualized as fixed-0.*/
            cpuid_04_eax_configured.raw = return_values.eax;

            return_values = vp_ctx->tdcs->executions_ctl2_fields.cpuid4_native_values[subleaf];
            cpuid_04_eax.raw = return_values.eax;
            cpuid_04_eax.addressable_ids_sharing_this_cache = cpuid_04_eax_configured.addressable_ids_sharing_this_cache;
            cpuid_04_eax.addressable_ids_for_cores_in_package = cpuid_04_eax_configured.addressable_ids_for_cores_in_package;

            return_values.eax = cpuid_04_eax.raw;
        }

        break;

    case 0x7:
        if (subleaf == 0)
        {
            cpuid_07_00_ebx.raw = return_values.ebx;
            cpuid_07_00_ecx.raw = return_values.ecx;
            cpuid_07_00_edx.raw = return_values.edx;

            /* Mutable Cases:  Field that depend on controls set by the TD
               Those cases are reflected by the value of TDCS.CPUID_FLAGS. */

            cpuid_07_00_ebx.rdt_a = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.rdt_a_supported;
            cpuid_07_00_ebx.rdt_m = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.rdt_m_supported;

            cpuid_07_00_ecx.tme   = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.tme_supported;

            cpuid_07_00_edx.pconfig_mktme                  = vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.pconfig_supported;
            cpuid_07_00_edx.ia32_core_capabilities_present = !vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.core_capabilities_not_supported;

            // Dynamic Cases:  Fields marked as STATUS in the CPUID spreadsheet
            if (vp_ctx->tdcs->executions_ctl_fields.cpuid_flags.tsx_supported)
            {
                // TSX is supported for the TD.  Emulate the effect of IA32_TSX_CTRL; if the TSX_CPUID_CLEAR
                // bit is 1, then clear the TSX CPUID bits in the virtual value that is returned to the guest.
                ia32_tsx_ctrl_t tsx_ctrl = { .raw = ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR) };
                if (tsx_ctrl.tsx_cpuid_clear)
                {
                    cpuid_07_00_ebx.hle = 0;
                    cpuid_07_00_ebx.rtm = 0;
                }
            }

            // CPUID(0x7, 0x0).ECX.OSPKE reflects guest CR4.PKE
            ia32_vmread(VMX_GUEST_CR4_ENCODE, &cr4.raw);
            cpuid_07_00_ecx.ospke = cr4.pke;

            return_values.ebx = cpuid_07_00_ebx.raw;
            return_values.ecx = cpuid_07_00_ecx.raw;
            return_values.edx = cpuid_07_00_edx.raw;
        }

        break;
    case 0xD:
        if (subleaf <= 1)
        {
            // EBX value, the maximum size of the XSAVE/XRSTOR save area required
            // by enabled features in XCR0 (sub-leaf 0) or XCR0 || IA32_XSS
            // (sub-leaf 1) is dynamically retrieved from the CPU.
            // This assumes that the TDX-SEAM module has not changed XCR0 or
            // IA32_XSS since VM exit from the guest TD.
            uint32_t eax, ecx, edx;
            ia32_cpuid(leaf, subleaf, &eax, &return_values.ebx, &ecx, &edx);
        }

        break;
    case 0xB:
    case 0x1F:
        if (vp_ctx->tdcs->executions_ctl_fields.td_ctls.enum_topology)
        {
            // EDX dynamically reflects x2APIC ID
            return_values.edx = vp_ctx->tdcs->x2apic_ids[vp_ctx->tdvps->management.vcpu_index];
        }
        else
        {
            // No topology enumeration
            tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, VE_INFO_CONFIG_PARAVIRT, vp_ctx->tdvps, 0, 0);
            return;
        }

        break;
    case 0x80000001:
        // If the guest is running in 64=bit mode, bit SYSCALL_SYSRET is returned as 1.  Otherwise, it's returned as 0
        cpuid_80000001_edx.raw = return_values.edx;
        cpuid_80000001_edx.syscall_sysret = is_td_guest_in_64b_mode();
        return_values.edx = cpuid_80000001_edx.raw;
        break;

    // Other leaves have no XFAM-related configuration
    default:
        break;
    }

EXIT:

    // Write the CPUID return values into the guest TD's GPR image
    vp_ctx->tdvps->guest_state.gpr_state.rax = return_values.eax;
    vp_ctx->tdvps->guest_state.gpr_state.rbx = return_values.ebx;
    vp_ctx->tdvps->guest_state.gpr_state.rcx = return_values.ecx;
    vp_ctx->tdvps->guest_state.gpr_state.rdx = return_values.edx;
}