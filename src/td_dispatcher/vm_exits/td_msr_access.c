// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_msr_access.c
 * @brief VM Exit handlers for RDMSR/WRMSR exits
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
#include "auto_gen/msr_config_lookup.h"

const static msr_lookup_t* find_msr_entry(uint32_t msr_addr)
{
    for (uint32_t i = 0; i < MAX_NUM_MSR_LOOKUP; i++)
    {
        if ((msr_addr >= msr_lookup[i].start_address) && (msr_addr <= msr_lookup[i].end_address))
        {
            return &msr_lookup[i];
        }
        else if (msr_addr < msr_lookup[i].start_address)
        {
            // No point searching forward, MSR's are ordered by address in the lookup table
            return NULL;
        }
    }

    return NULL;
}

static uint8_t get_msr_bitmap_bit(tdcs_t* tdcs_p, uint32_t msr_addr, bool_t wr)
{
    uint32_t byte_offset, bit_offset;
    byte_offset = (msr_addr & ~HIGH_MSR_MASK) ? MSR_BITMAP_SIZE : 0;
    byte_offset += (msr_addr & HIGH_MSR_MASK) / 8;
    bit_offset = (msr_addr & HIGH_MSR_MASK) % 8;

    uint8_t* byte_addr;

    if (wr)
    {
        byte_addr = &tdcs_p->MSR_BITMAPS[byte_offset + (MSR_BITMAP_SIZE * 2)];
    }
    else
    {
        byte_addr = &tdcs_p->MSR_BITMAPS[byte_offset];
    }

    return (((*byte_addr) & (1 << bit_offset)) >> bit_offset);
}

_STATIC_INLINE_ bool_t is_msr_covered_by_bitmap(uint32_t msr_addr)
{
    uint32_t num_of_msrs_in_bitmap = (MSR_BITMAP_SIZE * 8);
    bool_t msr_in_low_bitmap = (msr_addr < num_of_msrs_in_bitmap);
    bool_t msr_in_high_bitmap = ((msr_addr >= (uint32_t)HIGH_MSR_START) &&
                                    (msr_addr < (uint32_t)(HIGH_MSR_START + num_of_msrs_in_bitmap)));

    return (msr_in_low_bitmap || msr_in_high_bitmap);
}

static void msr_exit_sanity_check(uint32_t msr_addr, bool_t wr, tdcs_t* tdcs_p)
{
    // Sanity check: was there supposed to be a VM exit?
    if (is_msr_covered_by_bitmap(msr_addr) && (get_msr_bitmap_bit(tdcs_p, msr_addr, wr) != 1))
    {
        TDX_ERROR("VM exit wasn't supposed to happen on MSR 0x%llx (WR=%d)\n", msr_addr, wr);
        // Fatal error
        FATAL_ERROR();
    }
}

static void rd_wr_msr_generic_case(vm_exit_basic_reason_e vm_exit_reason, uint32_t msr_addr, bool_t wr,
                                   tdvps_t* tdvps_p, tdcs_t* tdcs_p)
{
    // Access to any MSR not in the bitmap ranges results in a #VE
    if (!is_msr_covered_by_bitmap(msr_addr))
    {
        tdx_inject_ve(vm_exit_reason, 0, tdvps_p, 0, 0);
        return;
    }

    const msr_lookup_t* msr_lookup_ptr = find_msr_entry(msr_addr);

    // Access to any MSR not in lookup table results in a #VE
    // To save space all MSR's with Fixed-1 RD+WR exit which result in #VE aren't stored in the lookup table
    if (msr_lookup_ptr == NULL)
    {
        tdx_inject_ve(vm_exit_reason, 0, tdvps_p, 0, 0);
        return;
    }

    if (msr_lookup_ptr->bit_meaning == MSR_BITMAP_FIXED_01 ||
            (msr_lookup_ptr->bit_meaning == MSR_BITMAP_PERFMON && msr_addr == IA32_MISC_ENABLES_MSR_ADDR))
    {
        // Case of fixed 0 bit was covered by previous check with fatal error
        if (wr)
        {
            tdx_inject_ve(vm_exit_reason, 0, tdvps_p, 0, 0);
            return;
        }
        else
        {
            TDX_ERROR("RDMSR VM exit wasn't supposed to happen on MSR 0x%llx (FIXED 01)\n", msr_addr);
            // Fatal error
            FATAL_ERROR();
        }
    }

    if (msr_lookup_ptr->bit_meaning == MSR_BITMAP_FIXED_10)
    {
        // Case of fixed 0 bit was covered by previous check with fatal error
        if (!wr)
        {
            inject_gp(0);
            return;
        }
        else
        {
            TDX_ERROR("RDMSR VM exit wasn't supposed to happen on MSR 0x%llx (FIXED 10)\n", msr_addr);
            // Fatal error
            FATAL_ERROR();
        }
    }

    // Check for MSRs enabled by XFAM and ATTRIBUTES bits

    if (((msr_lookup_ptr->bit_meaning == MSR_BITMAP_FIXED_1_GP_AT_EXIT)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_PERFMON) && !is_perfmon_supported_in_tdcs(tdcs_p) && (msr_addr != IA32_MISC_ENABLES_MSR_ADDR)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_XFAM_CET) && !is_cet_supported_in_tdvps(tdvps_p)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_XFAM_PT)  && !is_pt_supported_in_tdvps(tdvps_p)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_XFAM_ULI) && !is_uli_supported_in_tdvps(tdvps_p)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_XFAM_LBR) && !is_lbr_supported_in_tdvps(tdvps_p)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_OTHER) && (msr_addr == IA32_UMWAIT_CONTROL) &&
                !is_waitpkg_supported_in_tdcs(tdcs_p)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_OTHER) && (msr_addr == IA32_PERF_CAPABILITIES_MSR_ADDR) &&
                !is_perfmon_supported_in_tdcs(tdcs_p)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_OTHER) && (msr_addr == IA32_PKRS)
                && !is_pks_supported_in_tdcs(tdcs_p)) ||
        ((msr_lookup_ptr->bit_meaning == MSR_BITMAP_OTHER) && (msr_addr == IA32_XFD_MSR_ADDR || msr_addr == IA32_XFD_ERROR_MSR_ADDR) &&
                !is_xfd_supported_in_tdcs(tdcs_p)))
    {
        inject_gp(0);
        return;
    }
    if (msr_lookup_ptr->bit_meaning == MSR_BITMAP_FIXED_1_OTHER)
    {
        if ((msr_addr == IA32_PLATFORM_DCA_CAP) ||  (msr_addr == IA32_CPU_DCA_CAP)
                || (msr_addr == IA32_DCA_CAP))
        {
            if (!is_dca_supported_in_tdcs(tdcs_p))
            {
                inject_gp(0);
                return;
            }
            else
            {
                tdx_inject_ve(vm_exit_reason, 0, tdvps_p, 0, 0);
                return;
            }
        }
        if ((msr_addr == IA32_TME_CAPABILITY_MSR_ADDR) ||  (msr_addr == IA32_TME_ACTIVATE_MSR_ADDR)
                || (msr_addr == IA32_TME_EXCLUDE_MASK) || (msr_addr == IA32_TME_EXCLUDE_BASE))
        {
            if (!is_tme_supported_in_tdcs(tdcs_p))
            {
                inject_gp(0);
                return;
            }
            else
            {
                tdx_inject_ve(vm_exit_reason, 0, tdvps_p, 0, 0);
                return;
            }
        }
        if (msr_addr == IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR)
        {
            if (!is_mktme_supported_in_tdcs(tdcs_p))
            {
                inject_gp(0);
                return;
            }
            else
            {
                tdx_inject_ve(vm_exit_reason, 0, tdvps_p, 0, 0);
                return;
            }
        }
        if (msr_addr == IA32_ARCH_CAPABILITIES_MSR_ADDR)
        {
            TDX_ERROR("WRMSR VM exit wasn't supposed to happen on MSR 0x%llx (FIXED 10)\n", msr_addr);
            // Fatal error
            FATAL_ERROR();
        }
    }

    // Any other case is not covered and not expected
    TDX_ERROR("Unexpected case of MSR 0x%llx (WR=%d)\n", msr_addr, wr);
    // Fatal error
    FATAL_ERROR();
}

static void wrmsr_ia32_xss(tdvps_t* tdvps_p)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    ia32_xcr0_t value;

    value.raw = construct_wrmsr_value(tdvps_p->guest_state.rdx, tdvps_p->guest_state.rax);

    // Check that any bit that is set to 1 is supported by IA32_XSS and XFAM.
    // Note that CPU support has been enumerated on TDHSYSINIT and used to verify XFAM on TDHMNGINIT.

    if ((value.raw & ~((uint64_t)tdx_global_data_ptr->ia32_xss_supported_mask &
            tdvps_p->management.xfam)) != 0)
    {
        inject_gp(0);
        return;
    }

    // All checks passed, emulate the WRMSR instruction
    ia32_wrmsr(IA32_XSS_MSR_ADDR, value.raw);

    get_local_data()->vp_ctx.tdvps->guest_msr_state.ia32_xss = value.raw;
}

static void wrmsr_ia32_debugctl(tdvps_t* tdvps_p)
{
    ia32_debugctl_t old_value;
    ia32_debugctl_t new_value;

    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &old_value.raw);
    new_value.raw = construct_wrmsr_value(tdvps_p->guest_state.rdx, tdvps_p->guest_state.rax);

    if (new_value.reserved_0 || new_value.reserved_1)
    {
        inject_gp(0);
        return;
    }

    // Bits 7:6 must not be set to 01 unless the TD is in debug mode
    if (new_value.tr && !new_value.bts)
    {
        tdx_inject_ve(VMEXIT_REASON_MSR_WRITE, 0, tdvps_p, 0, 0);
        return;
    }

    // Bit 13 (Enable Uncore PMI) must be 0
    new_value.en_uncore_pmi = old_value.en_uncore_pmi;

    // Update TD VMCS with the input value
    ia32_vmwrite(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, new_value.raw);

    ia32_rflags_t rflags;
    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);

    if ((rflags.tf == 1) && (new_value.btf != old_value.btf))
    {
        pending_debug_exception_t pde;
        ia32_vmread(VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE, &pde.raw);

        pde.bs = old_value.btf; // set to 1 if new BTF value is 0 and vice versa
        ia32_vmwrite(VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE, pde.raw);
    }

}

static void rdmsr_ia32_debugctl(tdvps_t* tdvps_p)
{
    // Get the saved guest value
    ia32_debugctl_t ia32_debugctl;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &ia32_debugctl.raw);

    // Bit 13 is virtualized as 0
    ia32_debugctl.en_uncore_pmi = 0;

    // Return the value in EDX:EAX
    tdvps_p->guest_state.rdx = HIGH_32BITS(ia32_debugctl.raw);
    tdvps_p->guest_state.rax = LOW_32BITS(ia32_debugctl.raw);
}

static void rdmsr_ia32_arch_capabilities(tdvps_t* tdvps_p)
{
    tdx_module_global_t * global_data_ptr = get_global_data();

    // Get the value sampled during TDX module init
    ia32_arch_capabilities_t ia32_arch_capabilities_value = global_data_ptr->plt_common_config.ia32_arch_capabilities;

    // Enumerate IA32_TSX_CTRL MSR as non-existent
    ia32_arch_capabilities_value.tsx_ctrl = 0;

    // Virtualize as 0 all IA32_ARCH_CAPABILITIES bits that are known by the TDX module as reserved  
    ia32_arch_capabilities_value.misc_package_ctls = 0;
    ia32_arch_capabilities_value.energy_filtering_ctl = 0;
    ia32_arch_capabilities_value.rsvd = 0;
    
    // Return the value in EDX:EAX
    tdvps_p->guest_state.rdx = HIGH_32BITS(ia32_arch_capabilities_value.raw);
    tdvps_p->guest_state.rax = LOW_32BITS(ia32_arch_capabilities_value.raw);
}

static void rdmsr_ia32_misc_enables(tdvps_t* tdvps_p, tdcs_t* tdcs_p)
{
    if (tdcs_p->executions_ctl_fields.attributes.perfmon)
    {
        // Fatal error
        FATAL_ERROR();
    }
    else
    {
        // Get the current MSR value (the MSR is writable)
        ia32_misc_enable_t ia32_misc_enable;
        ia32_misc_enable.raw = ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR);

        ia32_misc_enable.perfmon_available = 0;
        ia32_misc_enable.pebs_unavailable = 1;

        // Return the value in EDX:EAX
        tdvps_p->guest_state.rdx = HIGH_32BITS(ia32_misc_enable.raw);
        tdvps_p->guest_state.rax = LOW_32BITS(ia32_misc_enable.raw);
    }
}

static void rdmsr_ia32_perf_capabilities(tdvps_t* tdvps_p, tdcs_t* tdcs_p)
{
    if (tdcs_p->executions_ctl_fields.attributes.perfmon)
    {
         if (!((ia32_xcr0_t)tdvps_p->management.xfam).pt)
         {
             // Return the native MSR value, with bit 16 (PEBS_TO_BT) cleared
             ia32_perf_capabilities_t perf_capabilities;
             perf_capabilities.raw = ia32_rdmsr(IA32_PERF_CAPABILITIES_MSR_ADDR);
             perf_capabilities.pebs_output_pt_avail = 0;
             tdvps_p->guest_state.rdx = perf_capabilities.raw >> 32;
             tdvps_p->guest_state.rax = perf_capabilities.raw & BIT_MASK_32BITS;
         }
         else
         {
             FATAL_ERROR();
         }
    }
    else
    {
        UNUSED(tdcs_p);
        // Return the value 0 in EDX:EAX
        tdvps_p->guest_state.rdx = 0ULL;
        tdvps_p->guest_state.rax = 0ULL;
    }
}

void td_wrmsr_exit(void)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    uint32_t msr_addr = (uint32_t)tdvps_p->guest_state.rcx;

    msr_exit_sanity_check(msr_addr, true, tdcs_p);

    switch (msr_addr)
    {
        case IA32_XSS_MSR_ADDR:
            wrmsr_ia32_xss(tdvps_p);
            break;
        case IA32_DEBUGCTL_MSR_ADDR:
            wrmsr_ia32_debugctl(tdvps_p);
            break;
        default:
            rd_wr_msr_generic_case(VMEXIT_REASON_MSR_WRITE, msr_addr, true, tdvps_p, tdcs_p);
            break;
    }
}

void td_rdmsr_exit(void)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    uint32_t msr_addr = (uint32_t)tdvps_p->guest_state.rcx;

    msr_exit_sanity_check(msr_addr, false, tdcs_p);

    switch (msr_addr)
    {
        case IA32_DEBUGCTL_MSR_ADDR:
            rdmsr_ia32_debugctl(tdvps_p);
            break;
        case IA32_MISC_ENABLES_MSR_ADDR:
            rdmsr_ia32_misc_enables(tdvps_p, tdcs_p);
            break;
        case IA32_PERF_CAPABILITIES_MSR_ADDR:
            rdmsr_ia32_perf_capabilities(tdvps_p, tdcs_p);
            break;
        case IA32_ARCH_CAPABILITIES_MSR_ADDR:
            rdmsr_ia32_arch_capabilities(tdvps_p);
            break;
        default:
            rd_wr_msr_generic_case(VMEXIT_REASON_MSR_READ, msr_addr, false, tdvps_p, tdcs_p);
            break;
    }
}
