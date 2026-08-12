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
#include TDX_ERROR_CODES_DEFS_HEADER
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"
#include MSR_CONFIG_LOOKUP_HEADER

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

_STATIC_INLINE_ bool_t is_msr_covered_by_bitmap(uint32_t msr_addr)
{
    uint32_t num_of_msrs_in_bitmap = (MSR_BITMAP_SIZE * 8);
    bool_t msr_in_low_bitmap = (msr_addr < num_of_msrs_in_bitmap);
    bool_t msr_in_high_bitmap = ((msr_addr >= HIGH_MSR_START) && (msr_addr < HIGH_MSR_START + num_of_msrs_in_bitmap));

    return (msr_in_low_bitmap || msr_in_high_bitmap);
}

static uint8_t get_msr_bitmap_bit(uint8_t* msr_bitmaps_page, uint32_t msr_addr, bool_t wr)
{
    uint32_t byte_offset, bit_offset;
    byte_offset = (msr_addr & ~HIGH_MSR_MASK) ? MSR_BITMAP_SIZE : 0;
    byte_offset += (msr_addr & HIGH_MSR_MASK) / 8;
    bit_offset = (msr_addr & HIGH_MSR_MASK) % 8;

    uint8_t* byte_addr;

    if (wr)
    {
        byte_addr = &msr_bitmaps_page[byte_offset + (MSR_BITMAP_SIZE * 2)];
    }
    else
    {
        byte_addr = &msr_bitmaps_page[byte_offset];
    }

    return (((*byte_addr) & (1 << bit_offset)) >> bit_offset);
}

static td_msr_access_status_t rd_wr_msr_generic_checks(uint32_t msr_addr, bool_t wr, tdvps_t* tdvps_p, uint16_t vm_id)
{
    // Access to any MSR not in the bitmap ranges results in a #VE
    if (!is_msr_covered_by_bitmap(msr_addr))
    {
        return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_NON_CONFIG_PARAVIRT);
    }

    lfence();

    if ((vm_id > 0) &&
        get_msr_bitmap_bit((uint8_t*)tdvps_p->l2_vm_ctrl[vm_id-1].l2_shadow_msr_bitmaps, msr_addr, wr))
    {
        return TD_MSR_ACCESS_L2_TO_L1_EXIT;
    }

    return TD_MSR_ACCESS_SUCCESS;
}

static uint16_t rd_wr_msr_generic_case(uint32_t msr_addr, bool_t wr, tdcs_t* tdcs_p, bool_t is_write)
{
    const msr_lookup_t* msr_lookup_ptr = find_msr_entry(msr_addr);

    // Access to any MSR not in lookup table results in a #VE
    // To save space all MSR's with Fixed-1 RD+WR exit which result in #VE aren't stored in the lookup table
    if (msr_lookup_ptr == NULL)
    {
        return tdcs_p->executions_ctl_fields.td_ctls.reduce_ve?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }

    msr_bitmap_action action = wr ? msr_lookup_ptr->wr_action : msr_lookup_ptr->rd_action;
    msr_bitmap_bit_type bit_type = wr ? msr_lookup_ptr->wr_bit_meaning : msr_lookup_ptr->rd_bit_meaning;

    IF_RARE ((bit_type == MSR_BITMAP_FIXED_0) || is_msr_dynamic_bit_cleared(tdcs_p, msr_addr, bit_type))
    {
        TDX_ERROR("VM exit (wr = %d) wasn't supposed to happen on MSR 0x%llx (FIXED/DYNAMIC 0)\n", wr, msr_addr);
        tdx_module_local_t* local_data = get_local_data();
        // Fatal error
        extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(local_data->vp_ctx.tdr_pa.raw,
                                                                                                   local_data->current_td_vm_id,
                                                                                                   (uint32_t)(is_write ? VMEXIT_REASON_MSR_WRITE : VMEXIT_REASON_MSR_READ),
                                                                                                   msr_addr);
        fatal_error(FATAL_ERROR_ID_103, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
    }

    if (action == MSR_ACTION_VE)
    {
        return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_NON_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP)
    {
        return TD_MSR_ACCESS_GP;
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_REDUCED_VE)
    {
        return tdcs_p->executions_ctl_fields.td_ctls.reduce_ve ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_EST)
    {
        return !tdcs_p->executions_ctl_fields.cpuid_flags.est_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_TM2)
    {
        return !tdcs_p->executions_ctl_fields.cpuid_flags.tm2_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_DCA)
    {
        return !is_dca_supported_in_tdcs(tdcs_p) ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_TSC_DEADLINE)
    {
        return !is_tsc_deadline_supported_in_tdcs(tdcs_p) ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_MTRR)
    {
        return tdcs_p->executions_ctl_fields.cpuid_flags.mtrr_not_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_MCA)
    {
        return tdcs_p->executions_ctl_fields.cpuid_flags.mca_not_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_ACPI)
    {
        return !tdcs_p->executions_ctl_fields.cpuid_flags.acpi_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_RDT_M)
    {
        return !tdcs_p->executions_ctl_fields.cpuid_flags.rdt_m_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_RDT_A)
    {
        return !tdcs_p->executions_ctl_fields.cpuid_flags.rdt_a_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_TME)
    {
        return !is_tme_supported_in_tdcs(tdcs_p) ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_PCONFIG)
    {
        return !is_pconfig_supported_in_tdcs(tdcs_p) ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if (action == MSR_ACTION_GP_OR_VE_BY_CORE_CAPABILITIES)
    {
        return tdcs_p->executions_ctl_fields.cpuid_flags.core_capabilities_not_supported ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }
    else if ((action == MSR_ACTION_GP_OR_VE) || (action == MSR_ACTION_OTHER))
    {
        return tdcs_p->executions_ctl_fields.td_ctls.reduce_ve ?
            TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
    }

    // Any other case is not covered and not expected
    TDX_ERROR("Unexpected case of MSR 0x%llx (WR=%d) (action=%d)\n", msr_addr, wr, action);
    tdx_module_local_t* local_data = get_local_data();
    // Fatal error
    extended_fatal_info_t extended_fatal_info = prepare_extended_fatal_info_unexpected_vm_exit(local_data->vp_ctx.tdr_pa.raw,
                                                                                               local_data->current_td_vm_id,
                                                                                               (uint32_t)(is_write ? VMEXIT_REASON_MSR_WRITE : VMEXIT_REASON_MSR_READ),
                                                                                               msr_addr);
    fatal_error(FATAL_ERROR_ID_22, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);

    return TD_MSR_ACCESS_SUCCESS; // No real success, can't reach here due to FATAL_ERROR above
}

static td_msr_access_status_t wrmsr_ia32_xss(tdvps_t* tdvps_p, tdcs_t* tdcs_p)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    ia32_xcr0_t value;

    value.raw = construct_wrmsr_value(tdvps_p->guest_state.gpr_state.rdx, tdvps_p->guest_state.gpr_state.rax);

    // Check that any bit that is set to 1 is supported by IA32_XSS and XFAM.  Note that CPU
    // support has been enumerated on TDH_SYS_INIT and used to verify XFAM on TDH_MNG_INIT.
    // Note that CPU support has been enumerated on TDHSYSINIT and used to verify XFAM on TDHMNGINIT.

    if ((value.raw & ~((uint64_t)tdx_global_data_ptr->ia32_xss_supported_mask & tdcs_p->executions_ctl_fields.xfam)) != 0)
    {
        return TD_MSR_ACCESS_GP;
    }

    // All checks passed, emulate the WRMSR instruction
    ia32_wrmsr(IA32_XSS_MSR_ADDR, value.raw);

    get_local_data()->vp_ctx.tdvps->guest_msr_state.ia32_xss = value.raw;

    return TD_MSR_ACCESS_SUCCESS;
}

static td_msr_access_status_t wrmsr_ia32_debugctl(tdvps_t* tdvps_p)
{
    ia32_debugctl_t old_value;
    ia32_debugctl_t new_value;

    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &old_value.raw);
    new_value.raw = construct_wrmsr_value(tdvps_p->guest_state.gpr_state.rdx, tdvps_p->guest_state.gpr_state.rax);

    if (new_value.reserved_0 || new_value.reserved_1)
    {
        return TD_MSR_ACCESS_GP;
    }

    // Bits 7:6 must not be set to 01 unless the TD is in debug mode
    if (new_value.tr && !new_value.bts)
    {
        return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_UNSUPPORTED_FEATURE);
    }

    // Bit 13 (Enable Uncore PMI) must be 0
    new_value.en_uncore_pmi = old_value.en_uncore_pmi;

    /* Bit 14 (Freeze while SMM) may be set only if virtual IA32_PERF_CAPABILITIES[12] (FREEZE_WHILE_SMM_SUPPORTED)
           is 1.  Since we check the h/w value of this bit to be 1, the virtual value actually equals ATTRIBUTES.PERFMON. */
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;
    if ((new_value.frz_while_smm) && (!tdcs_p->executions_ctl_fields.attributes.perfmon))
    {
        return TD_MSR_ACCESS_GP;
    }

    // Bit 15 (RTM) may be set only if TSX is enabled
    if ((new_value.rtm_debug) && (!tdcs_p->executions_ctl_fields.cpuid_flags.tsx_supported))
    {
        return TD_MSR_ACCESS_GP;
    }

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

    return TD_MSR_ACCESS_SUCCESS;
}

static td_msr_access_status_t wrmsr_ia32_efer(tdvps_t* tdvps_p)
{
    ia32_efer_t old_value;
    ia32_efer_t new_value;

    ia32_vmread(VMX_GUEST_IA32_EFER_FULL_ENCODE, &old_value.raw);
    new_value.raw = construct_wrmsr_value(tdvps_p->guest_state.gpr_state.rdx, tdvps_p->guest_state.gpr_state.rax);

    // The LMA bit is read-only, use the old value
    new_value.lma = old_value.lma;

    // We allow only the SCE bit to be changed.
    // For the comparison below, set the old value of this bit to the new value.
    old_value.syscall_enabled = new_value.syscall_enabled;

    if (tdvps_p->management.curr_vm != 0)
    {
        /* For L2 VMs, we allow the LME bit to be changed.
         * For the comparison below, set the old value of this bit to the new values.
         * We don't allow NXE bit to be changed.
         */
        old_value.lme = new_value.lme;
    }

    // If any other bit has changed, this is a non-architectural exception
    // (for L1: #VE, for L2: either #VE or L2-->L1 exit)
    if (old_value.raw != new_value.raw)
    {
        return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_UNSUPPORTED_FEATURE);
    }

    ia32_vmwrite(VMX_GUEST_IA32_EFER_FULL_ENCODE, new_value.raw);

    return TD_MSR_ACCESS_SUCCESS;
}

uint16_t wrmsr_ia32_misc_enable(tdvps_t* tdvps_p, tdcs_t* tdcs_p, uint64_t wr_value)
{
    ia32_misc_enable_t misc_enable;

    // Bits that cause #GP(0) if not 0 (see the ABI FAS)
#define GP_ON_NON_0_MASK            0xFFFFFFFFFF3AE776

    misc_enable.raw = wr_value;

    if (misc_enable.raw & GP_ON_NON_0_MASK)
    {
        return TD_MSR_ACCESS_GP;
    }

    ia32_misc_enable_t guest_misc_enable = { .raw = tdvps_p->guest_msr_state.ia32_misc_enable };

    misc_enable.perfmon_available = guest_misc_enable.perfmon_available;  // Ignore wr_value
    misc_enable.bts_unavailable = guest_misc_enable.bts_unavailable;      // Ignore wr_value
    misc_enable.pebs_unavailable = guest_misc_enable.pebs_unavailable;    // Ignore wr_value

    if (misc_enable.est && !tdcs_p->executions_ctl_fields.cpuid_flags.est_supported)
    {
        return TD_MSR_ACCESS_GP;
    }

    if (misc_enable.enable_monitor_fsm != guest_misc_enable.enable_monitor_fsm)
    {
        return construct_msr_status_with_ve_category(CR_ACCESS_NON_ARCH, VE_INFO_UNSUPPORTED_FEATURE);
    }

    if (misc_enable.limit_cpuid_maxval)
    {
        return construct_msr_status_with_ve_category(CR_ACCESS_NON_ARCH, VE_INFO_UNSUPPORTED_FEATURE);
    }

    if (misc_enable.tpr_message_disable && !tdcs_p->executions_ctl_fields.cpuid_flags.xtpr_update_supported)
    {
        return TD_MSR_ACCESS_GP;
    }

    tdvps_p->guest_msr_state.ia32_misc_enable = misc_enable.raw;

    return TD_MSR_ACCESS_SUCCESS;
}

_STATIC_INLINE_ void rdmsr_set_value_in_tdvps(tdvps_t* tdvps_p, uint64_t value)
{
    tdvps_p->guest_state.gpr_state.rdx = HIGH_32BITS(value);
    tdvps_p->guest_state.gpr_state.rax = LOW_32BITS(value);
}

/* Write an IA32_PERFEVTSEL MSR while handling event filtering
   Assumes either PERFMON is disabled or event filter is required (TDCS.EVENT_FILTERS_NUM > 0),
   otherwise no VM exit is expected.
*/
_STATIC_INLINE_ td_msr_access_status_t wrmsr_ia32_perfevtsel(tdcs_t *tdcs_p, tdvps_t *tdvps_p, uint32_t pmc_index, uint32_t msr_addr)
{
    tdx_sanity_check(8 == MAX_GP_CTRS, FATAL_ERROR_ID_274, 0);

    if (!tdcs_p->executions_ctl_fields.attributes.perfmon)
    {
        return TD_MSR_ACCESS_GP;
    }

    // VM exit should only happen if PERFMON is 0 or EVENT_FILTERS_NUM is not 0
    if (tdcs_p->executions_ctl2_fields.event_filters_num == 0)
    {
        extended_fatal_info_t extended_fatal_info =
                prepare_extended_fatal_info_unexpected_vm_exit(get_local_data()->vp_ctx.tdr_pa.raw,
                                                               get_local_data()->current_td_vm_id,
                                                               VMEXIT_REASON_MSR_WRITE,
                                                               msr_addr);

        fatal_error(FATAL_ERROR_ID_276, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
    }

    uint64_t msr_value = construct_wrmsr_value(tdvps_p->guest_state.gpr_state.rdx, tdvps_p->guest_state.gpr_state.rax);
    ia32_perfevtsel_t perfevtsel_value = { .raw = msr_value };
    ia32_perfevtsel_t perfevtsel_shadow = { .raw = msr_value };

    if (perfevtsel_value.en && !is_event_allowed(tdcs_p, perfevtsel_value.event_id, (uint16_t)tdcs_p->executions_ctl2_fields.event_filters_num))
    {
        // The requested event is not allowed

        /* For the value written to the MSR, clear the ENABLE bit (22) to 0 but keep the other bits.
           This ensures that the IA32_PERF_GLOBAL_INUSE MSR returns the in-use status bit for this
           counter as if it is being used, since the bit is set if and only if IA32_PERFEVTSELx
           EVENT_SELECT bits (7:0) are not 0. */
        perfevtsel_value.en = 0;

        // For the shadow in TDVPS, mark the event as forbidden
        perfevtsel_shadow.forbidden = 1;

        // Increment the filtered events counter for the current VM using an atomic operationt
        (void)_lock_xadd_64b(&tdcs_p->executions_ctl2_fields.filtered_events_count[tdvps_p->management.curr_vm], 1);
    }

    // Write the MSR, update the shadow in TDVPS only if write succeeded
    uint64_t msr_status = ia32_safe_wrmsr(msr_addr, perfevtsel_value.raw);
    if (0 == msr_status) // #GP occured
    {
        return TD_MSR_ACCESS_GP;
    }

    tdvps_p->guest_msr_state.ia32_pmc_gp_cfg_ax[pmc_index] = perfevtsel_shadow.raw;

    return TD_MSR_ACCESS_SUCCESS;
}

/* Read an IA32_PERFEVTSEL MSR while handling event filtering
   Assumes either PERFMON is disabled or event filter is required (TDCS.EVENT_FILTERS_NUM > 0),
   otherwise no VM exit is expected.
*/
_STATIC_INLINE_ td_msr_access_status_t rdmsr_ia32_perfevtsel(tdcs_t *tdcs_p, tdvps_t *tdvps_p, uint32_t pmc_index, uint32_t msr_addr)
{
    tdx_sanity_check(8 == MAX_GP_CTRS, FATAL_ERROR_ID_277, 0);

    if (!tdcs_p->executions_ctl_fields.attributes.perfmon)
    {
        return TD_MSR_ACCESS_GP;
    }

    // VM exit should only happen if PERFMON is 0 or EVENT_FILTERS_NUM is not 0
    if (tdcs_p->executions_ctl2_fields.event_filters_num == 0)
    {
        extended_fatal_info_t extended_fatal_info =
                prepare_extended_fatal_info_unexpected_vm_exit(get_local_data()->vp_ctx.tdr_pa.raw,
                                                               get_local_data()->current_td_vm_id,
                                                               VMEXIT_REASON_MSR_READ,
                                                               msr_addr);

        fatal_error(FATAL_ERROR_ID_279, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
    }

    ia32_perfevtsel_t perfevtsel_value = { .raw = tdvps_p->guest_msr_state.ia32_pmc_gp_cfg_ax[pmc_index] };
    perfevtsel_value.forbidden = 0;

    rdmsr_set_value_in_tdvps(tdvps_p, perfevtsel_value.raw);

    return TD_MSR_ACCESS_SUCCESS;
}

static td_msr_access_status_t rdmsr_ia32_debugctl(tdvps_t* tdvps_p)
{
    // Get the saved guest value
    ia32_debugctl_t ia32_debugctl;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &ia32_debugctl.raw);

    // Bit 13 is virtualized as 0
    ia32_debugctl.en_uncore_pmi = 0;

    // Return the value in EDX:EAX
    rdmsr_set_value_in_tdvps(tdvps_p, ia32_debugctl.raw);

    return TD_MSR_ACCESS_SUCCESS;
}

static td_msr_access_status_t rdmsr_ia32_arch_capabilities(tdvps_t* tdvps_p, tdcs_t* tdcs_p)
{
    if (is_not_gnr_a0_stepping())
    {
        // Return the value calculated on TDH.MNG.INIT or TDH.IMPORT.STATE.IMMUTABLE in EDX:EAX
    rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_arch_capabilities);
    }
    else
    {

        // Get the value sampled during TDX module init
        ia32_arch_capabilities_t ia32_arch_capabilities = get_global_data()->plt_common_config.ia32_arch_capabilities;

        // Force the enumeration of IA32_TSX_CTRL MSR existence to 0 if TSX is not supported
        if (!tdcs_p->executions_ctl_fields.cpuid_flags.tsx_supported)
        {
            ia32_arch_capabilities.tsx_ctrl = 0;
        }

        // Enumerate IA32_MISC_PACKAGE_CTLS as non-existent
        ia32_arch_capabilities.misc_package_ctls = 0;
        ia32_arch_capabilities.energy_filtering_ctl = 0;

        // Enumerate IA32_UARCH_MISC_CTL as non-existent
        ia32_arch_capabilities.doitm = 0;

        ia32_arch_capabilities.fb_clear = 0;
        ia32_arch_capabilities.fb_clear_ctrl = 0;
        ia32_arch_capabilities.rrsba = 1;
        ia32_arch_capabilities.bhi_no = 0;
        ia32_arch_capabilities.xapic_disable_status = 0;
        ia32_arch_capabilities.overclocking_status = 0;
        ia32_arch_capabilities.pbrsb_no = 0;

        // Clear the reserved bits
        ia32_arch_capabilities.reserved_1 = 0;
        ia32_arch_capabilities.reserved_2 = 0;
        ia32_arch_capabilities.reserved_3 = 0;

        // Return the value in EDX:EAX
        tdvps_p->guest_state.gpr_state.rdx = HIGH_32BITS(ia32_arch_capabilities.raw);
        tdvps_p->guest_state.gpr_state.rax = LOW_32BITS(ia32_arch_capabilities.raw);
    }

    return TD_MSR_ACCESS_SUCCESS;
}

static td_msr_access_status_t rdmsr_ia32_misc_enables(tdvps_t* tdvps_p)
{
    // Read the value from TDVPS, not from the h/w
    rdmsr_set_value_in_tdvps(tdvps_p, tdvps_p->guest_msr_state.ia32_misc_enable);

    return TD_MSR_ACCESS_SUCCESS;
}

static td_msr_access_status_t rdmsr_ia32_perf_capabilities(tdvps_t* tdvps_p, tdcs_t* tdcs_p)
{
    if (tdcs_p->executions_ctl_fields.attributes.perfmon)
    {
         if (!((ia32_xcr0_t)tdcs_p->executions_ctl_fields.xfam).pt)
         {
             // Return the native MSR value, with bit 16 (PEBS_TO_BT) cleared
             ia32_perf_capabilities_t perf_capabilities;
             perf_capabilities.raw = get_global_data()->plt_common_config.ia32_perf_capabilities.raw;
             perf_capabilities.pebs_output_pt_avail = 0;

             rdmsr_set_value_in_tdvps(tdvps_p, perf_capabilities.raw);
         }
         else
         {
             extended_fatal_info_t extended_fatal_info =
                     prepare_extended_fatal_info_unexpected_vm_exit(get_local_data()->vp_ctx.tdr_pa.raw,
                                                                    get_local_data()->current_td_vm_id,
                                                                    VMEXIT_REASON_MSR_READ,
                                                                    IA32_PERF_CAPABILITIES_MSR_ADDR);

             fatal_error(FATAL_ERROR_ID_104, FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO, &extended_fatal_info);
         }
    }
    else
    {
        UNUSED(tdcs_p);
        // Return the value 0 in EDX:EAX
        rdmsr_set_value_in_tdvps(tdvps_p, 0);
    }

    return TD_MSR_ACCESS_SUCCESS;
}

#define INVALID_PERFMON_MSR_INDEX (-1)

static uint32_t get_pmc_index_given_ia32_perfevtsel_index(const uint32_t msr_addr)
{
    uint32_t invalid_idx = (uint32_t)INVALID_PERFMON_MSR_INDEX;

    // Legacy range
    if ((msr_addr >= IA32_PERFEVTSEL0_MSR_ADDR) && (msr_addr < IA32_PERFEVTSEL0_MSR_ADDR + MAX_GP_CTRS))
    {
        return msr_addr - IA32_PERFEVTSEL0_MSR_ADDR;
    }
    // New perfmon range
    else if (get_global_data()->perfmon_new_msrs && (msr_addr >= IA32_A_PMC_BASE))
    {
        // Get offset from start of PMC range
        uint32_t msr_idx = msr_addr - IA32_A_PMC_BASE;

        // Check if the index is indeed of an IA32_PERFEVTSEL MSR
        if ((msr_idx % PERFMON_MSR_INDEX_DELTA) != IA32_PERFEVTSEL_OFFSET)
        {
            return invalid_idx;
        }

        // Get the perfmon counter index
        msr_idx /= PERFMON_MSR_INDEX_DELTA;

        if (msr_idx >= MAX_GP_CTRS)
        {
            return invalid_idx;
        }

        // Index is in the new Perfmon range
        return msr_idx;
    }

    // MSR_ADDR is not an ia32_perfevtsel_index
    return invalid_idx;
}

uint16_t td_wrmsr_exit(void)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    uint32_t msr_addr = (uint32_t)tdvps_p->guest_state.gpr_state.rcx;
    uint16_t vm_id = tdvps_p->management.curr_vm;

    uint16_t status = TD_MSR_ACCESS_SUCCESS;

    status = (uint16_t)rd_wr_msr_generic_checks(msr_addr, true, tdvps_p, vm_id);

    if (status != TD_MSR_ACCESS_SUCCESS)
    {
        return status;
    }

    uint64_t msr_value = construct_wrmsr_value(tdvps_p->guest_state.gpr_state.rdx, tdvps_p->guest_state.gpr_state.rax);

    // IA32_PERFEVTSEL MSRs have special handling since they can be accessed via two aliases
    uint32_t pmc_index = get_pmc_index_given_ia32_perfevtsel_index(msr_addr);
    lfence();
    if (pmc_index != (uint32_t)INVALID_PERFMON_MSR_INDEX)
    {
        // msr_index is a valid IA32_PEREVTSEL MSR
        return status = (uint16_t)wrmsr_ia32_perfevtsel(tdcs_p, tdvps_p, pmc_index, msr_addr);
    }

    switch (msr_addr)
    {
        case IA32_SMI_COUNT_MSR_ADDR:
            if (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                // Write the value to TDVPS.  The h/w is not written.
                tdvps_p->guest_msr_state.msr_smi_count = msr_value;
            }
            else
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;

        case IA32_BIOS_UPDT_TRIG_MSR_ADDR:
        case IA32_BIOS_SIGN_ID_MSR_ADDR:
            if (!tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;

        case IA32_FEATURE_ENABLES_MSR_ADDR:
            if (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                if (msr_value != 0)
                {
                    return TD_MSR_ACCESS_GP;
                }
            }
            else
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;

        case IA32_MISC_ENABLES_MSR_ADDR:
            if (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                // Check and write the value to TDVPS. The h/w is not written.
                status = wrmsr_ia32_misc_enable(tdvps_p, tdcs_p, msr_value);
            }
            else
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;
        case IA32_XSS_MSR_ADDR:
            status = (uint16_t)wrmsr_ia32_xss(tdvps_p, tdcs_p);
            break;
        case IA32_DEBUGCTL_MSR_ADDR:
            status = (uint16_t)wrmsr_ia32_debugctl(tdvps_p);
            break;
        case IA32_EFER_MSR_ADDR:
            status = (uint16_t)wrmsr_ia32_efer(tdvps_p);
            break;
        default:
        {
            if (msr_addr >= IA32_VMX_BASIC_MSR_ADDR && msr_addr <= IA32_VMX_PROCBASED_CTLS3_MSR_ADDR)
            {
                return TD_MSR_ACCESS_GP;
            }
            status = rd_wr_msr_generic_case(msr_addr, true, tdcs_p, true);
            break;
        }
    }

    return status;
}

// Returns true if the MSR was handled, false if not in the switch case
static bool_t rdmsr_l1_only_special_msrs(tdcs_t* tdcs_p, tdvps_t* tdvps_p, uint32_t msr_addr)
{
    switch (msr_addr)
    {
        case IA32_VMX_BASIC_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_basic.raw);
            break;
        case IA32_VMX_MISC_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_misc.raw);
            break;
        case IA32_VMX_CR0_FIXED0_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_cr0_fixed0.raw);
            break;
        case IA32_VMX_CR0_FIXED1_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_cr0_fixed1.raw);
            break;
        case IA32_VMX_CR4_FIXED0_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_cr4_fixed0.raw);
            break;
        case IA32_VMX_CR4_FIXED1_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_cr4_fixed1.raw);
            break;
        case IA32_VMX_PROCBASED_CTLS2_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_procbased_ctls2.raw);
            break;
        case IA32_VMX_EPT_VPID_CAP_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_ept_vpid_cap.raw);
            break;
        case IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_true_pinbased_ctls.raw);
            break;
        case IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_true_procbased_ctls.raw);
            break;
        case IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_true_exit_ctls.raw);
            break;
        case IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_true_entry_ctls.raw);
            break;
        case IA32_VMX_VMFUNC_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_vmfunc);
            break;
        case IA32_VMX_PROCBASED_CTLS3_MSR_ADDR:
            rdmsr_set_value_in_tdvps(tdvps_p, tdcs_p->virt_msrs.virtual_ia32_vmx_procbased_ctls3);
            break;
        default:
            return false;
            break;
    }

    return true;
}

uint16_t td_rdmsr_exit(void)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    uint32_t msr_addr = (uint32_t)tdvps_p->guest_state.gpr_state.rcx;
    uint16_t vm_id = tdvps_p->management.curr_vm;

    uint16_t status = TD_MSR_ACCESS_SUCCESS;

    status = (uint16_t)rd_wr_msr_generic_checks(msr_addr, false, tdvps_p, vm_id);

    if (status != TD_MSR_ACCESS_SUCCESS)
    {
        return status;
    }

    // IA32_PERFEVTSEL MSRs have special handling since they can be accessed via two aliases
    uint32_t pmc_index = get_pmc_index_given_ia32_perfevtsel_index(msr_addr);
    lfence();
    if (pmc_index != (uint32_t)INVALID_PERFMON_MSR_INDEX)
    {
        // msr_index is a valid IA32_PEREVTSEL MSR
        return status = (uint16_t)rdmsr_ia32_perfevtsel(tdcs_p, tdvps_p, pmc_index, msr_addr);
    }

    switch (msr_addr)
    {
        case IA32_SMI_COUNT_MSR_ADDR:
            if (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                // Read the value from TDVPS, not from the h/w
                rdmsr_set_value_in_tdvps(tdvps_p, tdvps_p->guest_msr_state.msr_smi_count);
            }
            else
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;

        case IA32_FEATURE_CONTROL_MSR_ADDR:
        case IA32_PPIN_CTL_MSR_ADDR:
            if (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                // Return 1 (locked)
                rdmsr_set_value_in_tdvps(tdvps_p, 1);
            }
            else
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;

        case IA32_BIOS_SIGN_ID_MSR_ADDR:
            if (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                // Return 0xFFFFFFFF
                rdmsr_set_value_in_tdvps(tdvps_p, 0xFFFFFFFF);
            }
            else
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;

        case IA32_PLATFORM_INFO_MSR_ADDR:
        case IA32_FEATURE_ENABLES_MSR_ADDR:
            if (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve)
            {
                // Return 0
                rdmsr_set_value_in_tdvps(tdvps_p, 0);
            }
            else
            {
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }
            break;
        case IA32_DEBUGCTL_MSR_ADDR:
            status = (uint16_t)rdmsr_ia32_debugctl(tdvps_p);
            break;
        case IA32_MISC_ENABLES_MSR_ADDR:
            status = (uint16_t)rdmsr_ia32_misc_enables(tdvps_p);
            break;
        case IA32_PERF_CAPABILITIES_MSR_ADDR:
            status = (uint16_t)rdmsr_ia32_perf_capabilities(tdvps_p, tdcs_p);
            break;
        case IA32_ARCH_CAPABILITIES_MSR_ADDR:
            status = (uint16_t)rdmsr_ia32_arch_capabilities(tdvps_p, tdcs_p);
            break;
        case IA32_X2APIC_APICID:
        {
            if (tdcs_p->executions_ctl_fields.td_ctls.enum_topology)
            {
                // Return the current VCPU's virtual x2APIC ID
                tdvps_p->guest_state.gpr_state.rdx = 0;
                tdvps_p->guest_state.gpr_state.rax = tdcs_p->x2apic_ids[tdvps_p->management.vcpu_index];
            }
            else
            {
                // No topology enumeration, #VE will be injected
                return construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
            }

            break;
        }
        case IA32_XAPIC_DISABLE_STATUS_MSR_ADDR:
        {
            if (is_not_gnr_a0_stepping())
            {
                ia32_xapic_disable_status_t ia32_xapic_disable_status = { .raw = 0 };
                ia32_xapic_disable_status.legacy_xapic_disabled = 1;

                rdmsr_set_value_in_tdvps(tdvps_p, ia32_xapic_disable_status.raw);
                status = TD_MSR_ACCESS_SUCCESS;
                break;
            }
            else
            {
                // no break
            }
        }
        default:
        {
            if ((msr_addr >= IA32_VMX_BASIC_MSR_ADDR) && (msr_addr <= IA32_VMX_PROCBASED_CTLS3_MSR_ADDR))
            {
                if (vm_id == 0 && rdmsr_l1_only_special_msrs(tdcs_p, tdvps_p, msr_addr))
                {
                    return TD_MSR_ACCESS_SUCCESS;
                }
                else
                {
                    return (tdcs_p->executions_ctl_fields.td_ctls.reduce_ve) ? TD_MSR_ACCESS_GP : construct_msr_status_with_ve_category(TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, VE_INFO_CONFIG_PARAVIRT);
                }
            }

            status = rd_wr_msr_generic_case(msr_addr, false, tdcs_p, false);
            break;
        }
    }

    return status;
}
