// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdH_sys_lp_init.c
 * @brief TDHSYSLPINIT API handler
 */
#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"

#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/loader_data.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"

#include "helpers/smrrs.h"
#include "memory_handlers/keyhole_manager.h"
#include "auto_gen/cpuid_configurations.h"

_STATIC_INLINE_ api_error_type check_msrs(tdx_module_global_t* tdx_global_data_ptr)
{

    // Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    if (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != tdx_global_data_ptr->plt_common_config.ia32_tsc_adjust)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_smrr_smrr2_config(tdx_module_global_t* tdx_global_data_ptr)
{
    ia32_mtrrcap_t local_mtrr_cap = {.raw = ia32_rdmsr(MTRR_CAP_MSR_ADDR)};

    if (local_mtrr_cap.raw != tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.raw)
    {
        TDX_ERROR("local MTRRCAP MSR mismatch with platform\n");
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, MTRR_CAP_MSR_ADDR);
    }

    smrr_mask_t tmp_smrr_mask;
    smrr_base_t tmp_smrr_base;

    //SMRR and SMRR2 must be configured the same on all LPs
    tmp_smrr_mask.raw = ia32_rdmsr(SMRR_MASK_MSR_ADDR);
    tmp_smrr_base.raw = ia32_rdmsr(SMRR_BASE_MSR_ADDR);

    if (tdx_global_data_ptr->plt_common_config.smrr[0].smrr_base.raw != tmp_smrr_base.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR_BASE_MSR_ADDR);
    }

    if (tdx_global_data_ptr->plt_common_config.smrr[0].smrr_mask.raw != tmp_smrr_mask.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR_MASK_MSR_ADDR);
    }

    if (get_sysinfo_table()->mcheck_fields.smrr2_not_supported == 0 && local_mtrr_cap.smrr2 != 0)
    {
        tmp_smrr_mask.raw = ia32_rdmsr(SMRR2_MASK_MSR_ADDR);
        tmp_smrr_base.raw = ia32_rdmsr(SMRR2_BASE_MSR_ADDR);


        if (tdx_global_data_ptr->plt_common_config.smrr[1].smrr_base.raw != tmp_smrr_base.raw)
        {
            return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR2_BASE_MSR_ADDR);
        }
        if (tdx_global_data_ptr->plt_common_config.smrr[1].smrr_mask.raw != tmp_smrr_mask.raw)
        {
            return api_error_with_operand_id(TDX_INCONSISTENT_MSR, SMRR2_MASK_MSR_ADDR);
        }

    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type compare_cpuid_configuration(
        tdx_module_global_t* tdx_global_data_ptr,
        tdx_module_local_t *tdx_local_data_ptr)
{

    //Check consistency with global configuration

    cpuid_config_t tmp_cpuid_config;
    cpuid_config_t tmp_verify_same_mask;
    cpuid_config_t pl_verify_same_mask;

    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        tmp_cpuid_config.leaf_subleaf =
                cpuid_lookup[i].leaf_subleaf;

        ia32_cpuid(tmp_cpuid_config.leaf_subleaf.leaf, tmp_cpuid_config.leaf_subleaf.subleaf,
                &tmp_cpuid_config.values.eax, &tmp_cpuid_config.values.ebx,
                &tmp_cpuid_config.values.ecx, &tmp_cpuid_config.values.edx);

        tmp_verify_same_mask.values.low = (tmp_cpuid_config.values.low & cpuid_lookup[i].verify_same.low);
        tmp_verify_same_mask.values.high = (tmp_cpuid_config.values.high & cpuid_lookup[i].verify_same.high);

        pl_verify_same_mask.values.low = (tdx_global_data_ptr->cpuid_values[i].values.low &
                cpuid_lookup[i].verify_same.low);
        pl_verify_same_mask.values.high = (tdx_global_data_ptr->cpuid_values[i].values.high &
                cpuid_lookup[i].verify_same.high);

        if (tmp_verify_same_mask.values.low != pl_verify_same_mask.values.low ||
            tmp_verify_same_mask.values.high != pl_verify_same_mask.values.high)
        {
            tdx_local_data_ptr->vmm_regs.rcx = tmp_cpuid_config.leaf_subleaf.raw;
            tdx_local_data_ptr->vmm_regs.rdx = cpuid_lookup[i].verify_same.low;
            tdx_local_data_ptr->vmm_regs.r8 = cpuid_lookup[i].verify_same.high;

            return TDX_INCONSISTENT_CPUID_FIELD;
        }

        /*------------------------------------------------------
           Special Handling of Selected CPUID Leaves/Sub-Leaves
        ------------------------------------------------------*/

        // Determine current core and packege IDs.
        if ((tmp_cpuid_config.leaf_subleaf.leaf == CPUID_GET_TOPOLOGY_LEAF) &&
            (tmp_cpuid_config.leaf_subleaf.subleaf == 0))
        {
            /* Update maximum APIC ID in the platform.
             * In places where we need to used the APIC in xAPIC mode,
             * maximum APIC ID must be lower than 256.
            */
            if (tdx_global_data_ptr->max_x2apic_id < tmp_cpuid_config.values.edx)
            {
                tdx_global_data_ptr->max_x2apic_id = tmp_cpuid_config.values.edx;
            }

            tdx_local_data_ptr->lp_info.core =
                    (tmp_cpuid_config.values.edx >> tdx_global_data_ptr->x2apic_core_id_shift_count) &
                    tdx_global_data_ptr->x2apic_core_id_mask;
            tdx_local_data_ptr->lp_info.pkg  =
                    (tmp_cpuid_config.values.edx >> tdx_global_data_ptr->x2apic_pkg_id_shift_count);

            // Sanity check
            if (tdx_local_data_ptr->lp_info.pkg >= MAX_PKGS)
            {
                return api_error_with_operand_id(TDX_INVALID_PKG_ID, tdx_local_data_ptr->lp_info.pkg);
            }
        }

    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type compare_vmx_msrs(tdx_module_global_t* tdx_global_data_ptr)
{
    platform_common_config_t* pl_msr_values_ptr = &tdx_global_data_ptr->plt_common_config;
    uint64_t tmp_msr;

    tmp_msr = ia32_rdmsr(IA32_VMX_BASIC_MSR_ADDR);
    if (pl_msr_values_ptr->ia32_vmx_basic.raw != tmp_msr)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_BASIC_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_pinbased_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_procbased_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_procbased_ctls2.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_procbased_ctls3)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_exit_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_true_entry_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_ept_vpid_cap)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_VMX_CR0_FIXED0_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr0_fixed0.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR0_FIXED0_MSR_ADDR);
    }
    tmp_msr = ia32_rdmsr(IA32_VMX_CR0_FIXED1_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr0_fixed1.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR0_FIXED1_MSR_ADDR);
    }
    tmp_msr = ia32_rdmsr(IA32_VMX_CR4_FIXED0_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr4_fixed0.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR4_FIXED0_MSR_ADDR);
    }
    tmp_msr = ia32_rdmsr(IA32_VMX_CR4_FIXED1_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_cr4_fixed1.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_CR4_FIXED1_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type compare_key_management_config(tdx_module_global_t* tdx_global_data_ptr)
{

    uint64_t tmp_msr;

    tmp_msr = ia32_rdmsr(IA32_TME_CAPABILITY_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->plt_common_config.ia32_tme_capability.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TME_CAPABILITY_MSR_ADDR);
    };

    tmp_msr = ia32_rdmsr(IA32_TME_ACTIVATE_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->plt_common_config.ia32_tme_activate.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TME_ACTIVATE_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR);
    }

    /* Check consistency of number of cache sub-blocks for TDWBINVD.
       Implementation may choose to do these checks once per package.
    */
    tmp_msr = ia32_rdmsr(IA32_WBINVDP_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->num_of_cached_sub_blocks)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_WBINVDP_MSR_ADDR);
    }

    tmp_msr = ia32_rdmsr(IA32_WBNOINVDP_MSR_ADDR);
    if (tmp_msr != tdx_global_data_ptr->num_of_cached_sub_blocks)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_WBNOINVDP_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_enumeration_and_compare_configuration(
        tdx_module_global_t* tdx_global_data_ptr)
{

    tdx_module_local_t *tdx_local_data_ptr = get_local_data();
    api_error_type err;

    if ((err = compare_cpuid_configuration(tdx_global_data_ptr, tdx_local_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    if ((err = check_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    /**
     * Check SMRR valid and consistent
     */
    if ((err = check_smrr_smrr2_config(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    if ((err = compare_vmx_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    /*---------------------------------------------------
        Check Performance Monitoring
      ---------------------------------------------------*/
    if ((err = check_perf_msrs()) != TDX_SUCCESS)
    {
        TDX_ERROR("Check of IA32 PERF MSRs failed\n");
        return err;
    }

    if ((err = compare_key_management_config(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ void increment_num_of_lps(tdx_module_global_t* tdx_global_data_ptr)
{
    _lock_xadd_32b(&tdx_global_data_ptr->num_of_init_lps, 1);
}

_STATIC_INLINE_ void tdx_local_init(tdx_module_local_t* tdx_local_data_ptr,
        tdx_module_global_t* tdx_global_data_ptr)
{

    sysinfo_table_t* sysinfo_table = get_sysinfo_table();

    //Set local defs
    init_keyhole_state();

    /**
     * Calc LPID from local_data_ptr
     */
    tdx_local_data_ptr->lp_info.lp_id = (uint32_t)(((uint64_t) tdx_local_data_ptr
            - sysinfo_table->data_rgn_base) / LOCAL_DATA_SIZE_PER_LP);

    uint64_t last_page_addr = sysinfo_table->data_rgn_base + sysinfo_table->data_rgn_size - _4KB;
    ia32_vmwrite(VMX_HOST_FS_BASE_ENCODE, last_page_addr);

    tdx_local_data_ptr->lp_is_init = true;

    increment_num_of_lps(tdx_global_data_ptr);
}

_STATIC_INLINE_ bool_t is_seamreport_available(void)
{
    seam_ops_capabilities_t caps = {.raw = ia32_seamops_capabilities()};
    if (caps.seamreport != 0)
    {
        return true;
    }
    return false;
}

api_error_type tdh_sys_lp_init(void)
{

    bool_t tmp_global_lock_acquired = false;
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    api_error_type retval = TDX_SYS_BUSY;

    tdx_local_data_ptr->vmm_regs.rcx = 0ULL;
    tdx_local_data_ptr->vmm_regs.rdx = 0ULL;
    tdx_local_data_ptr->vmm_regs.r8 = 0ULL;

    if (acquire_sharex_lock_sh(&tdx_global_data_ptr->global_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire global lock for LP\n");
        retval = TDX_SYS_BUSY;
        goto EXIT;
    }
    tmp_global_lock_acquired = true;

    if (tdx_global_data_ptr->global_state.sys_state != SYSINIT_DONE)
    {
        TDX_ERROR("Wrong sys_init state: %d\n", tdx_global_data_ptr->global_state.sys_state);
        retval = TDX_SYS_LP_INIT_NOT_PENDING;
        goto EXIT;
    }

    //Check current LP state
    if (tdx_local_data_ptr->lp_is_init)
    {
        TDX_ERROR("LP is already initialized\n");
        retval = TDX_SYS_LP_INIT_DONE;
        goto EXIT;
    }

    // Explicit LP-scope state initialization
    tdx_local_data_ptr->vp_ctx.last_tdvpr_pa.raw = NULL_PA;
    uint32_t lfsr_value = LFSR_INIT_VALUE;
    if (!lfsr_init_seed (&lfsr_value))
    {
        TDX_ERROR("LFSR initialization failed\n");
        retval = TDX_SYS_BUSY;
        goto EXIT;
    }
    tdx_local_data_ptr->single_step_def_state.lfsr_value = lfsr_value;

    /* Do a global EPT flush.  This is required to guarantee security in case of
       a TDX-SEAM module update. */
    const ept_descriptor_t zero_descriptor = { 0 };
    ia32_invept(&zero_descriptor, INVEPT_TYPE_2);

    //Verify that SEAMREPORT is available
    if (!is_seamreport_available())
    {
        TDX_ERROR("SEAMREPORT instruction is not enabled\n");
        retval = TDX_SEAMREPORT_NOT_AVAILABLE;
        goto EXIT;
    }

    // Check Capabilities MSRs to have the same values as sampled during TDHSYSINIT
    if (ia32_rdmsr(IA32_CORE_CAPABILITIES) !=
            tdx_global_data_ptr->plt_common_config.ia32_core_capabilities.raw)
    {
        TDX_ERROR("The check of CORE_CAPABILITIES MSR's value failed\n");
        retval =  api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_CORE_CAPABILITIES);
        goto EXIT;
    }

    if (ia32_rdmsr(IA32_ARCH_CAPABILITIES_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_arch_capabilities.raw)
    {
        TDX_ERROR("The check of ARCH_CAPABILITIES MSR's value failed\n");
        retval =  api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_ARCH_CAPABILITIES_MSR_ADDR);
        goto EXIT;
    }

    if (tdx_global_data_ptr->plt_common_config.ia32_arch_capabilities.tsx_ctrl)
    {
        if (ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR) !=
                tdx_global_data_ptr->plt_common_config.ia32_tsx_ctrl.raw)
        {
            TDX_ERROR("The check of TSX_CTRL MSR's value failed\n");
            retval =  api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSX_CTRL_MSR_ADDR);
            goto EXIT;
        }
    }

    // Boot NT4 bit should not be set
    if ((ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) & MISC_EN_BOOT_NT4_BIT ) != 0)
    {
        retval = TDX_BOOT_NT4_SET;
        goto EXIT;
    }

    if ((retval = check_enumeration_and_compare_configuration(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("comparing LP configuration with platform failed\n");
        goto EXIT;
    }

    tdx_local_init(tdx_local_data_ptr, tdx_global_data_ptr);

    retval = TDX_SUCCESS;
    EXIT:

    if (tmp_global_lock_acquired)
    {
        release_sharex_lock_sh(&tdx_global_data_ptr->global_lock);
    }

    return retval;
}

