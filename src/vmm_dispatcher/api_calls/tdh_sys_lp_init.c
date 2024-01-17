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
    // Check Capabilities MSRs to have the same values as sampled during TDHSYSINIT

    if (ia32_rdmsr(IA32_CORE_CAPABILITIES) !=
            tdx_global_data_ptr->plt_common_config.ia32_core_capabilities.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_CORE_CAPABILITIES);
    }

    if (ia32_rdmsr(IA32_ARCH_CAPABILITIES_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_arch_capabilities.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_ARCH_CAPABILITIES_MSR_ADDR);
    }

    if (ia32_rdmsr(IA32_MISC_PACKAGE_CTLS_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_misc_package_ctls.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_MISC_PACKAGE_CTLS_MSR_ADDR);
    }

    if (ia32_rdmsr(IA32_XAPIC_DISABLE_STATUS_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_xapic_disable_status.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_XAPIC_DISABLE_STATUS_MSR_ADDR);
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

_STATIC_INLINE_ api_error_type compare_cpuid_configuration(tdx_module_global_t* tdx_global_data_ptr,
                                                           tdx_module_local_t *tdx_local_data_ptr,
                                                           bool_t* tsx_ctrl_modified_flag,
                                                           ia32_tsx_ctrl_t* tsx_ctrl_original,
                                                           ia32_tsx_ctrl_t* tsx_ctrl_modified)
{

    //Check consistency with global configuration

    cpuid_config_t tmp_cpuid_config;
    cpuid_config_t tmp_verify_same_mask;
    cpuid_config_t pl_verify_same_mask;

    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;

    if (msr_values_ptr->ia32_arch_capabilities.tsx_ctrl)
    {
        tsx_ctrl_original->raw = ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR);
        if (tsx_ctrl_original->tsx_cpuid_clear)
        {
            // TSX_CPUID_CLEAR forces CPUID(7,0).EBX bits 4 and 11 to 0.
            // In order to get their real values, clear this bit.
            // It will be restored later, after we sample CPUID.
            tsx_ctrl_modified->raw = tsx_ctrl_original->raw;
            tsx_ctrl_modified->tsx_cpuid_clear = 0;
            ia32_wrmsr(IA32_TSX_CTRL_MSR_ADDR, tsx_ctrl_modified->raw);
            *tsx_ctrl_modified_flag = true;
        }
    }

    // Boot NT4 bit should not be set
    if ((ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) & MISC_EN_BOOT_NT4_BIT ) != 0)
    {
        return TDX_LIMIT_CPUID_MAXVAL_SET;
    }

    uint32_t last_base_leaf, last_extended_leaf;
    uint32_t ebx, ecx, edx;

    ia32_cpuid(CPUID_MAX_INPUT_VAL_LEAF, 0, &last_base_leaf, &ebx, &ecx, &edx);
    ia32_cpuid(CPUID_MAX_EXTENDED_VAL_LEAF, 0, &last_extended_leaf, &ebx, &ecx, &edx);

    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        if (!cpuid_lookup[i].valid_entry)
        {
            continue;
        }

        tmp_cpuid_config.leaf_subleaf =
                cpuid_lookup[i].leaf_subleaf;

        ia32_cpuid(tmp_cpuid_config.leaf_subleaf.leaf, tmp_cpuid_config.leaf_subleaf.subleaf,
                &tmp_cpuid_config.values.eax, &tmp_cpuid_config.values.ebx,
                &tmp_cpuid_config.values.ecx, &tmp_cpuid_config.values.edx);

        if (!((tmp_cpuid_config.leaf_subleaf.leaf <= last_base_leaf) ||
            ((tmp_cpuid_config.leaf_subleaf.leaf >= CPUID_FIRST_EXTENDED_LEAF) &&
             (tmp_cpuid_config.leaf_subleaf.leaf <= last_extended_leaf))))
        {
            continue;
        }

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

    // Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    if (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != tdx_global_data_ptr->plt_common_config.ia32_tsc_adjust)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
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

    tmp_msr = ia32_rdmsr(IA32_VMX_MISC_MSR_ADDR);
    if (tmp_msr != pl_msr_values_ptr->ia32_vmx_misc.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_VMX_MISC_MSR_ADDR);
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

_STATIC_INLINE_ api_error_type check_enumeration_and_compare_configuration(tdx_module_global_t* tdx_global_data_ptr,
                                                                           bool_t* tsx_ctrl_modified_flag,
                                                                           ia32_tsx_ctrl_t* tsx_ctrl_original,
                                                                           ia32_tsx_ctrl_t* tsx_ctrl_modified)
{

    tdx_module_local_t *tdx_local_data_ptr = get_local_data();
    api_error_type err;

    if ((err = check_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    if ((err = compare_cpuid_configuration(tdx_global_data_ptr, tdx_local_data_ptr, tsx_ctrl_modified_flag,
                                           tsx_ctrl_original, tsx_ctrl_modified)) != TDX_SUCCESS)
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
    if (ia32_rdmsr(IA32_PERF_CAPABILITIES_MSR_ADDR) !=
            tdx_global_data_ptr->plt_common_config.ia32_perf_capabilities.raw)
    {
        return api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_PERF_CAPABILITIES_MSR_ADDR);
    }

    if ((err = compare_key_management_config(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        return err;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ void increment_num_of_lps(tdx_module_global_t* tdx_global_data_ptr)
{
    (void)_lock_xadd_32b(&tdx_global_data_ptr->num_of_init_lps, 1);
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
    tdx_local_data_ptr->lp_info.lp_id = (uint32_t)get_current_thread_num(sysinfo_table, tdx_local_data_ptr);

    uint64_t last_page_addr = sysinfo_table->data_rgn_base + sysinfo_table->data_rgn_size - _4KB;
    ia32_vmwrite(VMX_HOST_FS_BASE_ENCODE, last_page_addr);

    tdx_local_data_ptr->vp_ctx.active_vmcs = ACTIVE_VMCS_NONE;

    // Read the LP-dependant host state from the VMCS and store it locally
    uint64_t val;
    ia32_vmread(VMX_HOST_RSP_ENCODE, &val);
    tdx_local_data_ptr->host_rsp = val;

    ia32_vmread(VMX_HOST_SSP_ENCODE, &val);
    tdx_local_data_ptr->host_ssp = val;

    ia32_vmread(VMX_HOST_GS_BASE_ENCODE, &val);
    tdx_local_data_ptr->host_gs_base = val;

    tdx_local_data_ptr->lp_is_init = true;

    // Mark the current LP as initialized
    increment_num_of_lps(tdx_global_data_ptr);
}

api_error_type tdh_sys_lp_init(void)
{

    bool_t tmp_global_lock_acquired = false;
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    api_error_type retval = TDX_SYS_BUSY;

    ia32_tsx_ctrl_t tsx_ctrl_original = { .raw = 0 };
    ia32_tsx_ctrl_t tsx_ctrl_modified = { .raw = 0 };
    bool_t tsx_ctrl_modified_flag = false;

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
        retval = TDX_RND_NO_ENTROPY;
        goto EXIT;
    }
    tdx_local_data_ptr->single_step_def_state.lfsr_value = lfsr_value;

    /* Do a global EPT flush.  This is required to help ensure security in case of
       a TDX-SEAM module update. */
    const ept_descriptor_t zero_descriptor = { 0 };
    ia32_invept(&zero_descriptor, INVEPT_GLOBAL);

    // Verify SEAM capabilities consistency
    seam_ops_capabilities_t caps = { .raw = ia32_seamops_capabilities() };

    if (tdx_global_data_ptr->seam_capabilities.raw != caps.raw)
    {
        TDX_ERROR("SEAM capabilities are inconsistent 0x%llx/0x%llx\n",
                tdx_global_data_ptr->seam_capabilities.raw, caps.raw);
        retval = TDX_INCOMPATIBLE_SEAM_CAPABILITIES;
        goto EXIT;
    }

    if ((retval = check_enumeration_and_compare_configuration(tdx_global_data_ptr, &tsx_ctrl_modified_flag,
                                                              &tsx_ctrl_original, &tsx_ctrl_modified)) != TDX_SUCCESS)
    {
        TDX_ERROR("comparing LP configuration with platform failed\n");
        goto EXIT;
    }

    tdx_local_init(tdx_local_data_ptr, tdx_global_data_ptr);

    retval = TDX_SUCCESS;
    EXIT:

    // Restore the original value of IA32_TSX_CTRL, if modified above
    if (tsx_ctrl_modified_flag)
    {
        ia32_wrmsr(IA32_TSX_CTRL_MSR_ADDR, tsx_ctrl_original.raw);
    }

    if (tmp_global_lock_acquired)
    {
        release_sharex_lock_sh(&tdx_global_data_ptr->global_lock);
    }

    return retval;
}

