// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_sys_init.c
 * @brief TDHSYSINIT API handler
 */
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"

#include "data_structures/tdx_global_data.h"
#include "data_structures/loader_data.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"

#include "helpers/smrrs.h"
#include "auto_gen/cpuid_configurations.h"

/*
 * check_allowed_vmx_ctls
 */
_STATIC_INLINE_ bool_t check_allowed_vmx_ctls(uint32_t* dest,
                                              ia32_vmx_allowed_bits_t src,
                                              uint32_t init,
                                              uint32_t variable_mask,
                                              uint32_t unknown_mask)
{
    // Sanity check on the MSR values returned by the CPU:
    // Any bit can't be both fixed-1 (bits that are 1 in NOT_ALLOWED0) and fixed-0 (bits that are 0 in ALLOWED1)
    tdx_sanity_check((src.not_allowed0 & ~src.allowed1) == 0, SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF), 0);

    // Sanity check on the TDX-SEAM module's constants:
    // Any unknown bits must be 0 in the init value and must not be variable
    tdx_sanity_check(((init | variable_mask) & unknown_mask) == 0,
                     SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF), 1);

    // Check bits that are fixed-1 (bits that are 1 in NOT_ALLOWED0).
    // Any fixed-1 bit must be initialized to 1.  For this check, ignore bits in the init value that are unknown.
    // Per Intel SDM:
    // Bits 31:0 indicate the allowed 0-settings of these controls.
    // VM entry allows control X to be 0 if bit X in the MSR is cleared to 0;
    // if bit X in the MSR is set to 1, VM entry fails if control X is 0.
    if ((src.not_allowed0 & ~(init | unknown_mask)) != 0)
    {
        return false;
    }

    // Check bits that are fixed-0 (bits that are 0 in ALLOWED1).
    // Any fixed-0 bit must be initialized to 0.
    // Per Intel SDM:
    // Bits 63:32 indicate the allowed 1-settings of these controls.
    // VM entry allows control X to be 1 if bit 32+X in the MSR is set to 1;
    // if bit 32+X in the MSR is cleared to 0, VM entry fails if control X is 1.
    if ((~src.allowed1 & init) != 0)
    {
        return false;
    }

    // Any fixed-1 bit (that is 1 in NOT_ALLOWED0) or fixed-0 bit (that is 0 in ALLOWED1) must not be variable
    if (((src.not_allowed0 | ~src.allowed1) & variable_mask) != 0)
    {
        return false;
    }

    // Return the value used for initializing the TD VMCS field (incl. unknown bits) Set fixed-1 (NOT_ALLOWED0) bits to 1.
    *dest = (init | src.not_allowed0);

    return true;
}

/*
 * check_allowed1_vmx_ctls
 */
_STATIC_INLINE_ bool_t check_allowed1_vmx_ctls(uint64_t* dest,
                                              uint64_t  allowed1,
                                              uint64_t  init,
                                              uint64_t  variable_mask,
                                              uint64_t  unknown_mask)
{
    /* Sanity check on the TDX-SEAM module's constants:
           Any unknown bits must be 0 in the init value and must not be variable */
    tdx_sanity_check(((init | variable_mask) & unknown_mask) == 0, SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF), 3);

    /* Check bits that are fixed-0 (bits that are 0 in ALLOWED1).  Any fixed-0
       bit must be initialized to 0. */
    if ((~allowed1 & init) != 0)
    {
        return false;
    }

    // Any fixed-0 bit (that is 0 in ALLOWED1) must not be variable.
    if ((~allowed1 & variable_mask) != 0)
    {
        return false;
    }

    // Return the value used for initializing the TD VMCS field (incl. unknown bits)
    *dest = init;
    return true;

}

_STATIC_INLINE_ bool_t is_smrr_mask_valid_for_tdx(smrr_base_t smrr_base, smrr_mask_t smrr_mask)
{
    // Create a bit mask from the first LSB which is 1 in the mask, until the uppermost bit 31
    // XOR it with the mask value to see if there are any "hole" bits in the mask
    uint32_t actual_mask = (uint32_t)(smrr_mask.raw & BITS(31, 12));
    uint32_t bitmask = (uint32_t)(BITS(31, bit_scan_forward64(actual_mask)));

    if ((actual_mask ^ bitmask) != 0)
    {
        return false;
    }

    // Check that the base is aligned on the range size
    uint32_t actual_base = (uint32_t)(smrr_base.raw & BITS(31, 12));

    if ((actual_base & ~bitmask) != 0)
    {
        return false;
    }

    return true;
}

_STATIC_INLINE_ api_error_type check_and_store_smrr_smrr2(tdx_module_global_t* tdx_global_data_ptr)
{
    uint8_t num_of_smrrs = 1;

    tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.raw = ia32_rdmsr(MTRR_CAP_MSR_ADDR);

    if (tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.smrr == 0)
    {
        TDX_ERROR("SMRR not enabled\n");
        return TDX_SMRR_NOT_SUPPORTED;
    }

    if (tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.smrr_lock == 0)
    {
            TDX_ERROR("SMRR Lock not enabled\n");
            return TDX_SMRR_LOCK_NOT_SUPPORTED;
    }

    tdx_global_data_ptr->plt_common_config.smrr[0].smrr_mask.raw = ia32_rdmsr(SMRR_MASK_MSR_ADDR);
    tdx_global_data_ptr->plt_common_config.smrr[0].smrr_base.raw = ia32_rdmsr(SMRR_BASE_MSR_ADDR);

    sysinfo_table_t * sysinfo_table_ptr = get_sysinfo_table();

    // Determine whether SMRR2 is supported
    if (sysinfo_table_ptr->mcheck_fields.smrr2_not_supported == 0 && tdx_global_data_ptr->plt_common_config.ia32_mtrrcap.smrr2 != 0)
    {
        tdx_global_data_ptr->plt_common_config.smrr[1].smrr_mask.raw = ia32_rdmsr(SMRR2_MASK_MSR_ADDR);
        tdx_global_data_ptr->plt_common_config.smrr[1].smrr_base.raw = ia32_rdmsr(SMRR2_BASE_MSR_ADDR);
        num_of_smrrs = 2U;
    }

    //SMRR and SMRR2 must be locked
    for (uint8_t smrr_idx = 0; smrr_idx < num_of_smrrs; smrr_idx++)
    {
        if (tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.lock == 0)
        {
            TDX_ERROR("SMRR %d not locked\n", smrr_idx+1);
            return api_error_with_operand_id(TDX_SMRR_NOT_LOCKED, (uint64_t)smrr_idx);
        }
    }

    //SMRR and SMRR2 must not overlap with any CMR

    for (uint8_t smrr_idx = 0; smrr_idx < num_of_smrrs; smrr_idx++)
    {
        if (tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.vld == 0)
        {
            continue;
        }
        smrr_base_t smrr_base = { .raw = 0 };
        smrr_base.base = tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_base.base;
        smrr_mask_t smrr_mask = { .raw = 0 };
        smrr_mask.mask = tdx_global_data_ptr->plt_common_config.smrr[smrr_idx].smrr_mask.mask;

        if (!is_smrr_mask_valid_for_tdx(smrr_base, smrr_mask))
        {
            TDX_ERROR("SMRR %d mask is corrupt 0x%llx (base 0x%llx)\n",
                    smrr_idx+1, smrr_mask.raw, smrr_base.raw);
            return api_error_with_operand_id(TDX_INVALID_SMRR_CONFIGURATION, (uint64_t)smrr_idx);
        }

        uint64_t smrr_size = mask_to_size(smrr_mask.raw);

        if (!is_valid_integer_range(smrr_base.raw, smrr_size))
        {
            TDX_ERROR("SMRR %d base and size cause integer overflow\n", smrr_idx+1);
            return api_error_with_operand_id(TDX_INVALID_SMRR_CONFIGURATION, (uint64_t)smrr_idx);
        }

        // Check SMRRs don't overlap with CMRs - at this point CMR ranges should be checked
        // for integer overflow
        for (uint8_t cmr_i = 0; cmr_i < MAX_CMR; cmr_i++)
        {
            if (sysinfo_table_ptr->cmr_data[cmr_i].cmr_size != 0 &&
                    is_overlap(smrr_base.raw, smrr_size, sysinfo_table_ptr->cmr_data[cmr_i].cmr_base,
                    sysinfo_table_ptr->cmr_data[cmr_i].cmr_size))
            {
                TDX_ERROR("SMRR %d overlap with CMR %d \n", smrr_idx+1, cmr_i);
                return api_error_with_multiple_info(TDX_SMRR_OVERLAPS_CMR, smrr_idx, cmr_i, 0, 0);
            }
        };
    }
    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_key_management_config(tdx_module_global_t* tdx_global_data_ptr)
{
    tdx_global_data_ptr->plt_common_config.ia32_tme_capability.raw = ia32_rdmsr(IA32_TME_CAPABILITY_MSR_ADDR);
    tdx_global_data_ptr->plt_common_config.ia32_tme_activate.raw = ia32_rdmsr(IA32_TME_ACTIVATE_MSR_ADDR);

    uint32_t msr_addr = check_mem_enc_alg(tdx_global_data_ptr->plt_common_config.ia32_tme_capability,
                                          tdx_global_data_ptr->plt_common_config.ia32_tme_activate);
    if (msr_addr != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, msr_addr);
    }

    tdx_global_data_ptr->hkid_start_bit = (uint32_t)(MAX_PA -
            (uint64_t)tdx_global_data_ptr->plt_common_config.ia32_tme_activate.mk_tme_keyid_bits);

    tdx_global_data_ptr->hkid_mask = BITS(MAX_PA - 1,
                                          tdx_global_data_ptr->hkid_start_bit);

    tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.raw =
            ia32_rdmsr(IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR);

    tdx_global_data_ptr->private_hkid_min =
            tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.num_mktme_kids + 1;

    tdx_global_data_ptr->private_hkid_max =
            tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.num_mktme_kids +
            tdx_global_data_ptr->plt_common_config.ia32_tme_keyid_partitioning.num_tdx_priv_kids;

    if (tdx_global_data_ptr->private_hkid_max >= MAX_HKIDS)
    {
        return api_error_with_operand_id(TDX_NUM_ACTIVATED_HKIDS_NOT_SUPPORTED, MAX_HKIDS);
    }

    /* Get the number of cache sub-blocks for TDWBINVD
    */
    // INIT number of cached blocks for WBINVD cycle
    tdx_global_data_ptr->num_of_cached_sub_blocks = ia32_rdmsr(IA32_WBINVDP_MSR_ADDR);

    // WBNOINVDP should return the same value
    if (ia32_rdmsr(IA32_WBNOINVDP_MSR_ADDR) != tdx_global_data_ptr->num_of_cached_sub_blocks)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_WBNOINVDP_MSR_ADDR);
    }

    tdx_global_data_ptr->max_mktme_hkids =
            MIN((uint64_t )tdx_global_data_ptr->plt_common_config.ia32_tme_capability.mk_tme_max_keys,
            BIT(tdx_global_data_ptr->plt_common_config.ia32_tme_activate.mk_tme_keyid_bits -
                    tdx_global_data_ptr->plt_common_config.ia32_tme_activate.tdx_reserved_keyid_bits)-1);

    return TDX_SUCCESS;
}


_STATIC_INLINE_ api_error_type check_cpuid_configurations(tdx_module_global_t* global_data_ptr)
{
    /**
     * Sample and Check Native CPUID Values
     */

    cpuid_config_t cpuid_config;
    sysinfo_table_t *sysinfo_table_ptr = get_sysinfo_table();
    uint32_t lpids_sharing_l3_cache = (uint32_t)-1; //Initialized to invalid value.
    bool_t core_level_scanned = false;
    uint32_t shift_count = (uint32_t)-1; //Initialized to invalid value.
    uint32_t prev_level_type = LEVEL_TYPE_INVALID;
    fms_info_t fms;

    global_data_ptr->xfd_faulting_mask = 0; // Updated later per CPUID leaf 0xD
    global_data_ptr->x2apic_core_id_shift_count = 0;  // Updated later per CPUID leaf 0x1F


    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        cpuid_config.leaf_subleaf = cpuid_lookup[i].leaf_subleaf;

        ia32_cpuid(cpuid_config.leaf_subleaf.leaf, cpuid_config.leaf_subleaf.subleaf,
                &cpuid_config.values.eax, &cpuid_config.values.ebx,
                &cpuid_config.values.ecx, &cpuid_config.values.edx);

        if (!(((cpuid_config.values.low & cpuid_lookup[i].verify_mask.low)
                == cpuid_lookup[i].verify_value.low)
                && ((cpuid_config.values.high
                        & cpuid_lookup[i].verify_mask.high)
                        == cpuid_lookup[i].verify_value.high)))
        {
            tdx_module_local_t *tdx_local_data_ptr = get_local_data();
            tdx_local_data_ptr->vmm_regs.rcx = cpuid_config.leaf_subleaf.raw;
            tdx_local_data_ptr->vmm_regs.rdx = cpuid_lookup[i].verify_mask.low;
            tdx_local_data_ptr->vmm_regs.r8 = cpuid_lookup[i].verify_mask.high;
            tdx_local_data_ptr->vmm_regs.r9 = cpuid_lookup[i].verify_value.low;
            tdx_local_data_ptr->vmm_regs.r10 = cpuid_lookup[i].verify_value.high;

            TDX_ERROR("CPUID 0x%x.0x%x doesn't match expected value!\n",
                    cpuid_config.leaf_subleaf.leaf, cpuid_config.leaf_subleaf.subleaf);
            TDX_ERROR("Verify mask: EAX = 0x%lx, EBX = 0x%lx, ECX = 0x%lx, EDX = 0x%lx\n",
                    cpuid_lookup[i].verify_mask.eax, cpuid_lookup[i].verify_mask.ebx,
                    cpuid_lookup[i].verify_mask.ecx, cpuid_lookup[i].verify_mask.edx);
            TDX_ERROR("Verify value: EAX = 0x%lx, EBX = 0x%lx, ECX = 0x%lx, EDX = 0x%lx\n",
                    cpuid_lookup[i].verify_value.eax, cpuid_lookup[i].verify_value.ebx,
                    cpuid_lookup[i].verify_value.ecx, cpuid_lookup[i].verify_value.edx);
            TDX_ERROR("Platform value: EAX = 0x%lx, EBX = 0x%lx, ECX = 0x%lx, EDX = 0x%lx\n",
                    cpuid_config.values.eax, cpuid_config.values.ebx,
                    cpuid_config.values.ecx, cpuid_config.values.edx);

            return TDX_INCORRECT_CPUID_VALUE;
        }

        /**
         * Special Handling of selected CPUIDs
         */

        uint32_t leaf = cpuid_config.leaf_subleaf.leaf;
        uint32_t subleaf = cpuid_config.leaf_subleaf.subleaf;

        if (leaf == CPUID_MAX_INPUT_VAL_LEAF)
        {
            if (cpuid_config.values.eax < CPUID_MIN_LAST_CPU_BASE_LEAF)
            {
                return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, CPUID_MIN_LAST_CPU_BASE_LEAF);
            }
            global_data_ptr->cpuid_last_base_leaf = CPUID_LAST_BASE_LEAF;
        }
        /* CPUID Leaf 1 is a special case.  The Stepping ID field, returned in RAX
           should be set to the minimal F/M/S of all packages in the platform.
           F/M/S values are read by MCHECK, which also assures Family and Model are
           the same in all packages.
           SEAMLDR verifies Family and Model compatibility with the TDX-SEAM module.
        */
        else if (leaf == CPUID_VER_INFO_LEAF)
        {
            fms.raw = sysinfo_table_ptr->mcheck_fields.socket_cpuid_table[0].raw;
            for (uint32_t pkg_index = 1; pkg_index < sysinfo_table_ptr->mcheck_fields.tot_num_sockets; pkg_index++)
            {
                if (fms.stepping_id > sysinfo_table_ptr->mcheck_fields.socket_cpuid_table[pkg_index].stepping_id)
                {
                    fms.stepping_id = sysinfo_table_ptr->mcheck_fields.socket_cpuid_table[pkg_index].stepping_id;
                }
            }
            cpuid_config.values.eax = fms.raw;
        }
        /* Get the number of LPIDs sharing the L3 cache. This is used later to verify
           the scope of WBINVD, which TDX-SEAM currently assumes to be package.
        */
        else if (leaf == CPUID_DET_CACHE_PARAMS_LEAF && subleaf == CPUID_DET_CACHE_PARAMS_SUBLEAF)
        {
            lpids_sharing_l3_cache =
                    ((cpu_cache_params_t)cpuid_config.values.eax).max_num_of_lps_sharing_cache;
        }

        /* Check Keylocker Support
        */
        else if (leaf == CPUID_EXT_FEATURES_LEAF && subleaf == CPUID_EXT_FEATURES_SUBLEAF)
        {
            // Check the number of supported sub-leaves
            if ((cpuid_config.values.eax < 1) || (cpuid_config.values.eax > 2))
            {
                return api_error_with_operand_id(TDX_CPUID_MAX_SUBLEAVES_UNRECOGNIZED, CPUID_EXT_FEATURES_LEAF);
            }

            //Sample the TSX support bits. 
            cpuid_07_00_ebx_t cpuid_07_00_ebx = {.raw = cpuid_config.values.ebx};
            global_data_ptr->hle_supported = cpuid_07_00_ebx.hle;
            global_data_ptr->rtm_supported = cpuid_07_00_ebx.rtm;

            global_data_ptr->waitpkg_supported = (cpuid_config.values.ecx & (uint32_t)BIT(CPUID_WAITPKG_BIT)) != 0;
        }

        /* Get the supported extended features.  Allow only features that are recognized
           by TDX-SEAM (as specified by XCR0_USER_BIT_MASK and XCR0_SUPERVISOR_BIT_MASK to avoid surprises. */
        else if (leaf == CPUID_EXT_STATE_ENUM_LEAF)
        {
            if (subleaf == CPUID_EXT_STATE_ENUM_MAIN_SUBLEAF)
            {
                global_data_ptr->xcr0_supported_mask = cpuid_config.values.eax & XCR0_USER_BIT_MASK;
            }
            else if (subleaf == CPUID_EXT_STATE_ENUM_XSAVES_SUBLEAF)
            {
                cpuid_0d_01_eax_t cpuid_0D_01_eax;
                cpuid_0D_01_eax.raw = cpuid_config.values.eax;
                global_data_ptr->xfd_supported = cpuid_0D_01_eax.xfd_support;
                global_data_ptr->ia32_xss_supported_mask = cpuid_config.values.ecx & XCR0_SUPERVISOR_BIT_MASK;

                // Sanity check: Masks for user and system extended features must be mutually exclusive
                tdx_sanity_check((global_data_ptr->xcr0_supported_mask & global_data_ptr->ia32_xss_supported_mask) == 0,
                                SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF),0);
            }
            else
            {
                // For sub-leaf > 1, collect extended state component size and alignment information.
                cpuid_0d_ecx_t cpuid_0d_ecx = { .raw = cpuid_config.values.ecx };

                global_data_ptr->xsave_comp[subleaf].size  = cpuid_config.values.eax;
                global_data_ptr->xsave_comp[subleaf].align = cpuid_0d_ecx.align_64;

                // Update the XFD faulting mask for this sub-leaf
                if (global_data_ptr->xfd_supported && cpuid_0d_ecx.xfd_faulting)
                {
                    global_data_ptr->xfd_faulting_mask |= (1 << subleaf);
                }

                // Sanity checks on the extended features masks
                if (cpuid_0d_ecx.ia32_xss)
                {
                    // This is a system feature and must not be in the XCR0 supported mask
                    if ((uint64_t)global_data_ptr->xcr0_supported_mask & (BIT(subleaf)))
                    {
                        // FATAL_ERROR
                        FATAL_ERROR();
                    }
                }
                else
                {
                    // This is a user feature and must not be in the IA32_XSS supported mask
                    if ((uint64_t)global_data_ptr->ia32_xss_supported_mask & (BIT(subleaf)))
                    {
                        // FATAL_ERROR
                        FATAL_ERROR();
                    }
                }
            }
        }

        else if (leaf == CPUID_TSC_ATTRIBUTES_LEAF)
        {
            // Get TSC attributes

            if (cpuid_config.values.ebx == 0)
            {
                return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, CPUID_TSC_ATTRIBUTES_LEAF);
            }

            // Calculate native TSC frequency. Calculation is done as unsigned 64b and
            //   in the proper order.
            global_data_ptr->native_tsc_frequency =
                    ((uint64_t)cpuid_config.values.ecx * (uint64_t)cpuid_config.values.ebx) /
                     (uint64_t)cpuid_config.values.eax;

            // Sanity check on native TSC frequency, to guarantee no overflow when TSC virtualization
            // params are calculated.
            if (global_data_ptr->native_tsc_frequency < NATIVE_TSC_FREQUENCY_MIN)
            {
                // Fatal Error
                FATAL_ERROR();
            }


        }
        else if (leaf == CPUID_LBR_CAPABILITIES_LEAF)
        {
            uint32_t cpuid_1c_eax;
            cpuid_1c_eax = (uint32_t)cpuid_config.values.eax;
            tdx_debug_assert((cpuid_1c_eax & (BIT(8)-1)) > 0);
            // get the index of the most significant bit set to '1' int lower 8 bits of cpuid_1c_eax
            uint32_t position = (uint32_t)bit_scan_reverse64(cpuid_1c_eax & (BIT(8)-1));
            global_data_ptr->max_lbr_depth = 8 * (position + 1);
        }
        /**
         * Get topology information and verify that the scope of WBINVD is package
         *
         * Notes:  1. The following algorithm assumes we scan sub-leaves sequentially, starting
         *            from 0.  The lookup tables must be built this way.
         *         2. The algorithm assumes that the sub-leaves are organized in order of level
         *            types.  Although the Intel SDM does not require it, actual CPU
         *            implementations work this way and it simplifies out life.
         */
        else if (leaf == CPUID_GET_TOPOLOGY_LEAF)
        {
            // Initialize maximum APIC ID in the platform.
            global_data_ptr->max_x2apic_id = cpuid_config.values.edx;

            if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type != (uint32_t)LEVEL_TYPE_INVALID)
            {
                /* This is a valid leaf.  Checks that level type higher than the last one
                   (initialized to INVALID, which is 0) but does not reach the max.
                 */
                if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type <= prev_level_type ||
                    ((cpuid_topology_level_t)cpuid_config.values.ecx).level_type >= (uint32_t)LEVEL_TYPE_MAX)
                {
                    return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
                }

                /* Get the shift count.  Per the Intel SDM, this is the "number of
                   bits to shift right on x2APIC ID to get a unique topology ID of
                   the next level type.  All logical processors with the same next
                   level ID share current level."
                 */
                shift_count = ((cpuid_topology_shift_t)cpuid_config.values.eax).shift_count;

                if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type == LEVEL_TYPE_SMT)
                {
                    // For the SMT level, save the core (which is the next level) shift count
                    global_data_ptr->x2apic_core_id_shift_count = shift_count;
                }
                else if (((cpuid_topology_level_t)cpuid_config.values.ecx).level_type == LEVEL_TYPE_CORE)
                {
                    core_level_scanned = true;   // Prepare a flag for a sanity check later
                }

                prev_level_type = ((cpuid_topology_level_t)cpuid_config.values.ecx).level_type;
            }
            else
            {
                /* The current sub-leaf is invalid, it marks the end of topology info.
                   Make sure we had at least one valid sub-leaf, otherwise
                   CPUID leaf 1F is not supported.
                 */
                if (cpuid_config.leaf_subleaf.subleaf == CPUID_GET_TOPOLOGY_INVALID_SUBLEAF)
                {
                    return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, OPERAND_ID_RAX);
                }
                // Sanity check: core level must have been scanned.
                if (!core_level_scanned)
                {
                    return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, OPERAND_ID_RAX);
                }

                /* Check if this is the first invalid topology sub-leaf.  The shift count
                    saved from the previous level indicates the shift count for
                    getting the package number.
                 */
                if (prev_level_type != LEVEL_TYPE_INVALID)
                {

                    tdx_sanity_check(shift_count != (uint32_t)-1,
                                     SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF), 1);
                    tdx_sanity_check(lpids_sharing_l3_cache != (uint32_t)-1,
                                     SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF), 2);

                    /* This is the first invalid topology sub-leaf.  The shift count
                       saved from the previous level indicates the shift count for
                       getting the package number.
                     */
                    global_data_ptr->x2apic_pkg_id_shift_count = shift_count;

                    // Calculate the core ID mask
                    tdx_sanity_check((shift_count - global_data_ptr->x2apic_core_id_shift_count) < 32,
                            SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF), 10);
                    global_data_ptr->x2apic_core_id_mask =
                            (uint32_t)(BIT(shift_count - global_data_ptr->x2apic_core_id_shift_count)) - 1U;

                    /* Verify that L3 cache is shared across package:
                       According to the Intel SDM description of CPUID leaf 4:
                       "The nearest power-of-2 integer that is not smaller than
                       (1 + EAX[25:14]) is the number of unique initial APIC IDs
                       reserved for addressing different logical processors sharing
                       this cache."
                       Thus, the value of lpids_sharing_l3_cache must fit within
                       shift_count bits, and its most significant bit must
                       be 1.
                     */
                    if ((lpids_sharing_l3_cache >> (shift_count - 1)) != (uint32_t)0x00000001)
                    {
                        TDX_ERROR("invalid wbinvd scope\n");
                        return TDX_INVALID_WBINVD_SCOPE;
                    }
                }
            }
        }
        else if (cpuid_config.leaf_subleaf.leaf == CPUID_MAX_EXTENDED_VAL_LEAF)
        {
            if (cpuid_config.values.eax < CPUID_LAST_EXTENDED_LEAF)
            {
                return api_error_with_operand_id(TDX_CPUID_LEAF_NOT_SUPPORTED, CPUID_LAST_EXTENDED_LEAF);
            }
            tdx_sanity_check(cpuid_config.values.eax >= CPUID_MAX_EXTENDED_VAL_LEAF, SCEC_SEAMCALL_SOURCE(TDH_SYS_INIT_LEAF), 4);
            global_data_ptr->cpuid_last_extended_leaf = cpuid_config.values.eax;
        }
        else if (cpuid_config.leaf_subleaf.leaf == CPUID_GET_MAX_PA_LEAF)
        {
            global_data_ptr->max_pa = MAX_PA;
        }

        global_data_ptr->cpuid_values[i] = cpuid_config;
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_capabilities_msrs(tdx_module_global_t* global_data_ptr)
{
    platform_common_config_t* msr_values_ptr = &global_data_ptr->plt_common_config;

    // Sample and Check Capabilities MSRs
    global_data_ptr->plt_common_config.ia32_core_capabilities.raw = ia32_rdmsr(IA32_CORE_CAPABILITIES);

    msr_values_ptr->ia32_arch_capabilities.raw = ia32_rdmsr(IA32_ARCH_CAPABILITIES_MSR_ADDR);
    if ((msr_values_ptr->ia32_arch_capabilities.rdcl_no == 0) ||
        (msr_values_ptr->ia32_arch_capabilities.irbs_all == 0) ||
        (msr_values_ptr->ia32_arch_capabilities.mds_no == 0) ||
        (msr_values_ptr->ia32_arch_capabilities.if_pschange_mc_no == 0) ||
        (msr_values_ptr->ia32_arch_capabilities.taa_no == 0) ||
        (msr_values_ptr->ia32_arch_capabilities.misc_package_ctls == 0) ||
        (msr_values_ptr->ia32_arch_capabilities.skip_l1dfl_vmentry == 0) ||
        (msr_values_ptr->ia32_arch_capabilities.energy_filtering_ctl == 0))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_ARCH_CAPABILITIES_MSR_ADDR);
    }

    if (msr_values_ptr->ia32_arch_capabilities.tsx_ctrl)
    {
        msr_values_ptr->ia32_tsx_ctrl.raw = ia32_rdmsr(IA32_TSX_CTRL_MSR_ADDR);
        if ((msr_values_ptr->ia32_tsx_ctrl.rtm_disable == 1) ||
            (msr_values_ptr->ia32_tsx_ctrl.tsx_cpuid_clear == 1))
        {
            return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_TSX_CTRL_MSR_ADDR);
        }
    }

    return TDX_SUCCESS;
}


_STATIC_INLINE_ bool_t check_cmrs()
{
    /*----------------------------------------------------------------
      Defense-in-depth sanity check on the CMR list provided by MCHECK
      ----------------------------------------------------------------*/
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    uint64_t prev_cmr_area_start = 0;
    uint64_t prev_cmr_area_end = 0;


    for (uint32_t i = 0; i < MAX_CMR; i++)
    {
        if (sysinfo_table->cmr_data[i].cmr_size > 0)
        {
            if (!is_valid_integer_range(sysinfo_table->cmr_data[i].cmr_base,
                                        sysinfo_table->cmr_data[i].cmr_size))
            {
                return false;
            }

            uint64_t cmr_area_start = sysinfo_table->cmr_data[i].cmr_base;
            uint64_t cmr_area_end = sysinfo_table->cmr_data[i].cmr_base
                    + sysinfo_table->cmr_data[i].cmr_size-1;

            // CMR ranges should be within the boundaries of the physical address range.
            // taking into account MAX_PA and HKID partitioning (HKID bits must be 0).
            if ((cmr_area_end > BIT(MAX_PA)) || ((cmr_area_end & tdx_global_data_ptr->hkid_mask) != 0) ||
                    ((cmr_area_start & tdx_global_data_ptr->hkid_mask) != 0))
            {
                return false;
            }

            // CMR range should be 4KB-aligned and range size should be a multiple of 4KB (range size is not required to be a power of two)
            if (!is_addr_aligned_any(cmr_area_start, _4KB) ||
                !is_addr_aligned_any(sysinfo_table->cmr_data[i].cmr_size,_4KB))
            {
                return false;
            }

            // CMR ranges must be ordered by a start address and must not overlap each other
            if (prev_cmr_area_end > 0 && (prev_cmr_area_start > cmr_area_start ||
                                          prev_cmr_area_end > cmr_area_start))
            {
                return false;
            }

            prev_cmr_area_start = cmr_area_start;
            prev_cmr_area_end = cmr_area_end;
        }

    }
    return true;
}

_STATIC_INLINE_ api_error_type check_vmx_msrs(tdx_module_global_t* tdx_global_data_ptr)
{
    platform_common_config_t* msr_values_ptr = &tdx_global_data_ptr->plt_common_config;

    td_vmcs_values_t* td_vmcs_values_ptr = &tdx_global_data_ptr->td_vmcs_values;

    msr_values_ptr->ia32_vmx_basic.raw = ia32_rdmsr(IA32_VMX_BASIC_MSR_ADDR);
    if ((msr_values_ptr->ia32_vmx_basic.vmcs_region_size > TD_VMCS_SIZE) ||
        (msr_values_ptr->ia32_vmx_basic.vmexit_info_on_ios != 1) ||
        (msr_values_ptr->ia32_vmx_basic.default_1_controls_clear != 1))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_BASIC_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_true_pinbased_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->pinbased_ctls, msr_values_ptr->ia32_vmx_true_pinbased_ctls,
            PINBASED_CTLS_INIT,
            PINBASED_CTLS_VARIABLE,
            PINBASED_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_true_procbased_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->procbased_ctls, msr_values_ptr->ia32_vmx_true_procbased_ctls,
            PROCBASED_CTLS_INIT,
            PROCBASED_CTLS_VARIABLE,
            PROCBASED_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR);
    }

    /*
     * procbased_ctls2 is a special case since: 
     * it depends on WAITPKG support.
     * It depends on the CPU support of ENCLV exiting.
     */
    vmcs_procbased_ctls2_t procbased_ctls2_init = {.raw = PROCBASED_CTLS2_INIT};
    procbased_ctls2_init.en_guest_wait_pause = tdx_global_data_ptr->waitpkg_supported;

    msr_values_ptr->ia32_vmx_procbased_ctls2.raw = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    
    vmcs_procbased_ctls2_t procbased_ctls2_allowed1 = {.raw = tdx_global_data_ptr->plt_common_config.ia32_vmx_procbased_ctls2.allowed1};
    if (!procbased_ctls2_allowed1.en_enclv_exiting)
    {
        procbased_ctls2_init.en_enclv_exiting = 0;
    }
             
    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->procbased_ctls2, msr_values_ptr->ia32_vmx_procbased_ctls2,
            procbased_ctls2_init.raw,
            PROCBASED_CTLS2_VARIABLE,
            PROCBASED_CTLS2_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_PROCBASED_CTLS2_MSR_ADDR);
    }

    vmcs_procbased_ctls3_t procbased_ctls3_init = {.raw = PROCBASED_CTLS3_INIT};

    msr_values_ptr->ia32_vmx_procbased_ctls3 = ia32_rdmsr(IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    if (!check_allowed1_vmx_ctls(&td_vmcs_values_ptr->procbased_ctls3, msr_values_ptr->ia32_vmx_procbased_ctls3,
            procbased_ctls3_init.raw,
            PROCBASED_CTLS3_VARIABLE,
            PROCBASED_CTLS3_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_PROCBASED_CTLS3_MSR_ADDR);
    }

    uint32_t exit_ctls_variable = EXIT_CTLS_VARIABLE;
    msr_values_ptr->ia32_vmx_true_exit_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);

    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->exit_ctls, msr_values_ptr->ia32_vmx_true_exit_ctls,
            EXIT_CTLS_INIT,
            exit_ctls_variable,
            EXIT_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_true_entry_ctls.raw = ia32_rdmsr(IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    if (!check_allowed_vmx_ctls(&td_vmcs_values_ptr->entry_ctls, msr_values_ptr->ia32_vmx_true_entry_ctls,
            ENTRY_CTLS_INIT,
            ENTRY_CTLS_VARIABLE,
            ENTRY_CTLS_UNKNOWN))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_ept_vpid_cap = ia32_rdmsr(IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    if ((msr_values_ptr->ia32_vmx_ept_vpid_cap & IA32_VMX_EPT_VPID_CAP_MASK) != IA32_VMX_EPT_VPID_CAP_MASK)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_EPT_VPID_CAP_MSR_ADDR);
    }

    ia32_cr0_t cr0_fixed0;
    cr0_fixed0.raw = ia32_rdmsr(IA32_VMX_CR0_FIXED0_MSR_ADDR);
    msr_values_ptr->ia32_vmx_cr0_fixed0.raw = cr0_fixed0.raw;
    cr0_fixed0.pe = 0;
    cr0_fixed0.pg = 0;
    if ((cr0_fixed0.raw & (uint64_t)~GUEST_CR0_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR0_FIXED0_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_cr0_fixed1.raw = ia32_rdmsr(IA32_VMX_CR0_FIXED1_MSR_ADDR);
    if ((~msr_values_ptr->ia32_vmx_cr0_fixed1.raw & GUEST_CR0_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR0_FIXED1_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_cr4_fixed0.raw = ia32_rdmsr(IA32_VMX_CR4_FIXED0_MSR_ADDR);
    if ((msr_values_ptr->ia32_vmx_cr4_fixed0.raw & (uint64_t)~GUEST_CR4_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR4_FIXED0_MSR_ADDR);
    }

    msr_values_ptr->ia32_vmx_cr4_fixed1.raw = ia32_rdmsr(IA32_VMX_CR4_FIXED1_MSR_ADDR);
    if ((~msr_values_ptr->ia32_vmx_cr4_fixed1.raw & GUEST_CR4_INIT) != 0)
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_VMX_CR4_FIXED1_MSR_ADDR);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type check_platform_config_and_cpu_enumeration(
        tdx_module_global_t* tdx_global_data_ptr)
{

    api_error_type err;

    /*------------------------------------------
      Sample and Check capabilities MSRs
      ------------------------------------------*/
    if ((err = check_capabilities_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Check capabilities MSRs failure\n");
        return err;
    }

    /*------------------------------------------
      Sample and Check Native CPUID Values
      ------------------------------------------*/
    if ((err = check_cpuid_configurations(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("check_cpuid_configurations failure\n");
        return err;
    }

    /*------------------------------------------
      Sample and Check IA32_VMX_* MSRs
      ------------------------------------------*/
    if ((err = check_vmx_msrs(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Check of IA32 VMX MSRs failed\n");
        return err;
    }

    /*---------------------------------------------------
        Sample and Check Key Management Configuration
    ---------------------------------------------------*/
    if ((err = check_key_management_config(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Check of key management configuration failed\n");
        return err;
    }

    /*--------------------------------------------
                  Time Stamp Counter
    --------------------------------------------*/
    // Sample IA32_TSC_ADJUST
    // This MSR should read the same value on all LP on TDSYSINITLP and during
    // TDX-SEAM operation on TDHVPENTER and other flows that rely on rdtsc.
    tdx_global_data_ptr->plt_common_config.ia32_tsc_adjust = ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR);

    /*---------------------------------------------------
        Sanity check on CMR info provided by MCHECK
    ---------------------------------------------------*/
    if (!check_cmrs())
    {
        err = TDX_CMR_LIST_INVALID;
        return err;
    }

    //Check SMRRs and store in global data
    if ((err = check_and_store_smrr_smrr2(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("check_and_store_smrr_smrr2 failure\n");
        return err;
    }

    // Check Performance Monitoring - Support of IA32_A_PMC MSRs
    if ((err = check_perf_msrs()) != TDX_SUCCESS)
    {
        TDX_ERROR("Check of IA32 PERF MSRs failed\n");
        return err;
    }

    return TDX_SUCCESS;
}


_STATIC_INLINE_ void tdx_init_global_data(tdx_module_global_t* tdx_global_data_ptr)
{

    sysinfo_table_t* sysinfo_table_ptr = get_sysinfo_table();

    //NUM_LPS
    tdx_global_data_ptr->num_of_lps = sysinfo_table_ptr->mcheck_fields.tot_num_lps;

    //NUM_PKGS
    tdx_global_data_ptr->num_of_pkgs = sysinfo_table_ptr->mcheck_fields.tot_num_sockets;

    //NUM_INIT_PKGS
    tdx_global_data_ptr->num_of_init_pkgs = (uint32_t)0;

    tdx_global_data_ptr->pkg_config_bitmap = (uint32_t)0;

    // INIT SEAMRR base and size
    tdx_global_data_ptr->seamrr_base = ia32_rdmsr(IA32_SEAMRR_BASE_MSR_ADDR) & IA32_SEAMRR_BASE_AND_MASK_MASK;

    uint64_t seamrr_mask = ia32_rdmsr(IA32_SEAMRR_MASK_MSR_ADDR) & IA32_SEAMRR_BASE_AND_MASK_MASK;
    tdx_global_data_ptr->seamrr_size = mask_to_size(seamrr_mask);

    tdx_global_data_ptr->num_of_init_lps = 0;

    tdx_global_data_ptr->global_state.sys_state = SYSINIT_DONE;

    tdx_global_data_ptr->shutdown_host_rip = sysinfo_table_ptr->shutdown_host_rip;

    // XBUF
    tdx_global_data_ptr->xbuf.xsave_header.xstate_bv = 0;
    tdx_global_data_ptr->xbuf.xsave_header.xcomp_bv = BIT(63);
    basic_memset_to_zero(&tdx_global_data_ptr->xbuf.xsave_header.reserved, sizeof(tdx_global_data_ptr->xbuf.xsave_header.reserved));
}

_STATIC_INLINE_ api_error_type tdx_init_stack_canary(void)
{
    ia32_rflags_t rflags = {.raw = 0};
    uint64_t canary;
    if (!ia32_rdrand(&rflags, &canary))
    {
        return TDX_SYS_BUSY;
    }


    sysinfo_table_t* sysinfo_table = get_sysinfo_table();
    uint64_t last_page_addr = sysinfo_table->data_rgn_base + sysinfo_table->data_rgn_size - _4KB;
    sysinfo_table_t* last_page_ptr = (sysinfo_table_t*)(last_page_addr);

    last_page_ptr->stack_canary.canary = canary;
    ia32_vmwrite(VMX_HOST_FS_BASE_ENCODE, last_page_addr);

    //Copy SYS_INFO_TABLE information that is being used in other flows
    for (uint64_t i = 0; i < MAX_CMR; i++)
    {
        last_page_ptr->cmr_data[i].cmr_base = sysinfo_table->cmr_data[i].cmr_base;
        last_page_ptr->cmr_data[i].cmr_size = sysinfo_table->cmr_data[i].cmr_size;
    }
    last_page_ptr->code_rgn_base = sysinfo_table->code_rgn_base;
    last_page_ptr->code_rgn_size = sysinfo_table->code_rgn_size;
    last_page_ptr->data_rgn_base = sysinfo_table->data_rgn_base;
    last_page_ptr->data_rgn_size = sysinfo_table->data_rgn_size;
    last_page_ptr->keyhole_edit_rgn_base = sysinfo_table->keyhole_edit_rgn_base;
    last_page_ptr->keyhole_edit_rgn_size = sysinfo_table->keyhole_edit_rgn_size;
    last_page_ptr->keyhole_rgn_base = sysinfo_table->keyhole_rgn_base;
    last_page_ptr->keyhole_rgn_size = sysinfo_table->keyhole_rgn_size;
    last_page_ptr->num_stack_pages = sysinfo_table->num_stack_pages;
    last_page_ptr->num_tls_pages = sysinfo_table->num_tls_pages;
    last_page_ptr->seam_status = sysinfo_table->seam_status;
    last_page_ptr->shutdown_host_rip = sysinfo_table->shutdown_host_rip;
    last_page_ptr->stack_rgn_base = sysinfo_table->stack_rgn_base;
    last_page_ptr->stack_rgn_size = sysinfo_table->stack_rgn_size;

    return TDX_SUCCESS;
}

api_error_type tdh_sys_init(sys_attributes_t tmp_sys_attributes)
{
    bool_t global_lock_acquired = false;
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    tdx_module_local_t *tdx_local_data_ptr = get_local_data();
    api_error_type retval = TDX_SYS_BUSY;
    api_error_type err;

    td_param_attributes_t attributes_fixed0;
    td_param_attributes_t attributes_fixed1;

    tdx_local_data_ptr->vmm_regs.rcx = 0;
    tdx_local_data_ptr->vmm_regs.rdx = 0;
    tdx_local_data_ptr->vmm_regs.r8 = 0;
    tdx_local_data_ptr->vmm_regs.r9 = 0;
    tdx_local_data_ptr->vmm_regs.r10 = 0;

    // Acquire an exclusive lock to the whole TDX-SEAM module
    if (acquire_sharex_lock_ex(&tdx_global_data_ptr->global_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire global lock\n");
        retval = TDX_SYS_BUSY;
        goto EXIT;
    }
    global_lock_acquired = true;

    //Check module attributes
    if (tmp_sys_attributes.reserved != 0)
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }
    tdx_global_data_ptr->sys_attributes.raw = tmp_sys_attributes.raw;

    // Check the system state
    if (tdx_global_data_ptr->global_state.sys_state != SYSINIT_PENDING)
    {
        TDX_ERROR("Wrong sys_init state: %d\n", tdx_global_data_ptr->global_state.sys_state);
        retval = TDX_SYS_INIT_NOT_PENDING;
        goto EXIT;
    }

    // Boot NT4 bit should not be set
    if ((ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) & MISC_EN_BOOT_NT4_BIT ) != 0)
    {
        retval = TDX_BOOT_NT4_SET;
        goto EXIT;
    }

    if ((err = check_platform_config_and_cpu_enumeration(tdx_global_data_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check and config CPU enumeration\n");
        retval = err;
        goto EXIT;
    }

    /*
     * Calculate allowed ATTRIBUTES bits.
     */
    attributes_fixed0.raw = TDX_ATTRIBUTES_FIXED0;
    attributes_fixed1.raw = TDX_ATTRIBUTES_FIXED1;

    tdx_global_data_ptr->attributes_fixed0 = attributes_fixed0.raw;
    tdx_global_data_ptr->attributes_fixed1 = attributes_fixed1.raw;

    if (tdx_init_stack_canary() != TDX_SUCCESS)
    {
        retval = TDX_SYS_BUSY;
        goto EXIT;
    }

    tdx_init_global_data(tdx_global_data_ptr);

    retval = TDX_SUCCESS;

    EXIT:
    if (global_lock_acquired)
    {
        release_sharex_lock_ex(&tdx_global_data_ptr->global_lock);
    }
    return retval;
}

