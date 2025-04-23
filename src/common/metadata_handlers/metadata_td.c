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
 * @file metadata_td.c
 * @brief TD-context (TDR and TDCS) metadata handler
 */

#include "metadata_generic.h"
#include "metadata_td.h"
#include "auto_gen/tdvps_fields_lookup.h"
#include "auto_gen/td_vmcs_fields_lookup.h"
#include "auto_gen/cpuid_configurations.h"
#include "helpers/error_reporting.h"
#include "helpers/helpers.h"
#include "helpers/virt_msr_helpers.h"
#include "accessors/ia32_accessors.h"
#include "helpers/cpuid_fms.h"

_STATIC_INLINE_ uint64_t get_element_num(md_field_id_t field_id, const md_lookup_t* entry, uint32_t cpuid_lookup_index)
{
    tdx_debug_assert(entry->field_id.inc_size == 0);

    IF_RARE (field_id.class_code == MD_TDCS_CPUID_CLASS_CODE)
    {
        tdx_sanity_check(cpuid_lookup_index < MAX_NUM_CPUID_LOOKUP, SCEC_METADATA_HANDLER_SOURCE, 10);

        // Check that element size is really 8 byte, so we can use sizeof(uint64_t)
        tdx_debug_assert(entry->field_id.element_size_code == 3);

        return field_id.cpuid_field_code.element +
               (cpuid_lookup_index * (sizeof(cpuid_config_return_values_t) / sizeof(uint64_t)));
    }

    return field_id.field_code - entry->field_id.field_code;
}

static uint64_t translate_hp_lock_timeout_to_usec(uint64_t timeout_in_tsc_ticks)
{
    uint64_t timeout_in_usec;

    // Assert that the casting below is safe
    tdx_sanity_check((get_global_data()->native_tsc_frequency <= BIT_MASK_32BITS), SCEC_METADATA_HANDLER_SOURCE, 25);

    // Avoid overflow in the calculation below (should not happen but better safe than sorry)
    if (timeout_in_tsc_ticks >= (BIT_MASK_64BITS / 1000000ULL))
    {
        timeout_in_tsc_ticks = (BIT_MASK_64BITS / 1000000ULL);
    }

    // The order of calculation is important to avoid underflow.
    timeout_in_usec = ((uint64_t)timeout_in_tsc_ticks * 1000000ULL) / get_global_data()->native_tsc_frequency;

    return timeout_in_usec;
}

static uint64_t check_hp_lock_timeout_and_translate_to_tsc(uint64_t timeout, uint64_t* tsc)
{
    // The timeout value, which is provided in usec units but stored as TSC tick units.
    // The timeout is stored as unsigned 32-bit but calculation is done in 64-bit to avoid overflow.
    // The order of calculation is important to avoid underflow.

    if ((timeout > MAX_HP_LOCK_TIMEOUT_USEC) || (timeout < MIN_HP_LOCK_TIMEOUT_USEC))
    {
        return false;
    }
    uint64_t native_tsc_frequency = get_global_data()->native_tsc_frequency;
    tdx_sanity_check((native_tsc_frequency <= BIT_MASK_32BITS), SCEC_METADATA_HANDLER_SOURCE, 26);

    // safe to cast due to the sanity check above
    uint64_t tsc_tmp = translate_usec_to_tsc((uint32_t)timeout, (uint32_t)native_tsc_frequency);

    *tsc = (uint32_t)tsc_tmp;

    return true;
}

static bool_t check_cpuid_xfam_masks(cpuid_config_return_values_t* cpuid_values,
                                     uint64_t xfam,
                                     const cpuid_config_return_values_t* cpuid_masks)
{
    uint64_t xfam_mask;   // 1-bit mask

    xfam_mask = 1ULL;
    for (uint32_t xfam_bit = 0; xfam_bit <= XCR0_MAX_VALID_BIT; xfam_bit++)
    {
        if ((xfam & xfam_mask) == 0)
        {
            // Loop on all 4 CPUID values
            for (uint32_t i = 0; i < 4; i++)
            {
                if (cpuid_values->values[i] & cpuid_masks[xfam_bit].values[i])
                {
                    return false;
                }
            }
        }
        xfam_mask <<= 1;
    }

    return true;
}

static bool_t check_cpuid_compatibility_and_set_flags(tdcs_t* tdcs_ptr, uint32_t leaf, uint32_t subleaf,
                                                      cpuid_config_return_values_t cpuid_values, uint32_t cpuid_index)
{
    td_param_attributes_t attributes;
    ia32_xcr0_t xfam;
    tdx_module_global_t* global_data_ptr = get_global_data();

    attributes.raw = tdcs_ptr->executions_ctl_fields.attributes.raw;
    xfam.raw = tdcs_ptr->executions_ctl_fields.xfam;

    if (cpuid_index == CPUID_LOOKUP_IDX_NA)
    {
        return false;
    }

    // CPUID leaves/sub-leaves that are CONFIG_DIRECT or ALLOW_DIRECT
    // Note: The following code assumes these are the first NUM_CONFIG entries
    // of the whole NUM_LOOKUP entries in the various CPUID tables.

    // Loop on all 4 CPUID values
    for (uint32_t i = 0; i < 4; i++)
    {
        uint32_t cpuid_value = cpuid_values.values[i];

        // Any bit whose value is 1 must not be FIXED_0 or DYNAMIC
        if ((cpuid_value & cpuid_lookup[cpuid_index].fixed0_or_dynamic.values[i]) != 0)
        {
            return false;
        }

        // Any bit whose value is 0 must not be FIXED_1
        if ((~cpuid_value & cpuid_lookup[cpuid_index].fixed1.values[i]) != 0)
        {
            return false;
        }

        uint32_t config_index = cpuid_lookup[cpuid_index].config_index;

        // configurable (CONFIG_DIRECT or ALLOW_DIRECT) CPUID leaf/sub-leaf
        if (config_index != CPUID_CONFIG_NULL_IDX)
        {
            // Any bit whose value is 1 and is ALLOW_DIRECT must be natively 1
            uint32_t masked_cpuid_value = cpuid_value & cpuid_configurable[config_index].allow_direct.values[i];
            if (masked_cpuid_value != (masked_cpuid_value & global_data_ptr->cpuid_values[cpuid_index].values.values[i]))
            {
                return false;
            }
        }
    }

    // Special CPUID Leafs/Sub-Leafs Handling
    // - Check bits that are not allowed by XFAM
    // - Check bits that are not allowed by ATTRIBUTES (KL, PERFMON etc.)
    // - Record CPUID flags that will be used for MSR virtualization and TD entry/exit.

    if (leaf == CPUID_VER_INFO_LEAF)
    {
        //  CPUID(1).EAX is the virtual Family/Model/Stepping configuration
        fms_info_t cpuid_01_eax = { .raw = cpuid_values.eax };

        if (!check_fms_config(cpuid_01_eax))
        {
            // The configured F/M/S value is not valid
            return false;
        }

        // Leaf 0x1 has ECX bits configurable by AVX (XFAM[2]).
        // If XFAM[2] is 0, the applicable bits must be 0.
        if (!xfam.avx && (cpuid_values.ecx & xfam_mask_0x1_0xffffffff[2].ecx))
        {
            return false;
        }

        cpuid_01_ecx_t cpuid_01_ecx;
        cpuid_01_ecx.raw = cpuid_values.ecx;

        tdcs_ptr->executions_ctl_fields.cpuid_flags.monitor_mwait_supported = cpuid_01_ecx.monitor;
        tdcs_ptr->executions_ctl_fields.cpuid_flags.dca_supported = cpuid_01_ecx.dca;
        tdcs_ptr->executions_ctl_fields.cpuid_flags.tsc_deadline_supported = cpuid_01_ecx.tsc_deadline;
    }
    else if (leaf == 0x5)
    {
        // CPUID(5) is virtualized as ALLOW_CPUID, based on CPUID(1).ECX(3) (MONITOR)
        // which was checked above.  On import, if enabled, the following checks are done:
        // - Virtual CPUID(5) bits that are known by the TDX module to be reserved are checked to be 0.
        //   This was done above.
        // - Virtual CPUID(5) bits that are not known by the TDX module to be reserved are checked for exact
        //   match with the native CPUID(5) values.
        if (tdcs_ptr->executions_ctl_fields.cpuid_flags.monitor_mwait_supported)
        {
            // MONITOR/MWAIT is supported, CPUID(5) is expected to be
            for (uint32_t i = 0; i < 4; i++)
            {
                // Compare to the native value and mask out fixed-0 bits
                if (((cpuid_values.values[i] ^ global_data_ptr->cpuid_values[cpuid_index].values.values[i]) &
                     ~cpuid_lookup[cpuid_index].fixed0_or_dynamic.values[i]) != 0)
                {
                    return false;
                }
            }
        }
        else
        {
            // MONITOR/MWAIT is not supported, CPUID(5) is expected to be all-0
            if ((cpuid_values.low != 0) || (cpuid_values.high != 0))
            {
                return false;
            }
        }
    }
    else if (leaf == CPUID_EXT_FEATURES_LEAF)
    {
        // Sub-leaves 0 and 1 have bits configurable by multiple XFAM bits.
        // If an XFAM bit is 0, the applicable CPUID values bits are cleared.
        if (subleaf == CPUID_EXT_FEATURES_SUBLEAF)
        {
            cpuid_07_00_ebx_t cpuid_07_00_ebx;
            cpuid_07_00_ecx_t cpuid_07_00_ecx;
            cpuid_07_00_edx_t cpuid_07_00_edx;

            if (!check_cpuid_xfam_masks(&cpuid_values, xfam.raw, xfam_mask_0x7_0x0))
            {
                return false;
            }

            cpuid_07_00_ebx.raw = cpuid_values.ebx;
            // Both CPUID bits that enumerate TSX must have the same virtual value
            if (cpuid_07_00_ebx.hle != cpuid_07_00_ebx.rtm)
            {
                return false;
            }

            // To support HLE, IA32_TSX_CTRL MSR must exist
            if (cpuid_07_00_ebx.hle && !global_data_ptr->plt_common_config.ia32_arch_capabilities.tsx_ctrl)
            {
                return false;
            }

            tdcs_ptr->executions_ctl_fields.cpuid_flags.tsx_supported = cpuid_07_00_ebx.hle;
            cpuid_07_00_ecx.raw = cpuid_values.ecx;

            if (cpuid_07_00_ecx.pks != attributes.pks || cpuid_07_00_ecx.kl_supported != 0)
            {
                return false;
            }

            tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported = cpuid_07_00_ecx.waitpkg;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.tme_supported = cpuid_07_00_ecx.tme;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.la57_supported = cpuid_07_00_ecx.la57;

            cpuid_07_00_edx.raw = cpuid_values.edx;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.pconfig_supported = cpuid_07_00_edx.pconfig_mktme;
       }
       else if (subleaf == 1)
       {
            if (!check_cpuid_xfam_masks(&cpuid_values, xfam.raw, xfam_mask_0x7_0x1))
            {
                return false;
            }

            cpuid_07_01_eax_t cpuid_07_01_eax;
            cpuid_07_01_eax.raw = cpuid_values.eax;

            if (cpuid_07_01_eax.lass != attributes.lass)
            {
                return false;
            }

            tdcs_ptr->executions_ctl_fields.cpuid_flags.perfmon_ext_leaf_supported = cpuid_07_01_eax.perfmon_ext_leaf;
       }
       else if (subleaf == 2)
       {
            // Check CPU side channel protection support
           cpuid_07_02_edx_t cpuid_07_02_edx;
           cpuid_07_02_edx.raw = cpuid_values.edx;
           tdcs_ptr->executions_ctl_fields.cpuid_flags.ddpd_supported = cpuid_07_02_edx.ddpd;

           // The TD will never be configured with DDPD support if the CPU doesn't support DDPD
           tdx_debug_assert(!tdcs_ptr->executions_ctl_fields.cpuid_flags.ddpd_supported ||
                            global_data_ptr->ddpd_supported);

           // IA32_SPEC_CTRL virtualization is required in the following case:
           //  - The TD is configured without DDPD support, and
           //  - The CPU supports DDPD
           // Because in this case we enable DDPD without the TD knowing about this.
           tdx_debug_assert(tdcs_ptr->executions_ctl_fields.cpuid_flags.ddpd_supported ||
                            !global_data_ptr->ddpd_supported ||
                            global_data_ptr->plt_common_config.ia32_vmx_procbased_ctls3.virt_ia32_spec_ctrl);
       }
       else
       {
           // Should never get here, this sub-leaf is faulting
           return false;
       }
    }
    else if (leaf == CPUID_PERFMON_LEAF)
    {
        if (cpuid_values.low || cpuid_values.high)
        {
            return false;
        }
    }
    else if (leaf == CPUID_EXT_STATE_ENUM_LEAF)
    {
        if (subleaf == 0)
        {
            if (!check_cpuid_xfam_masks(&cpuid_values, xfam.raw, xfam_mask_0xd_0x0) ||
                cpuid_values.ecx != calculate_xsave_area_max_size(xfam))
            {
                return false;
            }
        }
        else if (subleaf == 1)
        {
            cpuid_0d_01_eax_t cpuid_0d_01_eax;
            cpuid_0d_01_eax.raw = cpuid_values.eax;

            if (!check_cpuid_xfam_masks(&cpuid_values, xfam.raw, xfam_mask_0xd_0x1) ||
                (!global_data_ptr->xfd_supported && cpuid_0d_01_eax.xfd_support))
            {
                return false;
            }

            tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported = cpuid_0d_01_eax.xfd_support;
        }
        else if (subleaf <= XCR0_MAX_VALID_BIT)
        {
            // Each sub-leaf n, where 2 <= n <= 18, is configured by XFAM[n]
            if (((xfam.raw & BIT(subleaf)) == 0) && (cpuid_values.low != 0 || cpuid_values.high != 0))
            {
                return false;
            }
        }
    }
    else if (leaf == 0x14)
    {
        if (!xfam.pt && (cpuid_values.low != 0 || cpuid_values.high != 0))
        {
            return false;
        }
    }
    else if (leaf == CPUID_TSC_ATTRIBUTES_LEAF)
    {
        // The following check relies on TSC_FREQUENCY to be imported before CPUID configuration.
        tdx_debug_assert(tdcs_ptr->executions_ctl_fields.tsc_frequency != 0);

        if (cpuid_values.ebx != (uint32_t)tdcs_ptr->executions_ctl_fields.tsc_frequency)
        {
            return false;
        }
    }
    else if (leaf == CPUID_KEYLOCKER_ATTRIBUTES_LEAF)
    {
        if (cpuid_values.low != 0 || cpuid_values.high != 0)
        {
            return false;
        }
    }
    else if (leaf == 0x1A)
    {
        // For migratable TDs, native model information is N/A, and should have been set to 0.
        // This information is used for Perfmon, which is not enabled for migratable TDs.
        if (cpuid_values.low != 0 || cpuid_values.high != 0)
        {
            return false;
        }
    }
    else if (leaf == 0x1C)
    {
        // Leaf 0x1C is wholly configured by LBR (XFAM[15])
        if (xfam.lbr == 0 && (cpuid_values.low != 0 || cpuid_values.high != 0))
        {
            return false;
        }
    }
    else if (leaf == 0x1D)
    {
        // Leaf 0x1D is wholly configured by AMX (XFAM[18:17])
        if ((!xfam.amx_xtilecfg || !xfam.amx_xtiledata) && (cpuid_values.low != 0 || cpuid_values.high != 0))
        {
            return false;
        }
    }
    else if (leaf == 0x23)
    {
        // Leaf 0x23's values are defined as "ALLOW_ATTRIBUTES(PERFMON)", i.e., if ATTRRIBUTES.PERFMON
        // is set they return the native values, else they return 0.
        if (!attributes.perfmon || !tdcs_ptr->executions_ctl_fields.cpuid_flags.perfmon_ext_leaf_supported)
        {
            if (cpuid_values.low != 0 || cpuid_values.high != 0)
            {
                return false;
            }
        }
    }
    else if (leaf == 0x80000008)
    {
        cpuid_80000008_eax_t cpuid_80000008_eax = { .raw = cpuid_values.eax };

        if (!is_virt_maxpa_on_import_valid(cpuid_80000008_eax.pa_bits))
        {
            return false;
        }

        // Save the virtual MAXPA for easy access
        tdcs_ptr->executions_ctl_fields.virt_maxpa = cpuid_80000008_eax.pa_bits;
    }

    tdcs_ptr->executions_ctl_fields.cpuid_valid[cpuid_index] = true;

    return true;
}

_STATIC_INLINE_ bool_t write_element_by_size(void* elem_ptr, uint64_t rd_value, uint64_t wr_value,
                                             uint64_t wr_mask, uint64_t size)
{
    uint64_t new_value = (rd_value & ~wr_mask) | (wr_value & wr_mask);
    bool_t success = false;

    if (size == 1)
    {
        success = (_lock_cmpxchg_8bit((uint8_t)rd_value, (uint8_t)new_value, elem_ptr) == (uint8_t)rd_value);
    }
    else if (size == 2)
    {
        success = (_lock_cmpxchg_16b((uint16_t)rd_value, (uint16_t)new_value, elem_ptr) == (uint16_t)rd_value);
    }
    else if (size == 4)
    {
        success = (_lock_cmpxchg_32b((uint32_t)rd_value, (uint32_t)new_value, elem_ptr) == (uint32_t)rd_value);
    }
    else if (size == 8)
    {
        success = (_lock_cmpxchg_64b((uint64_t)rd_value, (uint64_t)new_value, elem_ptr) == (uint64_t)rd_value);
    }

    return success;
}

static api_error_code_e md_td_get_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx,
        uint64_t* out_rd_mask, uint64_t* out_wr_mask, uint64_t* out_rd_value, uint64_t** out_elem_ptr)
{
    uint64_t rd_mask = 0, wr_mask = 0;
    uint64_t read_value;

    uint8_t* page_ptr = NULL;
    uint32_t cpuid_lookup_index = 0;

    md_get_rd_wr_mask(entry, access_type, access_qual, &rd_mask, &wr_mask);

    switch (field_id.class_code)
    {
        case MD_TDR_TD_MANAGEMENT_CLASS_CODE:
        case MD_TDR_KEY_MANAGEMENT_CLASS_CODE:
        case MD_TDR_TD_PRESERVING_CLASS_CODE:
        {
            page_ptr = (uint8_t*)md_ctx.tdr_ptr;
            break;
        }
        case MD_TDCS_CPUID_CLASS_CODE:
        {
            // Check the CPUID field validity
            if (field_id.cpuid_field_code.reserved != 0)
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            // Check if encoded leaf and subleaf exist in the lookup table
            uint32_t leaf, subleaf;
            md_cpuid_field_id_get_leaf_subleaf(field_id, &leaf, &subleaf);
            cpuid_lookup_index = get_cpuid_lookup_entry(leaf, subleaf);

            if (cpuid_lookup_index >= MAX_NUM_CPUID_LOOKUP)
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            // CPUID leaf/subleaf that is faulting or not valid can't be read
            // This check is not done during import
            if ((access_type != MD_IMPORT_IMMUTABLE) &&
                (cpuid_lookup[cpuid_lookup_index].faulting
                 || !md_ctx.tdcs_ptr->executions_ctl_fields.cpuid_valid[cpuid_lookup_index]))
            {
                return TDX_METADATA_FIELD_NOT_READABLE;
            }

        }
        // No break - fallthrough
        case MD_TDCS_TD_MANAGEMENT_CLASS_CODE:
        case MD_TDCS_EXECUTION_CONTROLS_CLASS_CODE:
        case MD_TDCS_TLB_EPOCH_TRACKING_CLASS_CODE:
        case MD_TDCS_MEASUREMENT_CLASS_CODE:
        case MD_TDCS_SECURE_EPT_ROOT_CLASS_CODE:
        case MD_TDCS_MSR_BITMAPS_CLASS_CODE:
        case MD_TDCS_MIGRATION_CLASS_CODE:
        case MD_TDCS_SERVICE_TD_CLASS_CODE:
        case MD_TDCS_MIGSC_LINKS_CLASS_CODE:
        case MD_TDCS_VIRT_MSR_VALUES_CLASS_CODE:
        case MD_TDCS_X2APIC_IDS_CLASS_CODE:
        {
            page_ptr = (uint8_t*)md_ctx.tdcs_ptr;
            break;
        }
        case MD_TDCS_L2_SECURE_EPT_ROOT__1_CLASS_CODE:
        case MD_TDCS_L2_SECURE_EPT_ROOT__2_CLASS_CODE:
        case MD_TDCS_L2_SECURE_EPT_ROOT__3_CLASS_CODE:
        {
            if (md_ctx.tdcs_ptr->management_fields.num_l2_vms < md_td_get_l2_vm_index(field_id.class_code))
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            page_ptr = (uint8_t*)md_ctx.tdcs_ptr;
            break;
        }
        default:
            return TDX_METADATA_FIELD_ID_INCORRECT;
            break;
    }

    tdx_debug_assert(page_ptr != NULL);

    tdx_debug_assert(entry->field_id.inc_size == 0);

    uint64_t elem_size = BIT(entry->field_id.element_size_code);
    uint64_t elem_num = get_element_num(field_id, entry, cpuid_lookup_index);
    uint64_t offset = entry->offset + (elem_num * elem_size);
    uint64_t* elem_ptr = (uint64_t*)((uint8_t*)page_ptr + offset);

    *out_elem_ptr = elem_ptr;
    read_value = *elem_ptr;

    if (entry->special_rd_handling)
    {
        //----------------------------------
        //     Handle Special Read Cases
        //----------------------------------
        switch (entry->field_id.raw)
        {
            case MD_TDCS_HP_LOCK_TIMEOUT_FIELD_ID:
            {
                read_value = translate_hp_lock_timeout_to_usec(read_value);
                break;
            }
            case MD_TDCS_NUM_CPUID_VALUES_FIELD_ID:
            {
                read_value = MAX_NUM_CPUID_LOOKUP;
                break;
            }
            case MD_TDCS_MIG_ENC_KEY_FIELD_ID:
            {
                // MIG_ENC_KEY is composed of 4 elements. Only the first one above has a special read operation.
                if ((elem_num == 0) &&
                    (access_type == MD_SERV_TD_RD) &&
                    (access_qual.serv_td_qualifier.service_td_type == SERVTD_TYPE_MIGTD))
                {
                    // On every read of MIG_ENC_KEY by a Migration TD, we generate a new random key
                    if (!generate_256bit_random((uint256_t*)&md_ctx.tdcs_ptr->migration_fields.mig_enc_key))
                    {
                        return TDX_RND_NO_ENTROPY;
                    }

                    // Reassign 1st element read value after generation
                    read_value = md_ctx.tdcs_ptr->migration_fields.mig_enc_key.qwords[0];
                }

                break;
            }
            default:
                break;
        }
    }

    *out_rd_mask = rd_mask;
    *out_wr_mask = wr_mask;
    *out_rd_value = read_value & md_get_element_size_mask(entry->field_id.element_size_code);;

    return TDX_SUCCESS;
}

api_error_code_e md_td_read_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t* out_rd_value)
{
    uint64_t rd_mask = 0, wr_mask = 0;
    uint64_t read_value;
    uint64_t* elem_ptr;
    api_error_code_e status;

    status = md_td_get_element(field_id, entry, access_type, access_qual, md_ctx,
                               &rd_mask, &wr_mask, &read_value, &elem_ptr);

    if (status != TDX_SUCCESS)
    {
        return status;
    }

    if (rd_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_READABLE;
    }

    *out_rd_value = read_value & rd_mask;

    return TDX_SUCCESS;
}

api_error_code_e md_td_read_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t value[MAX_ELEMENTS_IN_FIELD])
{
    // Since we read a multiple elements of the same field, we would like to directly access the ptr of
    // the first element of the field, which will save us the time of searching the offset and size
    // of every element in the above if-else blocks.

    uint64_t rd_mask = 0, wr_mask = 0;
    uint64_t read_value;
    uint64_t* elem_ptr;
    api_error_code_e status;

    status = md_td_get_element(field_id, entry, access_type, access_qual, md_ctx,
                               &rd_mask, &wr_mask, &read_value, &elem_ptr);

    if (status != TDX_SUCCESS)
    {
        if ((field_id.class_code == MD_TDCS_CPUID_CLASS_CODE) &&
            (status == TDX_METADATA_FIELD_NOT_READABLE))
        {
            status = TDX_METADATA_FIELD_SKIP;
        }

        return status;
    }

    if (rd_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_READABLE;
    }

    if (entry->special_rd_handling)
    {
        //----------------------------------
        //     Handle Special Read Cases
        //----------------------------------
        switch (entry->field_id.raw)
        {
            case MD_TDCS_VIRTUAL_TSC_FIELD_ID:
                tdx_debug_assert(entry->num_of_elem == 1);
                // Calculate the current virtual TSC, as the guest TD sees it
                value[0] = calculate_virt_tsc(ia32_rdtsc(), md_ctx.tdcs_ptr->executions_ctl_fields.tsc_multiplier,
                                                            md_ctx.tdcs_ptr->executions_ctl_fields.tsc_offset);
                break;
            case MD_TDCS_CPUID_VALUES_FIELD_ID:
                tdx_debug_assert(entry->num_of_elem == 2);
                value[0] = elem_ptr[0];
                value[1] = elem_ptr[1];
                break;
            default:
                // Already handled by md_td_get_element!!!
                tdx_debug_assert(entry->num_of_elem == 1);
                value[0] = read_value;
                break;
        }
    }
    else
    {
        uint64_t first_elem_addr = (uint64_t)elem_ptr;
        uint64_t elem_size = BIT(entry->field_id.element_size_code);

        for (uint16_t i = 0; i < entry->num_of_elem; i++)
        {
            elem_ptr = (uint64_t*)(first_elem_addr + ((uint64_t)i * elem_size));

            value[i] = (*elem_ptr & rd_mask);
        }
    }

    return TDX_SUCCESS;
}

api_error_code_e md_td_write_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t wr_value, uint64_t wr_request_mask,
        uint64_t* old_value)
{
    uint64_t rd_mask = 0, wr_mask = 0, combined_wr_mask = 0;
    uint64_t read_value;
    uint64_t* elem_ptr;
    api_error_code_e status;

    status = md_td_get_element(field_id, entry, access_type, access_qual, md_ctx,
                               &rd_mask, &wr_mask, &read_value, &elem_ptr);

    if (status != TDX_SUCCESS)
    {
        return status;
    }

    // Narrow down the bits to be written with the input mask
    combined_wr_mask = wr_mask & wr_request_mask;

    // Check if the requested field is writable.
    // Note that there is no check for readable; we don't have write-only fields.
    if (combined_wr_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_WRITABLE;
    }

    if (!md_check_forbidden_bits_unchanged(read_value, wr_value, wr_request_mask, wr_mask))
    {
        return TDX_METADATA_FIELD_VALUE_NOT_VALID;
    }

    uint64_t elem_size = BIT(entry->field_id.element_size_code);

    bool_t write_done = false;

    // Insert the bits to be written
    wr_value = (read_value & ~combined_wr_mask) | (wr_value & combined_wr_mask);

    if (entry->special_wr_handling)
    {
        // Handle Special Write Cases
        // There are other special write cases that are only handled as a full field write

        switch (entry->field_id.raw)
        {
            case MD_TDCS_MIG_DEC_KEY_FIELD_ID:
                // Note that we actually set this flag before MIG_KEY is written below.
                // This is OK because the relevant case (writing by MigTD)
                // runs with a shared lock on OP_STATE, which MIG_KEY_SET
                // is read by TDH.EXPORT.STATE.IMMUTABLE, which runs with an exclusive lock on OP_STATE.
                md_ctx.tdcs_ptr->migration_fields.mig_dec_key_set = true;
                break;

            case MD_TDCS_MIG_VERSION_FIELD_ID:
                if ((wr_value < MIN_MIGRATION_EXPORT_VERSION) || (wr_value > MAX_MIGRATION_EXPORT_VERSION) ||
                    (wr_value < MIN_MIGRATION_IMPORT_VERSION) || (wr_value > MAX_MIGRATION_IMPORT_VERSION))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }
                break;
            case MD_TDCS_HP_LOCK_TIMEOUT_FIELD_ID:
            {
                // We only allow full field update
                tdx_debug_assert(elem_size == 8);
                if (combined_wr_mask != BIT_MASK_64BITS)
                {
                    return TDX_METADATA_WR_MASK_NOT_VALID;
                }

                uint64_t tsc;
                if (!check_hp_lock_timeout_and_translate_to_tsc(wr_value, &tsc))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                wr_value = tsc;
                *elem_ptr = wr_value;
                write_done = true;

                break;
            }
            case MD_TDCS_TD_CTLS_FIELD_ID:
            {
                if (!md_ctx.tdcs_ptr->executions_ctl_fields.config_flags.flexible_pending_ve)
                {
                    // The guest TD is not allowed to change TD_CTLS.PENDING_VE_DISABLE
                    td_ctls_t td_ctls_modified_bits = { .raw = wr_value ^ read_value };
                    if (td_ctls_modified_bits.pending_ve_disable)
                    {
                        return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                    }
                }

                // To enable virtual topology enumeration, all VCPU must have been properly configured
                td_ctls_t td_ctls = { .raw = wr_value };
                if (td_ctls.enum_topology && !md_ctx.tdcs_ptr->executions_ctl_fields.topology_enum_configured)
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                // check that no reserved bits are set
                if (td_ctls.reserved)
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                break;
            }
            default:
                tdx_debug_assert(0);   // Missing special handling
                break;
        }
    }

    // Update only the relevant bits per the write mask
    if (!write_done)
    {
        if (!write_element_by_size(elem_ptr, read_value, wr_value, combined_wr_mask, elem_size))
        {
            return api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_METADATA_FIELD);
        }
    }

    *old_value = read_value & rd_mask;

    return TDX_SUCCESS;
}

// Static asserts for some special fields handled in md_td_write_field:
tdx_static_assert(MD_TDCS_TSC_FREQUENCY_FIELD_CODE < MD_TDCS_VIRTUAL_TSC_FIELD_CODE,
                  wrong_field_code_order);
tdx_static_assert(MD_TDCS_EXECUTION_CONTROLS_CLASS_CODE < MD_TDCS_CPUID_CLASS_CODE,
                  wrong_field_class_order);

api_error_code_e md_td_write_field(md_field_id_t field_id, const md_lookup_t* entry,md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t value[MAX_ELEMENTS_IN_FIELD],
        uint64_t wr_request_mask, bool_t is_import)
{
    // Since we read a multiple elements of the same field, we would like to directly access the ptr of
    // the first element of the field, which will save us the time of searching the offset and size
    // of every element in the above if-else blocks.

    uint64_t rd_mask = 0, wr_mask = 0, combined_wr_mask = 0;
    uint64_t read_value;
    uint64_t* elem_ptr;
    api_error_code_e status;

    // Check that field writes are done only from import flows, so we won't need
    //  to worry about concurrency and atomic writes
    tdx_debug_assert((access_type == MD_IMPORT_IMMUTABLE) || (access_type == MD_IMPORT_MUTABLE));

    status = md_td_get_element(field_id, entry, access_type, access_qual, md_ctx,
                               &rd_mask, &wr_mask, &read_value, &elem_ptr);

    if (status != TDX_SUCCESS)
    {
        if ((field_id.class_code == MD_TDCS_CPUID_CLASS_CODE) &&
            (status == TDX_METADATA_FIELD_NOT_READABLE))
        {
            status = TDX_METADATA_FIELD_NOT_WRITABLE;
        }

        return status;
    }

    // Narrow down the bits to be written with the input mask
    combined_wr_mask = wr_mask & wr_request_mask;

    // Check if the requested field is writable.
    // Note that there is no check for readable; we don't have write-only
    // fields.
    if (combined_wr_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_WRITABLE;
    }

    bool_t write_done = false;

    if (entry->special_wr_handling)
    {
        //----------------------------------
        //     Handle Special Write Cases
        //----------------------------------
        switch (entry->field_id.raw)
        {
            case MD_TDCS_NUM_VCPUS_FIELD_ID:
            {
                break;
            }
            case MD_TDR_TD_UUID_FIELD_ID:
            {
                // TD_UUID is only written on import.
                // Save the existing value, it is checked on metadata access by service TDs
                md_ctx.tdcs_ptr->migration_fields.preimport_uuid.qwords[0] =
                        md_ctx.tdr_ptr->management_fields.td_uuid.qwords[0];
                md_ctx.tdcs_ptr->migration_fields.preimport_uuid.qwords[1] =
                        md_ctx.tdr_ptr->management_fields.td_uuid.qwords[1];
                md_ctx.tdcs_ptr->migration_fields.preimport_uuid.qwords[2] =
                        md_ctx.tdr_ptr->management_fields.td_uuid.qwords[2];
                md_ctx.tdcs_ptr->migration_fields.preimport_uuid.qwords[3] =
                        md_ctx.tdr_ptr->management_fields.td_uuid.qwords[3];
                break;
            }
            case MD_TDCS_ATTRIBUTES_FIELD_ID:
            {
                tdx_debug_assert(entry->num_of_elem == 1);
                td_param_attributes_t attributes;
                attributes.raw = value[0] & combined_wr_mask;
                if (!verify_td_attributes(attributes, is_import))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }
                break;
            }
            case MD_TDCS_CONFIG_FLAGS_FIELD_ID:
            {
                config_flags_t config_flags;
                config_flags.raw = value[0] & combined_wr_mask;
                if (!verify_td_config_flags(config_flags))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }
                break;
            }
            case MD_TDCS_EPTP_FIELD_ID:
            {
                tdx_debug_assert(entry->num_of_elem == 1);
                ia32e_eptp_t eptp;
                eptp.raw = value[0] & combined_wr_mask;
                if (!verify_and_set_td_eptp_controls(md_ctx.tdr_ptr, md_ctx.tdcs_ptr,
                                                     md_ctx.tdcs_ptr->executions_ctl_fields.gpaw, eptp))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }
                write_done = true;
                break;
            }
            case MD_TDCS_HP_LOCK_TIMEOUT_FIELD_ID:
            {
                if (!check_hp_lock_timeout_and_translate_to_tsc(value[0] & combined_wr_mask,
                        &md_ctx.tdcs_ptr->executions_ctl_fields.hp_lock_timeout))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                write_done = true;

                break;
            }
            case MD_TDCS_NUM_CPUID_VALUES_FIELD_ID:
            {
                if (value[0] != MAX_NUM_CPUID_LOOKUP)
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                write_done = true;   // Value is only checked

                break;
            }
            case MD_TDCS_NUM_L2_VMS_FIELD_ID:
            {
                if (value[0] > MAX_L2_VMS)
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                md_ctx.tdcs_ptr->management_fields.num_l2_vms = (uint16_t)value[0];

                // Now that we know the number of L2 VMs, check that enough pages have been allocated for TDCS
                if (!is_required_tdcs_allocated(md_ctx.tdr_ptr, (uint16_t)value[0]))
                {
                    return TDX_TDCS_NOT_ALLOCATED;
                }

                write_done = true;   // Value is only checked

                break;
            }
            case MD_TDCS_TD_CTLS_FIELD_ID:
            {
                // No special handling on import
                break;
            }
            case MD_TDCS_TSC_FREQUENCY_FIELD_ID:
            {
                // Sanity checks: see the TDR/TDCS spreadsheet
                tdx_debug_assert(entry->num_of_elem == 1);

                if ((value[0] < VIRT_TSC_FREQUENCY_MIN) || (value[0] > VIRT_TSC_FREQUENCY_MAX))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                break;
            }
            case MD_TDCS_VIRTUAL_TSC_FIELD_ID:
            {
                tdx_debug_assert(entry->num_of_elem == 1);

                // The calculation below relies on TSC_FREQUENCY being imported before VIRTUAL_TSC.
                // This is always true because of the order of field codes.
                // Checked by static assert above

                tdx_debug_assert(md_ctx.tdcs_ptr->executions_ctl_fields.tsc_frequency != 0);

                calculate_tsc_virt_params(ia32_rdtsc(),get_global_data()->native_tsc_frequency,
                                          md_ctx.tdcs_ptr->executions_ctl_fields.tsc_frequency, value[0],
                                          &md_ctx.tdcs_ptr->executions_ctl_fields.tsc_multiplier,
                                          &md_ctx.tdcs_ptr->executions_ctl_fields.tsc_offset);
                write_done = true;
                break;
            }
            case MD_TDCS_XFAM_FIELD_ID:
            {
                tdx_debug_assert(entry->num_of_elem == 1);
                ia32_xcr0_t xfam;
                xfam.raw = value[0] & combined_wr_mask;
                if (!check_xfam(xfam))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }
                break;
            }
            case MD_TDCS_CPUID_VALUES_FIELD_ID:
            {
                uint32_t leaf, subleaf, index;

                // The checks below rely on TD execution controls being imported before CPUID.
                // This is always true because of the order of class codes.
                // Checked by static assert above

                md_cpuid_field_id_get_leaf_subleaf(field_id, &leaf, &subleaf);
                index = get_cpuid_lookup_entry(leaf, subleaf);

                cpuid_config_return_values_t cpuid_values;
                cpuid_values.low = value[0];
                cpuid_values.high = value[1];

                if (!check_cpuid_compatibility_and_set_flags(md_ctx.tdcs_ptr, leaf, subleaf, cpuid_values, index))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                break;
            }
            
            case MD_TDCS_SERVTD_NUM_FIELD_ID:
            {
                // Sanity checks: see the TDR/TDCS spreadsheet
                // SERVTD_NUM is checked to be exactly 1 (the Migration TD)
                if (1 != value[0])
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                // The value is only checked (marked in the spreadsheet as CB), but not imported
                write_done = true;
                break;
            }
            case MD_TDCS_VIRTUAL_IA32_ARCH_CAPABILITIES_FIELD_ID:
            {
                ia32_arch_capabilities_t ia32_arch_cap = { .raw = value[0] };
                if (!check_virt_ia32_arch_capabilities(md_ctx.tdcs_ptr, ia32_arch_cap))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }

                break;
            }
            default:
                tdx_debug_assert(0);   // Missing special handling
                break;
        }
    }

    if (!write_done)
    {
        uint64_t first_elem_addr = (uint64_t)elem_ptr;
        uint64_t elem_size = BIT(entry->field_id.element_size_code);

        for (uint16_t i = 0; i < entry->num_of_elem; i++)
        {
            elem_ptr = (uint64_t*)(first_elem_addr + ((uint64_t)i * elem_size));
            read_value = *elem_ptr & md_get_element_size_mask(entry->field_id.element_size_code);

            if (!md_check_forbidden_bits_unchanged(read_value, value[i], wr_request_mask, wr_mask))
            {
                return TDX_METADATA_FIELD_VALUE_NOT_VALID;
            }

            // Update only the relevant bits per the write mask
            if (!write_element_by_size(elem_ptr, read_value, value[i], combined_wr_mask, elem_size))
            {
                return api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_METADATA_FIELD);
            }
        }
    }

    return TDX_SUCCESS;
}
