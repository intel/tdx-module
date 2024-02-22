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
 * @file metadata_sys.c
 * @brief Sys-context (Global system fields) metadata handler
 */

#include "metadata_generic.h"
#include "metadata_sys.h"
#include "auto_gen/global_sys_fields_lookup.h"
#include "helpers/error_reporting.h"
#include "accessors/data_accessors.h"
#include "auto_gen/cpuid_configurations.h"
#include "helpers/migration.h"
#include "data_structures/loader_data.h"
#include "x86_defs/msr_defs.h"
#include "helpers/cpuid_fms.h"

static bool_t md_sys_get_first_element_val_and_ptr(md_field_id_t field_id, const md_lookup_t* entry,
                                                   uint64_t* value, void** first_elem_ptr,
                                                   uint64_t* array_size)
{
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();
    tdx_module_global_t* global_data = get_global_data();

    handoff_data_header_t* handoff_data_hdr = (handoff_data_header_t*)sysinfo_table->data_rgn_base;

    *value = 0;
    *first_elem_ptr = NULL;
    *array_size = 0;

    tdx_debug_assert(entry->field_id.inc_size == 0);

    uint32_t field_num = (field_id.field_code - entry->field_id.field_code) / entry->num_of_elem;

    switch (entry->field_id.class_code)
    {
        case MD_SYS_PLATFORM_INFO_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_NUM_PKGS_FIELD_CODE)
            {
                *value = sysinfo_table->mcheck_fields.tot_num_sockets;
            }
            else if (entry->field_id.field_code == MD_SYS_PKG_FMS_FIELD_CODE)
            {
                *value = sysinfo_table->mcheck_fields.socket_cpuid_table[field_num].raw;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_TDX_MODULE_VERSION_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_VENDOR_ID_FIELD_CODE)
            {
                *value = 0x8086ULL;
            }
            else if (entry->field_id.field_code == MD_SYS_BUILD_DATE_FIELD_CODE)
            {
                *value = TDX_MODULE_BUILD_DATE;
            }
            else if (entry->field_id.field_code == MD_SYS_BUILD_NUM_FIELD_CODE)
            {
                *value = TDX_MODULE_BUILD_NUM;
            }
            else if (entry->field_id.field_code == MD_SYS_MINOR_VERSION_FIELD_CODE)
            {
                *value = TDX_MODULE_MINOR_VER;
            }
            else if (entry->field_id.field_code == MD_SYS_MAJOR_VERSION_FIELD_CODE)
            {
                *value = TDX_MODULE_MAJOR_VER;
            }
            else if (entry->field_id.field_code == MD_SYS_UPDATE_VERSION_FIELD_CODE)
            {
                *value = TDX_MODULE_UPDATE_VER;
            }
            else if (entry->field_id.field_code == MD_SYS_INTERNAL_VERSION_FIELD_CODE)
            {
                *value = TDX_MODULE_INTERNAL_VER;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_TDX_MODULE_INFO_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_SYS_ATTRIBUTES_FIELD_CODE)
            {
                *value = global_data->sys_attributes.raw;
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_TDX_FEATURES_FIELD_CODE)
            {
                *value = NUM_TDX_FEATRUES;
            }
            else if (entry->field_id.field_code == MD_SYS_TDX_FEATURES0_FIELD_CODE)
            {
                tdx_features_enum0_t tdx_features_0;

                tdx_features_0.raw = 0;
                tdx_features_0.td_migration = 1;
                tdx_features_0.service_td = 1;
                tdx_features_0.td_preserving = 1;
                tdx_features_0.tdg_vp_rdwr = 1;
                tdx_features_0.relaxed_mem_mng_concurrency = 1;
                tdx_features_0.cpuid_virt_guest_ctrl = 1;
                tdx_features_0.local_attestation = global_data->seamverifyreport_available;
                tdx_features_0.td_partitioning = 1;
                tdx_features_0.td_entry_enhancements = 1;
                tdx_features_0.host_priority_locks = 1;
                tdx_features_0.config_ia32_arch_cap = 1;
                tdx_features_0.no_rbp_mod = 1;
                tdx_features_0.pending_ept_violation_v2 = 1;
                tdx_features_0.l2_tlb_invd_opt = 1;
                tdx_features_0.fms_config = 1;

                *value = tdx_features_0.raw;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_CMR_INFO_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_NUM_CMRS_FIELD_CODE)
            {
                *value = MAX_CMR;
            }
            else if (entry->field_id.field_code == MD_SYS_CMR_BASE_FIELD_CODE)
            {
                *value = sysinfo_table->cmr_data[field_num].cmr_base;
            }
            else if (entry->field_id.field_code == MD_SYS_CMR_SIZE_FIELD_CODE)
            {
                *value = sysinfo_table->cmr_data[field_num].cmr_size;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_TDMR_INFO_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_MAX_TDMRS_FIELD_CODE)
            {
                *value = MAX_TDMRS;
            }
            else if (entry->field_id.field_code == MD_SYS_MAX_RESERVED_PER_TDMR_FIELD_CODE)
            {
                *value = MAX_RESERVED_AREAS;
            }
            else if (entry->field_id.field_code == MD_SYS_PAMT_4K_ENTRY_SIZE_FIELD_CODE ||
                     entry->field_id.field_code == MD_SYS_PAMT_2M_ENTRY_SIZE_FIELD_CODE ||
                     entry->field_id.field_code == MD_SYS_PAMT_1G_ENTRY_SIZE_FIELD_CODE)
            {
                *value = sizeof(pamt_entry_t);
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_TD_CONTROL_STRUCTURES_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_TDR_BASE_SIZE_FIELD_CODE)
            {
                *value = sizeof(tdr_t);
            }
            else if (entry->field_id.field_code == MD_SYS_TDCS_BASE_SIZE_FIELD_CODE)
            {
                *value = MIN_NUM_TDCS_PAGES * TDX_PAGE_SIZE_IN_BYTES;
            }
            else if (entry->field_id.field_code == MD_SYS_TDVPS_BASE_SIZE_FIELD_CODE)
            {
                *value = MIN_TDVPS_PAGES * TDX_PAGE_SIZE_IN_BYTES;
            }
            else if (entry->field_id.field_code == MD_SYS_TDCS_SIZE_PER_L2_VM_FIELD_CODE)
            {
                *value = TDCS_PAGES_PER_L2_VM * TDX_PAGE_SIZE_IN_BYTES;
            }
            else if (entry->field_id.field_code == MD_SYS_TDVPS_SIZE_PER_L2_VM_FIELD_CODE)
            {
                *value = TDVPS_PAGES_PER_L2_VM * TDX_PAGE_SIZE_IN_BYTES;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_TD_CONFIGURABILITY_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_ATTRIBUTES_FIXED0_FIELD_CODE)
            {
                *value = global_data->attributes_fixed0;
            }
            else if (entry->field_id.field_code == MD_SYS_ATTRIBUTES_FIXED1_FIELD_CODE)
            {
                *value = global_data->attributes_fixed1;
            }
            else if (entry->field_id.field_code == MD_SYS_CONFIG_FLAGS_FIXED0_FIELD_CODE)
            {
                *value = global_data->config_flags_fixed0.raw;
            }
            else if (entry->field_id.field_code == MD_SYS_CONFIG_FLAGS_FIXED1_FIELD_CODE)
            {
                *value = global_data->config_flags_fixed1.raw;
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_ALLOWED_FMS_FIELD_CODE)
            {
                *value = get_num_allowed_fms();
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_DISALLOWED_FMS_FIELD_CODE)
            {
                *value = NUM_OF_DISALLOWED_FMS;
            }
            else if (entry->field_id.field_code == MD_SYS_ALLOWED_FMS_FIELD_CODE)
            {
                if (field_num >= (uint32_t)get_num_allowed_fms())
                {
                    *value = 0;
                }
                else
                {
                    *value = get_allowed_fms((uint16_t)field_num).raw;
                }
            }
            else if (entry->field_id.field_code == MD_SYS_DISALLOWED_FMS_FIELD_CODE)
            {
                if (field_num >= NUM_OF_DISALLOWED_FMS)
                {
                    *value = 0;
                }
                else
                {
                    lfence();

                    *value = disallowed_fms[field_num].raw;
                }
            }
            else if (entry->field_id.field_code == MD_SYS_XFAM_FIXED0_FIELD_CODE)
            {
                *value = TDX_XFAM_FIXED0 &
                          (global_data->xcr0_supported_mask | global_data->ia32_xss_supported_mask);
            }
            else if (entry->field_id.field_code == MD_SYS_XFAM_FIXED1_FIELD_CODE)
            {
                *value = TDX_XFAM_FIXED1;
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_CPUID_CONFIG_FIELD_CODE)
            {
                *value = MAX_NUM_CPUID_CONFIG;
            }
            else if (entry->field_id.field_code == MD_SYS_CPUID_CONFIG_LEAVES_FIELD_CODE)
            {
                if (field_num >= MAX_NUM_CPUID_CONFIG)
                {
                    *value = ~(0ULL);
                }
                else
                {
                    lfence(); // Prevent speculative access to non-existant array field
                    *value = cpuid_configurable[field_num].leaf_subleaf.raw;
                }
            }
            else if (entry->field_id.field_code == MD_SYS_CPUID_CONFIG_VALUES_FIELD_CODE)
            {
                if (field_num >= MAX_NUM_CPUID_CONFIG)
                {
                    // No configurable bits
                    *value = 0;
                }
                else
                {
                    lfence(); // Prevent speculative access to non-existant array field

                    *value = cpuid_configurable[field_num].config_direct.low;
                    *first_elem_ptr = (void*)cpuid_configurable[field_num].config_direct.values;
                    *array_size = 16;
                }
            }
            else if (entry->field_id.field_code == MD_SYS_IA32_ARCH_CAPABILITIES_CONFIG_MASK_FIELD_CODE)
            {
                *value = IA32_ARCH_CAPABILITIES_CONFIG_MASK;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_MIGRATION_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_MIG_ATTRIBUTES_FIELD_CODE)
            {
                *value = 0;
            }
            else if (entry->field_id.field_code == MD_SYS_MIN_EXPORT_VERSION_FIELD_CODE)
            {
                *value = 0;
            }
            else if (entry->field_id.field_code == MD_SYS_MAX_EXPORT_VERSION_FIELD_CODE)
            {
                *value = 0;
            }
            else if (entry->field_id.field_code == MD_SYS_MIN_IMPORT_VERSION_FIELD_CODE)
            {
                *value = 0;
            }
            else if (entry->field_id.field_code == MD_SYS_MAX_IMPORT_VERSION_FIELD_CODE)
            {
                *value = 0;
            }
            else if (entry->field_id.field_code == MD_SYS_MAX_MIGS_FIELD_CODE)
            {
                *value = MAX_MIGS;
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_IMMUTABLE_STATE_PAGES_FIELD_CODE)
            {
                *value = MIN_TD_IMMUTABLE_STATE_EXPORT_PAGES;
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_TD_STATE_PAGES_FIELD_CODE)
            {
                *value = MIN_TD_STATE_EXPORT_PAGES;
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_VP_STATE_PAGES_FIELD_CODE)
            {
                *value = MIN_VP_STATE_EXPORT_PAGES;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_SERVICE_TD_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_MAX_SERV_TDS_FIELD_CODE)
            {
                *value = MAX_SERVTDS;
            }
            else if (entry->field_id.field_code == MD_SYS_SERVTD_ATTR_FIXED0_FIELD_CODE)
            {
                *value = SERVTD_ATTRIBUTES_FIXED_0;
            }
            else if (entry->field_id.field_code == MD_SYS_SERVTD_ATTR_FIXED1_FIELD_CODE)
            {
                *value = SERVTD_ATTRIBUTES_FIXED_1;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_TDX_MODULE_HANDOFF_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_MODULE_HV_FIELD_CODE)
            {
                *value = TDX_MODULE_HV;
            }
            else if (entry->field_id.field_code == MD_SYS_MIN_UPDATE_HV_FIELD_CODE)
            {
                *value = TDX_MIN_UPDATE_HV;
            }
            else if (entry->field_id.field_code == MD_SYS_NO_DOWNGRADE_FIELD_CODE)
            {
                *value = TDX_NO_DOWNGRADE;
            }
            else if (entry->field_id.field_code == MD_SYS_NUM_HANDOFF_PAGES_FIELD_CODE)
            {
                *value = global_data->num_handoff_pages;
            }
            else if (entry->field_id.field_code == MD_SYS_HANDOFF_DATA_VALID_FIELD_CODE)
            {
                *value = handoff_data_hdr->valid;
            }
            else if (entry->field_id.field_code == MD_SYS_HANDOFF_DATA_HV_FIELD_CODE)
            {
                *value = handoff_data_hdr->hv;
            }
            else if (entry->field_id.field_code == MD_SYS_HANDOFF_DATA_SIZE_FIELD_CODE)
            {
                *value = handoff_data_hdr->size;
            }
            else
            {
                return false;
            }
            break;
        case MD_SYS_TD_PARTITIONING_CLASS_CODE:
            if (entry->field_id.field_code == MD_SYS_GUEST_L2_GPA_ATTR_MASK_FIELD_CODE)
            {
                *value = GUEST_L2_GPA_ATTR_MASK;
            }
            else if (entry->field_id.field_code == MD_SYS_VM_CTLS_FIXED0_FIELD_CODE)
            {
                *value = ALLOWED_VM_CTLS;
            }
            else if (entry->field_id.field_code == MD_SYS_VM_CTLS_FIXED1_FIELD_CODE)
            {
                *value = 0;
            }
            else if (entry->field_id.field_code == MD_SYS_VPCU_L2_CTLS_FIXED0_FIELD_CODE)
            {
                *value = ALLOWED_L2_VCPU_CTLS;
            }
            else if (entry->field_id.field_code == MD_SYS_VCPU_L2_CTLS_FIXED1_FIELD_CODE)
            {
                *value = 0;
            }
            else if (entry->field_id.field_code == MD_SYS_VPCU_L2_DEBUG_CTLS_FIXED0_FIELD_CODE)
            {
                *value = ALLOWED_L2_VM_DEBUG_CTLS;
            }
            else if (entry->field_id.field_code == MD_SYS_VCPU_L2_DEBUG_CTLS_FIXED1_FIELD_CODE)
            {
                *value = 0;
            }
            else
            {
                return false;
            }

            break;
        default:
            return false;
    }

    return true;
}


api_error_code_e md_sys_read_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
                                     md_access_qualifier_t access_qual, uint64_t* out_rd_value)
{
    uint64_t read_mask, write_mask;
    uint64_t read_value;
    void* element_array_ptr = NULL;
    uint64_t array_size = 0;

    md_get_rd_wr_mask(entry, access_type, access_qual, &read_mask, &write_mask);

    if (read_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_READABLE;
    }

    if (!md_sys_get_first_element_val_and_ptr(field_id, entry, &read_value, &element_array_ptr, &array_size))
    {
        if ((entry->field_id.raw == MD_SYS_CPUID_CONFIG_LEAVES_FIELD_ID) ||
            (entry->field_id.raw == MD_SYS_CPUID_CONFIG_VALUES_FIELD_ID))
        {
            return TDX_METADATA_FIELD_SKIP;
        }
        else
        {
            return TDX_METADATA_FIELD_ID_INCORRECT;
        }
    }

    if (array_size)
    {
        uint64_t elem_size = BIT(entry->field_id.element_size_code);
        uint64_t elem_num_in_field = (field_id.field_code - entry->field_id.field_code) % entry->num_of_elem;
        uint64_t offset = elem_num_in_field * elem_size;

        tdx_sanity_check(offset + elem_size <= array_size, SCEC_METADATA_HANDLER_SOURCE, 20);

        uint64_t* elem_ptr = (uint64_t*)((uint8_t*)element_array_ptr + offset);
        read_value = *elem_ptr;
    }

    read_value &= read_mask;
    *out_rd_value = read_value;

    return TDX_SUCCESS;
}

api_error_code_e md_sys_read_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
                                   md_access_qualifier_t access_qual, uint64_t value[MAX_ELEMENTS_IN_FIELD])
{
    uint64_t read_mask, write_mask;
    uint64_t read_value;
    void* element_array_ptr = NULL;
    uint64_t array_size = 0;

    md_get_rd_wr_mask(entry, access_type, access_qual, &read_mask, &write_mask);

    if (read_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_READABLE;
    }

    if (!md_sys_get_first_element_val_and_ptr(field_id, entry, &read_value, &element_array_ptr, &array_size))
    {
        if ((entry->field_id.raw == MD_SYS_CPUID_CONFIG_LEAVES_FIELD_ID) ||
            (entry->field_id.raw == MD_SYS_CPUID_CONFIG_VALUES_FIELD_ID))
        {
            return TDX_METADATA_FIELD_SKIP;
        }
        else
        {
            return TDX_METADATA_FIELD_ID_INCORRECT;
        }
    }

    if (array_size)
    {
        uint64_t elem_size = BIT(entry->field_id.element_size_code);

        for (uint32_t i = 0; i < entry->num_of_elem; i++)
        {
            uint64_t offset = i * elem_size;
            tdx_sanity_check(offset + elem_size <= array_size, SCEC_METADATA_HANDLER_SOURCE, 21);
            uint64_t* elem_ptr = (uint64_t*)((uint8_t*)element_array_ptr + offset);
            read_value = *elem_ptr;
            value[i] = read_value & read_mask;
        }
    }
    else // single-element field
    {
        value[0] = read_value & read_mask;
    }

    return TDX_SUCCESS;
}

api_error_code_e md_sys_write_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, uint64_t wr_value, uint64_t wr_request_mask, uint64_t* old_value)
{
    UNUSED(field_id);
    UNUSED(entry);
    UNUSED(access_type);
    UNUSED(access_qual);
    UNUSED(wr_value);
    UNUSED(wr_request_mask);
    UNUSED(old_value);

    return TDX_METADATA_FIELD_NOT_WRITABLE;
}

api_error_code_e md_sys_write_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, uint64_t value[MAX_ELEMENTS_IN_FIELD], uint64_t wr_mask)
{
    UNUSED(field_id);
    UNUSED(entry);
    UNUSED(access_type);
    UNUSED(access_qual);
    UNUSED(value);
    UNUSED(wr_mask);

    return TDX_METADATA_FIELD_NOT_WRITABLE;
}
