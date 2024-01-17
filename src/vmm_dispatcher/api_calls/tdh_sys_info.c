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
 * @file tdh_sys_info.c
 * @brief TDHSYSINFO API handler
 */
#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"

#include "data_structures/tdx_global_data.h"
#include "helpers/helpers.h"
#include "memory_handlers/keyhole_manager.h"
#include "accessors/data_accessors.h"
#include "auto_gen/cpuid_configurations.h"

#define MAX_TDMRS 64

api_error_type tdh_sys_info(uint64_t tdhsysinfo_output_pa,
		uint64_t num_of_bytes_in_buffer, uint64_t target_cmr_info_pa,
		uint64_t num_of_cmr_info_entries)
{
    api_error_type retval = TDX_OPERAND_INVALID;
    pa_t tdhsysinfo_pa = {.raw = tdhsysinfo_output_pa};
    pa_t cmr_info_pa = {.raw = target_cmr_info_pa};
    td_sys_info_t * tdhsysinfo_output_la = 0;
    cmr_info_entry_t* cmr_info_la = 0;
    cmr_info_entry_t* cmr_info_la_start = 0;
    tdx_module_global_t * tdx_global_data_ptr = get_global_data();
    tdx_module_local_t * tdx_local_data_ptr = get_local_data();
    sysinfo_table_t * sysinfo_table_ptr = get_sysinfo_table();

    // Initialize output registers to default values
    tdx_local_data_ptr->vmm_regs.rdx = 0ULL;
    tdx_local_data_ptr->vmm_regs.r9 = 0ULL;

    // Check that LP-scope initialization has been done
    if (!tdx_local_data_ptr->lp_is_init)
    {
        retval = TDX_SYS_LP_INIT_NOT_DONE;
        TDX_ERROR("TDSYSINITLP not done!\n");
        goto EXIT;
    }

    //Check TD SYSINFO output PA
    retval = shared_hpa_check_with_pwr_2_alignment(tdhsysinfo_pa, _1KB);
    if (retval != TDX_SUCCESS)
    {
        retval = api_error_with_operand_id(retval, OPERAND_ID_RCX);
        TDX_ERROR("TD SYSINFO output PA is not a valid shared HPA pa=0x%llx, error=0x%llx\n", tdhsysinfo_pa.raw, retval);
        goto EXIT;
    }

    if (num_of_bytes_in_buffer < (uint64_t)sizeof(td_sys_info_t))
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    tdhsysinfo_output_la = (td_sys_info_t *) map_pa(tdhsysinfo_pa.raw_void, TDX_RANGE_RW);
    basic_memset_to_zero(tdhsysinfo_output_la, sizeof(td_sys_info_t));
    //Check CMR INFO PA
    retval = shared_hpa_check_with_pwr_2_alignment(cmr_info_pa, MAX_CMR*sizeof(cmr_info_entry_t));

    if (retval != TDX_SUCCESS)
    {
        retval = api_error_with_operand_id(retval, OPERAND_ID_R8);
        TDX_ERROR("CMR INFO PA is not a valid shared HPA pa=0x%llx, error=0x%llx\n", cmr_info_pa.raw, retval);
        goto EXIT;
    }

    if (num_of_cmr_info_entries < MAX_CMR)
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }

    cmr_info_la = (cmr_info_entry_t*) map_pa(cmr_info_pa.raw_void, TDX_RANGE_RW);

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    /**
     * Fill TDHSYSINFO_STRUCT
     */
    tdhsysinfo_output_la->attributes.raw = (uint32_t)0;
    tdhsysinfo_output_la->vendor_id = 0x8086;
    tdhsysinfo_output_la->build_date = TDX_MODULE_BUILD_DATE;
    tdhsysinfo_output_la->build_num = TDX_MODULE_BUILD_NUM;
    tdhsysinfo_output_la->minor_version = TDX_MODULE_MINOR_VER;
    tdhsysinfo_output_la->major_version = TDX_MODULE_MAJOR_VER;
    tdhsysinfo_output_la->sys_rd = true; // Indicate that TDH.SYS.RD* should be used
    tdhsysinfo_output_la->max_tdmrs = MAX_TDMRS;
    tdhsysinfo_output_la->max_reserved_per_tdmr = MAX_RESERVED_AREAS; //MAX_RESERVED_PER_TDMR;
    tdhsysinfo_output_la->pamt_entry_size = sizeof(pamt_entry_t);

    tdhsysinfo_output_la->tdcs_base_size = _4KB * MIN_NUM_TDCS_PAGES; //_4KB * TDCS_PAGES;

    tdhsysinfo_output_la->tdvps_base_size = _4KB * MIN_TDVPS_PAGES; //_4KB * TDVPS_PAGES;

    tdhsysinfo_output_la->tdvps_xfam_dependent_size = false;

    tdhsysinfo_output_la->xfam_fixed0 = TDX_XFAM_FIXED0 &
                                       (uint64_t)(tdx_global_data_ptr->xcr0_supported_mask |
                                       tdx_global_data_ptr->ia32_xss_supported_mask);
    tdhsysinfo_output_la->xfam_fixed1 = TDX_XFAM_FIXED1;
    tdhsysinfo_output_la->attributes_fixed0 = tdx_global_data_ptr->attributes_fixed0;
    tdhsysinfo_output_la->attributes_fixed1 = tdx_global_data_ptr->attributes_fixed1;

    /**
     *  Write the first NUM_CONFIG CPUID_CONFIG entries These enumerate bits that are configurable by the host VMM.
     *  - CONFIG_DIRECT bits
     *  - ALLOW_DIRECT bits, if their native value is 1
     */

    tdhsysinfo_output_la->num_cpuid_config = MAX_NUM_CPUID_CONFIG;

    for (uint32_t i = 0; i < MAX_NUM_CPUID_CONFIG; i++)
    {
        uint32_t lookup_index = cpuid_configurable[i].lookup_index;

        tdhsysinfo_output_la->cpuid_config_list[i].leaf_subleaf =
                cpuid_configurable[i].leaf_subleaf;

        tdhsysinfo_output_la->cpuid_config_list[i].values.low =
                 cpuid_configurable[i].config_direct.low |
                (cpuid_configurable[i].allow_direct.low & tdx_global_data_ptr->cpuid_values[lookup_index].values.low);

        tdhsysinfo_output_la->cpuid_config_list[i].values.high =
                 cpuid_configurable[i].config_direct.high |
                (cpuid_configurable[i].allow_direct.high & tdx_global_data_ptr->cpuid_values[lookup_index].values.high);
    }

    /**
     * Fill CMR_INFO array
     */
    cmr_info_la_start = cmr_info_la;
    for (uint8_t i = 0; i < MAX_CMR; i++)
    {
        *cmr_info_la = sysinfo_table_ptr->cmr_data[i];
        cmr_info_la++;
    };

    /**
     * Set output registers
     */

    tdx_local_data_ptr->vmm_regs.rdx = sizeof(td_sys_info_t);
    tdx_local_data_ptr->vmm_regs.r9 = MAX_CMR;

    retval = TDX_SUCCESS;

    EXIT:

    if (tdhsysinfo_output_la)
    {
        free_la(tdhsysinfo_output_la);
    }

    if (cmr_info_la_start)
    {
        free_la(cmr_info_la_start);
    }

    return retval;
}

