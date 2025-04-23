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
 * @file td_api_handlers.h
 * @brief TDX TD API Handelrs
 */

#ifndef INCLUDE_TDX_TD_API_HANDLERS_H_
#define INCLUDE_TDX_TD_API_HANDLERS_H_

#include "tdx_api_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_tdvps.h"


/**
 * @brief Initialize a pending private page
 *
 * Accept a pending private page and initialize the page to 0 using the TD ephemeral private key.
 *
 * @note
 *
 * @param page_to_accept_gpa Guest physical address of the private page to accept
 * @param interrupt_occurred flag indicate if interrupt occurred
 *
 * @return Success or Error type
 */
api_error_type tdg_mem_page_accept(uint64_t page_to_accept_gpa, bool_t* interrupt_occurred);


/**
 * @brief Extend a TDCS.RTMR measurement register.
 *
 * @note
 *
 * @param extension_data_gpa 64B-aligned guest physical address of a 48B extension data
 * @param index Index of the measurement register to be extended
 *
 * @return Success or Error type
 */
api_error_type tdg_mr_rtmr_extend(uint64_t extension_data_gpa, uint64_t index);


/**
 * @brief Get Virtualization Exception Information for the recent #VE exception
 *
 * @note
 *
 * @return Success or Error type
 */
api_error_type tdg_vp_veinfo_get(void);


/**
 * @brief Get guest TD execution environment information.
 *
 * @note
 *
 * @return Success
 */
api_error_type tdg_vp_info(void);


/**
 * @brief Creates a TDREPORT_STRUCT structure
 *
 * Creates a TDREPORT_STRUCT structure that contains the measurements/configuration
 * information of the guest TD that called the function, measurements/configuration
 * information of the TDX-SEAM module and a REPORTMACSTRUCT.
 *
 * @note
 *
 * @param report_struct_gpa 1024B-aligned guest physical address of newly created report structure
 * @param additional_data_gpa 64B-aligned guest physical address of additional data to be signed
 * @param sub_type Report sub type
 *
 * @return Success or Error type
 */
api_error_type tdg_mr_report(uint64_t report_struct_gpa, uint64_t additional_data_gpa, uint64_t sub_type, bool_t* interrupt_occurred);

/**
 * @brief Verifies a REPORTMACSTRUCT structure
 *
 * Verify a cryptographic REPORTMACSTRUCT that describes the contents of a TD, to determine that it
 * was created on the current TEE on the current platform.
 *
 * @note
 *
 * @param reportmacstruct_gpa 256B-aligned guest physical address of the REPORTMACSTRUCT to be verified.
 *
 * @return Success or Error type
 */
api_error_type tdg_mr_verifyreport(uint64_t reportmacstruct_gpa);

/**
 * @brief Controls unconditional #VE on CPUID execution by the guest TD.
 *
 * @param Controls whether CPUID executed by the guest TD will cause #VE unconditionally
 * @return Success or Error type
 */
api_error_type tdg_vp_cpuidve_set(uint64_t control);

/**
 * @brief Perform a TD Exit to the host VMM.
 *
 * @note
 *
 * @param controler_value Controls which part of the guest TD state is passed as-is to the VMM and back.
 *
 * @return Success
 */
api_error_type tdg_vp_vmcall(uint64_t controller_value);
/**
 * @brief Read a VM-scope metadata field (control structure field) of a TD.
 *
 * @note
 *
 * @param field_code is the Field identifier
 * @param version is the leaf version
 *
 * @return Success or Error type
 */
api_error_type tdg_vm_rd(uint64_t field_code, uint64_t vm_id, uint64_t version);
/**
 * @brief Write a VM-scope metadata field (control structure field) of a TD.
 *
 * @note
 *
 * @param field_code is the Field identifier
 * @param wr_data is the data to write to the field
 * @param wr_mask is a 64b write mask to indicate which bits of the value in R8 are to be written to the field
 * @param version is the leaf version
 *
 * @return Success or Error type
 */
api_error_type tdg_vm_wr(uint64_t field_code,
        uint64_t vm_id,
        uint64_t wr_data,
        uint64_t wr_mask,
        uint64_t version);

/**
 * @brief Read a TDX Module global-scope metadata field
 *
 * @param field_id - FIELD ID to read
 *
 * @return Success or Error type
 */
api_error_type tdg_sys_rd(md_field_id_t field_id);

/**
 * @brief Read all gust-readable TDX Module global-scope metadata fields
 *
 * @param md_list_gpa - GPA of the output metadata list
 * @param field_id  - FIELD ID to read
 *
 * @return Success or Error type
 */
api_error_type tdg_sys_rdall(uint64_t md_list_gpa, md_field_id_t field_id);

/**
 * @brief Read a VCPU-scope metadata field (control structure field) of a TD.
 *
 * @note
 *
 * @param requested_field_code is the Field identifier
 *
 * @return Success or Error type
 */
api_error_type tdg_vp_rd(uint64_t requested_field_code);

/**
 * @brief Write a VCPU-scope metadata field (control structure field) of a TD.
 *
 * @note
 *
 * @param requested_field_code is the Field identifier
 * @param wr_data is the data to write to the field
 * @param wr_mask is a 64b write mask to indicate which bits of the value in R8 are to be written to the field
 *
 * @return Success or Error type
 */
api_error_type tdg_vp_wr(uint64_t requested_field_code,
        uint64_t wr_data,
        uint64_t wr_mask);

/**
 * @brief As a service TD, write a metadata field (control structure field) of a target TD.
 *
 * @param req_binding_handle - Binding handle
 * @param requested_field_code - Field identifier
 * @param wr_data - Data to write to the field
 * @param wr_mask - A 64b write mask to indicate which bits of the value in R8 are to be written to the field
 *
 * @return Success or Error type
 */
api_error_type tdg_servtd_wr(uint64_t req_binding_handle, uint64_t requested_field_code,
                             uint64_t wr_data, uint64_t wr_mask);

/**
 * @brief As a service TD, read a metadata field (control structure field) of a target TD.
 *
 * @param req_binding_handle - Binding handle
 * @param requested_field_code - Field identifier
 *
 * @return Success or Error type
 */
api_error_type tdg_servtd_rd(uint64_t req_binding_handle, uint64_t requested_field_code);

/**
 * @brief
 *
 * @param flags -
 * @param reg_list_gpa -
 *
 * @return Success or Error type
 */
api_error_type tdg_vp_enter(uint64_t flags, uint64_t reg_list_gpa);

/**
 * @brief
 *
 * @param vm_mask -
 *
 */
api_error_type tdg_vp_invept(uint64_t vm_mask);

/**
 * @brief Flushes TLB for a specific L2 VM
 * @param flags - input flags and relevant VM number
 * @param entry_or_list -
 * @param interrupt_occurred flag indicate if interrupt occurred
 * @return
 */
api_error_type tdg_vp_invvpid(uint64_t flags, uint64_t entry_or_list, bool_t* interrupt_occurred);

/**
 * @brief Read the GPA mapping and attributes of a TD private page
 *
 * @param page_gpa
 *
 * @return Success or Error type
 */
api_error_type tdg_mem_page_attr_rd(pa_t page_gpa);

/**
 * @brief Write the attributes of a private page.  Create or remove L2 page aliases as required
 *
 * @param target_page_info
 * @param gpa_attr
 * @param attr_flags
 *
 * @return Success or Error type
 */
api_error_type tdg_mem_page_attr_wr(
    page_info_api_input_t target_page_info,
    gpa_attr_t gpa_attr,
    attr_flags_t attr_flags);

#endif /* INCLUDE_TDX_TD_API_HANDLERS_H_ */
