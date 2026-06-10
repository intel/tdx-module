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
 * @file error_reporting.h
 * @brief Runtime error reporting features for TDX module
 */

#ifndef SRC_COMMON_HELPERS_ERROR_REPORTING_H_
#define SRC_COMMON_HELPERS_ERROR_REPORTING_H_

#include "helpers/fatal_info.h"
#include "debug/tdx_debug.h"

void tdx_report_error_and_halt(uint32_t source_id, uint32_t code);

void tdx_arch_fatal_error(void);

/**
 * @brief Prepares the extended info specific struct (td_handle) for fatal error diagnostics logging
 * 
 * @param hpa - TDR HPA (HKID bits are 0)
 */
extended_fatal_info_t prepare_extended_fatal_info_td_handle(uint64_t hpa);

/**
 * @brief Prepares the extended info specific struct (sept with td_handle) for fatal error diagnostics logging
 *
 * @param hpa - TDR HPA (HKID bits are 0)
 * @param vm_index - VM (L1 or L2) index
 * @param offending_sept_level - Offending Secure EPT entry level
 * @param offending_gpa - Offending guest physical address
 * @param sept_entry - Secure EPT entry
 */
extended_fatal_info_t prepare_extended_fatal_info_sept_td_handle(uint64_t hpa, uint64_t vm_index, uint64_t offending_sept_level, uint64_t offending_gpa, ia32e_sept_t sept_entry);

/**
 * @brief Prepares the extended info specific struct (sept with EPTP) for fatal error diagnostics logging
 *
 * @param eptp - EPT pointer
 * @param offending_level - Offending Secure EPT entry level
 * @param offending_gpa - Offending guest physical address
 * @param sept_entry - Secure EPT entry
 */
extended_fatal_info_t prepare_extended_fatal_info_sept_eptp(uint64_t eptp, uint8_t offending_level, uint64_t offending_gpa, ia32e_sept_t sept_entry);

/**
 * @brief Prepares the extended info specific struct (page HPA) for fatal error diagnostics logging
 *
 * @param hpa - HPA that was used when a fatal error was detected. NULL_PA (-1) if not applicable
 * @param size - Page size (0: 4KB, 1: 2MB, 2: 1GB)
 */
extended_fatal_info_t prepare_extended_fatal_info_page_hpa(uint64_t hpa, uint8_t size);

/**
 * @brief Prepares the extended info specific struct (PAMT) for fatal error diagnostics logging
 *
 * @param pamt_entry - PAMT entry where a fatal error was detected
 * @param hpa - HPA that was used when a fatal error was detected
 * @param level - Level of PAMT where a fatal error was detected
 * @param pamt_page - HPA or linear address (depending on the error case) the PAMT page, if applicable
 */
//extended_fatal_info_t prepare_extended_fatal_info_pamt(pamt_entry_t pamt_entry, uint64_t hpa, uint8_t level, uint64_t pamt_page);

/**
 * @brief Prepares the extended info specific struct (unexpected_exception) for fatal error diagnostics logging
 *
 * @param vector - Exception vector
 */
extended_fatal_info_t prepare_extended_fatal_info_unexpected_exception(uint8_t vector);

/**
 * @brief Prepares the extended info specific struct (unexpected_vm_exit) for fatal error diagnostics logging
 *
 * @param hpa - TDR HPA (HKID bits are 0)
 * @param vm_index - VM (L1 or L2) index
 * @param exit_reason - The Exit Reason VMCS field
 * @param extended_info - 1) For an unexpected VM exit due to IDT vectoring information, this field will provide the VMCS IDT vectoring information field.
                          2) For an unexpected VM exit due to RDMSR or WRMSR, this field will provide the offending MSR index.
                          3) In other cases, this field will be set to 0.
 */
extended_fatal_info_t prepare_extended_fatal_info_unexpected_vm_exit(uint64_t hpa, uint64_t vm_index, uint32_t exit_reason, uint32_t extended_info);

void fatal_error(fatal_error_id_e error_id, fatal_info_format_e format, extended_fatal_info_t* extended_info);


#define ERROR_CODE(source_id, code)    (uint64_t)(((uint64_t)(source_id) << 32U) | (uint64_t)(code))


//Architectural Fatal Error Macro.
//#define FATAL_ERROR()       {\
//                                TDX_ERROR("Architectural fatal error at line: %d , in file %s\n", __LINE__, __FILENAME__);\
//                                tdx_arch_fatal_error();\
//                            }

//Runtime (includes product-build) Assertion
#define tdx_sanity_check(cond, err_id, code) IF_RARE (!(cond)) {\
                                                    TDX_ERROR("Runtime panic at line: %d , in file %s\n", __LINE__, __FILENAME__);\
                                                    TDX_ERROR("Error 0x%llx reported by the TDX Module\n", ERROR_CODE(err_id, code));\
                                                    TDX_ERROR("Module shutdown initiated\n");\
                                                    fatal_error(err_id, FATAL_INFO_FORMAT_BASIC_INFO, NULL);\
                                                }

#endif /* SRC_COMMON_HELPERS_ERROR_REPORTING_H_ */
