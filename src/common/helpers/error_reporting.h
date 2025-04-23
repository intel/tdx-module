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

#include "debug/tdx_debug.h"

void tdx_report_error_and_halt(uint32_t source_id, uint32_t code);

void tdx_arch_fatal_error(void);

//Architectural Fatal Error Macro.
#define FATAL_ERROR()       {\
                                TDX_ERROR("Architectural fatal error at line: %d , in file %s\n", __LINE__, __FILENAME__);\
                                tdx_arch_fatal_error();\
                            }

//Runtime (includes product-build) Assertion
#define tdx_sanity_check(cond, source_id, code) IF_RARE (!(cond)) {\
                                                    TDX_ERROR("Runtime panic at line: %d , in file %s\n", __LINE__, __FILENAME__);\
                                                    tdx_report_error_and_halt(source_id, code);\
                                                }

// SCEC - Sanity Check Error Code
#define SCEC_LOCK_SOURCE               0x0001
#define SCEC_HELPERS_SOURCE            0x0002
#define SCEC_PAMT_MANAGER_SOURCE       0x0003
#define SCEC_SEPT_MANAGER_SOURCE       0x0004
#define SCEC_KEYHOLE_MANAGER_SOURCE    0x0005
#define SCEC_VT_ACCESSORS_SOURCE       0x0006
#define SCEC_TD_DISPATCHER_SOURCE      0x0007
#define SCEC_VMM_DISPATCHER_SOURCE     0x0008
#define SCEC_TDEXIT_SOURCE             0x0009
#define SCEC_METADATA_HANDLER_SOURCE   0x000A
#define SCEC_TDCALL_SOURCE(n)          (0xA000 | ((n) & 0xFF))
#define SCEC_SEAMCALL_SOURCE(n)        (0xB000 | ((n) & 0xFF))
#define SCEC_CANARY_CORRUPT_SOURCE     0xC000


#define ERROR_CODE(source_id, code)    (uint64_t)(((uint64_t)(source_id) << 32U) | (uint64_t)(code))

#endif /* SRC_COMMON_HELPERS_ERROR_REPORTING_H_ */
