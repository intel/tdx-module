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
 * @file tdx_vmm_dispatcher.h
 * @brief VMM entry point and API dispatcher
 */
#ifndef __TDX_VMM_DISPATCHER_H_INCLUDED__
#define __TDX_VMM_DISPATCHER_H_INCLUDED__


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"


/**
 * @brief Entry point to TDX module from VMM
 *
 * @note Written in assembly and defined as the binary's entry point
 *
 * @return None
 */
void tdx_seamcall_entry_point(void);


/**
 * @brief Dispatcher for VMM side API calls
 *
 * @note
 *
 * @return None
 */
void tdx_vmm_dispatcher(void);


/**
 * @brief Return sequence from the module to the VMM
 *
 * Restores VMM state and eventually calls SEAMRET
 *
 * @return None
 */
void tdx_vmm_post_dispatching(void);


/**
 * @brief Exit the module
 *
 * @note Written in assembly
 *
 * @return None
 */
__attribute__((visibility("hidden"))) void tdx_seamret_to_vmm(void);


#endif // __TDX_VMM_DISPATCHER_H_INCLUDED__
