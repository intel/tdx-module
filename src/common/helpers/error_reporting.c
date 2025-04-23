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
 * @file error_reporting.c
 * @brief Runtime error reporting features for TDX module
 */

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "error_reporting.h"

void tdx_report_error_and_halt(uint32_t source_id, uint32_t code)
{
    uint64_t error_code = ERROR_CODE(source_id, code);
    TDX_ERROR("Error 0x%llx reported by the TDX Module\n", error_code);
    TDX_ERROR("Module shutdown initiated - UD2 expected\n");

    UNUSED(error_code);

    tdx_arch_fatal_error();
}

void tdx_arch_fatal_error( void )
{
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    TDX_ERROR("!!!!!!!!!!!!!!!!!! - Module critical error - UD2 - !!!!!!!!!!!!!!!!!!\n");
    TDX_ERROR("!!!!!!!!!!!!!!!!!!         - LAST MESSAGE -        !!!!!!!!!!!!!!!!!!\n");
    debug_control_t* p_ctl = &(get_global_data()->debug_control);
    dump_print_buffer_to_vmm_memory(p_ctl->emergency_buffer, 0);
#endif

    ia32_ud2();
}



