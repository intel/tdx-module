/**
 * Copyright (C) 2023 Intel Corporation                                          
 *                                                                               
 * Permission is hereby granted, free of charge, to any person obtaining a copy  
 * of this software and associated documentation files (the "Software"),         
 * to deal in the Software without restriction, including without limitation     
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,      
 * and/or sell copies of the Software, and to permit persons to whom             
 * the Software is furnished to do so, subject to the following conditions:      
 *                                                                               
 * The above copyright notice and this permission notice shall be included       
 * in all copies or substantial portions of the Software.                        
 *                                                                               
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS       
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL      
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES             
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,      
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE            
 * OR OTHER DEALINGS IN THE SOFTWARE.                                            
 *                                                                               
 * SPDX-License-Identifier: MIT
 */

/**
 * @file tdx_exit_to_vmm.S
 * @brief Module's VMM exit point - restores GPRs from local data and call SEAMRET
 */

#include "data_structures/tdx_local_data_offsets.h"


.section .text
.globl tdx_seamret_to_vmm
.type  tdx_seamret_to_vmm,@function
tdx_seamret_to_vmm:

    /**
     * Restore all VMM GPRs on module entry from LP local data
     * Local data is located at GSBASE
     */
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET,     %rax
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+8,   %rcx
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+16,  %rdx
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+24,  %rbx
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+32,  %rsp // not actually needed
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+40,  %rbp
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+48,  %rsi
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+56,  %rdi
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+64,  %r8
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+72,  %r9
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+80,  %r10
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+88,  %r11
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+96,  %r12
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+104, %r13
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+112, %r14
    movq %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+120, %r15

    /**
     * Call SEAMRET
     */
	.byte 0x66, 0x0F, 0x01, 0xCD

    /**
     * No accesible code from this point
     * Panic with UD2 if reached
     */
    ud2

