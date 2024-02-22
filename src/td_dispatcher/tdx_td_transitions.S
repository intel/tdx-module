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
 * @file tdx_td_transitions.S
 * @brief TD entry and exit points
 */

#include "data_structures/tdx_local_data_offsets.h"

.section .text
.globl tdx_tdexit_entry_point
.globl tdx_tdentry_to_td

tdx_tdexit_entry_point:

    /**
     * Save all TD GPRs on module entry to LP local data
     * Local data is located at GSBASE
     */
    movq %rax,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET
    movq %rcx,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+8
    movq %rdx,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+16
    movq %rbx,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+24
    movq %rsp,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+32
    movq %rbp,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+40
    movq %rsi,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+48
    movq %rdi,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+56
    movq %r8,   %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+64
    movq %r9,   %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+72
    movq %r10,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+80
    movq %r11,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+88
    movq %r12,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+96
    movq %r13,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+104
    movq %r14,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+112
    movq %r15,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+120

	/*
	 * clear TD GPRs on entry to the TDX module
	 */
    xor %rax, %rax
    xor %rcx, %rcx
    xor %rdx, %rdx
    xor %rbx, %rbx
    xor %rbp, %rbp
    xor %rsi, %rsi
    xor %rdi, %rdi
    xor %r8, %r8
    xor %r9, %r9
    xor %r10, %r10
    xor %r11, %r11
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    xor %r15, %r15

    // Protection against speculative attacks on GPRs
    lfence

    // Choose which dispatcher we want to call based on current TD VM,
    // stored in local data before the TD entry
    movq %gs:TDX_LOCAL_DATA_CURRENT_TD_VM_ID_OFFSET, %rax
    test %rax, %rax
    jnz l2_dispatcher

    /**
     * Call the VMM API dispatcher
     */
    callq tdx_td_dispatcher
     
    /**
     * Unreachable code.  panic. 
     */
    ud2

l2_dispatcher:

    callq tdx_td_l2_dispatcher

    /**
     * Unreachable code.  panic.
     */
    ud2



tdx_tdentry_to_td:

    /**
     * Restore all TD GPRs on module entry from a TDVPS GPR area ptr passed in RSI
     */
    movq (%rsi),     %rax
    movq 8(%rsi),    %rcx
    movq 16(%rsi),   %rdx
    movq 24(%rsi),   %rbx
    // movq 32(%rsi),   %rsp - keep the RSP of the TDX module for debug purposes.
    // Actual RSP of the TD will be loaded during the VMENTRY from the TDCS (TD VMCS)
    movq 40(%rsi),   %rbp

    // RSI and RDI will be restored later - we are still using them

    movq 64(%rsi),   %r8
    movq 72(%rsi),   %r9
    movq 80(%rsi),   %r10
    movq 88(%rsi),   %r11
    movq 96(%rsi),   %r12
    movq 104(%rsi),  %r13
    movq 112(%rsi),  %r14
    movq 120(%rsi),  %r15

    // Launch state is being passed as a parameter
    test %edi, %edi
    jz vmlaunch_lbl

    movq 56(%rsi),   %rdi
    movq 48(%rsi),   %rsi

    vmresume
    
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    call tdx_failed_vmentry
#endif

    /**
    * Unreachable code.  panic.
    */
    ud2

vmlaunch_lbl:

    movq 56(%rsi),   %rdi
    movq 48(%rsi),   %rsi

    vmlaunch
    
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    call tdx_failed_vmentry
#endif

    /**
     * Unreachable code.  panic. 
     */
    ud2

