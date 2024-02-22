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
 * @file exception_handling_asm_S
 * @brief Assembly code implementation of exception handlers
 */

#include "exception_handling_consts.h"

/**
 * Data stack after exception handler entry:
 * [       ...       ] <- RSP before exception
 * [     Spare 64    ] +48
 * [ Saved SS = 0x10 ] +40
 * [     Old RSP     ] +32
 * [    Old RFLAGS   ] +24
 * [ Saved CS = 0x8  ] +16
 * [   Faulting RIP  ] +8
 * [    Error code   ] +0 <- Current RSP after exception
 *
 * For exceptions that don't deliver error code, Current RSP will point at the "Faulting RIP"
 */

.section .text

#define CORRUPT_ADDRESS                                 (1ULL << 63) // Non-canonical Linear Address

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
#define EXCEPTION_HANDLER(func, vec)                    endbr64;            /* 4 bytes */ \
                                                        movq $vec, %rdi;    /* 7 bytes */ \
                                                        jmp func;           /* 5 bytes */


.globl tdx_fault_wrapper
.type  tdx_fault_wrapper,@function
tdx_fault_wrapper:

    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 0)           // Vector 0
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 1)           // Vector 1
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 2)           // Vector 2
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 3)           // Vector 3
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 4)           // Vector 4
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 5)           // Vector 5
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 6)           // Vector 6
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 7)           // Vector 7
    EXCEPTION_HANDLER(tdx_debug_handler_with_errc, 8)         // Vector 8
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 9)           // Vector 9
    EXCEPTION_HANDLER(tdx_debug_handler_with_errc, 10)        // Vector 10
    EXCEPTION_HANDLER(tdx_debug_handler_with_errc, 11)        // Vector 11
    EXCEPTION_HANDLER(tdx_debug_handler_with_errc, 12)        // Vector 12
    EXCEPTION_HANDLER(tdx_gp_handler, 13)                     // Vector 13 - #GP
    EXCEPTION_HANDLER(tdx_debug_handler_with_errc, 14)        // Vector 14
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 15)          // Vector 15
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 16)          // Vector 16
    EXCEPTION_HANDLER(tdx_debug_handler_with_errc, 17)        // Vector 17
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 18)          // Vector 18
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 19)          // Vector 19
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 20)          // Vector 20
    EXCEPTION_HANDLER(tdx_debug_handler_with_errc, 21)        // Vector 21
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 22)          // Vector 22
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 23)          // Vector 23
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 24)          // Vector 24
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 25)          // Vector 25
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 26)          // Vector 26
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 27)          // Vector 27
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 28)          // Vector 28
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 29)          // Vector 29
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 30)          // Vector 30
    EXCEPTION_HANDLER(tdx_debug_handler_no_errc, 31)          // Vector 31

    ud2


tdx_debug_handler_no_errc:

    movq $0, %rsi                          // Pass zero in error code as second parameter
    jmp skip_errc

tdx_debug_handler_with_errc:

    // We got the exception vector as the first parameter in RSI
    movq (%rsp), %rsi                      // Pass error code as second parameter
    addq $0x8, %rsp                        // Discard error code

skip_errc:

    movq (%rsp), %rdx                      // Get the faulting RIP as the third paramater
    callq tdx_debug_exception_handler

    ud2

#else/* DEBUG_IDT - DEBUGFEATURE_TDX_DBG_TRACE */

#define EXCEPTION_HANDLER(func)                         endbr64;            /* 4 bytes */ \
                                                        jmp func;           /* 5 bytes */\
                                                        /* 7 nops to fill 7 bytes to complete 16 bytes */\
                                                        nop; nop; nop; nop; \
                                                        nop; nop; nop; \

.globl tdx_fault_wrapper
.type  tdx_fault_wrapper,@function
tdx_fault_wrapper:

    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 0
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 1
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 2
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 3
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 4
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 5
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 6
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 7
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 8
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 9
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 10
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 11
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 12
    EXCEPTION_HANDLER(tdx_gp_handler)                 // Vector 13 - #GP
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 14
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 15
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 16
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 17
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 18
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 19
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 20
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 21
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 22
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 23
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 24
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 25
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 26
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 27
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 28
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 29
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 30
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 31

    ud2

#endif/* DEBUG_IDT - DEBUGFEATURE_TDX_DBG_TRACE*/

tdx_unsupported_handler:
    // This a generic handler for unsupported exception type
    // Initiate SEAM shutdown with a Triple Fault

    movq $CORRUPT_ADDRESS, %rsp            // Corrupt stack pointer
    movq $0, %rax
    jmpq *%rax                             // Jump to non-mapped address

    ud2

tdx_gp_handler:

    addq $0x8, %rsp                        // Discard error code

    movq (%rsp), %rsi                      // Get the faulting RIP
    movq -8(%rsi), %rsi                    // Read the magic indicator

    movq $FAULT_SAFE_MAGIC_INDICATOR, %rax

    xorq %rax, %rsi                        // Check indicator validity
    jz   indicator_valid                   // If not correct - Initiate SEAM shutdown

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    movq $13,      %rdi                      // Set up vector
    movq -8(%rsp), %rsi                      // Set up error code
    movq (%rsp),   %rdx                      // Set up faulting RIP
    callq tdx_debug_exception_handler
#else
    movq $CORRUPT_ADDRESS, %rsp            // Corrupt stack pointer
    movq $0, %rax
    jmpq *%rax                             // Jump to non-mapped address
#endif

indicator_valid:

    movq $NON_FAULTING_MSR_ADDR, %rcx      // Non-faulting MSR index
    movq $0x0, %rax                        // Non-faulting value low
    movq $0x0, %rdx                        // Non-faulting value high

    // Check how much bytes we need to pop from the stack
    // If the old stack wasn't aligned on 16-bytes, "Spare 64" will be inserted to align it

    btq  $3, 24(%rsp)                      // Check if old stack was aligned on 8 or 16 bytes
    jc aligned_stack_ret

    lretq $32

    ud2

aligned_stack_ret:

    lretq $24

    ud2
