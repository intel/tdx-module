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
 * @file exception_handling.c
 * @brief Exception handling for TDX module. IDT, GDT and exception handler definitions
 */

#include "exception_handling.h"

#include "accessors/ia32_accessors.h"

#define TDX_MODULE_CS_SELECTOR        0x8U


const idt_and_gdt_tables_t tdx_idt_and_gdt_tables =
{
    .idt_table =
    {
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
        [0] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [1] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [2] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [3] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [4] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [5] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [6] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [7] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [8] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [9] =  {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [10] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [11] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [12] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
#endif
        // #GP handler - the only exception currently supported
        [13] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
        [14] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [15] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [16] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [17] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [18] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [19] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [20] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [21] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [22] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [23] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [24] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [25] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [26] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [27] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [28] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [29] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [30] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               },
        [31] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               }
#endif

        // All other entries and bits are filled with zeroes by default
    },

    .gdt_table =
    {
        [1] = {
                  .type = CODE_SEGMENT_TYPE_WITH_CRA_BITS, .s = 1, .p = 1, .l = 1
              }

        // All other entries are filled with zeroes by default
    }
};

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
void tdx_debug_exception_handler(uint64_t vector, uint64_t errc, uint64_t faulting_rip)
{
    TDX_ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

    TDX_ERROR("Exception %d occurred at RIP - 0x%llx (error code - 0x%llx)\n", vector, faulting_rip, errc);

    if (vector == E_PF)
    {
        TDX_ERROR("Page fault CR2 = 0x%llx\n", ia32_store_cr2());
    }

    TDX_ERROR("Stopping the module and entering infinite loop\n");

    TDX_ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

    while(1) {};
}
#endif
