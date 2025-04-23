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
 * @file exception_handling.h
 * @brief Exception handling for TDX module. IDT, GDT and exception handler definitions
 */

#ifndef SRC_COMMON_EXCEPTION_HANDLING_EXCEPTION_HANDLING_H_
#define SRC_COMMON_EXCEPTION_HANDLING_EXCEPTION_HANDLING_H_

#include "tdx_basic_types.h"
#include "x86_defs/x86_defs.h"

#define IDT_ENTRIES_NUM          32
#define IDT_ENTRY_SIZE           16

#define GDT_ENTRIES_NUM           2
#define GDT_ENTRY_SIZE            8

// Do not change any names, without changing them in Makefile too

typedef union ALIGN(_4KB) PACKED idt_and_gdt_tables_u
{
    struct
    {
        ia32_idt_gate_descriptor idt_table[IDT_ENTRIES_NUM];

        // GDT table have to start at upper 2KB
        uint8_t reserved_1[_2KB - (sizeof(ia32_idt_gate_descriptor) * IDT_ENTRIES_NUM) ];

        ia32_segment_descriptor_t gdt_table[GDT_ENTRIES_NUM];
    };
    struct
    {
        uint8_t idt_table_raw[_2KB];
        uint8_t gdt_table_raw[_2KB];
    };
} idt_and_gdt_tables_t;
tdx_static_assert(sizeof(idt_and_gdt_tables_t) == _4KB, idt_and_gdt_tables_t);
tdx_static_assert(offsetof(idt_and_gdt_tables_t, gdt_table) == _2KB, idt_and_gdt_tables_t);

extern const idt_and_gdt_tables_t tdx_idt_and_gdt_tables;

void tdx_fault_wrapper(void);

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
void tdx_debug_exception_handler(uint64_t vector, uint64_t errc, uint64_t faulting_rip);
#endif

// Names from that point can be changed freely

#endif /* SRC_COMMON_EXCEPTION_HANDLING_EXCEPTION_HANDLING_H_ */
