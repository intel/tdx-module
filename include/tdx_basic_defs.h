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
 * @file tdx_basic_defs.h
 * @brief TDX Basic Definitions
 */

#ifndef SRC_COMMON_TDX_BASIC_DEFS_H_
#define SRC_COMMON_TDX_BASIC_DEFS_H_

#define _STATIC_INLINE_ static inline
#define _ASM_VOLATILE_ __asm__ volatile
#define _ASM_          __asm__

#ifndef NULL
#define NULL            ((void*)0)
#endif

//Static Assertion
#define tdx_static_assert(e,x) typedef char assertion_##x  [(e)?1:-1]

#define _1KB                    0x400ULL
#define _2KB                    (2 * _1KB)
#define _4KB                    (4 * _1KB)
#define _1MB                    (_1KB * _1KB)
#define _2MB                    (2 * _1MB)
#define _1GB                    (_1MB * _1KB)

#define BIT_MASK_8BITS        0xFFULL
#define BIT_MASK_16BITS       0xFFFFULL
#define BIT_MASK_32BITS       0xFFFFFFFFULL
#define BIT_MASK_64BITS       0xFFFFFFFFFFFFFFFFULL

#define HIGH_32BITS(a)        (((a) >> 32) & BIT_MASK_32BITS)
#define LOW_32BITS(a)         ((a) & BIT_MASK_32BITS)

#define TDX_PAGE_SIZE_IN_BYTES  _4KB

#define PG_OFFSET(a)            ((a) & 0xFFFLLU)
#define PG_START(a)             ((a) & ~0xFFFLLU)

#ifndef offsetof
#define offsetof(type, field)   (uint64_t)&(((type *)0)->field)
#endif

#define sizeof_field(type, field)    sizeof(((type *)0)->field)

#define PACKED                  __attribute__((__packed__))

#define RARE_COND(cond)             __builtin_expect((cond), 0)
#define COMMON_COND(cond)           __builtin_expect((cond), 1)
#define IF_RARE(rare_condition)     if ( RARE_COND(rare_condition) )
#define IF_COMMON(common_condition) if ( COMMON_COND(common_condition) )

#define __STR(x)        #x
#define STR(x)          __STR(x)

#endif /* SRC_COMMON_TDX_BASIC_DEFS_H_ */
