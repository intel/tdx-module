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
 * @file tdx_basic_types.h
 * @brief TDX basic types definitions
 */
#ifndef __TDX_BASIC_TYPES_H_INCLUDED__
#define __TDX_BASIC_TYPES_H_INCLUDED__

////////////////////////////////////////////////////////////////////////////
// ANSI C18 Compliant data types.
////////////////////////////////////////////////////////////////////////////
#if (!defined(__cplusplus) || defined(CTE_BUILD))

// unsigned
typedef unsigned char             uint8_t;
typedef unsigned short int        uint16_t;
typedef unsigned int              uint32_t;
typedef unsigned long long int    uint64_t;

// signed
typedef signed char            int8_t;
typedef signed short int       int16_t;
typedef signed int             int32_t;
typedef signed long long int   int64_t;

#else

#include <cstdint>

#endif

////////////////////////////////////////////////////////////////////////////
// Boolean and true/false definitions.
////////////////////////////////////////////////////////////////////////////

// Universal TRUE and FALSE values.

#ifndef __cplusplus

typedef uint8_t                  bool_t;

// Universal true and false values.
#ifndef true
#   define true  ((bool_t)1)
#endif
#ifndef false
#   define false ((bool_t)0)
#endif

#else
typedef bool                  bool_t;
#endif //__cplusplus

////////////////////////////////////////////////////////////////////////////
// Bits operations and definitions.
////////////////////////////////////////////////////////////////////////////

#define BIT(n)               (uint64_t)(1ULL<<(n))

#define BIT_MASK(value,n)    ({tdx_debug_assert(((value)==0) || ((value)==1)); (uint64_t)((value)<<(n));})

#define BITS(high,low)       ((BIT(high) - BIT(low) + BIT(high)))

#define BITS_MASK(value,high,low)  ((value) & BITS((high),(low)))

////////////////////////////////////////////////////////////////////////////
// Longer than 64bit types.
////////////////////////////////////////////////////////////////////////////
#define ALIGN(n) __attribute__ ((aligned(n)))

typedef union ALIGN(16)
{
    uint64_t  qwords[2];
    uint32_t  dwords[4];
    uint8_t   bytes[16];
} uint128_t;


typedef union
{
    uint64_t qwords[4];
    uint32_t dwords[8];
    uint8_t bytes[32];
} uint256_t;

// Only for power of 2 alignment
#define ROUND_UP(value, align)    ( ((value) + ((align) - 1)) & (~((align) - 1)) )

#define MAX_UINT64              (BITS(63,0))

///////////////////////////////////////////////////////////////////////////
/// Min Max helpers
///////////////////////////////////////////////////////////////////////////

#define MIN(A,B) ( (A) < (B) ? (A) : (B) )

#endif // __TDX_BASIC_TYPES_H_INCLUDED__

