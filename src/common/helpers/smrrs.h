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

/*
 * smrrs.h
 *
 *  Created on: 6 Mar 2019
 *      Author: pstedev
 */

#ifndef SRC_COMMON_HELPERS_SMRRS_H_
#define SRC_COMMON_HELPERS_SMRRS_H_

#include "tdx_basic_types.h"

#define MTRR_CAP_MSR_ADDR 0xFE

typedef union ia32_mtrrcap_u
{
    struct
    {
        uint64_t vcnt       : 8,  // 0-7
                 fix        : 1,  // 8
                 rsvd1      : 1,  // 9
                 wc         : 1,  // 10
                 smrr       : 1,  // 11
                 prmrr      : 1,  // 12
                 smrr2      : 1,  // 13
                 smrr_lock  : 1,  // 14
                 seamrr     : 1,  // 15
                 rsvd2      : 48; // 16-64
    };
    uint64_t raw;
} ia32_mtrrcap_t;

#define SMRR_BASE_MSR_ADDR 0x1F2
#define SMRR_MASK_MSR_ADDR 0x1F3

#define SMRR2_BASE_MSR_ADDR 0x1F6
#define SMRR2_MASK_MSR_ADDR 0x1F7

typedef union
{
    struct
    {
        uint64_t rsvd0 :10, // Bits 0-9
                 lock  :1,  // Bit 10
                 vld   :1,  // Bit 11
                 mask  :20, // Bits 12-31
                 rsvd1 :32; // Bits 32-63
    };
    uint64_t raw;
} smrr_mask_t;

typedef union
{
    struct
    {
        uint64_t memtype :8, rsvd0 :4, base :20, rsvd1 :32;
    };
    uint64_t raw;
} smrr_base_t;

typedef struct
{
    smrr_base_t smrr_base;
    smrr_mask_t smrr_mask;
} smrr_range_t;


#endif /* SRC_COMMON_HELPERS_SMRRS_H_ */
