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
 * @file tpa_hash.h
 *
 * @brief The TPA hash was extracted to an external header file in order to alternate between various hash values and minimize the binary's diff.
 *        The hash is set as a global volatile const in order to account for the binary diff edge case (explained below).
 *
 *        Binary diff edge case:
 *          During the design of the TPA hash assignment interface an edge case was found, where if atleast 2 QWORDS of the hash itself are identical
 *          then the binary changes would be scattered all around instead of staying 'local'.
 */

#ifndef __TPA_HASH_H__
#define __TPA_HASH_H__

#include "tdx_basic_types.h"

// Dummy TPA hash value, change when definition available
volatile const uint64_t GLOBAL_TPA_HASH_Q0 = TPA_HASH_Q0;
volatile const uint64_t GLOBAL_TPA_HASH_Q1 = TPA_HASH_Q1;
volatile const uint64_t GLOBAL_TPA_HASH_Q2 = TPA_HASH_Q2;
volatile const uint64_t GLOBAL_TPA_HASH_Q3 = TPA_HASH_Q3;
volatile const uint64_t GLOBAL_TPA_HASH_Q4 = TPA_HASH_Q4;
volatile const uint64_t GLOBAL_TPA_HASH_Q5 = TPA_HASH_Q5;

#endif // __TPA_HASH_H__
