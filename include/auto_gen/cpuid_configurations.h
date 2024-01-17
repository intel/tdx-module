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
 *  This File is Automatically generated by the TDX xls extract tool
 *  based on architecture commit id "5c1d21c9" 
 *  Spreadsheet Format Version - '7'
 **/

#ifndef _AUTO_GEN_CPUID_CONFIG_H_
#define _AUTO_GEN_CPUID_CONFIG_H_



#include "tdx_api_defs.h"
#include "data_structures/tdx_global_data.h"
#include "auto_gen/cpuid_configurations_defines.h"


/**
 * CPUID Lookup Table
 */
typedef struct
{
    cpuid_config_leaf_subleaf_t leaf_subleaf;

    bool_t valid_entry;
    bool_t faulting;

    cpuid_config_return_values_t verify_mask;
    cpuid_config_return_values_t verify_value;
    cpuid_config_return_values_t verify_same;

    cpuid_config_return_values_t fixed0_or_dynamic;
    cpuid_config_return_values_t fixed1;
    uint32_t config_index;
} cpuid_lookup_t;

typedef struct
{
    cpuid_config_leaf_subleaf_t leaf_subleaf;

    bool_t valid_entry;
    cpuid_config_return_values_t config_direct;
    cpuid_config_return_values_t allow_direct;
    uint32_t lookup_index;
} cpuid_configurable_t;


const cpuid_lookup_t cpuid_lookup[MAX_NUM_CPUID_LOOKUP];
const cpuid_configurable_t cpuid_configurable[MAX_NUM_CPUID_CONFIG];

const cpuid_config_return_values_t xfam_mask_0x7_0x1[XCR0_MAX_VALID_BIT + 1];
const cpuid_config_return_values_t xfam_mask_0x7_0x0[XCR0_MAX_VALID_BIT + 1];
const cpuid_config_return_values_t xfam_mask_0x1_0xffffffff[XCR0_MAX_VALID_BIT + 1];
const cpuid_config_return_values_t xfam_mask_0xd_0x0[XCR0_MAX_VALID_BIT + 1];
const cpuid_config_return_values_t xfam_mask_0xd_0x1[XCR0_MAX_VALID_BIT + 1];


#endif /* _AUTO_GEN_CPUID_CONFIG_H_ */
