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
 * @file cpuid_fms.h
 * @brief Allowed CPUID definitions
 */

#ifndef SRC_COMMON_HELPERS_CPUID_FMS_H_
#define SRC_COMMON_HELPERS_CPUID_FMS_H_

#include "x86_defs/x86_defs.h"

#define NUM_OF_DISALLOWED_FMS           0


#define SPR_NATIVE_FMS                  0x806F0
#define SPR_LATEST_STEPPING             0x8

#define EMR_NATIVE_FMS                  0xC06F0
#define EMR_LATEST_STEPPING             0x2

#define SRF_NATIVE_FMS                  0xA06F0
#define SRF_LATEST_STEPPING             0x0

#define GNR_SP_NATIVE_FMS               0xA06D0
#define GNR_SP_LATEST_STEPPING          0x0

#define GNR_D_NATIVE_FMS                0xA06E0
#define GNR_D_LATEST_STEPPING           0x0

#define CWF_NATIVE_FMS                  0xD06D0
#define CWF_LATEST_STEPPING             0x0


#define TOTAL_KNOWN_FMS                 6

extern const fms_info_t allowed_fms[TOTAL_KNOWN_FMS];
extern const fms_info_t disallowed_fms[TOTAL_KNOWN_FMS];

/**
 * @brief Get allowed FMS for a given index. For index 0, a current platform value FMS is returned.
 *        For any following index, one older supported generation FMS is returned
 *        For Stepping (bits 3:0), the maximum allowed configuration value is provided.
 *        For index bigger than number of entries available, all-0 are returned
 *
 * @param index
 * @return
 */
fms_info_t get_allowed_fms(uint16_t index);

/**
 * @brief Get the number of valid ALLOW_FMS entries
 * @return
 */
uint16_t get_num_allowed_fms(void);

/**
 * @brief Check Family/Model/Stepping configuration
 *        Return true only if the provide FMS is compliant with the list of allowed FMS settings.
 *
 * @param fms_config
 * @return
 */
bool_t check_fms_config(fms_info_t fms_config);


#endif /* SRC_COMMON_HELPERS_CPUID_FMS_H_ */
