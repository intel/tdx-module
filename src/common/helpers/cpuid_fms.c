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
 * @file cpuid_fms.c
 * @brief Allowed CPUID definitions
 */

#include "cpuid_fms.h"
#include "accessors/data_accessors.h"

const fms_info_t allowed_fms[TOTAL_KNOWN_FMS] = {

        { .raw = (CWF_NATIVE_FMS    | CWF_LATEST_STEPPING) },
        { .raw = (GNR_D_NATIVE_FMS  | GNR_D_LATEST_STEPPING) },
        { .raw = (GNR_SP_NATIVE_FMS | GNR_SP_LATEST_STEPPING) },
        { .raw = (SRF_NATIVE_FMS    | SRF_LATEST_STEPPING) },
        { .raw = (EMR_NATIVE_FMS    | EMR_LATEST_STEPPING) },
        { .raw = (SPR_NATIVE_FMS    | SPR_LATEST_STEPPING) },

};

// Currently empty
const fms_info_t disallowed_fms[TOTAL_KNOWN_FMS] = { 0 };

static bool_t are_equal_family_and_model(fms_info_t fms_config1, fms_info_t fms_config2)
{
    return ((fms_config1.raw & ~CPUID_S_MASK) == (fms_config2.raw & ~CPUID_S_MASK));
}

static uint16_t find_table_start(void)
{
    fms_info_t platform_fms = get_global_data()->platform_fms;

    for (uint16_t i = 0; i < TOTAL_KNOWN_FMS; i++)
    {
        if (are_equal_family_and_model(platform_fms, allowed_fms[i]))
        {
            return i;
        }
    }

    // Should never happen
    FATAL_ERROR();

    return 0;
}

fms_info_t get_allowed_fms(uint16_t index)
{
    fms_info_t platform_fms = get_global_data()->platform_fms;

    if (index == 0)
    {
        return platform_fms;
    }

    uint16_t table_start = find_table_start();

    if ((table_start + index) >= TOTAL_KNOWN_FMS)
    {
        fms_info_t zero_fms = { .raw = 0 };
        return zero_fms;
    }

    lfence();

    return allowed_fms[table_start + index];
}

uint16_t get_num_allowed_fms(void)
{
    uint16_t table_start = find_table_start();

    return (TOTAL_KNOWN_FMS - table_start);
}

bool_t check_fms_config(fms_info_t fms_config)
{
    fms_info_t platform_fms = get_global_data()->platform_fms;

    if (are_equal_family_and_model(platform_fms, fms_config) &&
        (fms_config.stepping_id > platform_fms.stepping_id))
    {
        return false;
    }

    uint16_t table_start = find_table_start();

    bool_t family_model_found = false;

    for (uint16_t i = table_start; i < TOTAL_KNOWN_FMS; i++)
    {
        if (are_equal_family_and_model(fms_config, allowed_fms[i]))
        {
            family_model_found = true;

            if (fms_config.stepping_id > allowed_fms[i].stepping_id)
            {
                return false;
            }
        }
    }

    return family_model_found;
}
