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
 * @file service_td.h
 * @brief
 */

#ifndef SRC_COMMON_HELPERS_SERVICE_TD_H_
#define SRC_COMMON_HELPERS_SERVICE_TD_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"

#include "x86_defs/x86_defs.h"
#include "debug/tdx_debug.h"

#define SERVTD_TYPE_MIGTD         0
#define SERVTD_TYPE_MAX_TYPE      SERVTD_TYPE_MIGTD

#define MAX_SERVTDS 1
#define MAX_MIGS  512

typedef union stdbc_link_u
{
    struct
    {
        uint64_t lock           : 1;   // Bit 0
        uint64_t bound          : 1;   // Bit 1
        uint64_t reserved_0     : 10;  // Bits 11:2
        uint64_t stdbc_hpa      : 40;  // Bits 51:12
        uint64_t reserved_1     : 12;  // Bits 63:52
    };
    uint64_t raw;
} stdbc_link_t;

typedef union ignore_tdinfo_bitmap_u
{
    struct
    {
        uint16_t attributes    : 1;
        uint16_t xfam          : 1;
        uint16_t mrtd          : 1;
        uint16_t mrconfig      : 1;
        uint16_t mrowner       : 1;
        uint16_t mrownerconfig : 1;
        uint16_t rtmr          : 4;
        uint16_t servtd_hash   : 1;
        uint16_t reserved      : 5;

    };
    uint16_t raw;
} ignore_tdinfo_bitmap_t;
tdx_static_assert(sizeof(ignore_tdinfo_bitmap_t) == 2, ignore_tdinfo_bitmap_t);

typedef union servtd_attributes_u
{
    struct
    {
        struct
        {
            uint32_t instance_binding   : 1;  // Bit 0
            uint32_t solicited_binding  : 1;  // Bit 1 (future, must be 0)
            uint32_t platform_binding   : 1;  // Bit 2 (future, must be 0)
            uint32_t migratable_binding : 1;  // Bit 3 (future, must be 0)
            uint32_t reserved0          : 28; // Bits 31:4
        };
        ignore_tdinfo_bitmap_t ignore_tdinfo; // Bits 47:32
        uint16_t               reserved1;     // Bits 63:48
    };
    uint64_t raw;
} servtd_attributes_t;
tdx_static_assert(sizeof(servtd_attributes_t) == 8, servtd_attributes_t);

#define SERVTD_ATTRIBUTES_FIXED_0  0x000007FF00000001ULL  // A bit value of 0 indicates corresponding SERVTD_ATTR bit must be 0
#define SERVTD_ATTRIBUTES_FIXED_1  0x0000000000000000ULL  // A bit value of 1 indicates corresponding SERVTD_ATTR bit must be 1

typedef union servtd_binding_handle_u
{
    struct
    {
        uint64_t binding_slot : 12;
        uint64_t tdr_page     : 40;
        uint64_t reserved     : 12;
    };
    uint64_t raw;
} servtd_binding_handle_t;
tdx_static_assert(sizeof(servtd_binding_handle_t) == 8, servtd_binding_handle_t);


typedef enum servtd_binding_state_e
{
    SERVTD_NOT_BOUND = 0,
    SERVTD_PRE_BOUND = 1,
    SERVTD_BOUND     = 2
} servtd_binding_state_t;


_STATIC_INLINE_ bool_t servtd_is_attrib_valid(const servtd_attributes_t *attrib)
{
    return (((attrib->raw & ~SERVTD_ATTRIBUTES_FIXED_0) |       // validate all FIXED_0 bits are '0'
             (~attrib->raw & SERVTD_ATTRIBUTES_FIXED_1)) == 0); // validate all FIXED_1 bits are '1'
}

_STATIC_INLINE_ servtd_binding_handle_t create_servtd_binding_handle(uint256_t servtd_uuid,
                                                                     pa_t tdr_hpa, uint64_t slot)
{
    servtd_binding_handle_t handle;
    handle.raw = 0;
    handle.tdr_page = tdr_hpa.page_4k_num;
    handle.binding_slot = slot;
    handle.raw += servtd_uuid.qwords[0];

    return handle;
}

_STATIC_INLINE_ void break_servtd_binding_handle(servtd_binding_handle_t handle, uint256_t servtd_uuid,
                                                 pa_t* tdr_hpa, uint64_t* slot)
{
    handle.raw -= servtd_uuid.qwords[0];
    tdr_hpa->raw = 0;
    tdr_hpa->page_4k_num = handle.tdr_page;
    *slot = handle.binding_slot;
}

// Check the type is supported
_STATIC_INLINE_ bool_t is_servtd_supported(uint16_t servtd_type)
{
    if (servtd_type == SERVTD_TYPE_MIGTD)
    {
        return true;
    }
    return false;
}

#if (MAX_SERVTDS > 1)
// There is only one type for now
_STATIC_INLINE_ bool_t is_servtd_singleton(uint16_t servtd_type)
{
    UNUSED(servtd_type);
    return true;
}
#endif

#endif /* SRC_COMMON_HELPERS_SERVICE_TD_H_ */
