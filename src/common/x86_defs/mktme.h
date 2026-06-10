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
 * @file mktme.h
 * @brief MKTME definitions
 */

#ifndef SRC_COMMON_X86_DEFS_MKTME_H_
#define SRC_COMMON_X86_DEFS_MKTME_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"


// Programming Status for MKTME_KEY_PROGRAM
#define MKTME_PROG_SUCCESS     0  // KeyID was successfully programmed
#define MKTME_INVALID_PROG_CMD 1  // Invalid KeyID programming command
#define MKTME_ENTROPY_ERROR    2  // Insufficient entropy
#define MKTME_INVALID_KEYID    3  // KeyID not valid
#define MKTME_INVALID_ENC_ALG  4  // Invalid encryption algorithm chosen (not supported)
#define MKTME_DEVICE_BUSY      5  // Failure to access key table


// keyid_ctrl command types
#define MKTME_KEYID_SET_KEY_DIRECT 0
#define MKTME_KEYID_SET_KEY_RANDOM 1
#define MKTME_KEYID_CLEAR_KEY      2
#define MKTME_KEYID_NO_ENCRYPT     3


typedef union
{
    struct
    {
        uint32_t
            command  : 8,
            enc_algo : 16,
            rsvd     : 8;
    };
    uint32_t raw;
} mktme_keyid_ctrl_t;


#define MKTME_KP_RESERVED1_SIZE (64 - sizeof(uint16_t) - sizeof(mktme_keyid_ctrl_t))
#define MKTME_KP_KEY_FIELD_SIZE (64)
#define MKTME_KP_RESERVED2_SIZE (256 - 64 - MKTME_KP_KEY_FIELD_SIZE*2)

typedef struct ALIGN(256) PACKED mktme_key_program_s {
    uint16_t            keyid;
    mktme_keyid_ctrl_t  keyid_ctrl;
    uint8_t             rsvd[MKTME_KP_RESERVED1_SIZE];
    //64 bytes
    union
    {
        uint128_t key; //16Bytes
        uint8_t key_field_1[MKTME_KP_KEY_FIELD_SIZE];
    };
    union
    {
        uint128_t tweak_key; //16Bytes
        uint8_t key_field_2[MKTME_KP_KEY_FIELD_SIZE];
    };
    uint8_t rsvd2[MKTME_KP_RESERVED2_SIZE];
} mktme_key_program_t;
tdx_static_assert(sizeof(mktme_key_program_t) == 256, mktme_key_program_t);


#endif /* SRC_COMMON_X86_DEFS_MKTME_H_ */
