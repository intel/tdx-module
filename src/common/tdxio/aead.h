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
 * @file aead.h
 * @brief
 */

#ifndef SRC_COMMON_TDXIO_AEAD_H_
#define SRC_COMMON_TDXIO_AEAD_H_


#include "tdx_api_defs.h"
#include "data_structures/tdxio/ide_stream_defs.h"
#include "tdxio/ide_stream.h"

#include "debug/tdx_debug.h"

/**
 * @brief // TODO
 *
 * @param spdm_info_ptr
 * @param aad_data_ptr
 * @param msg_payload_ptr - Plain/Cipher text
 * @param msg_payload_len - Plain text length
 * @param mac
 *
 * @return api_error_type
 */
api_error_type tdx_io_aead_encrypt(
    spdm_info_t *const spdm_info_ptr,
    void *const aad_data_ptr,
    void *const msg_payload_ptr,
    const uint64_t msg_payload_len,
    uint8_t *const mac);

api_error_type tdx_io_aead_decrypt(
    spdm_info_t *const spdm_info,
    void *const source_message_ptr,
    uint64_t source_msg_len,
    void *const dest_buff_ptr,
    uint64_t const dst_msg_len);


#endif /* SRC_COMMON_TDXIO_AEAD_H_ */
