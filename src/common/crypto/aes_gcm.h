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
 * @file aes_gcm.h
 * @brief Crypto API for AES GCM library
 */
#ifndef __AES_GCM_H_INCLUDED__
#define __AES_GCM_H_INCLUDED__

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"

typedef int32_t aes_gcm_api_error;

#define AES_GCM_NO_ERROR 0

typedef uint256_t key256_t;

/*********************************************
* CRYPRO CTX
*********************************************/
#define GCM_STATE_BUFFER_SIZE ((3 * _1KB) + 512)

/**
 * @struct aes_gcm_ctx_t
 *
 * @brief Holds AES GCM context state
 */
typedef struct aes_gcm_ctx_s
{
    int      size;
    uint8_t  state[GCM_STATE_BUFFER_SIZE];
} aes_gcm_ctx_t;

/*********************************************
* MIGSC IV
*********************************************/
#define CRYPTO_IV_SIZE 12
typedef uint8_t crypto_iv_t[CRYPTO_IV_SIZE];

/**
 * @struct migsc_iv_t
 *
 * @brief Holds crypto IV definition
 */
typedef union migs_iv_s
{
    struct PACKED
    {
        uint64_t iv_counter;
        uint16_t migs_index;
        uint16_t reserved;
    };
    crypto_iv_t raw;
} migs_iv_t;
tdx_static_assert(CRYPTO_IV_SIZE == sizeof(migs_iv_t), migs_iv_t);

aes_gcm_api_error aes_gcm_init(const key256_t *key, aes_gcm_ctx_t *ctx, const migs_iv_t *iv);    // validates also that enough memory was allocated for the context
// Refreshes AES-GCM context before usage to update internal pointers
// Should be called if the used AES-GCM context was initialized earlier by other SEAMCALL
aes_gcm_api_error aes_gcm_refresh_context(aes_gcm_ctx_t *ctx);
aes_gcm_api_error aes_gcm_reset(aes_gcm_ctx_t *ctx, const migs_iv_t *iv);    // does NOT resets the AAD
aes_gcm_api_error aes_gcm_process_aad(aes_gcm_ctx_t *ctx, const uint8_t *p_aad, int32_t size_aad);
aes_gcm_api_error aes_gcm_encrypt(aes_gcm_ctx_t *ctx, const uint8_t *src, uint8_t *dst, int32_t size);
aes_gcm_api_error aes_gcm_decrypt(aes_gcm_ctx_t *ctx, const uint8_t *src, uint8_t *dst, int32_t size);
aes_gcm_api_error aes_gcm_decrypt_direct(aes_gcm_ctx_t *ctx, const uint8_t *src, uint8_t *dst, int32_t size);
aes_gcm_api_error aes_gcm_finalize(aes_gcm_ctx_t *ctx, uint8_t *mac);

#endif /* __AES_GCM_H_INCLUDED__ */
