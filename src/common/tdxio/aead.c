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
 * @file aes_gcm.c
 * @brief Crypto implementation for AES GCM library
 */


#include "tdxio/aead.h"

api_error_type tdx_io_aead_encrypt(
    spdm_info_t *const spdm_info_ptr,
    void *const aad_data_ptr,
    void *const msg_payload_ptr,    // Plain/cipher text
    const uint64_t msg_payload_len, // Plain text length
    uint8_t *const mac_ptr)
{

    aes_gcm_api_error res;
    bool_t is_fatal_error = false;
    api_error_type return_val = UNINITIALIZE_ERROR;

    if (acquire_mutex_lock(&spdm_info_ptr->tx_lock) != LOCK_RET_SUCCESS)
    {
        // wipe secrets
        basic_memset_to_zero(msg_payload_ptr, msg_payload_len);

        TDX_ERROR("Failed to acquire tx lock on SPDM info\n");
        return TDX_OPERAND_BUSY;
    }

    if(spdm_info_ptr->binding_info.keys.tx_req_seq == (uint64_t)(-1))
    {
        // wipe secrets
        basic_memset_to_zero(msg_payload_ptr, msg_payload_len);
        TDX_ERROR("SPDM session key require refresh\n");

        return_val = TDX_SPDM_SESSION_KEY_REQUIRE_REFRESH;
        goto EXIT;
    }

    // The function, AEAD_Encrypt , fully encrypts the PLAINTEXT ,
    // computes the MAC across both the associated data -AAD- and
    // PLAINTEXT and produces the CIPHERTEXT which includes the
    // MAC as well.
    uint96_t tx_req_seq_96 = {
        .lower_64 = spdm_info_ptr->binding_info.keys.tx_req_seq,
        .upper_32 = 0};

    uint96_t iv = {
        .lower_64 = spdm_info_ptr->binding_info.keys.tx_req_salt.lower_64 ^ tx_req_seq_96.lower_64,
        .upper_32 = spdm_info_ptr->binding_info.keys.tx_req_salt.upper_32 ^ tx_req_seq_96.upper_32};

    key256_t *key = &spdm_info_ptr->binding_info.keys.tx_req_enc_key;
    aes_gcm_ctx_t ctx;

    res = aes_gcm_init(key, &ctx, (migs_iv_t *)&iv);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_init\n");
        is_fatal_error = true;
        goto EXIT;
    }

    res = aes_gcm_process_aad(
        &ctx,
        (uint8_t *)aad_data_ptr,
        AAD_SIZE);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_process_aad\n");
        is_fatal_error = true;
        goto EXIT;
    }

    // Inplace encryption
    res = aes_gcm_encrypt(
        &ctx,
        msg_payload_ptr, // src
        msg_payload_ptr, // dst
        (int32_t)msg_payload_len);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_encrypt\n");
        is_fatal_error = true;
        goto EXIT;
    }

    res = aes_gcm_finalize(&ctx, mac_ptr);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_finalize\n");
        is_fatal_error = true;
        goto EXIT;
    }

    spdm_info_ptr->binding_info.keys.tx_req_seq++;
    return_val = TDX_SUCCESS;

EXIT:
    basic_memset_to_zero(&ctx, sizeof(aes_gcm_ctx_t));

    if (is_fatal_error)
    {
        basic_memset_to_zero(mac_ptr, MAC256_LEN);
        fatal_error(FATAL_ERROR_ID_74, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
        // Unreachable code
        tdx_sanity_check(0, FATAL_ERROR_ID_240, 0);
    }

    release_mutex_lock(&spdm_info_ptr->tx_lock);

    return return_val;
}

api_error_type tdx_io_aead_decrypt(
    spdm_info_t *const spdm_info,
    void *const message_ptr,
    uint64_t msg_len,
    void *const sec_buff_ptr,
    uint64_t sec_buff_len)
{
    bool_t fatal_error_flag = false;
    bool_t rx_is_locked = false;
    api_error_type return_val = UNINITIALIZE_ERROR;
    aes_gcm_api_error res;

    key256_t *key;
    aes_gcm_ctx_t ctx;
    uint96_t iv;
    uint8_t local_mac[MAC256_LEN];

    uint8_t *aad;     // pointer to AAD data
    void *cipher_msg; // pointer to cipher text
    uint8_t *mac;

    uint64_t spdm_secure_msg_len;
    uint64_t payload_len;

    bool_t is_msg_decrypted = false;

    // Check Cipher message length does not overflow max buffer size and copy it to stream extended info page
    if (!check_length_and_copy(message_ptr, msg_len, sec_buff_ptr, sec_buff_len))
    {
        TDX_ERROR("Failed to copy message to buffer\n");
        return_val = TDX_SDPM_INVALID_MESSAGE;
        goto EXIT;
    }

    spdm_secure_msg_len = ((spdm_doe_headers_t *)sec_buff_ptr)->secure_spdm_header.length;

    if (spdm_secure_msg_len < MAC256_LEN)
    {
        TDX_ERROR("Invalid length in secure_spdm_header\n");
        return_val = TDX_SDPM_INVALID_MESSAGE;
        goto EXIT;
    }

    payload_len = spdm_secure_msg_len - MAC256_LEN;
    if (spdm_secure_msg_len > (sec_buff_len - SPDM_APP_DATA_LENGTH_OFST))
    {
        TDX_ERROR("Secure massage length (=%llu) is larger than \
                    (buffer length - SPDM_APP_DATA_LENGTH_OFST (=%llu))\n",
                    spdm_secure_msg_len, (sec_buff_len - SPDM_APP_DATA_LENGTH_OFST));
        return_val = TDX_SDPM_INVALID_MESSAGE;
        goto EXIT;
    }

    if (acquire_mutex_lock(&spdm_info->rx_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire rx lock on SPDM info\n");
        return TDX_OPERAND_BUSY;
    }
    rx_is_locked = true;

    if(spdm_info->binding_info.keys.rx_req_seq == (uint64_t)(-1))
    {
        TDX_ERROR("SPDM session key require refresh\n");
        return_val = TDX_SPDM_SESSION_KEY_REQUIRE_REFRESH;
        goto EXIT;
    }

    aad = (uint8_t *)&((spdm_doe_headers_t *)sec_buff_ptr)->secure_spdm_header;
    cipher_msg = &(((spdm_doe_headers_t *)sec_buff_ptr)->secure_spdm_header.app_data_length);
    mac = (uint8_t *)cipher_msg + payload_len;

    // The function, AEAD_Decrypt, fully decrypts the
    // CIPHERTEXT, verifies the MAC and if validation is
    // successful, produces the original PLAINTEXT.
    uint96_t rx_req_seq_96 = {.upper_32 = 0};
    rx_req_seq_96.lower_64 = spdm_info->binding_info.keys.rx_req_seq;

    iv.lower_64 = spdm_info->binding_info.keys.rx_req_salt.lower_64 ^ rx_req_seq_96.lower_64;
    iv.upper_32 = spdm_info->binding_info.keys.rx_req_salt.upper_32 ^ rx_req_seq_96.upper_32;

    key = &spdm_info->binding_info.keys.rx_req_enc_key;

    res = aes_gcm_init(key, &ctx, (migs_iv_t *)&iv);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_init\n");
        fatal_error_flag = true;
        goto EXIT;
    }

    res = aes_gcm_process_aad(&ctx, aad, AAD_SIZE);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_process_aad\n");
        fatal_error_flag = true;
        goto EXIT;
    }

    // AES-256-GCM_Decrypt should be designed to allow
    // separate buffers for plaintext and ciphertext.
    // Function should copy the AAD from input to plaintext
    uint8_t *src = cipher_msg; // Cipher text
    uint8_t *dst = cipher_msg; // Plain text
    res = aes_gcm_decrypt(&ctx, src, dst, (int32_t)payload_len);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_decrypt\n");
        fatal_error_flag = true;
        goto EXIT;
    }
    is_msg_decrypted = true;

    res = aes_gcm_finalize(&ctx, local_mac);
    if (res != AES_GCM_NO_ERROR)
    {
        TDX_ERROR("Failed on aes_gcm_finalize\n");
        fatal_error_flag = true;
        goto EXIT;
    }

    if (!tdx_memcmp_safe(local_mac, mac, sizeof(local_mac)))
    {
        TDX_ERROR("MAC mismatch\n");
        return_val = TDX_SDPM_INVALID_MESSAGE;
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

    spdm_info->binding_info.keys.rx_req_seq++;

EXIT:
    // Clean data from stack
    basic_memset_to_zero(&ctx, sizeof(aes_gcm_ctx_t));
    basic_memset_to_zero(local_mac, sizeof(local_mac));

    if (fatal_error_flag)
    {
        fatal_error(FATAL_ERROR_ID_75, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    if(is_msg_decrypted &&
       return_val != TDX_SUCCESS)
    {
        basic_memset_to_zero(sec_buff_ptr, sec_buff_len);
    }

    if (rx_is_locked)
    {
        release_mutex_lock(&spdm_info->rx_lock);
    }

    return return_val;
}

