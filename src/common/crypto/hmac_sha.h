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
 * @file hmac_sha256.h
 * @brief
 */

#ifndef SRC_COMMON_CRYPTO_HMAC_SHA_H_
#define SRC_COMMON_CRYPTO_HMAC_SHA_H_


#include "tdx_api_defs.h"
#include "data_structures/tdxio/ide_stream_defs.h"
#include "helpers/helpers.h"
#include "ippcp.h"
#include "ippcpdefs.h"

#define HMAC_MESSAGE_LENGTH (16)
void ide_kdf_hmac_sha256(uint8_t *key_derivation_key, uint8_t stream_id, uint8_t ide_km_param, uint8_t *key);

_STATIC_INLINE_ void hmac_sha256(uint8_t *msg, uint8_t *key_derivation_key, uint8_t *key)
{
    IppStatus status = ippStsErr;
    int32_t method_buffer_size;
    uint8_t hash_method_buffer[HASH_METHOD_BUFFER_SIZE];

    status = ippsHashMethodGetSize(&method_buffer_size);
    if (status != ippStsNoErr ||
        method_buffer_size > ((int32_t)HASH_METHOD_BUFFER_SIZE))
    {
        TDX_ERROR("failed with error code %d\n", status);
        fatal_error(FATAL_ERROR_ID_29, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    status = ippsHashMethodSet_SHA256_TT((IppsHashMethod *)hash_method_buffer);
    if (status != ippStsNoErr)
    {
        TDX_ERROR("failed with error code %d\n", status);
        fatal_error(FATAL_ERROR_ID_30, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }

    status = ippsHMACMessage_rmf(
        msg, HMAC_MESSAGE_LENGTH,
        key_derivation_key, sizeof(key_slot_t),
        key, sizeof(key_slot_t),
        (const IppsHashMethod *)hash_method_buffer);

    if (ippStsNoErr != status)
    {
        TDX_ERROR("failed with error code %d\n", status);
        fatal_error(FATAL_ERROR_ID_31, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
}
#endif /* SRC_COMMON_CRYPTO_HMAC_SHA_H_ */
