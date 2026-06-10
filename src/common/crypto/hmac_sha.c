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
 * @file hmac_sha.c
 * @brief Crypto implementation for HMAC SHA
 */

#include "crypto/hmac_sha.h"

void ide_kdf_hmac_sha256(uint8_t* key_derivation_key, uint8_t stream_id, uint8_t ide_km_param, uint8_t* key)
{
    // Implements NIST800-108 KDF in counter mode using AES-HMAC as PRF
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
    uint8_t msg[HMAC_MESSAGE_LENGTH];
    msg[15] = msg[14] = msg[13] = 0; // Counter = 1
    msg[12] = 1;
    msg[11] = 'I';                   // Label = “IDE-KM0”
    msg[10] = 'D';
    msg[9]  = 'E';
    msg[8]  = '-';
    msg[7]  = 'K';
    msg[6]  = 'M';
    msg[5]  = '0';                   // ascii 0
    msg[4]  = 0x00;                  // NULL
    msg[3]  = ide_km_param;          // Part of context
    msg[2]  = stream_id;             // Part of Context
    msg[1]  = 0x01;                  // Length = 256 bits
    msg[0]  = 0x01;

//    HMAC_SHA256(key_seed, msg, /*output*/ key);
    hmac_sha256(msg, key_derivation_key, key);

}
