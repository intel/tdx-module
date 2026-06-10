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
 * @file spdm_defs.h
 * @brief SPDM definitions and structures
 */

#ifndef SPDM_DEFS_H_
#define SPDM_DEFS_H_

#include "accessors/ia32_accessors.h"
#include "helpers/tdx_locks.h"
#include "crypto/sha384.h"

#pragma pack(push, 1)


#define DOE_HEADER_SIZE (8) // Size in Bytes
#define DOE_MSG_BUFF_SIZE (_4KB)
#define MAX_DOE_PADDING_SIZE (sizeof(uint32_t) - 1)
#define DOE_VENDOR_ID (0x1)
#define DOE_OBJECT_TYPE (0x2)

#define DOE_LENGTH_GRANULARITY (4) // DWORDS i.e. sizeof(uint32_t)
// DOE 1.0
typedef struct
{
    uint16_t vendor_id;
    uint8_t data_object_type;
    uint8_t rsvd;
    union
    {
        struct
        {
            // Length of the data object being transferred in number of DW
            uint32_t length : 18; // 17:0
            uint32_t rsvd : 14;   // 31:18
        };
        uint32_t raw;
    } doe_length;
} doe_header_t;
tdx_static_assert(sizeof(doe_header_t) == DOE_HEADER_SIZE, doe_header_t);

// Sizes in bytes
#define SPDM_HEADER_SIZE (8)
#define SPDM_SESSION_ID_SIZE (0x4)
#define SPDM_LENGTH_SIZE (0x2)
#define SPDM_APP_DATA_LENGTH_SIZE (2)

#define SPDM_SECURE_MSG_LEN_OFST  (12)
#define SPDM_APP_DATA_LENGTH_OFST (SPDM_SECURE_MSG_LEN_OFST+SPDM_LENGTH_SIZE)
#define SPDM_SECURE_HDR_OFST (DOE_HEADER_SIZE)
#define AAD_SIZE (SPDM_HEADER_SIZE - SPDM_APP_DATA_LENGTH_SIZE)

// SPDM 1.0
typedef struct
{
    uint32_t session_id;
    uint16_t length;          // Length of the message remaining data
    uint16_t app_data_length; // Length of the application data
} secure_spdm_header_t;
tdx_static_assert(offsetof(secure_spdm_header_t, length) == (SPDM_SECURE_MSG_LEN_OFST - SPDM_SECURE_HDR_OFST), secure_spdm_header_t);
tdx_static_assert(sizeof(secure_spdm_header_t) == SPDM_HEADER_SIZE, secure_spdm_header_t);

#define SPDM_VENDOR_DEFINED_HDR_SIZE (11)
#define SPDM_VENDOR_DEFINED_REQUEST_CODE (0xFE)
#define SPDM_VENDOR_DEFINED_RESPONCE_CODE (0x7E)
#define SPDM_PCI_SIG_STANDARD_ID (0x3)
#define SPDM_VENDOR_ID_FIELD_LENGTH (0x2)
#define SPDM_VENDOR_ID_PCI_SIG (0x1)
typedef struct
{
    uint8_t spdm_version; // SPDM negotiated version
    uint8_t spdm_code;    // 0xFE - VENDOR_DEFINED_REQUEST, 0x7E - VENDOR_DEFINED_RESPONSE
    uint8_t param1;       // Reserved, must be 0
    uint8_t param2;       // reserved, must be 0
    uint16_t standard_id; // PCI-SIG Standard ID = 0x3
    uint8_t len;          // Vendor ID field length, must be 0x2
    uint16_t vendor_id;   // PCI-SIG Vendor ID, must be 0x1 (PCI-SIG vendor ID)
    uint16_t payload_len; // Payload message length
} spdm_vendor_defined_msg_header_t;
tdx_static_assert(sizeof(spdm_vendor_defined_msg_header_t) == SPDM_VENDOR_DEFINED_HDR_SIZE, spdm_vendor_defined_msg_header_t);

#define DOE_SPDM_PROTOCOL_ID_HEADERS_LEN 27
typedef struct
{
    doe_header_t doe_header;
    secure_spdm_header_t secure_spdm_header;
    spdm_vendor_defined_msg_header_t spdm_vendor_defined_msg_header;
} spdm_doe_headers_t;
tdx_static_assert(offsetof(spdm_doe_headers_t, secure_spdm_header) == SPDM_SECURE_HDR_OFST, spdm_doe_headers_t);
tdx_static_assert(sizeof(spdm_doe_headers_t) == DOE_SPDM_PROTOCOL_ID_HEADERS_LEN, spdm_doe_headers_t);

#define SECURE_SPDM_MAC_SIZE 16

typedef union PACKED uint96_u
{
    uint8_t bytes[12];
    struct
    {
        uint64_t lower_64;
        uint32_t upper_32;
    };
} uint96_t;
tdx_static_assert(sizeof(uint96_t) == 12, uint96_t);

#define MAX_SPDM_SESSION_ID (256) // Not inclusive
#define SPDMDIR_ENTRY_LOCK_BIT_OFS (0)

typedef union
{
    struct
    {
        uint64_t lock : 1;
        uint64_t present : 1; // Adding a present bit allows for a zero PA SPDMDIR
        uint64_t rsvd1 : 10;
        uint64_t addr : 40;
        uint64_t rsvd2 : 12;
    };
    uint64_t raw;
    struct
    {
        uint32_t low_dword;
        uint32_t high_dword;
    };
} spdmdir_entry_t;
tdx_static_assert(sizeof(spdmdir_entry_t) == 8, spdmdir_entry_t);

typedef enum{
    SPDM_STATE_NOT_BOUND = 0,
    SPDM_STATE_BOUND = 1
} spdm_session_state_e;
typedef uint8_t spdm_session_state_t;

typedef struct
{
    uint256_t tx_req_enc_key; // 256-bit key for transmit record encryption
    uint96_t tx_req_salt;     // 96-bit salt for transmit record encryption
    uint64_t tx_req_seq;      // 64-bit sequence number for transmit record encryption
    uint8_t rsvd0[12];
    uint256_t rx_req_enc_key; // 256-bit key for receive record encryption
    uint96_t rx_req_salt;     // 96-bit salt for receive record encryption
    uint64_t rx_req_seq;      // 64-bit sequence number for receive record encryption
    uint8_t rsvd1[12];
} spdm_aes_gcm_ctx_t;
tdx_static_assert(sizeof(spdm_aes_gcm_ctx_t) == 128, spdm_aes_gcm_ctx_t);

typedef struct
{
    uint32_t spdm_session_id;           // Negotiated SPDM session ID setup by TPA
    uint8_t spdm_version;               // SPDM version negotiated by TPA
    uint8_t tdisp_version;              // TDISP version negotiated by TPA
    uint8_t dev_addr_width;             // Device address width from TDISP capabilities
    measurement_t dev_info_hash;        // SHA384 Hash of leaf (slot 0) public key of the device at the other end of this stream.
    spdm_aes_gcm_ctx_t keys;
    uint8_t reserved[841];
    uint8_t tpa_private_data[1024];     // TPA private context
} tpa_binding_info_t;
tdx_static_assert(sizeof(tpa_binding_info_t) == _2KB, tpa_binding_info_t);

typedef struct
{
    struct
    {
        spdm_session_state_t state; // Flag indication the SPDM station is in the bound state
        mutex_lock_t rx_lock; // Lock to serialize receive
        mutex_lock_t tx_lock; // Lock to serialize Transmit
        uint64_t reserved1 : 40;
    };

    uint16_t active_stream_count;      // IDE streams counter bound to the SPDM session
    uint8_t reserved2[2038];
    tpa_binding_info_t binding_info;
} spdm_info_t;
tdx_static_assert(sizeof(spdm_info_t) == _4KB, spdm_info_t);

// DOE_MSG_MIN_LEN constant can be defined as: all DOE/SPDM headers + 1 payload byte + MAC + paddig (which is 3 for 1 payload byte)
#define DEO_MSG_PAYLOAD_BYTE (1)
#define MAX_DEO_MSG_PADDING_BYTE (3)
#define TDISP_PROTOCOL_ID_SIZE (0X1)
#define DOE_MSG_MIN_LEN (DOE_SPDM_PROTOCOL_ID_HEADERS_LEN + TDISP_PROTOCOL_ID_SIZE + DEO_MSG_PAYLOAD_BYTE + MAC256_LEN + MAX_DEO_MSG_PADDING_BYTE)

#pragma pack(pop)

#endif // SPDM_DEFS_H_
