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
 * @file tdisp_defs.h
 * @brief TDISP definitions and structures
 */

#ifndef TDISP_DEFS_H_
#define TDISP_DEFS_H_

#include "accessors/ia32_accessors.h"
#include "iommu_defs.h"
#include "ide_stream_defs.h"

#pragma pack(push,1)

#define TDISP_PROTOCOL_ID (0X1)
#define TDISP_START_INTERFACE_NONCE_SIZE (32)

/**
 * @struct tdisp_payload_info_t
 *
 * @brief TDISP message request parameters
 */
typedef union
{
    struct
    {
        uint64_t payload_size : 12;  // TDISP payload size in bytes,
        uint64_t payload_pa   : MAX_PA - 12; // TDISP payload base address
        uint64_t reserved     : 11; // Reserved, must be 0
        // Flag indicating request/response belongs to a TD pending request or TD response. TDG.DEVIF.REQUEST: reserverd and must be 0
        uint64_t td_flag      : 1;
    };
    uint64_t raw;
} tdisp_payload_info_t;
tdx_static_assert(sizeof(tdisp_payload_info_t) == 8, tdisp_payload_info_t);

typedef enum
{
//  NAME                             CODE    INTIATOR
    LOCK_INTERFACE_RESPONSE          = 0x03, // Device
    DEVICE_INTERFACE_REPORT_RESPONSE = 0x04, // Device
    DEVICE_INTERFACE_STATE_RESPONSE  = 0x05, // Device
    START_INTERFACE_RESPONSE         = 0x06, // Device
    STOP_INTERFACE_RESPONSE          = 0x07, // Device
    TDISP_ERROR                      = 0x7F, // Device
    LOCK_INTERFACE_REQUEST           = 0x83, // VMM
    DEVICE_INTERFACE_REPORT_REQUEST  = 0x84, // TD
    DEVICE_INTERFACE_STATE_REQUEST   = 0x85, // TD
    START_INTERFACE_REQUEST          = 0x86, // TD
    STOP_INTERFACE_REQUEST           = 0x87, // TD
} tdisp_msg_type_e;
typedef uint8_t tdisp_msg_type_t;

//RID unique identifier
typedef union
{
    struct {
        rp_bdf_t rid;                              // Requested ID
        uint16_t segment_id                 : 8;   // Segment ID
        uint16_t requester_segment_valid    : 1;   // Segment is unsupported. Must be 0
        uint16_t reserved                   : 7;   // Reserved, must be 0
    };
    uint32_t raw;
} fucntion_id_t;
tdx_static_assert(sizeof(fucntion_id_t) == 4, fucntion_id_t);

typedef union
{
    struct
    {
        fucntion_id_t function_id;
        uint32_t reserved; //Should be zero
    };
    uint64_t raw;
} function_id_reg_t;
tdx_static_assert(sizeof(function_id_reg_t) == 8, function_id_reg_t);

// TDISP 1.0 INTERFACE_ID
typedef struct
{
    fucntion_id_t function_id;
    uint64_t reserved;                          // Reserved, must be 0
} tdisp_interface_id_t;
tdx_static_assert(sizeof(tdisp_interface_id_t) == 12, tdisp_interface_id_t);

#define TDISP_HEADER_SIZE (16)

// TDISP 1.0 header
typedef struct
{
    uint8_t tdisp_version;
    tdisp_msg_type_t msg_type;
    uint16_t reserved;
    tdisp_interface_id_t interface_id;
} tdisp_header_t;
tdx_static_assert(sizeof(tdisp_header_t) == TDISP_HEADER_SIZE, tdisp_header_t);

#define TDISP_PAYLOAD_MIN_SIZE (sizeof(tdisp_header_t))
// Max TDISP payload size (4037 bytes) DOE hdr  SPDM Hdr  PCI-SIG Vendor Hdr  SPDM MAC  Max padding - Protocol ID byte
#define TDISP_PAYLOAD_MAX_SIZE (DOE_MSG_BUFF_SIZE - sizeof(spdm_doe_headers_t) - SECURE_SPDM_MAC_SIZE - MAX_DOE_PADDING_SIZE - TDISP_PROTOCOL_ID_SIZE)
tdx_static_assert(TDISP_PAYLOAD_MAX_SIZE == 4049, TDISP_PAYLOAD_MAX_SIZE);

// TDISP 1.0 LOCK_INTERFACE_REQUEST
#define LOCK_INTERFACE_REQUEST_SIZE (36)

typedef struct
{
    tdisp_header_t header;
    uint16_t flags;
    stream_id_t stream_id;
    uint8_t  reserved;
    uint64_t mmio_reporting_offset;
    uint64_t bind_p2p_address_mask;
} tdisp_lock_interface_request_t;
tdx_static_assert(sizeof(tdisp_lock_interface_request_t) == LOCK_INTERFACE_REQUEST_SIZE, tdisp_lock_interface_request_t);

/**
 * @brief Enum for TD initiated TDISP request status
 */
typedef enum
{
    TDISP_REQ_AVAILABLE = 0, // TD can set new request(using TDG.DEVIF.REQUEST).
    TDISP_REQ_REQUESTED = 1, // TDISP requested was set
    TDISP_REQ_GENERATED = 2, // TDISP request was generated
    TDISP_REQ_PROCESSED = 3, // TDISP response was processed
} tdisp_req_sts_e;
typedef uint8_t tdisp_req_sts_t;

/**
 * @brief Enum for TDISP state enumeration as defined by TEE-IO spec
 */
typedef enum
{
    TDISP_STATE_CONFIG_UNLOCKED = 0,
    TDISP_STATE_CONFIG_LOCKED   = 1,
    TDISP_STATE_RUN             = 2,
    TDISP_STATE_ERROR           = 3
} tdisp_state_e;
typedef uint8_t tdisp_state_t;

/**
 * @brief Secured Message Application Data, which contains the TDISP header and payload
 *
 */
typedef struct
{
    tdisp_header_t header;
    uint8_t payload; // Variable size
}tdisp_payload_t;

typedef struct
{
    spdm_doe_headers_t spdm_doe_headers;
    uint8_t protocol_id;
    tdisp_payload_t tdisp_payload;
} tdisp_msg_t;

// TDISP ERROR response. Note, EXTENDED_ERROR_DATA can continue beyond tdisp_error_response_t
typedef struct
{
    tdisp_header_t header;
    uint32_t error_code;
    uint32_t error_data;
} tdisp_error_response_t;
tdx_static_assert(sizeof(tdisp_error_response_t) == TDISP_HEADER_SIZE + 8, tdisp_error_response_t);

// TDISP LOCK_INTERFACE_RESPONSE
typedef struct
{
    tdisp_header_t header;
    uint8_t start_interface_nonce[TDISP_START_INTERFACE_NONCE_SIZE];
} tdisp_lock_interface_response_t;
tdx_static_assert(sizeof(tdisp_lock_interface_response_t) == TDISP_HEADER_SIZE + TDISP_START_INTERFACE_NONCE_SIZE, tdisp_lock_interface_response_t);

// TDISP Interface State
typedef struct
{
    tdisp_header_t header;
    uint8_t tdi_state; // See TDISP_STATE
} tdisp_device_interface_state_response_t;
tdx_static_assert(sizeof(tdisp_device_interface_state_response_t) == TDISP_HEADER_SIZE + 1, tdisp_device_interface_state_response_t);

// TDISP DEVICE_INTERFACE_REPORT_RESPONSE
typedef struct
{
    tdisp_header_t header;
    uint16_t portion_length;
    uint16_t remainder_length;
} tdisp_device_interface_report_response_t;
tdx_static_assert(sizeof(tdisp_device_interface_report_response_t) == TDISP_HEADER_SIZE + 4, tdisp_device_interface_report_response_t);

// TDISP START_INTERFACE_REQUEST
typedef struct
{
    tdisp_header_t header;
    uint8_t start_interface_nonce[TDISP_START_INTERFACE_NONCE_SIZE];
} tdisp_start_interface_request_t;
tdx_static_assert(sizeof(tdisp_start_interface_request_t) == TDISP_HEADER_SIZE + TDISP_START_INTERFACE_NONCE_SIZE, tdisp_start_interface_request_t);

// TDISP GET_DEVICE_INTERFACE_REPORT_REQUEST
typedef struct
{
    tdisp_header_t header;
    uint16_t offset;
    uint16_t length;
} tdisp_device_interface_report_request_t;
tdx_static_assert(sizeof(tdisp_device_interface_report_request_t) == TDISP_HEADER_SIZE + 4, tdisp_device_interface_report_request_t);

// TDISP DEVICE_INTERFACE_REPORT 1st report portion layout
// Starting after tdisp_device_interface_report_response_t
typedef union
{
    struct
    {
        uint16_t no_fw_update : 1; // Device updates not permitted while in CONFIG_LOCKED
        uint16_t wo_pasid     : 1; // TDI generates DMA requests without PASID
        uint16_t w_pasid      : 1; // TDI generates DMA requests with PASID
        uint16_t ats          : 1; // ATS supported and enabled for the TDI
        uint16_t prs          : 1; // PRS supported for the TDI
        uint16_t reserved     : 11;
    };
    uint16_t raw;
} device_report_interface_info_t;
tdx_static_assert(sizeof(device_report_interface_info_t) == 2, device_report_interface_info_t);

// TDISP 1.0 device interface report start layout
typedef struct
{
    device_report_interface_info_t interface_info;
    uint16_t reserved;
    uint16_t msi_x_message_control;
    uint16_t lnr_control;
    uint32_t tph_control;
    uint32_t mmio_range_count;
} tdisp_device_interface_1st_report_layout_t;
tdx_static_assert(sizeof(tdisp_device_interface_1st_report_layout_t) == 16, tdisp_device_interface_1st_report_layout_t);

#pragma pack(pop)

#endif /* TDISP_DEFS_H_ */
