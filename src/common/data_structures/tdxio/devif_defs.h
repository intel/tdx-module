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
 * @file devif_defs.h
 * @brief devif definitions and structures
 */

#ifndef DEVIF_DEFS_H_
#define DEVIF_DEFS_H_

#include "ide_stream_defs.h"
#include "iommu_defs.h"
#include "devifmt_defs.h"

// Max number of TDX-IO supported function IDs per device interface
#define MAX_DEVIF_FUNC_ID (255)

// The number of child 4KB pages associated with TDR that are added during devif.create
#define NUM_OF_CHILD_ADD_DEVIF (3)
// The number of child 4KB pages associated with TDR that are removed during devif.remove
#define NUM_OF_CHILD_REMOVE_DEVIF ((-1) * NUM_OF_CHILD_ADD_DEVIF)

/**
 * @brief Enum for Device interface type
 */
typedef enum
{
    DEVIF_TYPE_PFVF = 0, // Physical or virtual function device, identified by RID
} devif_type_e;
typedef uint8_t devif_type_t;

typedef enum
{
    TDISP_MIN_FIELD_CODE = 0,
    TDISP_VER_FIELD_CODE = 1,
    TDISP_MAX_FIELD_CODE = 2
} devif_field_code_e;
typedef uint8_t devif_field_code_t;

/**
 * @struct devif_id_t
 *
 * @brief Device interface type, IOMMU, IDE stream and RID unique identifier
 */
typedef union
{
    struct
    {
        iommu_id_t iommu_id;        // IOMMU index
        stream_id_t stream_id;      // IDE stream index
        devif_type_t devif_type;    // Device interface type (see: DEVIF_TYPE_T)
        fucntion_id_t function_id;
    };
    uint64_t raw;
} devif_id_t;
tdx_static_assert(sizeof(devif_id_t) == 8, devif_id_t);

/**
 * @struct devifcs_t
 *
 * @brief DEVIF root control structure
 */
typedef struct
{
    // Flag to indicating if the DEVICS was bound by the TD
    // and is valid. Cleared by TDH.DEVIF.CREATE and set by
    // TDG.DEVIF.VALIDATE
    bool_t valid;

    devif_id_t devif_id; // Device interface type, IOMMU, IDE Stream IDs and RID as configured by TDH.DEVIF.CREATE
    uint8_t spdm_id;     // SPDM session index of this device interface

    // On TDH.DEVIF.CREATE, this field will be initialized to the TDISP version from the associated SDPM info page
    uint8_t tdisp_version;

    // On TDH.DEVIF.CREATE, this field will be initialized to the INIT_DEV_INFO_HASH from the associated SPDM info page.
    measurement_t dev_info_hash;

    // On TDH.DEVIF.CREATE, this field will be initialized to TDR_PA associated with the TD
    pa_t tdr_pa;

    // Report offset initialized on TDH.DEVIF.CREATE to RND_HPA_OFFSET field of its TDR owner
    uint64_t mmio_reporting_offset;

    tdisp_state_t tdisp_sts;          // Device interface TDISP state
    tdisp_req_sts_t td_tdisp_req_sts; // TD initiated TDISP request status

    // Outstanding request. If true, a response to the outstanding request is expected
    // before next TDISP request can be generated
    bool_t out_tdisp_req;

    /**
     * Physical page address of the second DEVIFCS used for hosting TDISP message buffer for
     * TD initiated messages
     */
    pa_t td_tdisp_msg_buff_pa;

    // Physical page address of the DEVIFCS page used for hosting TDISP message buffer for
    // VMM initiated messages
    pa_t vmm_tdisp_msg_buff_pa;

    // Payload length of the requested TD-initated message. Valid only when td_tdisp_req_sts == REQUESTED
    uint16_t td_tdisp_payload_length;
    uint64_t mmio_page_cnt; // Total device interface MMIO pages mapped to its TD owner

    bool_t dmar_mapped_flag; // Flag for tracking DMAR mapping state

    // For TDISP encapsulation
    // Start interface nonce, initialized by TDISP LOCK_INTERFACE_RESPONSE to be used in START_INTERFACE_REQUEST
    uint8_t start_interface_nonce[TDISP_START_INTERFACE_NONCE_SIZE];

    // Device report offset. Resets to 0 on TDISP LOCK_INTERFACE_RESPONSE, keeps the current device report offset for
    // next DEVICE_INTERFACE_REPORT_REQUEST call (i.e. the sum of previous device report portions)
    uint16_t dev_report_offset;

    // Device report length. Resets to the max report page size on TDISP LOCK_INTERFACE_RESPONSE. Then updated by
    // DEVICE_INTERFACE_REPORT_RESPONSE according to the REMAINDER_LENGTH
    uint16_t dev_report_len;
} devifcs_t;

#define DEVIFCS_FREE (0)
#define DEVIFCS_VALID (1)

/**
 * @brief This struct is used to obtain DEVIFCS by FUNCTION_ID, verify and map it with given permissions
 * 1. Walk DEVIFMT from DEVIFMT_ROOT to DEVIFCS
 * 2. Invoke PAMT walk leaf entry exclusively (only for guest!!)
 * 4. In case of td_flag, verify the entry owner is the td_owner
 * 5. Map the DEVIFCS root page using TX reserved HKID and given permissions
 *
 */
typedef struct
{
    devifmt_walk_res_t devifmt_walk_res;            // DEVIFMT walk result
    devifmt_idx_t      devifmt_idx;                 // DEVIFMT index (const)
    devifcs_t*         devifcs_ptr;                 // Mapped DEVIFCS
    bool_t             is_devifcs_mapped;
    bool_t             is_devifmt_walked;
} devif_verify_param_t;

// Used in the context of TDISP as *_devif_request input
typedef union
{
    struct
    {
        tdisp_msg_type_t req_code;  // TDISP Request Code
        uint64_t no_fw_update : 1;  // Only for TDH.DEVIF.REQUEST(LOCK_INTERFACE_REQUEST), must be 0 for all other requests
        uint64_t reserved     : 54; // Reserved, must be 0
        // TDH.DEVIF.REQUEST: Flag indicating request belongs to the TD pending request
        // TDG.DEVIF.REQUEST: reserverd and must be 0
        uint64_t td_flag      : 1;
    };
    uint64_t raw;
} devif_req_in_t;
tdx_static_assert(sizeof(devif_req_in_t) == 8, devif_req_in_t);

typedef union
{
    struct
    {
        uint64_t message_code   : 8;
        uint64_t target_length  : 16;
        uint64_t rsrvd          : 40;
    };
    uint64_t raw;
} devif_req_out_t;
tdx_static_assert(sizeof(devif_req_out_t) == 8, devif_req_out_t);

// Used in the context of TDISP as *_devif_response input
typedef union
{
    struct
    {
        uint64_t reserved1 : 12; // Reserved, must be 0 (4KB aligned)
        uint64_t pa        : 40; // Page addres of the response input
        uint64_t reserved2 : 11; // Reserved, must be 0
        uint64_t td_flag   : 1;  // Flag indicating the response is for the TD request
    };
    uint64_t raw;
} devif_rsp_in_t;
tdx_static_assert(sizeof(devif_rsp_in_t) == 8, devif_rsp_in_t);

#pragma pack(push, 1)

// DEVIF.RESPONSE 64-bit output structure
typedef union
{
    struct
    {
        tdisp_msg_type_t resp_code; // TDISP responce code
        uint16_t output_len;        // (16 bit) TDISP message response length (TDISP payload)

        union
        {
            // For TDISP_ERROR response
            struct
            {
                uint8_t reserved;
                uint32_t tdisp_error_code;
            } rsp_error;
            // For DEVICE_INTERFACE_STATE response
            struct
            {
                tdisp_state_t tdi_state;
                uint32_t reserved;
            } rsp_state;
            // for DEVICE_INTERFACE_REPORT response
            struct
            {
                uint8_t reserved;
                uint16_t portion_len;  // portion_length of the device report
                uint16_t remainder_len;// remainder_length of the device report
            } rsp_report;
        };
    };
    uint64_t raw;
} devif_rsp_out_t;
tdx_static_assert(sizeof(devif_rsp_out_t) == 8, devif_rsp_out_t);

typedef union
{
    struct
    {
        devif_field_code_t devif_field_code;
        uint64_t reserved:56;
    };
    uint64_t raw;
} devif_rd_input_t;
tdx_static_assert(sizeof(devif_rd_input_t) == 8, devif_rd_input_t);

#pragma pack(pop)


#endif /* DEVIF_DEFS_H_ */
