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
 * @file spdm.h
 * @brief SPDM handlers
 */

#ifndef SRC_COMMON_TDXIO_SPDM_H_
#define SRC_COMMON_TDXIO_SPDM_H_

#include "tdx_api_defs.h"
#include "x86_defs/x86_defs.h"
#include "helpers/helpers.h"

#include "data_structures/tdxio/spdm_defs.h"
#include "data_structures/tdxio/iommu_defs.h"
#include "data_structures/tdxio/ide_stream_defs.h"

/**
 * @brief Acquire lock on spdm entry
 *
 * @param spdmdir_ptr
 * @param spdm_id
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t lock_spdmdir_entry(
    spdmdir_entry_t *const spdmdir_ptr,
    const uint64_t spdm_id)
{
    return acquire_bit_lock(&spdmdir_ptr[spdm_id].low_dword, SPDMDIR_ENTRY_LOCK_BIT_OFS) == TDX_SUCCESS;
}

/**
 * @brief Release lock on spdm entry
 *
 * @note Assume lock already acquired, otherwise crash
 *
 * @param spdmdir_ptr
 * @param spdm_id
 *
 * @return void
 */
_STATIC_INLINE_ void unlock_spdmdir_entry(
    spdmdir_entry_t *const spdmdir_ptr,
    const uint64_t spdm_id)
{
    release_bit_lock(&spdmdir_ptr[spdm_id].low_dword, SPDMDIR_ENTRY_LOCK_BIT_OFS);
}

/**
 * @brief Map and lock spdmdir_entry_ptr.
 *
 * @param iommu_config_ptr
 * @param spdm_id
 *
 * @return If lock fails - NULL, if lock succeeds - pointer to the spdm base entry
*/
spdmdir_entry_t *map_and_lock_spdmdir_entry(
    const iommu_config_t *const iommu_config_ptr,
    const uint64_t spdm_id);

/**
 * @brief check
 *          - SPDM info configured
 *          - Verify the present bit is set in the SPDM entry
 *          - Lock on SPDM entry can be acquired
 *          - SPDM info is in state SPDM_STATE_BOUND
 *
 * @param spdm_id
 * @param operand_id
 * @param iommu_config_ptr
 * @param expected_spdm_state
 * @param spdm_info_ptr
 * @param spdmdir_entry_ptr
 *
 * @return Success or Error type
 */
api_error_type lock_check_and_map_spdm_metadata(
    const uint64_t spdm_id,
    const uint64_t operand_id,
    const iommu_config_t *const iommu_config_ptr,
    const spdm_session_state_t expected_spdm_state,
    spdm_info_t **spdm_info_ptr,
    spdmdir_entry_t **spdmdir_entry_ptr);

/**
 * @brief Called from the SPDM client side
 *        Check
 *          - Caller TD is a valid TPA TD
 *          - Valid IOMMU metadata
 *              - iommu_id < max iommu
 *              - lock can be acquired (if @param lock_iommu is set)
 *              - Equal to expected IOMMU state
 *              - rp_bitmap
 *          - Valid SPDM metadata
 *              - SPDM info already configured in directory
 *              - Lock on SPDM DIR can be acquired
 *              - Equal to expected SPDM state
 *          - Valid GPA binding
 *              - Private GPA tranlate and map it as RO
 *
 * @param iommu_id_reg
 * @param expected_spdm_state
 * @param spdm_id
 * @param binding_info_gpa
 * @param mapping_type
 * @param spdm_info_ptr
 * @param spdmdir_entry_ptr
 * @param binding_info_ptr
 *
 * @return Success or Error type
 */
api_error_type tdg_spdm_binding_prologue(
    const iommu_id_reg_t iommu_id_reg,
    const uint64_t spdm_id,
    const spdm_session_state_t expected_spdm_state,
    const pa_t binding_info_gpa,
    const mapping_type_t binding_info_mapping_type,
    spdm_info_t **spdm_info_ptr,
    spdmdir_entry_t **spdmdir_entry_ptr,
    void **binding_info_ptr);

_STATIC_INLINE_ void generate_doe_header(
    void *const full_msg_ptr,
    doe_header_t *const doe_header_ptr,
    const uint16_t spdm_length, // (secure_spdm_header_t) Length of the message's remaining data
    const uint32_t max_buff_size)
{
    doe_header_ptr->vendor_id = DOE_VENDOR_ID;
    doe_header_ptr->data_object_type = DOE_OBJECT_TYPE;
    doe_header_ptr->rsvd = 0;
    doe_header_ptr->doe_length.raw = 0;

    // Message is padded to complete 4 bytes (DW)
    uint32_t total_msg_length = spdm_length + sizeof(doe_header_t) + SPDM_SESSION_ID_SIZE + SPDM_LENGTH_SIZE;

    // (Y + (x-1))/x == padded Y to be x aligned
    uint32_t padded_message_length_in_dwords = (uint32_t)CALCULATE_NUMBER_OF_UNITS_WITH_PADDING(total_msg_length, DOE_LENGTH_GRANULARITY);
    // Defence in depth
    tdx_sanity_check((padded_message_length_in_dwords * DOE_LENGTH_GRANULARITY < max_buff_size), SCEC_SEAMCALL_SOURCE(SCEC_DOE_GEN_SOURCE), 0);

    doe_header_ptr->doe_length.length = padded_message_length_in_dwords;
    uint32_t padding_count_in_bytes = padded_message_length_in_dwords * DOE_LENGTH_GRANULARITY - total_msg_length;
    // Zero padded bytes
    basic_memset_to_zero((void *)((uint64_t)full_msg_ptr + total_msg_length), padding_count_in_bytes);

}

_STATIC_INLINE_ bool_t is_valid_doe_header(
    const doe_header_t *const doe_header_ptr,
    const uint16_t payload_len)
{
    uint32_t expected_dw_length = sizeof(doe_header_t) + sizeof(secure_spdm_header_t) + sizeof(spdm_vendor_defined_msg_header_t) +
                                                payload_len + SECURE_SPDM_MAC_SIZE;

    uint32_t expected_dw_length_with_padding = (uint32_t)CALCULATE_NUMBER_OF_UNITS_WITH_PADDING(expected_dw_length, DOE_LENGTH_GRANULARITY);

    bool_t res = doe_header_ptr->vendor_id == DOE_VENDOR_ID &&
                    doe_header_ptr->data_object_type == DOE_OBJECT_TYPE &&
                    doe_header_ptr->rsvd == 0 &&
                    doe_header_ptr->doe_length.length == expected_dw_length_with_padding &&
                    doe_header_ptr->doe_length.rsvd == 0;

    if(!res)
    {
        TDX_ERROR("Invalid DOE header -\n\
                    vendor id = %u, data object type = %u, reserved = %u, \
                    DOE length = %lu expected DOE length = %lu \n, doe_length.rsvd = %u",
                    doe_header_ptr->vendor_id, doe_header_ptr->data_object_type,
                    doe_header_ptr->rsvd, doe_header_ptr->doe_length.length, expected_dw_length,
                    doe_header_ptr->doe_length.rsvd);
    }

    return res;
}

_STATIC_INLINE_ void generate_secure_spdm_header(
    secure_spdm_header_t *const secure_spdm_header_ptr,
    const uint32_t session_id,
    const uint16_t payload_len)
{
    secure_spdm_header_ptr->session_id = session_id;
    secure_spdm_header_ptr->app_data_length = payload_len + sizeof(spdm_vendor_defined_msg_header_t);
    secure_spdm_header_ptr->length = secure_spdm_header_ptr->app_data_length + SECURE_SPDM_MAC_SIZE + SPDM_APP_DATA_LENGTH_SIZE;
}

_STATIC_INLINE_ bool_t is_valid_secure_spdm_header(
    const secure_spdm_header_t *const secure_spdm_header_ptr,
    const uint16_t payload_len,
    const uint32_t expected_spdm_session_id)
{
    bool_t res = secure_spdm_header_ptr->app_data_length == payload_len + sizeof(spdm_vendor_defined_msg_header_t) &&
                    secure_spdm_header_ptr->length == secure_spdm_header_ptr->app_data_length + SECURE_SPDM_MAC_SIZE + SPDM_APP_DATA_LENGTH_SIZE &&
                    secure_spdm_header_ptr->session_id == expected_spdm_session_id;
    if(!res)
    {
        TDX_ERROR("Invalid secure SPDM header -\n\
                    app_data_length = %u, expected app_data_length = %u\n\
                    length = %u, expected length = %u\n\
                    session_id = %lu, expected session_id = %lu",
                    secure_spdm_header_ptr->app_data_length, payload_len + sizeof(spdm_vendor_defined_msg_header_t),
                    secure_spdm_header_ptr->length,
                    secure_spdm_header_ptr->app_data_length + SECURE_SPDM_MAC_SIZE + SPDM_APP_DATA_LENGTH_SIZE,
                    secure_spdm_header_ptr->session_id, expected_spdm_session_id);
    }
    return res;
}

_STATIC_INLINE_ void generate_spdm_vendor_defined_msg_header(
    spdm_vendor_defined_msg_header_t *const spdm_vendor_defined_msg_header_ptr,
    const uint8_t spdm_version,
    const uint16_t payload_len)
{
    spdm_vendor_defined_msg_header_ptr->spdm_version = spdm_version;
    spdm_vendor_defined_msg_header_ptr->spdm_code = SPDM_VENDOR_DEFINED_REQUEST_CODE;
    spdm_vendor_defined_msg_header_ptr->param1 = 0;
    spdm_vendor_defined_msg_header_ptr->param2 = 0;
    spdm_vendor_defined_msg_header_ptr->standard_id = SPDM_PCI_SIG_STANDARD_ID;
    spdm_vendor_defined_msg_header_ptr->len = SPDM_VENDOR_ID_FIELD_LENGTH;
    spdm_vendor_defined_msg_header_ptr->vendor_id = SPDM_VENDOR_ID_PCI_SIG;
    spdm_vendor_defined_msg_header_ptr->payload_len = payload_len;
}

/**
 * @note The payload length is not validated since the decryption won't succeed otherwise, since the MAC comes directly after it
 *       Which means we can directly use to calculate expected_dw_length_with_padding
 *
 * @param spdm_vendor_defined_msg_header_ptr
 * @param expected_spdm_version
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t is_valid_spdm_vendor_defined_msg_header(
    const spdm_vendor_defined_msg_header_t *const spdm_vendor_defined_msg_header_ptr,
    const uint32_t expected_payload_length,
    const uint32_t expected_spdm_version)
{
    bool_t res = spdm_vendor_defined_msg_header_ptr->spdm_version == expected_spdm_version &&
                    spdm_vendor_defined_msg_header_ptr->spdm_code == SPDM_VENDOR_DEFINED_RESPONCE_CODE &&
                    spdm_vendor_defined_msg_header_ptr->param1 == 0 &&
                    spdm_vendor_defined_msg_header_ptr->param2 == 0 &&
                    spdm_vendor_defined_msg_header_ptr->standard_id == SPDM_PCI_SIG_STANDARD_ID &&
                    spdm_vendor_defined_msg_header_ptr->len == SPDM_VENDOR_ID_FIELD_LENGTH &&
                    spdm_vendor_defined_msg_header_ptr->vendor_id == SPDM_VENDOR_ID_PCI_SIG &&
                    spdm_vendor_defined_msg_header_ptr->payload_len == expected_payload_length;

    if(!res)
    {
        TDX_ERROR("Invalid SPDM vendor defined massage header -\n\
                    spdm_version = %u, expected spdm_version = %u\n\
                    spdm_code = %u, param1 = %u, param2 = %u, standard_id = %u, len = %u, vendor_id = %u\n",
                    spdm_vendor_defined_msg_header_ptr->spdm_version, expected_spdm_version,
                    spdm_vendor_defined_msg_header_ptr->spdm_code,
                    spdm_vendor_defined_msg_header_ptr->param1,
                    spdm_vendor_defined_msg_header_ptr->param2,
                    spdm_vendor_defined_msg_header_ptr->standard_id,
                    spdm_vendor_defined_msg_header_ptr->len,
                    spdm_vendor_defined_msg_header_ptr->vendor_id);
    }

    return res;
}


#endif // SRC_COMMON_TDXIO_SPDM_H_
