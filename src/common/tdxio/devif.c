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
 * @file devif.c
 * @brief
 */

#include "spdm.h"
#include "iommu.h"
#include "aead.h"
#include "devifmt.h"
#include "devif.h"

void devif_unmap_devifcs(devif_verify_param_t *const devif_verify_param)
{
    if (devif_verify_param->is_devifcs_mapped)
    {
        free_la(devif_verify_param->devifcs_ptr);
    }

    if (devif_verify_param->is_devifmt_walked)
    {
        devifmt_unwalk(&devif_verify_param->devifmt_walk_res);
    }
}

api_error_type generate_tdisp_req_msg(
    const devifcs_t *const devifcs_ptr,
    tdisp_msg_t *const doe_spdm_buff_ptr,
    const uint16_t payload_len,
    const uint64_t devifcs_operand_id,
    const pa_t target_pa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    spdmdir_entry_t *spdmdir_entry_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        devifcs_ptr->devif_id.iommu_id.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Lock check and map SPDM info
    return_val = lock_check_and_map_spdm_metadata(
        devifcs_ptr->spdm_id,
        devifcs_operand_id,
        iommu_config_ptr,
        SPDM_STATE_BOUND,
        &spdm_info_ptr,
        &spdmdir_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    doe_spdm_buff_ptr->protocol_id = TDISP_PROTOCOL_ID;
    // The protocol_id is part of the overall payload but not included in the TDISP payload
    const uint16_t payload_size = payload_len + TDISP_PROTOCOL_ID_SIZE;

    uint8_t spdm_version = spdm_info_ptr->binding_info.spdm_version;
    // Fill all SPDM vendor defined message header fields
    generate_spdm_vendor_defined_msg_header(
        &doe_spdm_buff_ptr->spdm_doe_headers.spdm_vendor_defined_msg_header,
        spdm_version,
        payload_size);

    // Fill message with constant secure spdm header values
    // Fill all secure SPDM header fields
    generate_secure_spdm_header(
        &doe_spdm_buff_ptr->spdm_doe_headers.secure_spdm_header,
        spdm_info_ptr->binding_info.spdm_session_id,
        payload_size);

    // Fill all DOE header fields + Zero padded bytes in message buffer
    generate_doe_header(
        doe_spdm_buff_ptr,
        &doe_spdm_buff_ptr->spdm_doe_headers.doe_header,
        doe_spdm_buff_ptr->spdm_doe_headers.secure_spdm_header.length,
        DOE_MSG_BUFF_SIZE);

    // Zero out unused section bytes in message buffer
    basic_memset_to_zero(
        (void *)((uint64_t)doe_spdm_buff_ptr + doe_spdm_buff_ptr->spdm_doe_headers.doe_header.doe_length.length * DOE_LENGTH_GRANULARITY),
        (uint64_t)DOE_MSG_BUFF_SIZE - doe_spdm_buff_ptr->spdm_doe_headers.doe_header.doe_length.length * DOE_LENGTH_GRANULARITY);

    const uint64_t encrypted_data_len = doe_spdm_buff_ptr->spdm_doe_headers.secure_spdm_header.length - SECURE_SPDM_MAC_SIZE;
    uint8_t *mac_ptr = ((uint8_t *)&doe_spdm_buff_ptr->spdm_doe_headers.secure_spdm_header.app_data_length) + encrypted_data_len;

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    const uint32_t *const msg_in_dwords = (uint32_t *)doe_spdm_buff_ptr;
    uint32_t msg_length = doe_spdm_buff_ptr->spdm_doe_headers.doe_header.doe_length.length;
    TDX_LOG("Printing DEVIF plaintext message before encryption:\n");

    for (uint32_t idx = 0; idx < msg_length; idx++)
    {
        TDX_LOG("0x%lx\n", msg_in_dwords[idx]);
    }
#endif // DEBUGFEATURE_TDX_DBG_TRACE

    return_val = tdx_io_aead_encrypt(
        spdm_info_ptr,
        (void *)&doe_spdm_buff_ptr->spdm_doe_headers.secure_spdm_header,                 // Start of AAD ptr
        (void *)&doe_spdm_buff_ptr->spdm_doe_headers.secure_spdm_header.app_data_length, // Start of plain text ptr
        encrypted_data_len,                                                              // Size of plain text ptr                                                                                        // Size of plain text ptr
        mac_ptr);                                                                        // Start of MAC ptr
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    tdisp_msg_t *target_ptr = map_pa(
        target_pa.raw_void,
        TDX_RANGE_RW);

    // Copy entire message from buffer to pointer
    tdx_memcpy(
        (void *)target_ptr,
        TDX_PAGE_SIZE_IN_BYTES,
        (void *)doe_spdm_buff_ptr,
        DOE_MSG_BUFF_SIZE);

    free_la(target_ptr);

    return_val = TDX_SUCCESS;

EXIT:

    if (spdm_info_ptr != NULL)
    {
        free_la(spdm_info_ptr);
    }

    if (spdmdir_entry_ptr != NULL)
    {
        unlock_spdmdir_entry(spdmdir_entry_ptr, devifcs_ptr->spdm_id);
        free_la(spdmdir_entry_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}

bool_t verify_tdisp_message_content(
    tdisp_msg_t *tdisp_msg_ptr,
    spdm_info_t *const spdm_info_ptr)
{
    bool_t return_res = false;

    // Note, the payload length is not validated since the decryption won't succeed otherwise, since the MAC comes directly after it
    // Which means we can directly use to calculate expected_dw_length_with_padding
    uint16_t payload_len = tdisp_msg_ptr->spdm_doe_headers.spdm_vendor_defined_msg_header.payload_len;

    if (!is_valid_doe_header(&tdisp_msg_ptr->spdm_doe_headers.doe_header, payload_len))
    {
        goto EXIT;
    }

    if (!is_valid_secure_spdm_header(&tdisp_msg_ptr->spdm_doe_headers.secure_spdm_header, payload_len, spdm_info_ptr->binding_info.spdm_session_id))
    {
        goto EXIT;
    }

    uint32_t expected_spdm_version = spdm_info_ptr->binding_info.spdm_version;

    /**
     * @note - Regarding the expected_payload_length parameter in is_valid_spdm_vendor_defined_msg_header -
     *          we don't know which package we got in devif and that is why we are simply passing a value that won't fail
     *
     */
    if (!is_valid_spdm_vendor_defined_msg_header(
            &tdisp_msg_ptr->spdm_doe_headers.spdm_vendor_defined_msg_header,
            tdisp_msg_ptr->spdm_doe_headers.spdm_vendor_defined_msg_header.payload_len,
            expected_spdm_version))
    {
        goto EXIT;
    }

    // Validate PROTOCOL_ID
    if (tdisp_msg_ptr->protocol_id != TDISP_PROTOCOL_ID)
    {
        TDX_ERROR("TDISP protocol id(=%u) is invalid", tdisp_msg_ptr->protocol_id);
        goto EXIT;
    }

    return_res = true;

EXIT:
    return return_res;
}

stream_info_t *map_stream_info_from_devifcs(
    const devif_id_t devif_id,
    const iommu_config_t *const iommu_config_ptr)
{
    // Select correct stream info pa
    pa_t stream_info_pa = devif_id.stream_id.page_selector ? iommu_config_ptr->stinfopa_1 : iommu_config_ptr->stinfopa_0;

    stream_info_t *stream_info_base_ptr = map_pa_with_global_hkid(
        stream_info_pa.raw_void,
        TDX_RANGE_RO);

    // Return correct index
    return &stream_info_base_ptr[devif_id.stream_id.index];
}
