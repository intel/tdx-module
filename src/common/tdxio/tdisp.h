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
 * @file tdisp.h
 * @brief TDISP handlers
 */

#ifndef SRC_COMMON_TDXIO_TDISP_H_
#define SRC_COMMON_TDXIO_TDISP_H_

#include "tdx_api_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/tdxio/tdisp_defs.h"
#include "data_structures/tdxio/devif_defs.h"

/**
 * @brief Checks the TDISP header for a request/response
 *
 * @param devifcs_p
 * @param header
 *
 * @return bool_t
 */
bool_t is_valid_tdisp_header(
    const devifcs_t *const devifcs_ptr,
    const tdisp_header_t *const header);

/**
 * @brief Check if the TDISP request message type is valid
 *
 * @param msg_type
 * @param td_flag
 *
 * @return bool_t
 */
bool_t is_valid_tdisp_req_msg_type(
    const tdisp_msg_type_t msg_type,
    const uint8_t td_flag);

/**
 * @brief Create the TDISP header for DEVIF requrest and return the message payload length
 *
 * @param tdisp_msg_ptr
 * @param devif_req_in
 * @param devif_verify_param_ptr
 * @param ret_payload_length_ptr
 *
 * @return bool_t
 */
bool_t assign_tdisp_header(
    tdisp_msg_t *const tdisp_msg_ptr,
    const devif_req_in_t devif_req_in,
    const devif_verify_param_t *const devif_verify_param_ptr,
    uint16_t *const ret_payload_length_ptr);

/**
 * @brief
 *
 * @param response_header_ptr
 * @param devif_rsp_out_ptr
 * @param devif_verify_param_ptr
 *
 * @return api_error_type
 */
api_error_type tdisp_process_response(
    const tdisp_header_t *const response_header_ptr,
    devif_rsp_out_t *const devif_rsp_out_ptr,
    devif_verify_param_t *const devif_verify_param_ptr);

#endif /* SRC_COMMON_TDXIO_TDISP_H_ */
