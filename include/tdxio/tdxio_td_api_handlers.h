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
 * @file tdxio_td_api_handlers.h
 * @brief TDXIO TD API Handlers
 */

#ifndef INCLUDE_TDXIO_TD_API_HANDLERS_H_
#define INCLUDE_TDXIO_TD_API_HANDLERS_H_

#include "tdx_api_defs.h"
#include "x86_defs/vmcs_defs.h"

#include "data_structures/tdxio/devif_defs.h"
#include "data_structures/tdxio/tdisp_defs.h"
#include "data_structures/tdxio/dmar_defs.h"

/**
 * @brief Read register from a device interface.
 *
 * @note
 *
 * @param function_id
 * @param field_code
 * @param param
 *
 * @return Success or Error type
 */
api_error_type tdg_devif_rd(
    function_id_reg_t function_id,
    devif_rd_input_t devif_rd_input,
    uint64_t unused_r9);

/**
 * @brief TD initiated new TDISP request.
 *
 * @note
 *
 * @param function_id_reg
 * @param devif_req_in
 * @param unused_r9
 *
 * @return Success or Error type
 */
api_error_type tdg_devif_request(
    function_id_reg_t function_id_reg,
    devif_req_in_t devif_req_in,
    uint64_t unused_r9);

/**
 * @brief handling TD response to TDISP request.
 *
 * @note
 *
 * @param function_id
 * @param dest_page_gpa
 * @param unused_r9
 *
 * @return Success or Error type
 */
api_error_type tdg_devif_response(
    function_id_reg_t function_id,
    pa_t dest_page_gpa,
    uint64_t unused_r9);

/**
 * @brief Validate Device Public Key Hash.
 *
 * @note
 *
 * @param function_id
 * @param dev_pkh_qw_0
 * @param dev_pkh_qw_1
 * @param dev_pkh_qw_2
 * @param dev_pkh_qw_3
 * @param dev_pkh_qw_4
 * @param dev_pkh_qw_5
 *
 * @return Success or Error type
 */
api_error_type tdg_devif_validate(
    function_id_reg_t function_id_reg,
    uint64_t dev_pkh_qw_0,
    uint64_t dev_pkh_qw_1,
    uint64_t dev_pkh_qw_2,
    uint64_t dev_pkh_qw_3,
    uint64_t dev_pkh_qw_4,
    uint64_t dev_pkh_qw_5);

/**
 * @brief Accept a PASID table entry and optionally update the first level paging parameters
 *
 * @note
 *
 * @param function_id_reg
 * @param dmar_target
 * @param param1
 * @param param2
 * @param param3
 * @param param4
 * @param param5
 * @param param6
 * @param param7
 * @param param8
 *
 * @return Success or Error type
 */
api_error_type tdg_dmar_accept(
    function_id_reg_t function_id_reg,
    dmar_target_t dmar_target,
    uint64_t param1,
    uint64_t param2,
    uint64_t param3,
    uint64_t param4,
    uint64_t param5,
    uint64_t param6,
    uint64_t param7,
    uint64_t param8);

/**
 * @brief Bind keys and identities to an SPDM session
 *
 * @param iommu_id_reg
 * @param spdm_id
 * @param binding_info_gpa
 *
 * @return Success or Error type
 */
api_error_type tdg_spdm_tpa_set(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id,
    pa_t binding_info_gpa);

/**
 * @brief Read SPDM session binding information and take ownership of SPDM secure session
 *
 * @param iommu_id_reg
 * @param spdm_id
 * @param binding_info_gpa
 *
 * @return Success or Error type
 */
api_error_type tdg_spdm_tpa_get(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id,
    pa_t binding_info_gpa);

/**
 * @brief Accept TD private GPA MMIO page mapping
 *
 * @note
 *
 * @param gpa_mapping
 * @param mmio_pa_offset
 *
 * @return Success or Error type
 */
api_error_type tdg_mmio_accept(
    page_info_api_input_t gpa_mapping,
    uint64_t mmio_pa_offset);

/**
 * @brief
 *
 * @param num_inv_descs
 * @param req_pa
 *
 * @return Success or Error type
 */
api_error_type tdg_iq_inv_request(
    uint64_t num_inv_descs,
    pa_t req_pa);


#endif /* INCLUDE_TDXIO_TD_API_HANDLERS_H_ */
