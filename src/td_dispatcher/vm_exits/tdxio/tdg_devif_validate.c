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
 * @file tdg_devif_validate.c
 * @brief TDGDEVIFVALIDATE API handler
 */

#include "tdxio/tdxio_td_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/iommu_common.h"
#include "tdxio/devif.h"
#include "tdxio/spdm.h"
#include "tdxio/devifmt.h"

api_error_type tdg_devif_validate(
    function_id_reg_t function_id_reg,
    uint64_t dev_pkh_qw_0,
    uint64_t dev_pkh_qw_1,
    uint64_t dev_pkh_qw_2,
    uint64_t dev_pkh_qw_3,
    uint64_t dev_pkh_qw_4,
    uint64_t dev_pkh_qw_5)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    devif_verify_param_t devif_verify_param = {0};

    measurement_t dev_info_hash = {0};
    dev_info_hash.qwords[0] = dev_pkh_qw_0;
    dev_info_hash.qwords[1] = dev_pkh_qw_1;
    dev_info_hash.qwords[2] = dev_pkh_qw_2;
    dev_info_hash.qwords[3] = dev_pkh_qw_3;
    dev_info_hash.qwords[4] = dev_pkh_qw_4;
    dev_info_hash.qwords[5] = dev_pkh_qw_5;

    // Lock, map and check devifcs
    return_val = tdg_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_RCX,
        false,
        &devif_verify_param,
        NULL);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify DEVIF_PKH matches the one hashed in the DEVIFCS
    // or fail with TDX_DEVIF_PKH_MISMATCH
    if (!tdx_memcmp(&devif_verify_param.devifcs_ptr->dev_info_hash,
                    &dev_info_hash,
                    sizeof(devif_verify_param.devifcs_ptr->dev_info_hash)))
    {
        TDX_ERROR("DEVIF_PKH does not match the one hashed in the DEVIFCS\n");
        return_val = api_error_with_operand_id(TDX_DEVIF_PKH_MISMATCH, OPERAND_ID_RDX);
        goto EXIT;
    }

    uint8_t prev_devifcs_valid = _lock_cmpxchg_8bit(
        DEVIFCS_FREE,
        DEVIFCS_VALID,
        &devif_verify_param.devifcs_ptr->valid);
    if (prev_devifcs_valid == DEVIFCS_VALID)
    {
        TDX_ERROR("DEVIFCS already valid\n");
        return_val = api_error_with_operand_id(TDX_DEVIF_ALREADY_VALID, OPERAND_ID_RCX);

        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free keyhole mappings
    devif_unmap_devifcs(&devif_verify_param);

    return return_val;
}
