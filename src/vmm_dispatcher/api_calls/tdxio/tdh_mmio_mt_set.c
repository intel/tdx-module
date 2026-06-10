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
 * @file tdh_mmio_mt_set.c
 * @brief TDHMMIOMTSET API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "helpers/helpers.h"
#include "tdxio/mmiomt.h"
#include "tdxio/devifmt.h"

api_error_type tdh_mmio_mt_set(
    mmiomt_idx_t mmiomt_idx,
    mmiomt_set_info_t mmiomt_set_info)
{
    // mmiomt_walk variables
    mmiomt_walk_res_t mmiomt_walk_res = {0};
    bool_t is_mmiomt_walked = false;
    mmiomt_entry_t *mmiomt_entry_ptr = NULL;

    devif_verify_param_t devif_verify_param = {0};
    function_id_reg_t function_id_reg = {.raw = 0};

    api_error_type return_val = UNINITIALIZE_ERROR;

    /**
     * Verify MMIOMT_IDX validity +
     * In TDH.MMIO.MT.SET the max MMIOMT index LEVEL should be L2 since we have 2 cases:
     *      - Set DATA to QNODE
     *      - Set QNODE as DATA
     * and in both cases, the common levels for Qnode and DATA are <= L2
    */
        if ((mmiomt_idx.level > MMIOMT_L2) ||
        (!is_valid_mmiomt_idx(mmiomt_idx, MMIOMT_L0)))
    {
        TDX_ERROR("MMIOMT index (0x%llx) is not valid\n", mmiomt_idx.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    return_val = mmiomt_walk(
        mmiomt_idx,
        true,
        TDX_RANGE_RW,
        &is_mmiomt_walked,
        &mmiomt_walk_res);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to perform mmiomt walk\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    mmiomt_entry_ptr = mmiomt_walk_res.mmiomt_path_arr[mmiomt_idx.level];

    // Verify MMIOMT_SET_INFO
    if (mmiomt_set_info.rsvd1 ||
        mmiomt_set_info.rsvd2 ||
        mmiomt_set_info.type > MMIOMT_DATA ||
        (mmiomt_set_info.type == MMIOMT_QNODE && mmiomt_set_info.function_id != 0) ||
        (mmiomt_set_info.type == MMIOMT_DATA && mmiomt_set_info.function_id == 0))
    {
        TDX_ERROR("Invalid MMIOMT set info (0x%llx)\n", mmiomt_set_info.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (mmiomt_set_info.type == MMIOMT_QNODE) // DATA to QNODE
    {
        // Verify entry type is DATA and MAPPED flag is clear
        if (mmiomt_entry_ptr->type != MMIOMT_DATA ||
            mmiomt_entry_ptr->data.mapped)
        {
            TDX_ERROR("MMIOMT type QNODE: entry type (=%u) is not MMIOMT_DATA or mapped flag (=%u) is not clear\n",
                      mmiomt_entry_ptr->type, mmiomt_entry_ptr->data.mapped);
            return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_MMIOMT);
            goto EXIT;
        }

        // Update mmiomt_entry
        mmiomt_entry_ptr->type = MMIOMT_QNODE;
        mmiomt_entry_ptr->qnode[0].p = 0;
        mmiomt_entry_ptr->qnode[1].p = 0;
        mmiomt_entry_ptr->qnode[2].p = 0;
        mmiomt_entry_ptr->qnode[3].p = 0;
    }
    else // QNODE TO DATA
    {
        // Verify entry type is QNODE and none of the present bits are set
        if (mmiomt_entry_ptr->type != MMIOMT_QNODE ||
            mmiomt_entry_ptr->qnode[0].p ||
            mmiomt_entry_ptr->qnode[1].p ||
            mmiomt_entry_ptr->qnode[2].p ||
            mmiomt_entry_ptr->qnode[3].p)
        {
            TDX_ERROR("MMIOMT type QNODE: entry type (=%u) is not MMIOMT_QNODE or one of the present bits are set\n",
                      mmiomt_entry_ptr->type);
            return_val = api_error_with_operand_id(TDX_MMIO_INVALID_PAGE_METADATA, OPERAND_ID_MMIOMT);
            goto EXIT;
        }

        function_id_reg.function_id.raw = mmiomt_set_info.function_id;

        // Lock, map and check devifcs
        return_val = tdh_devifmt_get_devifcs(
            function_id_reg,
            TDX_RANGE_RO,
            OPERAND_ID_RDX,
            &devif_verify_param);
        if (return_val != TDX_SUCCESS)
        {
            goto EXIT;
        }
        // update mmiomt_entry
        mmiomt_entry_ptr->type = MMIOMT_DATA;
        mmiomt_entry_ptr->data.function_id = devif_verify_param.devifmt_idx.function_id.raw;
    }

EXIT:

    devif_unmap_devifcs(&devif_verify_param);

    if (is_mmiomt_walked)
    {
        mmiomt_unwalk(&mmiomt_walk_res);
    }
    return return_val;
}
