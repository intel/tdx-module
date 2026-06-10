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
 * @file tdh_ide_stream_block.c
 * @brief TDHIDESTREAMBLOCK API handler
 */

#include "tdxio/tdxio_vmm_api_handlers.h"
#include "tdxio/iommu.h"
#include "tdxio/rp_cfg_page.h"
#include "tdxio/seam_sai.h"
#include "tdxio/ide_stream.h"
#include "tdxio/kcbar.h"
#include "helpers/helpers.h"

_STATIC_INLINE_ api_error_type disable_ide_stream(
    const socket_io_info_t *const socket_io_info_ptr,
    const rp_cfg_page_t *const rp_cfg_page_ptr,
    const uint8_t ide_id,
    const ide_stream_type_t ide_stream_type)
{
    rid_assoc_1_t rid_assoc_1 = {0};
    rid_assoc_2_t rid_assoc_2 = {0};
    ide_addr_assoc_1_t ide_addr_assoc_1 = {0};
    ide_addr_assoc_2_t ide_addr_assoc_2 = {0};
    ide_addr_assoc_3_t ide_addr_assoc_3 = {0};

    void *ide_reg_block_ptr = get_ide_reg_block(
        socket_io_info_ptr,
        rp_cfg_page_ptr,
        ide_id,
        ide_stream_type);
    if (ide_reg_block_ptr == NULL)
    {
        return api_error_with_operand_id(TDX_IDE_STREAM_NOT_SUPPORTED, OPERAND_ID_R8);
    }

    ide_stream_ctrl_t ide_stream_ctrl = {0};
    if (ide_stream_type == IDE_STREAM_SEL_IDE)
    {
        ide_stream_ctrl.raw = vol_read_reg32(&((sel_ide_stream_reg_block_t *)ide_reg_block_ptr)->control.raw);
    }
    else
    {
        ide_stream_ctrl.raw = vol_read_reg32(&((lnk_ide_stream_reg_block_t *)ide_reg_block_ptr)->control.raw);
    }
    ide_stream_ctrl.enabled = 0;

    return setup_ide_ecap_regs(
        socket_io_info_ptr,
        rp_cfg_page_ptr,
        ide_reg_block_ptr,
        ide_id,
        ide_stream_type,
        ide_stream_ctrl,
        rid_assoc_1,
        rid_assoc_2,
        ide_addr_assoc_1,
        ide_addr_assoc_2,
        ide_addr_assoc_3);
}

api_error_type tdh_ide_stream_block(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id_reg)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    stream_info_t *stream_info_ptr = NULL;
    stream_info_t *stream_info_base_ptr = NULL;

    rp_cfg_page_t *rp_cfg_page_ptr = NULL;

    kcbar_t *kcbar_ptr = NULL;
    bool_t is_seam_sai_enabled = false;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    // Lock IOMMU entry and verify it is configured
    return_val = tdh_check_and_lock_iommu_config(
        iommu_id_reg.raw,
        OPERAND_ID_RCX,
        &is_iommu_locked,
        &iommu_config_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify Stream ID
    if (stream_id_reg.raw >= MAX_IDE_STREAM_ID)
    {
        TDX_ERROR("Stream ID - %u is greater than max IDE Streams allowd\n", stream_id_reg.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    pa_t stream_info_pa = stream_id_reg.stream_id.page_selector == 1 ? iommu_config_ptr->stinfopa_1 : iommu_config_ptr->stinfopa_0;
    stream_info_base_ptr = (stream_info_t *)map_pa_with_global_hkid(
        stream_info_pa.raw_void,
        TDX_RANGE_RW);
    stream_info_ptr = &stream_info_base_ptr[stream_id_reg.stream_id.index];

    if (stream_info_ptr->stream_sts.config_lock == 0)
    {
        TDX_ERROR("IDE Stream not configured\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_NOT_CONFIGURED, OPERAND_ID_RDX);
        goto EXIT;
    }

    if (stream_info_ptr->stream_sts.stream_block == 1)
    {
        TDX_ERROR("IDE Stream blocked\n");
        return_val = api_error_with_operand_id(TDX_IDE_STREAM_BLOCKED, OPERAND_ID_RDX);
        goto EXIT;
    }

    enable_seam_sai_generation();
    is_seam_sai_enabled = true;

    socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
    hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

    // Initialize and clear IDE - ECAP registers associated with STREAM_ID
    //  - Disable stream control register
    //  - For Selective - IDE stream, initialize RIDand address association registers to 0
    rp_cfg_page_ptr = map_rp_mmcfg(
        hiop_info_ptr,
        stream_info_ptr->rp_df_num);

    ide_ecap_t *ide_ecap_ptr = get_rp_ide_ecap_regaddr(socket_io_info_ptr, rp_cfg_page_ptr);
    if (ide_ecap_ptr == NULL)
    {
        return_val = TDX_IDE_STREAM_NOT_SUPPORTED;
        goto EXIT;
    }

    return_val = disable_ide_stream(
        socket_io_info_ptr,
        rp_cfg_page_ptr,
        stream_info_ptr->ide_id,
        stream_info_ptr->stream_sts.stream_type);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    kcbar_ptr = map_kcbar(
        socket_io_info_ptr,
        hiop_info_ptr);

    initialize_kcbar_registers(
        kcbar_ptr,
        stream_info_ptr->key_id,
        stream_id_reg.stream_id,
        false);

    stream_info_ptr->stream_sts.stream_block = 1;
    return_val = TDX_SUCCESS;

EXIT:

    if (kcbar_ptr != NULL)
    {
        free_la(kcbar_ptr);
    }

    if (rp_cfg_page_ptr != NULL)
    {
        free_la(rp_cfg_page_ptr);
    }

    if (is_seam_sai_enabled)
    {
        disable_seam_sai_generation();
    }

    if (stream_info_base_ptr != NULL)
    {
        free_la(stream_info_base_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
