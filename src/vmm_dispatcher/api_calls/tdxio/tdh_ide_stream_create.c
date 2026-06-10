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
 * @file tdh_ide_stream_create.c
 * @brief TDHIDESTREAMCREATE API handler
 */
#include "tdxio/tdxio_vmm_api_handlers.h"

#include "tdxio/iommu.h"
#include "tdxio/seam_sai.h"
#include "tdxio/ide_stream.h"
#include "tdxio/spdm.h"
#include "tdxio/kcbar.h"

api_error_type tdh_ide_stream_create(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id,
    ide_stream_cfg_reg_t stream_cfg_reg,
    ide_stream_ctrl_reg_t stream_ctrl_reg,
    rid_assoc_1_reg_t rid_assoc_1_reg,
    rid_assoc_2_reg_t rid_assoc_2_reg,
    ide_addr_assoc_1_reg_t addr_assoc_1_reg,
    ide_addr_assoc_2_reg_t addr_assoc_2_reg,
    ide_addr_assoc_3_reg_t addr_assoc_3_reg,
    pa_t stream_exinfo_pa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;

    kcbar_t *kcbar_ptr = NULL;

    spdmdir_entry_t *spdmdir_entry_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;

    stream_info_t *stream_info_ptr = NULL;
    stream_info_t *stinfo_0_ptr = NULL;
    stream_info_t *stinfo_1_ptr = NULL;

    stream_exinfo_t *stream_exinfo_ptr = NULL;
    pamt_walk_result_t stream_exinfo_pamt_walk_result;
    bool_t is_stream_exinfo_locked = false;

    rp_cfg_page_t *rp_cfg_page_ptr = NULL;

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

    // Verify SPDM ID input
    if (spdm_id >= MAX_SPDM_SESSION_ID)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        TDX_ERROR("SPDM id (=%u) is greater than max SPDM sessions (%u)\n", spdm_id, MAX_SPDM_SESSION_ID);

        goto EXIT;
    }

    return_val = lock_check_and_map_spdm_metadata(
        spdm_id,
        OPERAND_ID_RDX,
        iommu_config_ptr,
        SPDM_STATE_BOUND,
        &spdm_info_ptr,
        &spdmdir_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    socket_io_info_t *socket_io_info_ptr = get_socket_io_info(iommu_id_reg.iommu_id);
    hiop_info_t *hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, socket_io_info_ptr);

    kcbar_ptr = map_kcbar(
        socket_io_info_ptr,
        hiop_info_ptr);

    // Verify stream_config input and map kcbar and ide-ecap registers
    api_error_code_e err_code = verify_stream_config_reg_and_map_rp_cfg(
        socket_io_info_ptr,
        hiop_info_ptr,
        stream_cfg_reg,
        kcbar_ptr,
        &rp_cfg_page_ptr);
    if (err_code != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(err_code, OPERAND_ID_R8);
        goto EXIT;
    }

    stinfo_0_ptr = (stream_info_t *)map_pa_with_global_hkid(
        iommu_config_ptr->stinfopa_0.raw_void,
        TDX_RANGE_RW);

    stinfo_1_ptr = (stream_info_t *)map_pa_with_global_hkid(
        iommu_config_ptr->stinfopa_1.raw_void,
        TDX_RANGE_RW);

    stream_info_ptr = stream_ctrl_reg.ide_stream_ctrl.stream_id.page_selector == 1 ? stinfo_1_ptr : stinfo_0_ptr;
    stream_info_ptr = &stream_info_ptr[stream_ctrl_reg.ide_stream_ctrl.stream_id.index];

    // Verify IDE stream control register input
    err_code = verify_stream_control_reg(
        stream_cfg_reg.ide_stream_cfg,
        stream_ctrl_reg,
        stream_info_ptr);
    if (err_code != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(err_code, OPERAND_ID_R9);
        goto EXIT;
    }

    // Verify RID and address association register inputs (R10 - R11)
    return_val = verify_rid_assoc_regs(
        hiop_info_ptr,
        stream_cfg_reg.ide_stream_cfg,
        rid_assoc_1_reg,
        rid_assoc_2_reg);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify address association register inputs (R12 - R14)
    return_val = verify_addr_assoc_regs(
        hiop_info_ptr,
        stream_cfg_reg.ide_stream_cfg,
        addr_assoc_1_reg,
        addr_assoc_2_reg,
        addr_assoc_3_reg);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify new IDE Stream RID and Address registers do not overlap with other IDE streams
    if (stream_cfg_reg.ide_stream_cfg.stream_type == IDE_STREAM_SEL_IDE)
    {
        return_val = verify_no_stream_overlaps(
            stinfo_0_ptr,
            stinfo_1_ptr,
            rid_assoc_1_reg.rid_assoc_1,
            rid_assoc_2_reg.rid_assoc_2,
            addr_assoc_1_reg.ide_addr_assoc_1,
            addr_assoc_2_reg.ide_addr_assoc_2,
            addr_assoc_3_reg.ide_addr_assoc_3);
        if (return_val != TDX_SUCCESS)
        {
            goto EXIT;
        }

    }

    // Verify IDE stream extended info metadata page input
    if (!is_pa_smaller_than_max_pa(stream_exinfo_pa.raw) ||
        get_hkid_from_pa(stream_exinfo_pa))
    {
        TDX_ERROR("IDE stream extended info page address is not valid: 0x%llx, page address HKID: 0x%llx\n",
                  stream_exinfo_pa, get_hkid_from_pa(stream_exinfo_pa));
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R15);
        goto EXIT;
    }

    return_val = check_and_lock_explicit_4k_private_hpa(
        stream_exinfo_pa,
        OPERAND_ID_R15,
        TDX_LOCK_EXCLUSIVE,
        PT_NDA,
        &stream_exinfo_pamt_walk_result,
        &is_stream_exinfo_locked);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock IDE stream extended info page pamt entry\n");
        goto EXIT;
    }

    // Enable SEAM SAI generation
    enable_seam_sai_generation();

    return_val = setup_ide_ecap_regs(
        socket_io_info_ptr,
        rp_cfg_page_ptr,
        NULL,
        stream_cfg_reg.ide_stream_cfg.ide_id,
        stream_cfg_reg.ide_stream_cfg.stream_type,
        stream_ctrl_reg.ide_stream_ctrl,
        rid_assoc_1_reg.rid_assoc_1,
        rid_assoc_2_reg.rid_assoc_2,
        addr_assoc_1_reg.ide_addr_assoc_1,
        addr_assoc_2_reg.ide_addr_assoc_2,
        addr_assoc_3_reg.ide_addr_assoc_3);
    if (return_val != TDX_SUCCESS)
    {
        disable_seam_sai_generation();
        goto EXIT;
    }

    // Initialize kcbar registers
    initialize_kcbar_registers(
        kcbar_ptr,
        stream_cfg_reg.ide_stream_cfg.key_id,
        stream_ctrl_reg.ide_stream_ctrl.stream_id,
        stream_ctrl_reg.ide_stream_ctrl.enabled);

    disable_seam_sai_generation();

    // No failures after this point, update all metadata fields

    // Update PAMT of IDE stream extended info page
    stream_exinfo_pamt_walk_result.pamt_entry_p->pt = PT_IOMMU_MT;
    stream_exinfo_pamt_walk_result.pamt_entry_p->owner = iommu_id_reg.iommu_id.raw;
    stream_exinfo_pamt_walk_result.pamt_entry_p->bepoch.raw = iommu_config_ptr->iommu_generation;

    // Initialize the IDE stream extended info page
    stream_exinfo_ptr = (stream_exinfo_t *)map_pa_with_global_hkid(
        stream_exinfo_pa.raw_void,
        TDX_RANGE_RW);
    zero_area_cacheline(stream_exinfo_ptr, TDX_PAGE_SIZE_IN_BYTES);

    // Update IDE Extended Info
    stream_exinfo_ptr->spdm_id = (uint8_t)spdm_id;
    stream_exinfo_ptr->outstanding_req_object_id = IDE_OBJECT_INVALID;

    spdm_info_ptr->active_stream_count++;

    // Update Stream Info
    stream_info_ptr->stream_sts.stream_type = stream_cfg_reg.ide_stream_cfg.stream_type;
    stream_info_ptr->rp_df_num = stream_cfg_reg.ide_stream_cfg.rp_df_num;
    stream_info_ptr->ide_id = stream_cfg_reg.ide_stream_cfg.ide_id;
    stream_info_ptr->key_id = stream_cfg_reg.ide_stream_cfg.key_id;
    stream_info_ptr->ide_stream_ctrl.raw = stream_ctrl_reg.ide_stream_ctrl.raw;
    stream_info_ptr->ide_rid_assoc_reg.limit = rid_assoc_1_reg.rid_assoc_1.rid_limit;
    stream_info_ptr->ide_rid_assoc_reg.base = rid_assoc_2_reg.rid_assoc_2.rid_base;
    stream_info_ptr->ide_addr_assoc_reg1 = addr_assoc_1_reg.ide_addr_assoc_1;
    stream_info_ptr->ide_addr_assoc_reg2 = addr_assoc_2_reg.ide_addr_assoc_2;
    stream_info_ptr->ide_addr_assoc_reg3 = addr_assoc_3_reg.ide_addr_assoc_3;
    stream_info_ptr->stream_exinfo_pa = stream_exinfo_pa;
    stream_info_ptr->stream_sts.config_lock = 1;

    return_val = TDX_SUCCESS;

EXIT:

    if (stream_exinfo_ptr != NULL)
    {
        free_la(stream_exinfo_ptr);
    }

    if (is_stream_exinfo_locked)
    {
        pamt_unwalk(&stream_exinfo_pamt_walk_result);
    }

    if (stinfo_1_ptr != NULL)
    {
        free_la(stinfo_1_ptr);
    }

    if (stinfo_0_ptr != NULL)
    {
        free_la(stinfo_0_ptr);
    }

    if (rp_cfg_page_ptr != NULL)
    {
        free_la(rp_cfg_page_ptr);
    }

    if (kcbar_ptr != NULL)
    {
        free_la(kcbar_ptr);
    }

    if (spdm_info_ptr != NULL)
    {
        free_la(spdm_info_ptr);
    }

    if (spdmdir_entry_ptr != NULL)
    {
        unlock_spdmdir_entry(spdmdir_entry_ptr, spdm_id);
        free_la(spdmdir_entry_ptr);
    }

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
