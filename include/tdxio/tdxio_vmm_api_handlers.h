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
 * @file tdxio_vmm_api_handelrs.h
 * @brief TDXIO VMM API Handlers
 */
#ifndef __TDXIO_VMM_API_HANDLERS_H_INCLUDED__
#define __TDXIO_VMM_API_HANDLERS_H_INCLUDED__

#include "tdx_api_defs.h"
#include "data_structures/tdxio/iommu_defs.h"
#include "data_structures/tdxio/ide_stream_defs.h"
#include "data_structures/tdxio/devif_defs.h"
#include "data_structures/tdxio/dmar_defs.h"
#include "data_structures/tdxio/inv_queue_defs.h"
#include "data_structures/tdxio/mmiomt_defs.h"
#include "data_structures/tdxio/devifmt_defs.h"

/**
 * @brief Set IOMMU registers
 *
 * @note
 *
 * @param iommu_id
 * @param reg_id
 * @param reg_value
 *
 * @return Success or Error type
 */
api_error_type tdh_iommu_setreg(
    iommu_id_reg_t iommu_id_reg,
    iommu_register_id_e reg_id,
    uint64_t reg_value);

/**
 * @brief Get IOMMU registers
 *
 * @note output IOMMU register value
 *
 * @param param
 * @param reg_id
 *
 * @return Success or Error type
 */
api_error_type tdh_iommu_getreg(
    uint64_t param,
    iommu_register_id_e reg_id);

/**
 * @brief Create a new IDE Stream
 *
 * @note
 *
 * @param iommu_id_reg
 * @param spdm_id
 * @param stream_cfg
 * @param stream_ctrl_reg
 * @param rid_assoc1_reg
 * @param rid_assoc2_reg
 * @param addr_assoc_1_reg
 * @param addr_assoc_2_reg
 * @param addr_assoc_3_reg
 * @param stream_exinfo_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_ide_stream_create(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id,
    ide_stream_cfg_reg_t stream_cfg,
    ide_stream_ctrl_reg_t stream_ctrl_reg,
    rid_assoc_1_reg_t rid_assoc1_reg,
    rid_assoc_2_reg_t rid_assoc2_reg,
    ide_addr_assoc_1_reg_t addr_assoc_1_reg,
    ide_addr_assoc_2_reg_t addr_assoc_2_reg,
    ide_addr_assoc_3_reg_t addr_assoc_3_reg,
    pa_t stream_exinfo_pa);

/**
 * @brief Create an IDE Key Management Request Message
 *
 * @note
 *
 * @param iommu_id
 * @param stream_id
 * @param object_id
 * @param ide_km_param
 * @param slot_id
 * @param message_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_ide_stream_idekmreq(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id_reg,
    ide_object_id_t object_id,
    ide_km_param_reg_t ide_km_param_reg,
    uint64_t slot_id,
    pa_t message_pa);

/**
 * @brief Process an IDE Key Management Response Message
 *
 * @note
 *
 * @param iommu_id
 * @param stream_id
 * @param message_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_ide_stream_idekmrsp(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id_reg,
    pa_t message_pa);

/**
 * @brief Block an IDE Stream
 *
 * @note
 *
 * @param iommu_id
 * @param stream_id
 *
 * @return Success or Error type
 */
api_error_type tdh_ide_stream_block(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id);

/**
 * @brief Delete an IDE Stream
 *
 * @note
 *
 * @param iommu_id
 * @param stream_id
 *
 * @return Success or Error type
 */
api_error_type tdh_ide_stream_delete(
    iommu_id_reg_t iommu_id_reg,
    stream_id_reg_t stream_id);

/**
 * @brief Build the DEVIFMT tree - adds the new DEVIFMT page to DEVIFMT tree
 *
 * @param devifmt_idx   DEVIFMT parent entry index
 * @param table_pa      HPA address to allocate the new DEVIFMT page
 *
 * @return Success or Error type
 */
api_error_type tdh_devif_mt_add(
    devifmt_idx_t devifmt_idx,
    pa_t table_pa);

/**
 * @brief Reclaims a page from the DEVIFMT tree
 *
 * @param devifmt_idx - DEVIFMT index (DEVIF HPA address and level) of the DEVIFMT page parent entry
 * @return api_error_type
 */
api_error_type tdh_devif_mt_remove(devifmt_idx_t devifmt_idx);

/**
 * @brief Read the DEVIFMT entry
 *
 * @param devifmt_idx -  DEVIFMT index (DEVIF HPA address and level) of the DEVIFMT page parent entry
 * @return api_error_type
 */
api_error_type tdh_devif_mt_rd(devifmt_idx_t devifmt_idx);

/**
 * @brief Add new device interface control structure
 *
 * @note
 *
 * @param devif_info - Host device interface ID
 * @param tdr_pa - Physical page address of TDR page
 * @param devifcs_root_pa - Physical address for hosting a new DEVIFCS main page
 * @param td_tdisp_msg_buffer_pa - Physical page address of TDISP message buffer page
 * @param vmm_tdisp_msg_buffer_pa - Physical page address of TDISP message buffer page
 *
 * @return Success or Error type
 */
api_error_type tdh_devif_create(
    devif_id_t devif_info,
    pa_t tdr_pa,
    pa_t devifcs_root_pa,
    pa_t td_tdisp_msg_buffer_pa,
    pa_t vmm_tdisp_msg_buffer_pa);

/**
 * @brief Generate VMM or TD initiated TDISP request message
 *
 * @param function_id_reg
 * @param devif_req_in
 * @param tdisp_req_out_pa
 * @param unused_r9
 *
 * @return Success or Error type
 */
api_error_type tdh_devif_request(
    function_id_reg_t function_id_reg,
    devif_req_in_t devif_req_in,
    pa_t tdisp_req_out_pa,
    uint64_t unused_r9);

/**
 * @brief Authenticate and process TDISP response message
 *
 * @note
 *
 * @param function_id_reg
 * @param devif_rsp_in
 * @param vmm_msg_buff_output_pa
 * @param unused_r9
 *
 * @return Success or Error type
 */
api_error_type tdh_devif_response(
    function_id_reg_t function_id_reg,
    devif_rsp_in_t devif_rsp_in,
    pa_t vmm_msg_buff_output_pa,
    uint64_t unused_r9);

/**
 * @brief Removes a device interface control structure
 *
 * @note
 *
 * @param function_id_reg
 *
 * @return Success or Error type
 */
api_error_type tdh_devif_remove(function_id_reg_t function_id_reg);

/**
 * @brief Add MMIOMT page
 *
 * @note
 *
 * @param mmiomt_idx
 * @param mmiomt_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_mmio_mt_add(
    mmiomt_idx_t mmiomt_idx,
    pa_t mmiomt_pa);

/**
 * @brief Read MMIOMT entry
 *
 * @note
 *
 * @param mmiomt_idx
 *
 * @return Success or Error type
 */
api_error_type tdh_mmio_mt_rd(mmiomt_idx_t mmiomt_idx);

/**
 * @brief Set MMIOMT leaf entry parameters
 *
 * @note
 *
 * @param mmiomt_idx
 * @param mmiomt_set_info
 *
 * @return Success or Error type
 */
api_error_type tdh_mmio_mt_set(
    mmiomt_idx_t mmiomt_idx,
    mmiomt_set_info_t mmiomt_set_info);

/**
 * @brief Remove an empty MMIOMT page
 *
 * @note
 *
 * @param mmiomt_idx
 *
 * @return Success or Error type
 */
api_error_type tdh_mmio_mt_remove(mmiomt_idx_t mmiomt_idx);

/**
 * @brief Map private MMIO page to a TD
 *
 * @note
 *
 * @param gpa_mapping
 * @param tdr_pa
 * @param mmio_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_mmio_map(
    page_info_api_input_t gpa_mapping,
    pa_t tdr_pa,
    pa_t mmio_pa);

/**
 * @brief Block MMIO page
 *
 * @note
 *
 * @param gpa_mapping
 * @param tdr_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_mmio_block(
    page_info_api_input_t gpa_mapping,
    pa_t tdr_pa);

/**
 * @brief UNMAP MMIO page
 *
 * @note
 *
 * @param gpa_mapping
 * @param tdr_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_mmio_unmap(
    page_info_api_input_t gpa_mapping,
    pa_t tdr_pa);

/**
 * @brief Add and map a trusted DMA re-mapping structure
 *
 * @note
 *
 * @param dmar_idx
 * @param dmar_val_1
 * @param dmar_val_2
 * @param dmar_val_3
 * @param dmar_val_4
 * @param dmar_val_5
 * @param dmar_val_6
 * @param dmar_val_7
 * @param dmar_val_8
 *
 * @return Success or Error type
 */
api_error_type tdh_dmar_add(
    dmar_idx_t dmar_idx,
    uint64_t dmar_val_1,
    uint64_t dmar_val_2,
    uint64_t dmar_val_3,
    uint64_t dmar_val_4,
    uint64_t dmar_val_5,
    uint64_t dmar_val_6,
    uint64_t dmar_val_7,
    uint64_t dmar_val_8);

/**
 * @brief Block a DMA remapping table entry
 *
 * @note
 *
 * @param dmar_index
 *
 * @return Success or Error type
 */
api_error_type tdh_dmar_block(dmar_idx_t dmar_idx);

/**
 * @brief Read a DMA remapping table entry
 *
 * @note
 *
 * @param dmar_index
 *
 * @return Success or Error type
 */
api_error_type tdh_dmar_read(dmar_idx_t dmar_idx);

/**
 * @brief Remove a DMA remapping table entry
 *
 * @param dmar_idx
 *
 * @return Success or Error type
 */
api_error_type tdh_dmar_remove(dmar_idx_t dmar_idx);

/**
 * @brief Create a SPDM session
 *
 * @param iommu_id_reg
 * @param spdm_id
 * @param spdm_info_pa
 *
 * @return Success or Error type
 */
api_error_type tdh_spdm_create(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id,
    pa_t spdm_info_pa);

/**
 * @brief Delete a SPDM session
 *
 * @param iommu_id_reg
 * @param spdm_id
 *
 * @return Success or Error type
 */
api_error_type tdh_spdm_delete(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id);

/**
 * @brief Issue an invalidation request to Invalidation Queue
 *
 * @param iommu_id_reg
 * @param inv_req_type
 * @param inv_target
 * @param inv_wait_dsc_qword_1
 * @param inv_wait_dsc_qword_2
 * @param inv_wait_dsc_qword_3
 * @param inv_wait_dsc_qword_4
 *
 * @return Success or Error type
 */
api_error_type tdh_iq_inv_request(
    iommu_id_reg_t iommu_id_reg,
    inv_req_type_t inv_req_type,
    uint64_t inv_target,
    uint64_t inv_wait_dsc_qword_1,
    uint64_t inv_wait_dsc_qword_2,
    uint64_t inv_wait_dsc_qword_3,
    uint64_t inv_wait_dsc_qword_4);

/**
 * @brief Process invalidation requests
 *
 * @param iommu_id_reg
 *
 * @return Success or Error type
 */
api_error_type tdh_iq_inv_process(iommu_id_reg_t iommu_id_reg);

/**
 * @brief Enables VMM to map/un-map shared EPT root table entries used to support trusted
 *        DMA access to TD shared GPA space
 *
 * @note
 *
 * @param gpa_page_info
 * @param tdr_pa
 * @param ept_entry
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_shared_sept_wr(
    page_info_api_input_t gpa_page_info,
    pa_t tdr_pa,
    ia32e_sept_t ept_entry_0,
    ia32e_sept_t ept_entry_1,
    ia32e_sept_t ept_entry_2,
    ia32e_sept_t ept_entry_3,
    uint64_t version);

#endif // __TDXIO_VMM_API_HANDLERS_H_INCLUDED__
