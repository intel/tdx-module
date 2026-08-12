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
 * @file ide_stream.h
 */

#ifndef SRC_COMMON_TDXIO_IDE_STREAM_H_
#define SRC_COMMON_TDXIO_IDE_STREAM_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "helpers/helpers.h"

#include "data_structures/tdxio/ide_stream_defs.h"
#include "data_structures/tdxio/kcbar_defs.h"
#include "data_structures/tdxio/spdm_defs.h"
#include "data_structures/tdxio/iommu_defs.h"

api_error_code_e verify_stream_config_reg_and_map_rp_cfg(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    const ide_stream_cfg_reg_t ide_stream_cfg_reg,
    kcbar_t *const kcbar_ptr,
    rp_cfg_page_t **rp_cfg_page_ptr);

api_error_code_e verify_stream_control_reg(
    const ide_stream_cfg_t ide_stream_cfg,
    const ide_stream_ctrl_reg_t stream_ctrl_reg,
    const stream_info_t *const stream_info_ptr);

api_error_type verify_rid_assoc_regs(
    const hiop_info_t *const hiop_info_ptr,
    const ide_stream_cfg_t ide_stream_cfg,
    const rid_assoc_1_reg_t rid_assoc_1_reg,
    const rid_assoc_2_reg_t rid_assoc_2_reg);

api_error_type verify_addr_assoc_regs(
    const hiop_info_t *const hiop_info_ptr,
    const ide_stream_cfg_t ide_stream_cfg,
    const ide_addr_assoc_1_reg_t ide_addr_assoc_1_reg,
    const ide_addr_assoc_2_reg_t ide_addr_assoc_2_reg,
    const ide_addr_assoc_3_reg_t ide_addr_assoc_3_reg);

api_error_type verify_no_stream_overlaps(
    void *stinfo_0_ptr,
    void *stinfo_1_ptr,
    const rid_assoc_1_t rid_assoc_1,
    const rid_assoc_2_t rid_assoc_2,
    const ide_addr_assoc_1_t ide_addr_assoc_1,
    const ide_addr_assoc_2_t ide_addr_assoc_2,
    const ide_addr_assoc_3_t ide_addr_assoc_3);

api_error_type setup_ide_ecap_regs(
    const socket_io_info_t *const socket_io_info_ptr,
    const rp_cfg_page_t *const rp_cfg_page_ptr,
    void *ide_reg_block_ptr,
    const uint8_t ide_id,
    const ide_stream_type_t ide_stream_type,
    const ide_stream_ctrl_t ide_stream_ctrl,
    const rid_assoc_1_t rid_assoc_1,
    const rid_assoc_2_t rid_assoc_2,
    const ide_addr_assoc_1_t ide_addr_assoc_1,
    const ide_addr_assoc_2_t ide_addr_assoc_2,
    const ide_addr_assoc_3_t ide_addr_assoc_3);

/**
 * @brief Transform Address association registers into base and limit address ranges.
 *        Function assumes input is already valid
 *
 * @param reg1 IDE RID association register 1
 * @param reg2 IDE RID association register 2
 * @param reg3 IDE RID association register 3
 * @param base - holds the base address range selecting the selective IDE stream
 * @param limit - holds the limit address range selecting the selective IDE stream
 */
void transform_assoc_reg_to_range(
    const ide_addr_assoc_1_t reg1,
    const ide_addr_assoc_2_t reg2,
    const ide_addr_assoc_3_t reg3,
    uint64_t *const base,
    uint64_t *const limit);

void cfg_rc_ide_keys(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const uint8_t direction,
    const uint8_t key_set_select,
    const uint8_t sub_stream,
    const uint8_t slot_id,
    key_slot_t *const key_val_ptr);

void prime_rc_ide_keys(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const ide_stream_direction_t direction,
    const ide_stream_key_set_sel_t key_set_select);

bool_t is_ide_ks_ready(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const ide_stream_key_set_sel_t key_set_select);

void set_rc_tx_ide_key_set(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const ide_stream_key_set_sel_t key_set);

/**
 * @brief Depending on the message type at hand generate the relevant payload message
 *
 * @param object_id
 * @param stream_id
 * @param ide_km_param
 * @param key_val_ptr
 * @param payload_ptr
 * @param payload_len_ptr
 */
void generate_idekm_payload(
    const ide_object_id_t object_id,
    const stream_id_t stream_id,
    const ide_km_param_t ide_km_param,
    const key_slot_t *const key_val_ptr,
    void *const payload_ptr,
    uint16_t *const payload_len_ptr);

api_error_type generate_ide_km_req_msg(
    stream_exinfo_t *const stream_exinfo_ptr,
    const stream_id_t stream_id,
    spdm_info_t *const spdm_info_ptr,
    const ide_object_id_t object_id,
    const ide_km_param_t ide_km_param,
    const key_slot_t *const key_val_ptr,
    idekm_msg_t *const message_ptr);

bool_t verify_idekm_message_content(
    const stream_exinfo_t *const stream_exinfo_ptr,
    const stream_id_t stream_id,
    const spdm_info_t *const spdm_info_ptr);

bool_t is_ide_disabled(
    const socket_io_info_t *const socket_io_info_ptr,
    const rp_cfg_page_t *const rp_cfg_page_ptr);


#endif /* SRC_COMMON_TDXIO_IDE_STREAM_H_ */
