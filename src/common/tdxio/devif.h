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
 * @file devif.h
 * @brief
 */

#ifndef SRC_COMMON_TDXIO_DEVIF_H_
#define SRC_COMMON_TDXIO_DEVIF_H_

#include "data_structures/tdxio/devif_defs.h"
#include "helpers/helpers.h"
#include "td_transitions/td_exit.h"
#include "tdisp.h"

_STATIC_INLINE_ bool_t is_valid_field_code(const devif_field_code_e field_code)
{
    return (field_code > TDISP_MIN_FIELD_CODE) && (field_code < TDISP_MAX_FIELD_CODE);
}

/**
 * @brief Must be called after tdh(g)_devif_obtain_devifcs
 * to unmap DEVIFCS, unlock/unwalk the DEVIFCS root PAMT and unlock/unwalk DEVIFMT
 * The argument must be the unmodified structure after tdh(g)_devif_obtain_devifcs.
 *
 * @param devif_par
 */
void devif_unmap_devifcs(devif_verify_param_t *const devif_par);

/**
 * @brief Generate a TDISP message request (see TDISP spec) using DOE and SPDM message format
 *
 * @param devifcs_ptr - DEVIFCS pointer
 * @param doe_spdm_buff_ptr
 * @param payload_len - TDISP payload length in bytes
 * @param devifcs_operand_id - operand_id of devifcs
 * @param target_pa - Target TDISP message HPA
 *
 * @return Success or Error type
 */
api_error_type generate_tdisp_req_msg(
    const devifcs_t *const devifcs_ptr,
    tdisp_msg_t *const doe_spdm_buff_ptr,
    const uint16_t payload_len,
    const uint64_t devifcs_operand_id,
    const pa_t target_pa);

/**
 * @brief Authenticate an TDISP response message
 *
 * @param tdisp_msg_ptr
 * @param spdm_info_ptr
 *
 * @return Success or Error type
 */
bool_t verify_tdisp_message_content(
    tdisp_msg_t *tdisp_msg_ptr,
    spdm_info_t *const spdm_info_ptr);

/**
 * @brief Check function_id:
 *          - Reserved must be 0
 *          - requester_segment_valid  must be 0
 *          - segment_id must be 0
 *
 * @param function_id
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t verify_function_id(fucntion_id_t function_id)
{
    return function_id.segment_id == 0 &&
           function_id.requester_segment_valid == 0 &&
           function_id.reserved == 0;
}

/**
 * @brief Returns pointer to stream info related to the devifcs_ptr
 *
 * @param devifcs_ptr
 * @param iommu_config_ptr
 *
 * @return stream_info_t
 */
stream_info_t *map_stream_info_from_devifcs(
    const devif_id_t devif_id,
    const iommu_config_t *iommu_config_ptr);

#endif /* SRC_COMMON_TDXIO_DEVIF_H_ */
