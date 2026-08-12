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
 * @file common_iommu.h
 * @brief
 */

#ifndef SRC_COMMON_TDXIO_COMMON_IOMMU_H_
#define SRC_COMMON_TDXIO_COMMON_IOMMU_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "helpers/helpers.h"
#include "data_structures/tdxio/iommu_defs.h"

/**
 * @brief Given iommu_id return the corresponding socket_io_info_ptr
 *
 * @param iommu_id
 * @param tdx_global_data_ptr
 *
 * @return socket_io_info_ptr
 */
_STATIC_INLINE_ socket_io_info_t *get_socket_io_info(const iommu_id_t iommu_id)
{
    return &get_io_system_info_table()->socket_io_info[iommu_id.socket_id];
}

/**
 * @brief Given iommu_id return the corresponding hiop_info_ptr
 *
 * @param iommu_id
 * @param socket_io_info_ptr
 *
 * @return hiop_info_ptr
 */
_STATIC_INLINE_ hiop_info_t *get_hiop_info(
    const iommu_id_t iommu_id,
    socket_io_info_t *socket_io_info_ptr)
{
    IF_RARE(socket_io_info_ptr == NULL)
    {
        socket_io_info_ptr = get_socket_io_info(iommu_id);
    }
    return &socket_io_info_ptr->hiop_info[iommu_id.hiop_id];
}

/**
 * Release IOMMU hp exclusive lock (only if iommu is locked)
 */
_STATIC_INLINE_ void release_iommu_lock(
    const bool_t is_iommu_locked,
    iommu_config_t *const iommu_config_ptr)
{
    if (is_iommu_locked)
    {
        release_sharex_lock_hp_ex(&iommu_config_ptr->lock);
    }
}

/**
 * @brief check
 *          - iommu_id < max iommu
 *          - host/guest lock is acquired
 *          - Equal to expected IOMMU state
 *          - rp_bitmap
 *
 * @note This function shouldn't be directly called.
 *       Guest and Host APIs have their own version to use
 *
 * @param iommu_id
 * @param operand_id
 * @param expected_iommu_state
 * @param rp_configured
 * @param lock_iommu
 * @param is_iommu_locked_ptr
 * @param iommu_config_ptr
 *
 * @return Success or Error type
 */
_STATIC_INLINE_ api_error_type general_check_and_lock_iommu_config(
    const uint64_t iommu_id_val,
    const uint64_t operand_id,
    const bool_t is_guest,
    bool_t *const is_iommu_locked_ptr,
    iommu_config_t **iommu_config_ptr)
{
    api_error_type ret_val = (api_error_type)UNINITIALIZE_ERROR;
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    *is_iommu_locked_ptr = false;

    hiop_info_t *hiop_info_ptr = NULL;
    uint16_t rp_bitmap = 0;
    iommu_id_reg_t iommu_id_reg = {.raw = 0};

    if (iommu_id_val >= (uint64_t)TOT_NUM_IOMMUS)
    {
        TDX_ERROR("Invalid IOMMU index (=%llu)\n", iommu_id_val);
        ret_val = api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
        goto EXIT;
    }
    // Prevent invalid access to iommu_configs arr
    lfence();

    iommu_id_reg.raw = iommu_id_val;

    *iommu_config_ptr = &tdx_global_data_ptr->iommu_configs[iommu_id_reg.iommu_id.raw];
    ret_val = acquire_sharex_lock_hp_ex(&(*iommu_config_ptr)->lock, is_guest);

    if (ret_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on IOMMU %llu\n", iommu_id_val);
        ret_val = api_error_with_operand_id(ret_val, operand_id);
        goto EXIT;
    }
    *is_iommu_locked_ptr = true;

    if ((*iommu_config_ptr)->state != (iommu_states_t)IOMMU_STATE_CONFIGURED)
    {
        TDX_ERROR("IOMMU is not in configured state (IOMMU state = %u)\n", (*iommu_config_ptr)->state);
        ret_val = api_error_with_operand_id(TDX_IOMMU_INVALID_STATE, operand_id);
        goto EXIT;
    }

    hiop_info_ptr = get_hiop_info(iommu_id_reg.iommu_id, NULL);
    rp_bitmap = hiop_info_ptr->hiop_rp_bit_vector;
    if ((*iommu_config_ptr)->rp_reg_sts != rp_bitmap)
    {
        TDX_ERROR("IOMMU RP not configured properly (IOMMU rp bitmap = 0x%x, HIOP rp bitmap = 0x%x)\n",
                  (*iommu_config_ptr)->rp_reg_sts, rp_bitmap);
        ret_val = api_error_with_operand_id(TDX_IOMMU_RP_NOT_CONFIGURED, operand_id);
        goto EXIT;
    }

    ret_val = TDX_SUCCESS;

EXIT:
    // If function fails and lock_iommu is set, release acquired lock
    if (*is_iommu_locked_ptr &&
        ret_val != TDX_SUCCESS)
    {
        release_iommu_lock(*is_iommu_locked_ptr, *iommu_config_ptr);
        *is_iommu_locked_ptr = false;
    }

    return ret_val;
}

#endif // SRC_COMMON_TDXIO_COMMON_IOMMU_H_