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
 * @file devifmt.h
 * @brief
 */

#ifndef SRC_COMMON_TDXIO_DEVIFMT_H_
#define SRC_COMMON_TDXIO_DEVIFMT_H_

#include "data_structures/tdxio/devifmt_defs.h"
#include "data_structures/tdxio/devif_defs.h"
#include "helpers/helpers.h"
#include "tdxio/devif.h"


/**
 * @brief Get the devifcs via devifmt's LEAF entry.
 *          If is_check_devifcs_validity is true - then check that devifcs valid bit is on
 *
 * @param function_id_reg
 * @param mapping_type
 * @param function_id_operand_id
 * @param is_check_devifcs_validity
 * @param devif_verify_param_ptr - output containing relevant info
 *
 * @return api_error_type
 */
api_error_type tdg_devifmt_get_devifcs(
    const function_id_reg_t function_id_reg,
    const mapping_type_t mapping_type,
    const uint64_t function_id_operand_id,
    const bool_t is_check_devifcs_validity,
    devif_verify_param_t *const devif_verify_param_ptr,
    tdx_module_local_t *local_data);

/**
 * @brief Get the devifcs via devifmt's LEAF entry.
 *
 * @param function_id_reg
 * @param mapping_type
 * @param function_id_operand_id
 * @param devif_verify_param_ptr - - output containing relevant info
 *
 * @return api_error_type
 */
api_error_type tdh_devifmt_get_devifcs(
    const function_id_reg_t function_id_reg,
    const mapping_type_t mapping_type,
    const uint64_t function_id_operand_id,
    devif_verify_param_t *const devif_verify_param_ptr);

/**
 * @brief Gets the devifcs via devifmt last entry.
 * The devifmt_idx is taken from function_id parameter
 *
 * @param function_id_reg
 * @param mapping_type
 * @param lock_mode - Specifiecs if a HP lock (false) or a guest lock (True)
 * @param devif_verify_param_ptr
 *
 * @return api_error_type
 */
api_error_type devifmt_get_devifcs(
    const function_id_reg_t function_id_reg,
    const mapping_type_t mapping_type,
    const bool_t lock_mode,
    devif_verify_param_t *const devif_verify_param_ptr,
    const bool_t is_guest);

/**
 * @brief Check the validity of devifmt_idx.
 *          - Reserved bits must be zero
 *          - IDX must be a valid index
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t is_valid_devifmt_idx(
    const devifmt_idx_t devifmt_idx,
    const bool_t is_level_zero_valid)
{
    return (devifmt_idx.reserved == 0) &&
           ((is_level_zero_valid && devifmt_idx.level >= DEVIFMT_L0) ||
            (!is_level_zero_valid && devifmt_idx.level > DEVIFMT_L0)) &&
           (devifmt_idx.level <= DEVIFMT_ROOT_L) &&
           verify_function_id(devifmt_idx.function_id);
}

/**
 * @brief This function walks the devifmt table in order to reach the entry on the specified level
 *        Once reached the desired level, the last entry visited will be locked (if required)
 *
 * @param devifmt_idx - Specifies the desired level
 * @param lock_entry - Specifies if the last entry should be locked
 * @param is_guest - Specifies if the lock is for guest or host
 * @param lock_mode - Specifiecs if a HP lock (false) or a guest lock (True)
 * @param is_mmiomt_walked_ptr - Reminds the user to unwalk the DEVIFMT tree
 * @param devifmt_walk_result - Saves level that was reached, and the path of visited entries and PAMTs that were visited during the walk
 *
 * @return api_error_code_e - TDX_SUCCESS if reached the specified level successfuly, else returns an error code
 */
api_error_code_e devifmt_walk(
    const devifmt_idx_t devifmt_idx,
    const bool_t lock_entry,
    const bool_t lock_mode,
    const bool_t is_guest,
    bool_t *const  is_devifmt_walked_ptr,
    devifmt_walk_res_t *const devifmt_walk_result);

/**
 * @brief Release the entrie pointers and the PAMT entries that were visited during the walk.
 *        If the last entrie was locked than it will be released
 *
 * @param devifmt_walk_result_ptr
 */
void devifmt_unwalk(devifmt_walk_res_t *const devifmt_walk_result_ptr);

/**
 * @brief Acquire the lock bit, incase the it's already set, fail and set the hp bit.
 *
 * @param devifmt_entry_ptr
 * @return api_error_type
 */
api_error_type devifmt_acquire_host_lock(devifmt_entry_t *const devifmt_entry_ptr);

/**
 * @brief Acquire the lock bit, fail incase the HP is already set.
 *
 * @param devifmt_entry_ptr
 * @return api_error_type
 */
api_error_type devifmt_acquire_guest_lock(devifmt_entry_t *const devifmt_entry_ptr);

#endif // SRC_COMMON_TDXIO_DEVIFMT_H_
