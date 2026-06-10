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
 * @file tdh_iommu
 * @brief TDH IOMMU handlers
 */

#ifndef TDH_IOMMU_H_
#define TDH_IOMMU_H_

#include "data_structures/tdxio/iommu_defs.h"
#include "iommu_common.h"

/**
 *@brief Guest side call of general_check_and_lock_iommu_config that CAN'T acquire the lock
 *       check
 *        - iommu_id < max iommu
 *        - is in the expected_iommu_state
 *        - rp_bitmap
 *
 * @param iommu_id
 * @param operand_id
 * @param expected_iommu_state
 * @param rp_configured
 * @param iommu_config_p
 *
 * @return Success or Error type
 */
_STATIC_INLINE_ api_error_type tdg_check_iommu_config(
    const uint64_t iommu_id_val,
    const uint64_t operand_id,
    iommu_config_t **iommu_config_ptr,
    bool_t *const is_iommu_locked)
{
    return general_check_and_lock_iommu_config(
        iommu_id_val,
        operand_id,
        true,
        is_iommu_locked,
        iommu_config_ptr);
}

#endif /* TDH_IOMMU_H_ */
