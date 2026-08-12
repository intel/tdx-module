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
 * @file tdg_spdm_tpa_get.c
 * @brief TDG.SPDM.TPA.GET API handler
 */

#include "tdxio/tdxio_td_api_handlers.h"
#include "helpers/tdx_locks.h"
#include "memory_handlers/keyhole_manager.h"
#include "helpers/helpers.h"

#include "data_structures/tdxio/iommu_defs.h"
#include "tdxio/spdm.h"

api_error_type tdg_spdm_tpa_get(
    iommu_id_reg_t iommu_id_reg,
    uint64_t spdm_id,
    pa_t binding_info_gpa)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    void *binding_info_ptr = NULL;
    spdm_info_t *spdm_info_ptr = NULL;
    spdmdir_entry_t *spdmdir_ptr = NULL;

    return_val = tdg_spdm_binding_prologue(
        iommu_id_reg,
        spdm_id,
        SPDM_STATE_BOUND,
        binding_info_gpa,
        TDX_RANGE_RW,
        &spdm_info_ptr,
        &spdmdir_ptr,
        &binding_info_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Make state configured
    spdm_info_ptr->state = SPDM_STATE_NOT_BOUND;
    // Copy spdm_info->binding into binding_info
    tdx_memcpy(
        binding_info_ptr,
        TDX_PAGE_SIZE_IN_BYTES,
        (void *)&spdm_info_ptr->binding_info,
        sizeof(spdm_info_ptr->binding_info));

    return_val = TDX_SUCCESS;

EXIT:

    if (binding_info_ptr != NULL)
    {
        free_la(binding_info_ptr);
    }

    if (spdm_info_ptr != NULL)
    {
        free_la(spdm_info_ptr);
    }

    if (spdmdir_ptr != NULL)
    {
        unlock_spdmdir_entry(spdmdir_ptr, spdm_id);
        free_la(spdmdir_ptr);
    }

    return return_val;
}
