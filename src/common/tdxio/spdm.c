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
 * @file spdm.c
 * @brief
 */

#include "spdm.h"
#include "helpers/helpers.h"
#include "tdxio/tdg_iommu.h"

spdmdir_entry_t *map_and_lock_spdmdir_entry(
    const iommu_config_t *const iommu_config_ptr,
    const uint64_t spdm_id)
{
    // Map IOMMU.SPDMDIRPA using TDX reserved HKID
    spdmdir_entry_t *spdmdir_entry_ptr = (spdmdir_entry_t *)map_pa_with_global_hkid(
        iommu_config_ptr->spdmdirpa.raw_void,
        TDX_RANGE_RW);

    if (!lock_spdmdir_entry(spdmdir_entry_ptr, spdm_id))
    {
        TDX_ERROR("Failed to lock spdmdir\n");
        free_la(spdmdir_entry_ptr);
        spdmdir_entry_ptr = NULL;
    }

    return spdmdir_entry_ptr;
}

api_error_type lock_check_and_map_spdm_metadata(
    const uint64_t spdm_id,
    const uint64_t operand_id,
    const iommu_config_t *const iommu_config_ptr,
    const spdm_session_state_t expected_spdm_state,
    spdm_info_t **spdm_info_ptr,
    spdmdir_entry_t **spdmdir_entry_ptr)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    *spdmdir_entry_ptr = map_and_lock_spdmdir_entry(iommu_config_ptr, spdm_id);
    if (*spdmdir_entry_ptr == NULL)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, operand_id);
        goto EXIT_FAILURE;
    }

    // SPDM info must be already configured in directory
    if ((*spdmdir_entry_ptr)[spdm_id].present == 0)
    {
        TDX_ERROR("SPDM info must be already configured in directory (=0x%llx)\n", (*spdmdir_entry_ptr)[spdm_id].raw);
        return_val = api_error_with_operand_id(TDX_SPDM_ENTRY_NOT_PRESENT, operand_id);
        goto EXIT_FAILURE;
    }

    // Map SPDM info page
    pa_t spdm_info_pa = {.raw = 0};
    spdm_info_pa.page_4k_num = (*spdmdir_entry_ptr)[spdm_id].addr;

    *spdm_info_ptr = (spdm_info_t *)map_pa_with_global_hkid(
        spdm_info_pa.raw_void,
        TDX_RANGE_RW);

    if ((*spdm_info_ptr)->state != expected_spdm_state)
    {
        TDX_ERROR("Invalid SPDM state (SPDM state = %u, Expected SPDM state = %u)\n",
                  (*spdm_info_ptr)->state, expected_spdm_state);
        return_val = api_error_with_operand_id(TDX_SPDM_INVALID_STATE, operand_id);
        goto EXIT_FAILURE;
    }

    return_val = TDX_SUCCESS;

    goto EXIT_SUCCESS;

EXIT_FAILURE:

    if (*spdm_info_ptr != NULL)
    {
        free_la(*spdm_info_ptr);
        *spdm_info_ptr = NULL;
    }

    if (*spdmdir_entry_ptr != NULL)
    {
        unlock_spdmdir_entry(*spdmdir_entry_ptr, spdm_id);
        free_la(*spdmdir_entry_ptr);
        *spdmdir_entry_ptr = NULL;
    }

EXIT_SUCCESS:
    return return_val;
}

#include "tpa_hash.h"
/**
 * @brief Get the tpa info hash value from the relevant header file
 *
 * @param tpa_info_hash
 */
_STATIC_INLINE_ void get_tpa_info_hash(measurement_t *const tpa_info_hash)
{
    tpa_info_hash->qwords[0] = GLOBAL_TPA_HASH_Q0;
    tpa_info_hash->qwords[1] = GLOBAL_TPA_HASH_Q1;
    tpa_info_hash->qwords[2] = GLOBAL_TPA_HASH_Q2;
    tpa_info_hash->qwords[3] = GLOBAL_TPA_HASH_Q3;
    tpa_info_hash->qwords[4] = GLOBAL_TPA_HASH_Q4;
    tpa_info_hash->qwords[5] = GLOBAL_TPA_HASH_Q5;
}

/**
 * @brief Generate and compare the running TD-TPA hash with the expected Intel TPA hash
 *
 * @return Success or Error type
 */
_STATIC_INLINE_ api_error_type is_valid_tpa_td(void)
{
    tdcs_t *tdcs_ptr = get_local_data()->vp_ctx.tdcs;
    tdx_sanity_check(tdcs_ptr != NULL, SCEC_TDCALL_SOURCE(SCEC_SPDM_SOURCE), 1);

    ALIGN(64)
    measurement_t tee_info_hash = {0};
    td_info_t td_info;

    if (tdcs_ptr->executions_ctl_fields.attributes.tpa == 0)
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
    }

    ignore_tdinfo_bitmap_t ignore = {.raw = 0};
    api_error_code_e ret_val = get_tdinfo_and_teeinfohash(tdcs_ptr, ignore, &td_info, &tee_info_hash, true);
    if (ret_val != TDX_SUCCESS)
    {
        return api_error_with_operand_id(ret_val, OPERAND_ID_RTMR);
    }

    measurement_t tpa_info_hash;
    get_tpa_info_hash(&tpa_info_hash);

    if (!tdx_memcmp(tpa_info_hash.qwords, tee_info_hash.qwords, SIZE_OF_SHA384_HASH_IN_QWORDS))
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
    }

    return TDX_SUCCESS;
}

api_error_type tdg_spdm_binding_prologue(
    const iommu_id_reg_t iommu_id_reg,
    const uint64_t spdm_id,
    const spdm_session_state_t expected_spdm_state,
    const pa_t binding_info_gpa,
    const mapping_type_t binding_info_mapping_type,
    spdm_info_t **spdm_info_ptr,
    spdmdir_entry_t **spdmdir_entry_ptr,
    void **binding_info_ptr)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    iommu_config_t *iommu_config_ptr = NULL;
    bool_t is_iommu_locked = false;
    tdcs_t *tdcs_ptr = NULL;

    return_val = is_valid_tpa_td();
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Verify spdm_id operand
    if (spdm_id >= MAX_SPDM_SESSION_ID)
    {
        TDX_ERROR("SPDM id (=%u) is greater than max SPDM sessions (%u)\n", spdm_id, MAX_SPDM_SESSION_ID);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    tdx_module_local_t *local_data_ptr = get_local_data();
    tdcs_ptr = local_data_ptr->vp_ctx.tdcs;

    // Check and translate binding info GPA. Must be private page
    if (!(is_addr_aligned_pwr_of_2(binding_info_gpa.raw, TDX_PAGE_SIZE_IN_BYTES) &&
          is_pa_smaller_than_max_pa(binding_info_gpa.raw)))
    {
        TDX_ERROR("Invalid binding_info_gpa = 0x%llx\n", binding_info_gpa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Translation may implicitly mutate into a TD exit or throw a #VE on EPT violation/misconfiguration
    return_val = check_walk_and_map_guest_side_gpa(
        tdcs_ptr,
        local_data_ptr->vp_ctx.tdvps,
        binding_info_gpa,
        local_data_ptr->vp_ctx.tdr->key_management_fields.hkid,
        binding_info_mapping_type,
        PRIVATE_ONLY,
        binding_info_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to walk and map binding info (binding_info_gpa = 0x%llx)\n", binding_info_gpa);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_R8);
        goto EXIT;
    }

    return_val = tdg_check_iommu_config(
        iommu_id_reg.raw,
        OPERAND_ID_RCX,
        &iommu_config_ptr,
        &is_iommu_locked);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    return_val = lock_check_and_map_spdm_metadata(
        spdm_id,
        OPERAND_ID_RDX,
        iommu_config_ptr,
        expected_spdm_state,
        spdm_info_ptr,
        spdmdir_entry_ptr);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:

    release_iommu_lock(is_iommu_locked, iommu_config_ptr);

    return return_val;
}
