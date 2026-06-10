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
 * @file migration.c
 * @brief TDX migration implementation file
 */

#include "helpers/migration.h"
#include "x86_defs/x86_defs.h"
#include SEPT_STATE_LOOKUP_HEADER
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/sept_manager.h"
#include TDX_ERROR_CODES_DEFS_HEADER
#include "helpers/helpers.h"


/**
 * migsc_init
 * Initialize the migration stream context and the crypto encryption context
 * @param migsc - migration stream context
 * @param key - encryption key
 */
void migsc_init(migsc_t *migsc, const key256_t *key)
{
    migsc->iv_counter = 0ull;
    migsc->next_mb_counter = 0ull;
    migsc->expected_mb_counter = 0ull;
    migsc->interrupted_state.valid = false;

    migs_iv_t iv;
    // The IV value below is only an initial value. Real value can be overwritten by calling 'aes_gcm_reset'
    // and passing the actual IV to it
    iv.iv_counter = 1ull;
    iv.migs_index = 0u; // TODO - TBD
    iv.reserved = 0;

    if (aes_gcm_init(key, &migsc->aes_gcm_context, &iv) != AES_GCM_NO_ERROR)
    {
        fatal_error(FATAL_ERROR_ID_43, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
    }
}

api_error_type check_and_map_gpa_list(gpa_list_info_t gpa_list_info, gpa_list_entry_t** gpa_list_p)
{
    pa_t               gpa_list_pa;
    api_error_type     return_val;

    if (!((gpa_list_info.reserved_0 == 0) && (gpa_list_info.first_entry <= gpa_list_info.last_entry) &&
        ((gpa_list_info.format == GPA_LIST_FORMAT_GPA_ONLY)
            || (gpa_list_info.format == GPA_LIST_FORMAT_GPA_AND_ATTR)
         )))
    {
        return TDX_OPERAND_INVALID;
    }

    gpa_list_pa.raw = 0;
    gpa_list_pa.page_4k_num = gpa_list_info.hpa;

    // Verify the GPA list physical address is canonical, shared, and aligned to 4KB
    return_val = shared_hpa_check_with_pwr_2_alignment(gpa_list_pa, _4KB);
    if (return_val != TDX_SUCCESS)
    {
        return return_val;
    }

    // Map the page list
    *gpa_list_p = (gpa_list_entry_t*)map_pa(gpa_list_pa.raw_void, TDX_RANGE_RW);

    return TDX_SUCCESS;
}

bool_t check_and_get_gpa_from_entry(gpa_list_entry_t gpa_entry, bool_t gpaw, pa_t* output_gpa, uint8_t virt_maxpa)
{
    pa_t gpa = { .raw = 0 };
    gpa.page_4k_num = gpa_entry.gpa;

    if (!gpa_list_entry_is_valid(gpa_entry) || !check_gpa_validity(gpa, gpaw, PRIVATE_ONLY, virt_maxpa))
    {
        return false;
    }

    *output_gpa = gpa;

    return true;
}

void copy_mbmd(mbmd_t* mbmd_dst, mbmd_t* mbmd_src)
{
    tdx_memcpy(mbmd_dst, sizeof(mbmd_t), mbmd_src, sizeof(mbmd_t));
}

void decrement_mig_interrupted_counters(uint16_t* mig_interrupted_count, migsc_t* migsc_p, bool_t decrement_interrupted_count)

{
    /* Check the following to avoid an underflow:
       - The interrupted flow was executed on a TDX module which supported MIG_INTERRUPTED_COUNT.
       - The interrupted flow indeed incremented MIG_INTERRUPTED_COUNT, as indicated by AES_GCM_CONTEXT_VERSION > 0. */
    if (decrement_interrupted_count && (migsc_p->interrupted_state.aes_gcm_context_version > 0))
    {
        uint16_t old_val = _lock_xadd_16b(&get_global_data()->mig_interrupted_count, (uint16_t)-1);
        tdx_sanity_check(old_val > 0, FATAL_ERROR_ID_362, 0);
        old_val = _lock_xadd_16b(mig_interrupted_count, (uint16_t)-1);
        tdx_sanity_check(old_val > 0, FATAL_ERROR_ID_363, 0);
    }
}

api_error_type check_migsc_aes_gcm_context_compatibility_on_export_resume(migsc_t* migsc_p, uint16_t migs_index)
{
    if(migsc_p->interrupted_state.aes_gcm_context_version != CRYPTO_LIB_COMPAT_VERSION)
    {
        if(get_global_data()->update_compatibility)
        {
            return TDX_INCOMPATIBLE_MBMD_MAC_CONTEXT;
        }
        else
        {
            /* The host VMM did not opt-in to receive an error on update compatibility mismatch.  Reset the crypto library context using the new IV
               counter and continue the export session.  This will cause an incorrect MAC to be calculated, and eventually will fail on import with
               a TDX_INCORRECT_MBMD_MAC error. */
            reset_to_next_iv(migsc_p, migsc_p->iv_counter, migs_index);

            mbmd_immutable_td_state_t dummy_mbmd = { 0 };
            if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (uint8_t*)&dummy_mbmd, MBMD_SIZE_NO_MAC(dummy_mbmd)) != AES_GCM_NO_ERROR)
            {
                fatal_error(FATAL_ERROR_ID_370, FATAL_INFO_FORMAT_BASIC_INFO, NULL);
            }
            
            migsc_p->iv_counter++;
        }
    }

    return TDX_SUCCESS;
}

api_error_type check_migsc_aes_gcm_context_compatibility_on_import_resume(migsc_t* migsc_p)
{
    if(migsc_p->interrupted_state.aes_gcm_context_version != CRYPTO_LIB_COMPAT_VERSION)
    {
        if(get_global_data()->update_compatibility)
        {
            return TDX_INCOMPATIBLE_MBMD_MAC_CONTEXT;
        }
        else
        {
            return TDX_INCORRECT_MBMD_MAC;
        }
    }

    return TDX_SUCCESS;
}

