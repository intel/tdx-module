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
 * @file tdh_mr_finalize
 * @brief TDHMRFINALIZE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "crypto/sha384.h"

typedef struct PACKED servtd_hash_buff_s
{
    measurement_t       info_hash;
    uint16_t            type;
    servtd_attributes_t attrib;
} servtd_hash_buff_t;
tdx_static_assert(sizeof(servtd_hash_buff_t) == 58, servtd_hash_buff_t);


/* Prepare the temporary buffer for SERVTD_HASH calculation.
   1. Get all service TD binding slots whose SERVTD_BINDING_STATE is not NOT_BOUND.
      If no service TD binding slots apply, return 0.
   2. Sort in ascending order by SERVTD_TYPE as the primary key, SERVTD_INFO_HASH a
      s a secondary key (if multiple service TDs of the same type are bound).
   3. Copy SERVTD_INFO_HASH, SERVTD_TYPE and SERVTD_ATTR of each slot into a
      servtd_has_buff entry.
   4. Return the actual number of entries.
*/
static uint32_t prepare_servtd_hash_buff(tdcs_t *tdcs_ptr, servtd_hash_buff_t *servtd_has_buf)
{
    uint32_t num_tds = 0;

    tdx_debug_assert(MAX_SERVTDS <= 1);
    // TODO: add sorting for the array when the MAX_SERVTDS is greater than 1

    for (int i = 0; i < MAX_SERVTDS; i++)
    {
        if (tdcs_ptr->service_td_fields.servtd_bindings_table[i].state != SERVTD_NOT_BOUND)
        {
            tdx_memcpy(servtd_has_buf[num_tds].info_hash.qwords, sizeof(measurement_t),
                       tdcs_ptr->service_td_fields.servtd_bindings_table[i].info_hash.qwords, sizeof(measurement_t));

            servtd_has_buf[num_tds].type = tdcs_ptr->service_td_fields.servtd_bindings_table[i].type;
            servtd_has_buf[num_tds].attrib.raw = tdcs_ptr->service_td_fields.servtd_bindings_table[i].attributes.raw;
            num_tds++;
        }
    }
    return num_tds;
}

api_error_type tdh_mr_finalize(uint64_t target_tdr_pa)
{
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    uint128_t             xmms[16];                  // SSE state backup for crypto
    crypto_api_error      sha_error_code;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_NO_LOCK,
                                               false, TDH_MR_FINALIZE_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // The TD must have at least one VCPU
    if (tdcs_ptr->management_fields.num_vcpus == 0)
    {
        TDX_ERROR("No VCPU's\n");
        return_val = TDX_NO_VCPUS;
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The instruction is guaranteed to succeed

    /**
     *  Calculate finalized version of MRTD.
     *  SHA384 algorithm requires one last update that compresses the length (in bits)
     *  of the hashed message into the output SHA384 digest.
     */

    store_xmms_in_buffer(xmms);

    if ((sha_error_code = sha384_finalize(&(tdcs_ptr->measurement_fields.td_sha_ctx),
                                            tdcs_ptr->measurement_fields.mr_td.qwords)) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        FATAL_ERROR();
    }

    /* Calculate SERVTD_HASH
    */
    servtd_hash_buff_t  servtd_hash_buff[MAX_SERVTDS];
    uint32_t num_servtds = prepare_servtd_hash_buff(tdcs_ptr, servtd_hash_buff);

    if (num_servtds == 0)
    {
        basic_memset_to_zero(tdcs_ptr->service_td_fields.servtd_hash.bytes, sizeof(measurement_t));
    }
    else
    {
        sha_error_code = sha384_generate_hash((uint8_t*)servtd_hash_buff, (num_servtds * sizeof(servtd_hash_buff_t)),
                                              tdcs_ptr->service_td_fields.servtd_hash.qwords);
        if (sha_error_code != 0)
        {
            // Unexpected error - Fatal Error
            TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
            FATAL_ERROR();
        }
    }

    load_xmms_from_buffer(xmms);
    basic_memset_to_zero(xmms, sizeof(xmms));

    tdcs_ptr->management_fields.op_state = OP_STATE_RUNNABLE;


EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    return return_val;
}
