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
 * @file tdh_servtd_prebind.c
 * @brief TDHSERVTDPREBIND API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "helpers/helpers.h"
#include "helpers/service_td.h"
#include "helpers/tdx_locks.h"

api_error_type tdh_servtd_prebind(uint64_t target_tdr_pa, uint64_t servtd_info_hash, uint64_t servtd_slot,
        uint64_t servtd_type_raw, servtd_attributes_t servtd_attr)
{
    // TDR and TDCS
    tdr_t             *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t               tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t       tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t      *tdr_pamt_entry_ptr = NULL;
    tdcs_t            *tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t             tdr_locked_flag = false;

    bool_t             op_state_locked_flag = false; // Indicate OP is locked

    // Crypto data
    pa_t               servtd_info_hash_pa = {.raw = servtd_info_hash};
    void              *servtd_info_hash_p = NULL;
    bool_t             servtd_bindings_locked_flag = false;

    uint16_t           servtd_type;

    api_error_type     return_val = TDX_OPERAND_INVALID;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;


    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_SHARED, false,
                                            TDH_SERVTD_PREBIND_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    /*
     * Verify the service TD hash physical address is canonical, shared, and aligned to 64B, and map it.
     */
    return_val = shared_hpa_check_with_pwr_2_alignment(servtd_info_hash_pa, 64);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }
    servtd_info_hash_p = map_pa(servtd_info_hash_pa.raw_void, TDX_RANGE_RO);

    if (servtd_slot >= MAX_SERVTDS)
    {
       return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
       goto EXIT;
    }
    if (servtd_type_raw > 0xFFFF) // 16-bits field
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }
    servtd_type = (uint16_t)servtd_type_raw;
    if (!is_servtd_supported(servtd_type))
    {
       return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
       goto EXIT;
    }
    if (!servtd_is_attrib_valid(&servtd_attr))
    {
       return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
       goto EXIT;
    }

    if ((return_val = acquire_sharex_lock_hp(&tdcs_p->service_td_fields.servtd_bindings_lock,
                                            TDX_LOCK_EXCLUSIVE, false)) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_SERVTD_BINDINGS);
        goto EXIT;
    }
    servtd_bindings_locked_flag = true;

#if (MAX_SERVTDS > 1)
    if (is_servtd_singleton(servtd_type))
    {
        // Only a single TD of this type may be bound
        for (uint32_t i = 0; i < MAX_SERVTDS; i++)
        {
            if ((tdcs_p->service_td_fields.servtd_binding_state[i] != SERVTD_NOT_BOUND) &&
                (tdcs_p->service_td_fields.servtd_type[i] == servtd_type))
            {
                return_val = TDX_SERVTD_ALREADY_BOUND_FOR_TYPE;
                goto EXIT;
            }
        }
    }
#endif

    if (tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state == SERVTD_BOUND)
    {
        return_val = TDX_SERVTD_BOUND;
        goto EXIT;
    }

    if (tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state == SERVTD_NOT_BOUND)
    {
        tdcs_p->service_td_fields.servtd_num++;
    }

    tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].type = servtd_type;
    tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].attributes = servtd_attr;
    tdx_memcpy(&tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].info_hash,
               sizeof(tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].info_hash),
               servtd_info_hash_p, sizeof(measurement_t));
    tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state = SERVTD_PRE_BOUND;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (servtd_bindings_locked_flag)
    {
        release_sharex_lock_hp(&tdcs_p->service_td_fields.servtd_bindings_lock, TDX_LOCK_EXCLUSIVE);
    }

    if (servtd_info_hash_p != NULL)
    {
        free_la(servtd_info_hash_p);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp_sh(&(tdcs_p->management_fields.op_state_lock));
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_p);
    }
    return return_val;
}
