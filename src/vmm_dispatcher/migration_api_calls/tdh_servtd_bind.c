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
 * @file tdh_servtd_bind.c
 * @brief TDHSERVTDBIND API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "helpers/helpers.h"
#include "helpers/service_td.h"
#include "helpers/tdx_locks.h"

api_error_type tdh_servtd_bind(uint64_t target_tdr_pa, uint64_t servtd_tdr, uint64_t servtd_slot,
        uint64_t servtd_type_raw, servtd_attributes_t servtd_attr)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();

    // TDR and TDCS
    tdr_t             *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t               tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t       tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t      *tdr_pamt_entry_ptr = NULL;
    tdcs_t            *tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t             tdr_locked_flag = false;

    bool_t             op_state_locked_flag = false; // Indicate OP is locked

    // SRVICE TD TDR
    tdr_t             *servtd_tdr_p = NULL;         // Pointer to the Service-TD TDR page
    pa_t               servtd_tdr_pa;               // Physical address of the Service-TD TDR page
    pamt_block_t       servtd_tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t      *servtd_tdr_pamt_entry_ptr = NULL;
    tdcs_t            *servtd_tdcs_p = NULL;        // Pointer to the Service-TD TDCS structure
    bool_t             servtd_tdr_locked_flag = false;

    bool_t             servtd_op_state_locked_flag = false; // Indicate OP is locked

    ALIGN(64) measurement_t  servtd_info_hash = { 0 };       // SHA384 hash over Service TD's TDINFO
    bool_t             servtd_bindings_locked_flag = false;

    uint16_t           servtd_type;

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Default output values
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.r10 = 0ULL;
    local_data_ptr->vmm_regs.r11 = 0ULL;
    local_data_ptr->vmm_regs.r12 = 0ULL;
    local_data_ptr->vmm_regs.r13 = 0ULL;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;
    servtd_tdr_pa.raw = servtd_tdr;

    // Check that the service TD is not the same as the target TD
    if (servtd_tdr_pa.raw == tdr_pa.raw)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

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
                                                TDH_SERVTD_BIND_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(servtd_tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &servtd_tdr_pamt_block,
                                                 &servtd_tdr_pamt_entry_ptr,
                                                 &servtd_tdr_locked_flag,
                                                 &servtd_tdr_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = othertd_check_state_map_tdcs_and_lock(servtd_tdr_p, TDX_RANGE_RW, TDX_LOCK_SHARED, false,
                                                       TDH_SERVTD_BIND_LEAF, false, &servtd_tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    servtd_op_state_locked_flag = true;

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

    // Calculate the service TD's TDINFO_HASH
    if ((return_val = get_teeinfohash(servtd_tdcs_p, servtd_attr.ignore_tdinfo,
                           &servtd_info_hash)) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RTMR);
        goto EXIT;
    }

    switch (tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state)
    {
    // Initial Binding
    case SERVTD_NOT_BOUND:
        if ((tdcs_p->management_fields.op_state != OP_STATE_UNINITIALIZED) &&
            (tdcs_p->management_fields.op_state != OP_STATE_INITIALIZED))
        {
            return_val = TDX_OP_STATE_INCORRECT;
            goto EXIT;
        }
        tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].type = servtd_type;
        tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].attributes = servtd_attr;
        tdx_memcpy(tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].info_hash.qwords, sizeof(measurement_t),
                   servtd_info_hash.qwords, sizeof(servtd_info_hash));
        tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].uuid = servtd_tdr_p->management_fields.td_uuid;
        tdcs_p->service_td_fields.servtd_num++;
        break;

    // Late Initial Binding
    case SERVTD_PRE_BOUND:
        if (tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].type != servtd_type)
        {
            return_val = TDX_SERVTD_TYPE_MISMATCH;
            goto EXIT;
        }
        if (tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].attributes.raw != servtd_attr.raw)
        {
            return_val = TDX_SERVTD_ATTR_MISMATCH;
            goto EXIT;
        }
        if (!tdx_memcmp(tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].info_hash.qwords,
                        servtd_info_hash.qwords, sizeof(servtd_info_hash)))
        {
            return_val = TDX_SERVTD_INFO_HASH_MISMATCH;
            goto EXIT;
        }
        tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].uuid = servtd_tdr_p->management_fields.td_uuid;
        break;

    // Rebinding
    case SERVTD_BOUND:
        if (tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].type != servtd_type)
        {
            return_val = TDX_SERVTD_TYPE_MISMATCH;
            goto EXIT;
        }
        if (tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].attributes.raw != servtd_attr.raw)
        {
            return_val = TDX_SERVTD_ATTR_MISMATCH;
            goto EXIT;
        }

        if (!tdx_memcmp(tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].info_hash.qwords,
                        servtd_info_hash.qwords, sizeof(servtd_info_hash)))
        {
            return_val = TDX_SERVTD_INFO_HASH_MISMATCH;
            goto EXIT;
        }
        tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].uuid = servtd_tdr_p->management_fields.td_uuid;

        break;
    default:
        FATAL_ERROR();
    }

    tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state = SERVTD_BOUND;

    // Write the output operands
    servtd_binding_handle_t servtd_binding_handle =
            create_servtd_binding_handle( tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].uuid,
                                          tdr_pa, servtd_slot);

    local_data_ptr->vmm_regs.rcx = servtd_binding_handle.raw;
    local_data_ptr->vmm_regs.r10 = tdr_p->management_fields.td_uuid.qwords[0];
    local_data_ptr->vmm_regs.r11 = tdr_p->management_fields.td_uuid.qwords[1];
    local_data_ptr->vmm_regs.r12 = tdr_p->management_fields.td_uuid.qwords[2];
    local_data_ptr->vmm_regs.r13 = tdr_p->management_fields.td_uuid.qwords[3];

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (servtd_bindings_locked_flag)
    {
        release_sharex_lock_hp(&tdcs_p->service_td_fields.servtd_bindings_lock, TDX_LOCK_EXCLUSIVE);
    }

    if (servtd_op_state_locked_flag)
    {
        release_sharex_lock_hp_sh(&(servtd_tdcs_p->management_fields.op_state_lock));
    }

    if (servtd_tdr_locked_flag)
    {
        pamt_unwalk(servtd_tdr_pa, servtd_tdr_pamt_block, servtd_tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(servtd_tdr_p);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp_sh(&(tdcs_p->management_fields.op_state_lock));
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (servtd_tdcs_p != NULL)
    {
        free_la(servtd_tdcs_p);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_p);
    }

    return return_val;
}
