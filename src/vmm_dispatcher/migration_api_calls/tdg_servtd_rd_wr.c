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
 * @file tdg_servd_rd_wr.c
 * @brief TDGSERVTDRDWR API handler
 */

#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "x86_defs/x86_defs.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"
#include "common/metadata_handlers/metadata_generic.h"
#include "td_transitions/td_exit.h"

_STATIC_INLINE_ bool_t is_operand_busy_error_code(api_error_type error)
{
    if (HIGH_32BITS(error) == HIGH_32BITS(TDX_OPERAND_BUSY))
    {
        return true;
    }

    return false;
}

static api_error_type tdg_servtd_rd_wr(servtd_binding_handle_t binding_handle, md_field_id_t field_id,
                                       bool_t write, uint64_t wr_value, uint64_t wr_request_mask)
{
    tdx_module_local_t* lp = get_local_data();

    tdr_t               * target_tdr_ptr = NULL;            // Pointer to the TDR page (linear address)
    pamt_block_t          target_tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * target_tdr_pamt_entry_ptr = NULL; // Pointer to the TDR PAMT entry
    bool_t                target_tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * target_tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    bool_t                target_bindings_locked_flag = false;

    uint256_t             target_uuid;
    pa_t                  target_tdr_pa;
    uint64_t              target_slot;
    ALIGN(64) measurement_t tdinfo_hash = { 0 };

    md_access_t           access_type = write ? MD_SERV_TD_WR : MD_SERV_TD_RD;
    md_context_ptrs_t     md_ctx;
    md_access_qualifier_t access_qual = { .raw = 0 };
    uint64_t              rd_value;           // Data read from field

    api_error_type        return_val = TDX_SUCCESS;
    api_error_type        cross_td_trap_status = TDX_SUCCESS;

    target_uuid.qwords[0] = lp->vp_ctx.tdvps->guest_state.gpr_state.r10;
    target_uuid.qwords[1] = lp->vp_ctx.tdvps->guest_state.gpr_state.r11;
    target_uuid.qwords[2] = lp->vp_ctx.tdvps->guest_state.gpr_state.r12;
    target_uuid.qwords[3] = lp->vp_ctx.tdvps->guest_state.gpr_state.r13;

    // Default output register operands
    if (!write)
    {
        lp->vp_ctx.tdvps->guest_state.gpr_state.rdx = MD_FIELD_ID_NA;
    }
    lp->vp_ctx.tdvps->guest_state.gpr_state.r8 = 0;

    break_servtd_binding_handle(binding_handle, lp->vp_ctx.tdr->management_fields.td_uuid,
                                &target_tdr_pa, &target_slot);

    if (target_slot >= MAX_SERV_TDS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Target slot %d is greater or equal than MAX_SERVTDS\n", target_slot);
        goto EXIT;
    }

    // Process the target TD's control structures and check state
    return_val = othertd_check_lock_and_map_explicit_tdr(target_tdr_pa,
                                                 OPERAND_ID_TDR,
                                                 write ? TDX_RANGE_RW : TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &target_tdr_pamt_block,
                                                 &target_tdr_pamt_entry_ptr,
                                                 &target_tdr_locked_flag,
                                                 &target_tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        if (is_operand_busy_error_code(return_val))
        {
            TDX_ERROR("Failed to check/lock/map a Target TDR - error = %llx\n", return_val);
            goto EXIT;
        }
        else
        {
            cross_td_trap_status = return_val;
            goto EXIT;
        }
    }

    // Map the TDCS structure and check the state
    return_val = othertd_check_state_map_tdcs_and_lock(target_tdr_ptr,
                                                       TDX_RANGE_RW, TDX_LOCK_SHARED, true,
                                                       write ? TDG_SERVTD_WR_LEAF : TDG_SERVTD_RD_LEAF, true, &target_tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        if (is_operand_busy_error_code(return_val))
        {
            TDX_ERROR("State check or Target TDCS lock failure - error = %llx\n", return_val);
            goto EXIT;
        }
        else
        {
            cross_td_trap_status = return_val;
            goto EXIT;
        }
    }

     if (!is_equal_256bit(target_tdr_ptr->management_fields.td_uuid, target_uuid))
     {
         if (is_equal_256bit(target_tdcs_ptr->migration_fields.preimport_uuid, target_uuid))
         {
             // This is the case where the binding happened before import
             lp->vp_ctx.tdvps->guest_state.gpr_state.r10 = target_tdr_ptr->management_fields.td_uuid.qwords[0];
             lp->vp_ctx.tdvps->guest_state.gpr_state.r11 = target_tdr_ptr->management_fields.td_uuid.qwords[1];
             lp->vp_ctx.tdvps->guest_state.gpr_state.r12 = target_tdr_ptr->management_fields.td_uuid.qwords[2];
             lp->vp_ctx.tdvps->guest_state.gpr_state.r13 = target_tdr_ptr->management_fields.td_uuid.qwords[3];

             return_val = TDX_TARGET_UUID_UPDATED;
             TDX_ERROR("Binding happened before import!\n");
             goto EXIT;
         }
         else
         {
             return_val = TDX_TARGET_UUID_MISMATCH;
             TDX_ERROR("UUID mismatch!\n");
             goto EXIT;
         }
     }

     // Lock the target TD's service TDs table in shared mode.
     // Note that this is a host-priority lock.
     if ((return_val = acquire_sharex_lock_hp(&(target_tdcs_ptr->service_td_fields.servtd_bindings_lock),
                                             TDX_LOCK_SHARED, true)) != TDX_SUCCESS)
     {
         return_val = api_error_with_operand_id(return_val, OPERAND_ID_SERVTD_BINDINGS);
         TDX_ERROR("SERVTD Bindings lock is busy\n");
         goto EXIT;
     }
     target_bindings_locked_flag = true;

     if (target_tdcs_ptr->service_td_fields.servtd_bindings_table[target_slot].state != SERVTD_BOUND)
     {
         cross_td_trap_status = api_error_with_operand_id(TDX_SERVTD_NOT_BOUND, target_slot);
         goto EXIT;
     }

     if (!is_equal_256bit(target_tdcs_ptr->service_td_fields.servtd_bindings_table[target_slot].uuid,
                          lp->vp_ctx.tdr->management_fields.td_uuid))
     {
         cross_td_trap_status = TDX_SERVTD_UUID_MISMATCH;
         goto EXIT;
     }

     // Calculate the service TD's TDINFO_HASH
     if ((return_val = get_tdinfo_and_teeinfohash(lp->vp_ctx.tdcs,
             target_tdcs_ptr->service_td_fields.servtd_bindings_table[target_slot].attributes.ignore_tdinfo,
             NULL, &tdinfo_hash, true)) != TDX_SUCCESS)
     {
         return_val = api_error_with_operand_id(return_val, OPERAND_ID_RTMR);
         goto EXIT;
     }

     // Regular memcmp is used, because this is not a secret
     if (!tdx_memcmp(&target_tdcs_ptr->service_td_fields.servtd_bindings_table[target_slot].info_hash,
                     &tdinfo_hash, sizeof(tdinfo_hash)))
     {
         cross_td_trap_status = TDX_SERVTD_INFO_HASH_MISMATCH;
         goto EXIT;
     }

     /*------------------------------------------------------
        Binding checks done, access the target TD metadata
     ------------------------------------------------------*/

     md_ctx.tdr_ptr = target_tdr_ptr;
     md_ctx.tdcs_ptr = target_tdcs_ptr;
     md_ctx.tdvps_ptr = NULL;
     
     field_id.context_code = MD_CTX_TD;

     access_qual.serv_td_qualifier.service_td_type =
             target_tdcs_ptr->service_td_fields.servtd_bindings_table[target_slot].type;

     if (!write)
     {
         // For read, a null field ID means return the first field ID in context readable by the Service TD
         if (is_null_field_id(field_id))
         {
             lp->vp_ctx.tdvps->guest_state.gpr_state.rdx = (md_get_next_element_in_context(field_id.context_code, field_id, md_ctx, access_type, access_qual)).raw;

             return_val = TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT;
             goto EXIT;
         }
     }

     return_val = md_check_as_single_element_id(field_id);

     if (return_val != TDX_SUCCESS)
     {
         TDX_ERROR("Request field id doesn't match single element = %llx\n", field_id.raw);
         goto EXIT;
     }

     if (write)
     {
         return_val = md_write_element(MD_CTX_TD, field_id, access_type, access_qual,
                                       md_ctx, wr_value, wr_request_mask, &rd_value);
     }
     else
     {
         return_val = md_read_element(MD_CTX_TD, field_id, access_type, access_qual,
                                      md_ctx, &rd_value);

         if (return_val == TDX_SUCCESS)
         {
             // Get the next field id if no error or if the current field id in null
             lp->vp_ctx.tdvps->guest_state.gpr_state.rdx =
                     md_get_next_element_in_context(MD_CTX_TD, field_id, md_ctx, access_type, access_qual).raw;
         }
     }

     if (return_val != TDX_SUCCESS)
     {
         TDX_ERROR("Failed to Read or Write data to a TDCS field - error = %llx\n", return_val);
         goto EXIT;
     }

     lp->vp_ctx.tdvps->guest_state.gpr_state.r8 = rd_value;

     return_val = TDX_SUCCESS;

EXIT:

    if (target_bindings_locked_flag)
    {
        release_sharex_lock_hp(&(target_tdcs_ptr->service_td_fields.servtd_bindings_lock), TDX_LOCK_SHARED);
    }

    if (target_tdcs_ptr != NULL)
    {
        release_sharex_lock_hp(&(target_tdcs_ptr->management_fields.op_state_lock), TDX_LOCK_SHARED);
        free_la(target_tdcs_ptr);
    }

    if (target_tdr_locked_flag)
    {
        pamt_unwalk(target_tdr_pa, target_tdr_pamt_block, target_tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(target_tdr_ptr);
    }

    IF_RARE (cross_td_trap_status != TDX_SUCCESS)
    {
        async_tdexit_cross_td(TDX_CROSS_TD_TRAP, cross_td_trap_status, target_tdr_pa);
    }

    return return_val;
}

api_error_type tdg_servtd_wr(uint64_t req_binding_handle, uint64_t requested_field_code,
                             uint64_t wr_data, uint64_t wr_mask)
{
    md_field_id_t           field_code = { .raw = requested_field_code };
    servtd_binding_handle_t binding_handle = { .raw = req_binding_handle };

    return tdg_servtd_rd_wr(binding_handle, field_code, true, wr_data, wr_mask);
}

api_error_type tdg_servtd_rd(uint64_t req_binding_handle, uint64_t requested_field_code)
{
    md_field_id_t           field_code = { .raw = requested_field_code };
    servtd_binding_handle_t binding_handle = { .raw = req_binding_handle };

    return tdg_servtd_rd_wr(binding_handle, field_code, false, 0, 0);
}
