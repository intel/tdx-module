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
 * @file tdh_mem_scan_reset
 * @brief TDH_MEM_SCAN_RESET API handler
 */


#include "tdx_vmm_api_handlers.h"
#include "helpers/migration.h"
#include "helpers/mem_scan.h"
#include "helpers/helpers.h"

api_error_type tdh_mem_scan_reset(uint64_t tdr)
{
    // TDH.MEM.SCAN.RESET is supported if TDH.MEM.SCAN.COMP is supported
    if (!(is_non_blocking_export_configured()
        || is_scan_export_restore_supported()
        ))
    {
        TDX_ERROR("TDH.MEM.SCAN.RESET is supported if Non-Blocking Export is configured. non_blocking_export = %d, scan_export_restore = %d\n",
                  is_non_blocking_export_configured(), is_scan_export_restore_supported());
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
    }

    pa_t tdr_hpa = { .raw = tdr };

    // TDR, contexts and TDCS
    pamt_walk_result_t tdr_pamt_walk_result;
    bool_t tdr_locked_flag = false;
    tdr_t* tdr_p = NULL;
    tdcs_t* tdcs_p = NULL;
    bool_t op_state_locked_flag = false;

    // control structures

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_hpa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_walk_result,
                                                 &tdr_locked_flag,
                                                 &tdr_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_p,
                                               TDX_RANGE_RW,
                                               TDX_LOCK_SHARED,
                                               false,
                                               TDH_MEM_SCAN_RESET_LEAF,
                                               &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

	return_val = mem_scan_reset(tdcs_p, false);
	if (return_val != TDX_SUCCESS)
	{
		TDX_ERROR("Failed to reset mem scan - error = %llx\n", return_val);
        goto EXIT;
    }

EXIT:
    // Release all acquired locks
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
        pamt_unwalk(&tdr_pamt_walk_result);
        free_la(tdr_p);
    }

    return return_val;
}
