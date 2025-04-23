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
 * @file tdh_sys_shutdown
 * @brief TDH_SYS_SHUTDOWN API handler
 */

#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"

#include "data_structures/tdx_global_data.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"

api_error_type tdh_sys_shutdown(uint64_t hv_input)
{
    // Global data
    tdx_module_global_t* global_data = get_global_data();
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();

    uint16_t handoff_version;
    bool_t global_locked_flag = false;
    api_error_type ret_val = TDX_OPERAND_INVALID;

    // Verify that request HV is supported
    if ((hv_input < (uint64_t)global_data->min_update_hv) ||
        (hv_input > (uint64_t)global_data->module_hv) ||
        (global_data->no_downgrade && (hv_input != (uint64_t)global_data->module_hv)))
    {
        ret_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    handoff_version = (uint16_t)hv_input;   // Cast down is safe after the above checks

    // Acquire an exclusive lock to the whole TDX-SEAM module
    if (acquire_sharex_lock_ex(&global_data->global_lock) != LOCK_RET_SUCCESS)
    {
        ret_val = TDX_SYS_BUSY;
        goto EXIT;
    }
    global_locked_flag = true;

    // This is checked by the VMM dispatcher
    tdx_sanity_check(global_data->global_state.sys_state == SYS_READY, SCEC_SEAMCALL_SOURCE(TDH_SYS_SHUTDOWN_LEAF), 0);

    // Mark the TDX-SEAM module as being shut down
    global_data->global_state.sys_state = SYS_SHUTDOWN;

    // Serialize global system state setup
    mfence();

    // Verify that no other LP is "busy"
    uint32_t num_busy = 0;

    for (uint64_t lp_num = 0; lp_num < get_num_addressable_lps(sysinfo_table); lp_num++)
    {
        if (get_other_lp_local_data(global_data, sysinfo_table, lp_num)->lp_is_busy)
        {
            num_busy++;
        }
    }

    tdx_sanity_check(num_busy > 0, SCEC_SEAMCALL_SOURCE(TDH_SYS_SHUTDOWN_LEAF), 1);

    if (num_busy > 1) // another LP is in SEAM mode
    {
        global_data->global_state.sys_state = SYS_READY;
        ret_val = TDX_SYS_BUSY;
        goto EXIT;
    }

    uint32_t buff_size = (global_data->num_handoff_pages + 1) * TDX_PAGE_SIZE_IN_BYTES
                         - sizeof(handoff_data_header_t);

    handoff_data_header_t* handoff_data_hdr = (handoff_data_header_t*)sysinfo_table->data_rgn_base;
    uint8_t* handoff_data_bytes = (uint8_t*)(sysinfo_table->data_rgn_base + sizeof(handoff_data_header_t));

    uint32_t size = prepare_handoff_data(handoff_version, buff_size, handoff_data_bytes);

    tdx_sanity_check((size > 0) && (size <= buff_size), SCEC_SEAMCALL_SOURCE(TDH_SYS_SHUTDOWN_LEAF), 1);

    handoff_data_hdr->valid = true;
    handoff_data_hdr->hv    = handoff_version;
    handoff_data_hdr->size  = size;

    ret_val = TDX_SUCCESS;

EXIT:
    // Release all locks
    if (global_locked_flag)
    {
        release_sharex_lock_ex(&global_data->global_lock);
    }

    return ret_val;
}
