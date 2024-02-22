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
 * @file tdh_sys_key_config.c
 * @brief TDHSYSKEYCONFIG API handler
 */
#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/mktme.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"

api_error_type tdh_sys_key_config(void)
{
    bool_t tmp_global_lock_acquired = false;
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    api_error_type retval = TDX_SYS_BUSY;

    if (acquire_sharex_lock_ex(&tdx_global_data_ptr->global_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire global lock for LP\n");
        retval = TDX_SYS_BUSY;
        goto EXIT;
    }
    tmp_global_lock_acquired = true;

    // Verify that TDHSYSCONFIG has completed successfully (PL.SYS_STATE is SYSCONFIG_DONE)
    if (tdx_global_data_ptr->global_state.sys_state != SYSCONFIG_DONE)
    {
        TDX_ERROR("Wrong sys_init state: %d\n", tdx_global_data_ptr->global_state.sys_state);
        {
            retval = TDX_SYS_KEY_CONFIG_NOT_PENDING;
            goto EXIT;
        }
    }

    // Use an atomic operation (e.g., LOCK BTS) on PL.PKG_CONFIG_BITMAP to verify
    // the package has not been configured and mark it as configured.
    if (_lock_bts_32b(&tdx_global_data_ptr->pkg_config_bitmap, tdx_local_data_ptr->lp_info.pkg))
    {
        TDX_ERROR("Package %d already configured its key\n", tdx_local_data_ptr->lp_info.pkg);
        retval = TDX_KEY_CONFIGURED;
        goto EXIT;
    }

    // Execute PCONFIG to configure the TDX-SEAM global private HKID on the package, with a CPU-generated random key.
    // PCONFIG may fail due to and entropy error or a device busy error.
    // In this case, the VMM should retry TDHSYSKEYCONFIG.
    retval = program_mktme_keys(tdx_global_data_ptr->hkid);
    if (retval != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to program MKTME keys for this package\n");
        // Clear the package configured bit
        _lock_btr_32b(&tdx_global_data_ptr->pkg_config_bitmap, tdx_local_data_ptr->lp_info.pkg);
        goto EXIT;
    }

    // Update the number of initialized packages. If this is the last one, update the system state.
    tdx_global_data_ptr->num_of_init_pkgs++;

    if (tdx_global_data_ptr->num_of_init_pkgs == tdx_global_data_ptr->num_of_pkgs)
    {
        tdx_global_data_ptr->global_state.sys_state = SYS_READY;
    }

    retval = TDX_SUCCESS;

EXIT:

    if (tmp_global_lock_acquired)
    {
        release_sharex_lock_ex(&tdx_global_data_ptr->global_lock);
    }

    return retval;
}

