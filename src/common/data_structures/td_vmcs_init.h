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
 * @file td_vmcs_init.h
 * @brief Predefined init fields for TD's VMCS
 */

#ifndef __TD_VMCS_INIT_H_INCLUDED__
#define __TD_VMCS_INIT_H_INCLUDED__

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "data_structures/td_control_structures.h"
#include "data_structures/tdx_tdvps.h"


#define VMCS_TSC_OFFSET_BIT_LOCATION                 3
#define VMCS_RDPMC_BIT_LOCAITON                      11

#define VMCS_TSC_SCALING_BIT_LOCATION                25
#define VMCS_ENABLE_USER_LEVEL_OFFSET_BIT_LOCATION   26
#define VMCS_ENABLE_PCONFIG_OFFSET_BIT_LOCATION      27

#define VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FIXED_VALUES 0
#define VMCS_LOADIWKEY_BIT_LOCATION                           0
#define VMCS_GPAW_BIT_LOCATION                                5

#define VMCS_EXIT_LOAD_PERF_GLBL_CTRL_BIT_LOCATION        12
#define VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION        30

#define VMCS_ENTRY_LOAD_PERF_GLBL_CTRL_BIT_LOCATION       13
#define VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION                 22

// Platform-unique VPID for each TD VM
typedef union tdx_vpid_u
{
    struct
    {
        uint16_t vm   : 2;   // Bits 1:0:  VM index
        uint16_t hkid : 14;  // Bits 15:2:  TD's HKID
    };
    uint16_t raw;
} tdx_vpid_t;

#define MAX_HKID_FOR_VPID           4096

// Compose a VPID based on VM index and the TD's HKID.
// If HKID or VM index don't fit in the TDX VPID structure, return 0
_STATIC_INLINE_ uint16_t compose_vpid(uint16_t vm_id, uint16_t hkid)
{
    tdx_vpid_t vpid;

    if ((vm_id >= MAX_VMS) || (hkid >= MAX_HKID_FOR_VPID))
    {
        return 0;
    }

    vpid.vm = vm_id;
    vpid.hkid = hkid;

    return vpid.raw;
}

/**
 * @brief Read non-LP host field value from the current active VMCS and save them in the input structure
 *
 * @param host_fields_ptr
 */
void save_vmcs_non_lp_host_fields(vmcs_host_values_t* host_fields_ptr);

/**
 * @brief Initialize address fields for the currently active TD VMCS
 *
 * @param tdr_ptr
 * @param tdvps_ptr
 * @param curr_hkid
 *  @param vm_id - 0 if L1 TD VMCS is initialized, >0 if L2 TD VMCS is initialized
 */
void init_guest_td_address_fields(tdr_t* tdr_ptr, tdvps_t* tdvps_ptr, uint16_t curr_hkid, uint16_t vm_id);

/**
 * @brief Initializes LP-dependant host-state field from the current SEAM VMCS (saved at TDH.SYS.INIT and TDH.SYSINIT.LP)
 *        and writes it to the currently loaded TD VMCS
 *
 * @param ld_p - Local data pointer where the LP-dependant host-state is saved
 */
void init_module_lp_host_state_in_td_vmcs(tdx_module_local_t* ld_p);

/**
 * @brief Initializes all host state fields from the current SEAM VMCS (saved at TDH.SYS.INIT and TDH.SYSINIT.LP)
 *        and writes it to the currently loaded TD VMCS
 *        Also sets the HOST_RIP to TD-exit module entry pointer function
 *
 */
void init_module_host_state_in_td_vmcs(void);

/**
 *  @brief Initialize the TD VMCS fields
 *
 *  Zero fields are initialized by default (done on TDHVPADDCX)
 *
 *  @param tdr_ptr - pointer to TDR
 *  @param tdcs_ptr - pointer to TDCS
 *  @param tdvps_ptr - pointer to TDVPS
 *  @param init_on_import - if the function is called from VMCS import flow
 *  @param vm_id - 0 if L1 TD VMCS is initialized, >0 if L2 TD VMCS is initialized
 *
 */
void init_td_vmcs(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr, bool_t init_on_import, uint16_t vm_id);

#endif // __TD_VMCS_INIT_H_INCLUDED__

