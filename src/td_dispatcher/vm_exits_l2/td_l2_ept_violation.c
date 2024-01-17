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
 * @file td_ept_violation.c
 * @brief VM Exit handler for EPT violation VM exit
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_dispatcher/vm_exits_l2/td_l2_vmexit.h"
#include "td_transitions/td_exit.h"

void td_l2_ept_violation_exit(vm_vmexit_exit_reason_t vm_exit_reason, vmx_exit_qualification_t exit_qualification)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvps_t* tdvps_ptr = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_ptr = tdx_local_data_ptr->vp_ctx.tdcs;
    tdr_t* tdr_ptr = tdx_local_data_ptr->vp_ctx.tdr;

    vmx_exit_inter_info_t exit_inter_info;
    ia32_vmread(VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE, &(exit_inter_info.raw));
    
    bool_t gpaw = tdcs_ptr->executions_ctl_fields.gpaw;
    pa_t gpa;

    ia32e_sept_t * l1_sept_entry_ptr = NULL;
    ia32e_sept_t   l1_sept_entry_copy;
    ept_level_t    l1_sept_entry_level = LVL_PT;

    // Get GPA
    ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &gpa.raw);

    // Special treatment for GPAW==0 (i.e., SHARED bit is bit 47) and MAX_PA > 48.
    // If any GPA bit between the SHARED bit and bit (MAX_PA-1) is set,
    // and there is a valid guest linear address, morph the EPT_VIOLATION into L2->L1 exit.
    if (are_gpa_bits_above_shared_set(gpa.raw, gpaw, MAX_PA) &&
        exit_qualification.ept_violation.gla_valid)
    {
        td_l2_to_l1_exit(vm_exit_reason, exit_qualification, 0, exit_inter_info);
    }

    bool_t shared_bit = get_gpa_shared_bit(gpa.raw, gpaw);

    if (!shared_bit)
    {
        // Walk the L1 SEPT to locate the leaf entry.  Actual level is returned.
        l1_sept_entry_ptr = secure_ept_walk(tdcs_ptr->executions_ctl_fields.eptp, (pa_t)gpa,
                                            tdr_ptr->key_management_fields.hkid,
                                            &l1_sept_entry_level, &l1_sept_entry_copy, false);
        
        // L1 leaf SEPT entry found - Check if the EPT violation needs to be handled by the L1 VMM
        if (sept_state_is_guest_accessible_leaf(l1_sept_entry_copy))
        {
            if (l1_sept_entry_ptr != NULL)
            {
                free_la(l1_sept_entry_ptr);
            }
            // In each of the above cases, L1 VMM should handle the EPT violation
            td_l2_to_l1_exit(vm_exit_reason, exit_qualification, 0, exit_inter_info);
        }
        else if (sept_state_is_any_pending_and_guest_acceptable(l1_sept_entry_copy))
        {
            if (l1_sept_entry_ptr != NULL)
            {
                free_la(l1_sept_entry_ptr);
            }

            l2_enter_eeq_t eeq = { .raw = 0 };
            eeq.type = L2_ENTER_EEQ_PEND_EPT_VIOLATION;

            // In each of the above cases, L1 VMM should handle the EPT violation
            td_l2_to_l1_exit(vm_exit_reason, exit_qualification, eeq.raw, exit_inter_info);
        }

        /* At this point we're going to do a TD exit.
         * Log suspected 0-step attacks that repeatedly cause EPT violations with the same RIP. */
        td_exit_epf_stepping_log(gpa);
    }

    // Sanitize exit information and do a TD exit

    /* EPT violation is one case where NMI may have been unblocked by an IRET instruction 
     * before the VM exit happened.  NMI unblocking is only applicable is no IDT vectoring is indicated. 
     * Record this so NMI will be re-blocked if L2 will be reentered following a TD exit and TD entry. */
    if ((exit_qualification.ept_violation.nmi_unblocking_due_to_iret) && !is_idt_vectoring_info_valid())
    {
        tdvps_ptr->management.nmi_unblocking_due_to_iret = true;
    }

    // Clear GPA bits 11:0
    gpa.low_12_bits = 0;

    if (l1_sept_entry_ptr != NULL)
    {
        free_la(l1_sept_entry_ptr);
    }

    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qualification.raw, 0);
}

