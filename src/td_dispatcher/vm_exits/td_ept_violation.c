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

void td_ept_violation_exit(vmx_exit_qualification_t exit_qualification, vm_vmexit_exit_reason_t vm_exit_reason)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    bool_t gpaw = tdcs_p->executions_ctl_fields.gpaw;
    pa_t gpa;

    vmx_guest_inter_state_t guest_inter_state;

    // EPT violation is the only case in TDX-SEAM where NMI may have been unblocked
    // by an IRET instruction before the VM exit happened.  In this case, since we
    // inject a #PF, we re-block NMI.
     if (exit_qualification.ept_violation.nmi_unblocking_due_to_iret)
    {
        ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);
        guest_inter_state.blocking_by_nmi = 1;
        ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
    }

    ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &gpa.raw);

    /* Check whether any GPA bits that are considered reserved are set:
       - SHARED bit may be 0 or 1.  If GPAW is false, SHARED is bit 47.  Else, SHARED is bit 51.
       - If virt_max_pa < 52, then bits in the range 51:virt_max_pa (other than the SHARED bit) must be 0.
         If failed, morph the EPT_VIOLATION into a #PF exception.*/
    if (are_gpa_bits_above_virt_maxpa_set(gpa.raw, gpaw, tdcs_p->executions_ctl_fields.virt_maxpa) &&
        exit_qualification.ept_violation.gla_valid)
    {
        // Morph into a #PF(PFEC.RSVD=1)
        pfec_t pfec = { .raw = 0 };
        pfec.p  = 1;
        pfec.wr = exit_qualification.ept_violation.data_write;
        pfec.us = (get_guest_td_cpl() == 3);
        pfec.r  = 1;
        pfec.id = exit_qualification.ept_violation.insn_fetch;
        pfec.ss = exit_qualification.ept_violation.ss;

        uint64_t gla;
        ia32_vmread(VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE, &gla);

        inject_pf(gla, pfec);
        return;
    }

    vmx_ext_exit_qual_t ext_exit_qual = { .raw = 0 };
    ext_exit_qual.type = VMX_EEQ_NONE;

    bool_t shared_bit = get_gpa_shared_bit(gpa.raw, gpaw);

    if (!shared_bit)
    {
        // Check if the EPT violation happened due to an access to a PENDING page.
        // If so, there are two options:
        //  - #VE injection to the guest TD.
        //  - TD exit with Extended Exit Qualification set to denote a PENDING page.

        // Walk the L1 SEPT to locate the leaf entry.
        tdr_t* tdr_p = tdx_local_data_ptr->vp_ctx.tdr;

        ept_level_t level = LVL_PT; // Walk till leaf entry
        ia32e_sept_t  sept_entry;
        ia32e_sept_t* sept_entry_ptr = secure_ept_walk(tdcs_p->executions_ctl_fields.eptp, gpa,
                                                       tdr_p->key_management_fields.hkid, &level,
                                                       &sept_entry, false);

        free_la(sept_entry_ptr);

        if (sept_state_is_any_pending_and_guest_acceptable(sept_entry))
        {
            // This is a pending page waiting for acceptable by the TD
            if (tdcs_p->executions_ctl_fields.td_ctls.pending_ve_disable)
            {
                // The TD is configured to TD exit on access to a PENDING page
                ext_exit_qual.type = VMX_EEQ_PENDING_EPT_VIOLATION;
            }
            else
            {
                // The TD is configured to throw a #VE on access to a PENDING page
                uint64_t gla;
                ia32_vmread(VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE, &gla);
                tdx_inject_ve(vm_exit_reason.raw, exit_qualification.raw,
                                tdx_local_data_ptr->vp_ctx.tdvps, gpa.raw, gla);
                return;
            }
        }

        // At this point we're going to do a TD exit. If the GPA is private, log suspected 0-step
        // attacks that repeatedly cause EPT violations with the same RIP.
        td_exit_epf_stepping_log(gpa);
    }

    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qualification.raw, ext_exit_qual.raw);
}
