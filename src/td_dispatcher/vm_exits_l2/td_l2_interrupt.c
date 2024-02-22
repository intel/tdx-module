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
 * @file td_l2_interrupt.c
 * @brief VM Exit handlers interrupts coming from L2
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
#include "td_dispatcher/vm_exits_l2/td_l2_vmexit.h"
#include "td_transitions/td_exit.h"


static l2_exit_route_t handle_l2_posted_interrupt(tdvps_t* tdvps_p, uint16_t vm_id)
{
    posted_intr_descriptor_t* pid_p;

    // Read and map L1 PID address.  A shadow copy was stored in TDVPS when the L1 VMCS field was written.
    pid_p = map_pa((void*)tdvps_p->management.shadow_pid_hpa, TDX_RANGE_RW);

    // Atomically clear the ON bit in the PID
    _lock_and_8b(&pid_p->on_byte, (uint8_t)~0x1);

    // Write EOI to the Local APIC.
    // Note: This code assumes local APIC works in x2APIC mode.
    ia32_wrmsr(IA32_X2APIC_EOI, 0);

    // Merge L1PID.PIR into L1 VMM's VAPIC.VIRR and calculate highest requested posted interrupt vector.
    // Remember that VIRR is composed of 8 32-bit fields, thus it is processed 32 bits at a time.
    uint8_t rvi = 0;
    volatile ia32_apic_register_t* vapic_irr = (ia32_apic_register_t*)&tdvps_p->vapic.apic[APIC_MMIO_IRR_OFFSET];

    for (uint32_t i = 0; i < PID_PIR_DWORDS; i++)
    {
        // Atomically read & clear 32 PID.PIR bits
        uint32_t pir = _xchg_32b(&pid_p->pir[i], 0);

        // Merge L1PID.PIR into L1 VMM's VIRR
        vapic_irr[i].value |= pir;

        // Find highest bit set in PID.PIR as RVI
        if (pir != 0)
        {
            uint32_t msb_position;
            (void)bit_scan_reverse32(pir, &msb_position);
            rvi = (uint8_t)(i * 32 + msb_position);
        }
    }

    free_la(pid_p); // Not needed anymore;
    pid_p = NULL;

    // Ignore any vector bits in the range 30:0 when calculating RVI
    if (rvi < 31)
    {
        rvi = 0;
    }

    // VMPTRLD L1 VMCS
    set_vm_vmcs_as_active(tdvps_p, 0);

    // Calculate L1 VMM's RVI as maximum of current L1 VMM's RVI and highest requested posted vector.
    // The CPU will use this updated RVI value when entering into L1.
    guest_interrupt_status_t inter_status;
    ia32_vmread(VMX_GUEST_INTERRUPT_STATUS_ENCODE, &inter_status.raw);

    if (rvi > inter_status.rvi)
    {
        inter_status.rvi = rvi;
        ia32_vmwrite(VMX_GUEST_INTERRUPT_STATUS_ENCODE, inter_status.raw);
    }

    // If RVI priority (bits 7:4) is not higher than current L1 VMM's VAPIC.VPPR priority,
    // virtual interrupt can't be injected to L1 VMM right now.
    // Resume L2 VM; the CPU will use the updated RVI later, on L2->L1 exit, when L1 is entered.
    volatile uint32_t ppr = *(uint32_t*)&tdvps_p->vapic.apic[APIC_MMIO_PPR_OFFSET];

    if ((inter_status.rvi & 0xF0) <= (ppr & 0xF0))
    {
        // VMPTRLD L2 VM's VMCS (this is the context expected on return)
        set_vm_vmcs_as_active(tdvps_p, vm_id);

        return L2_EXIT_ROUTE_RESUME_L2;
    }

    // Deliver the virtual interrupt to the L1 VMM.
    // VMPTRLD L2 VM's VMCS (this is the context expected on return)
    set_vm_vmcs_as_active(tdvps_p, vm_id);

    return L2_EXIT_ROUTE_L2_TO_L1_EXIT;
}

l2_exit_route_t td_l2_interrupt_exit(tdx_module_local_t* tdx_local_data_ptr,
                                     vmx_exit_inter_info_t vm_exit_inter_info, uint16_t vm_id)
{
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;

    // Check if this was a notification interrupt targeted to L1 VMM. If not, TD-exit to the host VMM

    // Check the L1 VCPU's process posted interrupts pin-based execution control.
    // A shadow copy was stored in TDVPS when the L1 VMCS field was written.
    // If PID is not enabled then TD-exit to the host VMM.
    vmx_pinbased_ctls_t shadow_pinbased_exec_ctls = { .raw = tdvps_p->management.shadow_pinbased_exec_ctls };

    if (!shadow_pinbased_exec_ctls.process_posted_interrupts)
    {
        return L2_EXIT_ROUTE_TD_EXIT;
    }

    // Check the L1 VCPU's posted interrupts notification vector.
    // A shadow copy was been stored in TDVPS when the L1 VMCS field was written.
    // If the vector is not PID NV vector then TD-exit to the host VMM.
    // Note: Since the basic exit reason had been checked to be 1 (external interrupt) before this function
    //       was called, there's no need to check fields other than VECTOR
    if (vm_exit_inter_info.vector != (uint32_t)tdvps_p->management.shadow_posted_int_notification_vector)
    {
        return L2_EXIT_ROUTE_TD_EXIT;
    }

    // Dismiss the interrupt.
    // This was a notification interrupt targeted to L1 VMM.
    // Register the highest priority virtual interrupt as requested for L1 VMM,
    // and check if it can be delivered immediately.
    // If not, resume L2 VM; the interrupt will be delivered later.

    return handle_l2_posted_interrupt(tdvps_p, vm_id);
}

