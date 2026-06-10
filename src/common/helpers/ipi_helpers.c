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
 * @file ipi_helpers.c
 * @brief IPI-related feature helpers
 */

#include "helpers/ipi_helpers.h"
#include "helpers/helpers.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/msr_defs.h"
#include "metadata_handlers/metadata_generic.h"


uint8_t scan_pids_and_update_irr_and_rvi(pidsc_t* sec_pid_p, pidsc_t* other_pid_p, bool_t is_shared_pid,
                                         const uint32_t pir_mask[PID_PIR_DWORDS], apic_t* vapic_p)
{
    guest_interrupt_status_t inter_status;
    uint8_t rvi = 0;
    uint32_t pir = 0;

    /* Equivalent to Intel SDM, Vol. 3, 31.6, step 5:
       "5. The logical processor performs a logical-OR of PIR into VIRR and clears PIR. No other agent can read or write a
           PIR bit (or group of bits) between the time it is read (to determine what to OR into VIRR) and when it is cleared."

           Merge Main PID.PIR and Shared PID.PIR (masked by PIR_MASK) into VAPIC.VIRR and calculate highest requested posted
           interrupt vector.
           Remember that VIRR is composed of 8 32-bit fields, thus it is processed 32 bits at a time. */

    for (uint32_t i = 0; i < PID_PIR_DWORDS; i++)
    {
        pir = 0;

        // Atomically read & clear 32 PID.PIR bits
        if (sec_pid_p)
        {
            pir = _xchg_32b(&sec_pid_p->pir[i], 0);
        }

        if (other_pid_p)
        {
            if (is_shared_pid)
            {
                pir |= _xchg_32b(&other_pid_p->pir[i], 0) & pir_mask[i];
            }
            else
            {
                pir |= _xchg_32b(&other_pid_p->pir[i], 0);
            }
        }

        // Merge L1 PID.PIR into L1 VMM's VIRR
        vapic_p->irr[i].value |= pir;

        // Find highest bit set in PID.PIR as rvi
        if (pir != 0)
        {
            uint32_t msb;
            bit_scan_reverse32(pir, &msb);
            rvi = (uint8_t)(i * 32 + msb);
        }
    }

    // Ignore any vector bits in the range 30:0 when calculating RVI
    if (rvi < 31)
    {
        rvi = 0;
    }

    /* Equivalent to Intel SDM, Vol. 3, 31.6, step 6:
       "6. The logical processor sets RVI to be the maximum of the old value of RVI and the highest index of all bits that
           were set in PIR; if no bit was set in PIR, RVI is left unmodified."

       Calculate L1 VMM's RVI as maximum of current L1 VMM's RVI and highest requested
       posted vector.  The CPU will use this updated RVI value when entering into L1. */

    ia32_vmread(VMX_GUEST_INTERRUPT_STATUS_ENCODE, &inter_status.raw);
    if (rvi > inter_status.rvi)
    {
        inter_status.rvi = rvi;
        ia32_vmwrite(VMX_GUEST_INTERRUPT_STATUS_ENCODE, inter_status.raw);
    }

    return inter_status.rvi;
}



void update_vcpu_intr_state(tdvps_t* tdvps_p, uint16_t vm_id)
{
    if (vm_id == 0)
    {
        update_vcpu_state_details_for_l1(tdvps_p, false);
    }
    else
    {
        update_vcpu_state_details_for_l2(tdvps_p);
    }
}

bool_t update_vcpu_state_details_on_td_exit(tdcs_t* tdcs_p, tdvps_t* tdvps_p, uint16_t vm_id)
{
    if (vm_id == 0)
    {
        update_vcpu_state_details_for_l1(tdvps_p, true);
    }
    else
    {
        update_vcpu_state_details_for_l2(tdvps_p);
    }


    if ((tdcs_p->executions_ctl_fields.vm_ctls[vm_id].hint_on_vintr_pending &&
         tdvps_p->guest_state.vcpu_state_details.any_vintr_pending) ||
        (tdcs_p->executions_ctl_fields.vm_ctls[vm_id].hint_on_vintr_in_service &&
         tdvps_p->guest_state.vcpu_state_details.any_vintr_in_service) ||
        (tdcs_p->executions_ctl_fields.vm_ctls[vm_id].hint_on_vnmi_pending &&
         tdvps_p->guest_state.vcpu_state_details.any_vnmi_pending))
    {
        return true;
    }

    return false;
}

void update_vcpu_state_details_on_l1_rd(tdcs_t* tdcs_p, tdvps_t* tdvps_p)
{
    update_vcpu_state_details_for_l1(tdvps_p, true);

    UNUSED(tdcs_p);
}
