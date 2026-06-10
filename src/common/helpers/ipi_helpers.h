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
 * @file ipi_helpers.h
 * @brief IPI-related feature helpers
 */

#ifndef SRC_COMMON_HELPERS_IPI_HELPERS_H_
#define SRC_COMMON_HELPERS_IPI_HELPERS_H_

#include "helpers.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"


/**
 * @brief Scan Regular or Secure PID and Shared PID, if applicable, and update the Virtual APIC IRR and VMCS RVI
 *
 * @note The proper VMCS is assumed to be current
 *
 * @param sec_pid_p Secure PID, null if N/A
 * @param other_pid_p Regular or Shared PID, null if N/A
 * @param is_shared_pid
 * @param pir_mask - Mask for shared PID
 * @param vapic_p - Virtual APIC page
 *
 * @return Updated RVI
 */
uint8_t scan_pids_and_update_irr_and_rvi(pidsc_t* sec_pid_p, pidsc_t* other_pid_p, bool_t is_shared_pid,
                                 const uint32_t pir_mask[PID_PIR_DWORDS], apic_t* vapic_p);

// Check if RVI priority(bits 7:4) is higher than current Virtual PPR priority
_STATIC_INLINE_ bool_t is_rvi_priority_higher_than_ppr(uint8_t rvi, apic_t* vapic_p)
{
    return ((rvi & 0xF0) > ((uint8_t)vapic_p->ppr & 0xF0));
}


/**
 * @brief Update the TDVPS.VCPU_STATE_DETAILS VINTR_PENDING and VINTR_IN_SERVICE bits for the given VM.
 *
 * @note Assumes the VMCS is active.
 */
void update_vcpu_intr_state(tdvps_t* tdvps_p, uint16_t vm_id);

/**
 * @brief Update TDVPS.VCPU_STATE_DETAILS and calculate IMM_RESUME_HINT on TD exit
 */
bool_t update_vcpu_state_details_on_td_exit(tdcs_t* tdcs_p, tdvps_t* tdvps_p, uint16_t vm_id);

/**
 * @brief Update TDVPS.VCPU_STATE_DETAILS on read by L1
 */
void update_vcpu_state_details_on_l1_rd(tdcs_t* tdcs_p, tdvps_t* tdvps_p);


#endif /* SRC_COMMON_HELPERS_IPI_HELPERS_H_ */
