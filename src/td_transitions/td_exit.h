// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_exit.h
 * @brief Everything related to VMM<--->TD transitions
 */


#ifndef SRC_TD_TRANSITIONS_TD_EXIT_H_
#define SRC_TD_TRANSITIONS_TD_EXIT_H_

#include "auto_gen/tdx_error_codes_defs.h"

#define IA32_DEBUGCTLMSR_BTF                   BIT(1)
#define IA32_DEBUGCTLMSR_FREEZE_PERFMON_ON_PMI BIT(12)
#define IA32_DEBUGCTLMSR_FREEZE_WHILE_SMM      BIT(14)
#define IA32_DEBUGCTLMSR_MASK_BITS_PRESERVED   (IA32_DEBUGCTLMSR_BTF | IA32_DEBUGCTLMSR_FREEZE_PERFMON_ON_PMI | IA32_DEBUGCTLMSR_FREEZE_WHILE_SMM)

#define VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_INIT_VALUE 0x0
#define VMX_GUEST_RTIT_CTL_INIT_VALUE                 0x0
#define VMX_GUEST_LBR_CTL_INIT_VALUE                  0x0
#define VMX_GUEST_DR7_INIT_VALUE                      0x00000400

#ifdef DEBUG  
#define NUM_OF_PRESERVED_KEYHOLES              2
#endif

/**
 * @brief Handler routine for asynchronous exit from TD to VMM
 */
void async_tdexit_to_vmm(api_error_code_e tdexit_case,
                         vm_vmexit_exit_reason_t vm_exit_reason,
                         uint64_t exit_qualification,
                         uint64_t extended_exit_qualification,
                         uint64_t gpa,
                         uint64_t vm_exit_interruption_information);

/**
 * @brief Converged exit point from TD to VMM, for both async vmexit and vmcall.
 *
 * @param vcpu_state
 * @param scrub_mask
 * @param xmm_select
 * @param is_td_dead
 */
void td_vmexit_to_vmm(uint8_t vcpu_state, uint64_t scrub_mask, uint16_t xmm_select, bool_t is_td_dead);

#endif /* SRC_TD_TRANSITIONS_TD_EXIT_H_ */
