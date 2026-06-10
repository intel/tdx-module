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
 * @file td_vmexit.h
 * @brief Everything related to handling of VMEXIT's and VT-related flows
 */

#ifndef SRC_TD_DISPATCHER_VM_EXITS_TD_VMEXIT_H_
#define SRC_TD_DISPATCHER_VM_EXITS_TD_VMEXIT_H_

/**
 * @brief Handler for XSETBV instruction exit
 */
void td_xsetbv_instruction_exit(void);

/**
 * @brief Handler for EPT violation exit
 *
 * @param exit_qualification
 * @param vm_exit_reason
 */
void td_ept_violation_exit(vmx_exit_qualification_t exit_qualification, vm_vmexit_exit_reason_t vm_exit_reason);

/**
 * @brief Handler for EPT misconfiguration exit
 *
 * @param vm_exit_reason
 */
void td_ept_misconfiguration_exit(vm_vmexit_exit_reason_t vm_exit_reason);

/**
 * @brief Handler for CPUID exit
 */
void td_cpuid_exit(void);

/**
 * @brief Handler for RDPMC exit
 *
 * @param vm_exit_reason
 * @param vm_exit_qualification
 */
void td_rdpmc_exit(vm_vmexit_exit_reason_t vm_exit_reason, uint64_t  vm_exit_qualification);

/**
 * @brief Handler for CR access exit
 *
 * @param vm_exit_qualification
 *
 * @return In case the operation is unexpected for a production TD, return value is false
 */
bool_t td_cr_access_exit(vmx_exit_qualification_t vm_exit_qualification);

/**
 * @brief Handler for Exception/NMI exit
 *
 * @param vm_exit_reason
 * @param vm_exit_qualification
 * @param vm_exit_inter_info
 */
void td_exception_or_nmi_exit(vm_vmexit_exit_reason_t vm_exit_reason,
                              vmx_exit_qualification_t vm_exit_qualification,
                              vmx_exit_inter_info_t vm_exit_inter_info);

typedef enum td_msr_access_status_e
{
    TD_MSR_ACCESS_SUCCESS,
    TD_MSR_ACCESS_GP,                     // #GP(0)
    TD_MSR_ACCESS_MSR_NON_ARCH_EXCEPTION, // Non-architectural exception. Injected to the TD as #VE
    TD_MSR_ACCESS_L2_TO_L1_EXIT           // In case when RD/WRMSR was handled for L2, and a bit was set in shadow bitmap
} td_msr_access_status_t;

/**
 * @brief Handler for RDMSR exit
 *
 */
td_msr_access_status_t td_rdmsr_exit(void);


/**
 * @brief Handler for WRMSR exit
 *
 */
td_msr_access_status_t td_wrmsr_exit(void);


// VM-transitions and injections helper flows

/**
 * @brief Sets output operands for EPT violation, and continues to async_td_exit_to_vmm routine
 *
 * @param gpa                    - Violating GPA
 * @param exit_qualification     - VM-exit qualification to be passed to VMM
 * @param ext_exit_qual          - VM-exit extended qualification
 */
void tdx_ept_violation_exit_to_vmm(pa_t gpa, vm_vmexit_exit_reason_t vm_exit_reason, uint64_t exit_qual, uint64_t ext_exit_qual);

/**
 * @brief Sets output operands for EPT misconfiguration, and continues to async_td_exit_to_vmm routine
 *
 * @param gpa                    - Misconfigured GPA
 */
void tdx_ept_misconfig_exit_to_vmm(pa_t gpa);

/**
 * @brief Handles #VE injection according to the current valid state of VE_AREA in TDVPS.
 *        Injects #VE to the guest if the VE_AREA not valid, and #DF if valid, and calls tdx_return_to_td routine
 *
 * @param vm_exit_reason     - Exit reason to be stored in the VE_AREA
 * @param exit_qualification - VM-exit qualification to be stored in the VE AREA
 * @param tdvps_p            - TDVPS where the VE_AREA is located
 * @param gpa                - guest physical address to be stored in the VE_AREA
 * @param glp                - guest linear address to be stored in the VE_AREA
 */
void tdx_inject_ve(uint64_t vm_exit_reason, uint64_t exit_qualification, tdvps_t* tdvps_p,
        uint64_t gpa, uint64_t gla);

/**
 * @brief Handler for nmi exit, Inject an NMI if applicable
 *
 * @param tdx_local_data_ptr - pointer to local data
 */
void td_nmi_exit(tdx_module_local_t* tdx_local_data_ptr);

/**
 * @brief Do an asynchronous TD exit due to an EPT violation, with extended exit qualification
 *        detailing requested vs. actual SEPT information.
 *        Used by TDG.MEM.PAGE.ACCEPT and TDG.MEM.PAGE.ATTR.WR.
 *
 * @param gpa - faulting GPA to report
 * @param req_level - level that was requested
 * @param sept_entry - failing SEPT entry copy
 * @param ept_level - actual failed level
 * @param sept_entry_ptr - failing SEPT entry pointer - will be freed if not NULL
 * @param eeq_type - Extended exit qualification type
 */
void async_tdexit_ept_violation(pa_t gpa, ept_level_t req_level, ia32e_sept_t sept_entry,
                                ept_level_t ept_level, ia32e_sept_t* sept_entry_ptr, vmx_eeq_type_t eeq_type);

#endif /* SRC_TD_DISPATCHER_VM_EXITS_TD_VMEXIT_H_ */
