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
 * @file tdh_vp_init
 * @brief TDHVPINIT API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "data_structures/td_vmcs_init.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"


_STATIC_INLINE_ void init_vcpu_gprs_and_registers(tdvps_t * tdvps_ptr, tdcs_t * tdcs_ptr, uint64_t init_rcx, uint32_t vcpu_index)
{
    /**
     *  GPRs init
     */
    if (tdcs_ptr->executions_ctl_fields.gpaw)
    {
        tdvps_ptr->guest_state.gpr_state.rbx = MAX_PA_FOR_GPAW;
    }
    else
    {
        tdvps_ptr->guest_state.gpr_state.rbx = MAX_PA_FOR_GPA_NOT_WIDE;
    }
    // Set RCX and R8 to the input parameter's value
    tdvps_ptr->guest_state.gpr_state.rcx = init_rcx;
    tdvps_ptr->guest_state.gpr_state.r8 = init_rcx;

    // CPUID(1).EAX - returns Family/Model/Stepping in EAX - take the saved value by TDHSYSINIT
    tdx_debug_assert(get_cpuid_lookup_entry(0x1, 0x0) < MAX_NUM_CPUID_LOOKUP);
    tdvps_ptr->guest_state.gpr_state.rdx = (uint64_t)get_global_data()->cpuid_values[get_cpuid_lookup_entry(0x1, 0x0)].values.eax;

    /**
     *  Registers init
     */
    tdvps_ptr->guest_state.xcr0 = XCR0_RESET_STATE;
    tdvps_ptr->guest_state.dr6 = DR6_RESET_STATE;


    // Set RSI to the VCPU index
    tdvps_ptr->guest_state.gpr_state.rsi = vcpu_index & BITS(31,0);

    /**
     *  All other GPRs/Registers are set to 0 or
     *  that their INIT state is 0
     *  Doesn’t include values initialized in VMCS
     */
}


_STATIC_INLINE_ void init_vcpu_msrs(tdvps_t * tdvps_ptr)
{
    tdvps_ptr->guest_msr_state.ia32_fmask = IA32_FMASK_MSR_RESET_STATE; // doesn’t include values initialized in VMCS

    /**
     *  All other MSR's are set to 0
     */
}


api_error_type tdh_vp_init(uint64_t target_tdvpr_pa, uint64_t td_vcpu_rcx)
{
    // TDVPS related variables
    pa_t                  tdvpr_pa = {.raw = target_tdvpr_pa};  // TDVPR physical address
    tdvps_t             * tdvps_ptr = NULL;                     // Pointer to the TDVPS structure ((Multi-page linear address)
    pamt_block_t          tdvpr_pamt_block;                     // TDVPR PAMT block
    pamt_entry_t        * tdvpr_pamt_entry_ptr;                 // Pointer to the TDVPR PAMT entry
    bool_t                tdvpr_locked_flag = false;            // Indicate TDVPR is locked

    // TDR related variables
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    // VMCS related variables
    uint16_t              curr_hkid;
    uint64_t              init_rcx = td_vcpu_rcx;               // Initial value of RDX in TDVPS
    uint32_t              vcpu_index;

    api_error_type        return_val = UNINITIALIZE_ERROR;


    // Check and lock the parent TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RCX,
                                                         TDX_LOCK_EXCLUSIVE,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_block,
                                                         &tdvpr_pamt_entry_ptr,
                                                         &tdvpr_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock a TDVPR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock and map the TDR page
    return_val = lock_and_map_implicit_tdr(get_pamt_entry_owner(tdvpr_pamt_entry_ptr),
                                           OPERAND_ID_TDR,
                                           TDX_RANGE_RO,
                                           TDX_LOCK_SHARED,
                                           &tdr_pamt_entry_ptr,
                                           &tdr_locked_flag,
                                           &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_ptr, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_VP_INIT_LEAF, &tdcs_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    // Get the TD's ephemeral HKID
    curr_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the multi-page TDVPS structure
    tdvps_ptr = map_tdvps(tdvpr_pa, curr_hkid, tdcs_ptr->management_fields.num_l2_vms, TDX_RANGE_RW);

    if (tdvps_ptr == NULL)
    {
        TDX_ERROR("TDVPS mapping failed\n");
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    // Check the VCPU state
    if (tdvps_ptr->management.state != VCPU_UNINITIALIZED)
    {
        TDX_ERROR("TDVPS is already initialized\n");
        return_val = TDX_VCPU_STATE_INCORRECT;
        goto EXIT;
    }

    /*
     * Set the VCPU index and increment the number of VCPUs in the TD
     * MAX_VCPUS can be in the range 0x0001 to 0xFFFF.
     * Thus, VCPU_INDEX is in the range 0x0000 to 0xFFFE.
     * This assures that there in no overflow in the 16b VPID, later assigned as VCPU_INDEX + 1.
     */
    vcpu_index = _lock_xadd_32b(&tdcs_ptr->management_fields.num_vcpus, 1);
    if (vcpu_index >= tdcs_ptr->executions_ctl_fields.max_vcpus)
    {
        (void)_lock_xadd_32b(&tdcs_ptr->management_fields.num_vcpus, (uint32_t)-1);
        TDX_ERROR("Max VCPUS (%d) has been exceeded\n", tdcs_ptr->executions_ctl_fields.max_vcpus);
        return_val = TDX_MAX_VCPUS_EXCEEDED;
        goto EXIT;
    }
    tdvps_ptr->management.vcpu_index = vcpu_index;


    // We read TSC below.  Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    // to make sure the host VMM doesn't play any trick on us. */
    if (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != get_global_data()->plt_common_config.ia32_tsc_adjust)
    {
        return_val = api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
        goto EXIT;
    }

    // Read TSC and store as the initial value of LAST_EXIT_TSC
    tdvps_ptr->management.last_exit_tsc = ia32_rdtsc();

    // Copy XFAM to TDVPS; in DEBUG mode the debugger is allowed to change it per VCPU
    tdvps_ptr->management.xfam = tdcs_ptr->executions_ctl_fields.xfam;

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    /**
     *  Initialize the TD VCPU GPRs.  Default GPR value is 0.
     *  Initialize the TD VCPU non-GPR register state in TDVPS:
     *  CRs, DRs, XCR0, IWK etc.
     */
    init_vcpu_gprs_and_registers(tdvps_ptr, tdcs_ptr, init_rcx, vcpu_index);

    /**
     *  Initialize the TD VCPU MSR state in TDVPS
     */
    init_vcpu_msrs(tdvps_ptr);

    /**
     *  No need to explicitly initialize TD VCPU extended state pages.
     *  Since the pages are initialized to 0 on TDHVPCREATE/TDVPADDCX.
     */

    // Bit 63 of XCOMP_BV should be set to 1, to indicate compact format.
    // Otherwise XSAVES and XRSTORS won't work
    tdvps_ptr->guest_extension_state.xbuf.xsave_header.xcomp_bv = BIT(63);

    // Initialize TDVPS.LBR_DEPTH to MAX_LBR_DEPTH supported on the core
    if (((ia32_xcr0_t)tdcs_ptr->executions_ctl_fields.xfam).lbr)
    {
        tdvps_ptr->guest_msr_state.ia32_lbr_depth = (uint64_t)get_global_data()->max_lbr_depth;
    }

    /**
     *  No need to explicitly initialize VAPIC page.
     *  Since the pages are initialized to 0 on TDHVPCREATE/TDVPADDCX,
     *  VAPIC page is already 0.
     */

    /**
     *  No need to explicitly initialize VE_INFO.
     *  Since the pages are initialized to 0 on TDHVPCREATE/TDVPADDCX,
     *  VE_INFO.VALID is already 0.
     */

    // Mark the VCPU as initialized and ready
    tdvps_ptr->management.state = VCPU_READY;
    tdvps_ptr->management.last_td_exit = LAST_EXIT_ASYNC_FAULT;
    
    init_tdvps_fields(tdcs_ptr, tdvps_ptr);

    associate_vcpu_initial(tdvps_ptr, tdcs_ptr);

    // Prepare and initialize the L1 VMCS
    prepare_td_vmcs(tdvps_ptr, 0);
    set_vm_vmcs_as_active(tdvps_ptr, 0);
    init_td_vmcs(tdr_ptr, tdcs_ptr, tdvps_ptr, false, 0);

    // Prepare and initialize the L2 VMCSes and MSR bitmaps
    for (uint16_t vm_id = 1; vm_id <= tdcs_ptr->management_fields.num_l2_vms; vm_id++)
    {
        prepare_td_vmcs(tdvps_ptr, vm_id);
        set_vm_vmcs_as_active(tdvps_ptr, vm_id);
        init_td_vmcs(tdr_ptr, tdcs_ptr, tdvps_ptr, false, vm_id);

        // There's no need to explicitly initialize the MSR exiting bitmaps.
        // They were initialized to all-1 when their pages were added by TDH.VP.ADDCX.
    }

EXIT:

    set_seam_vmcs_as_active();

    // Release all acquired locks and free keyhole mappings
    if (tdcs_ptr != NULL)
    {
        release_sharex_lock_hp_sh(&tdcs_ptr->management_fields.op_state_lock);
        free_la(tdcs_ptr);
    }
    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
        free_la(tdr_ptr);
    }
    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }

    return return_val;
}
