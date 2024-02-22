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
 * @file td_l2_other_exits.c
 * @brief L2 VM Exit handlers for various other small reasons
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

// Check if any of the host-owned bits of a CR is being modified
_STATIC_INLINE_ bool_t is_any_host_owned_bit_modified(uint64_t cr, uint64_t guest_host_mask, uint64_t read_shadow)
{
    // We only care about bits that are 1 in the guest/host mask
    return (cr & guest_host_mask) != (read_shadow & guest_host_mask);
}

// CR0 bits that can be modified by LMSW
// For L2, only PE, MP, EM and TD bits can be modified
#define CR0_L2_LMSW_MASK 0xFULL

cr_write_status_e td_l2_cr_access_exit(vmx_exit_qualification_t vm_exit_qualification, uint16_t vm_id)
{
    uint64_t   value;
    ia32_cr0_t cr0;
    cr_write_status_e status = CR_ACCESS_SUCCESS;

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    switch (vm_exit_qualification.cr_access.access_type)
    {
        case VMEXIT_CR_ACCESS_MOV_TO_CR:
        {
            if (vm_exit_qualification.cr_access.mov_cr_gpr == GPR_RSP_IDX)
            {
                ia32_vmread(VMX_GUEST_RSP_ENCODE, &value);
            }
            else
            {
                value = tdvps_p->guest_state.gpr_state.gprs[vm_exit_qualification.cr_access.mov_cr_gpr];
            }

            switch (vm_exit_qualification.cr_access.cr_num)
            {
                case 0:
                    // MOV to CR0
                    // All valid cases of accessing CR0 are controlled by the CR0 guest/host mask
                    // and CR0 read shadow fields of the TD VMCS, and do not cause a VM exit.

                    // Modification of any bit owned by L1 causes an L2->L1 exit
                    if (is_any_host_owned_bit_modified(value, tdvps_p->management.shadow_cr0_guest_host_mask[vm_id],
                                                       tdvps_p->management.shadow_cr0_read_shadow[vm_id]))
                    {
                        return CR_L2_TO_L1_EXIT; // L2->L1 exit
                    }

                    status = write_guest_cr0(value, true); // L2 allowed to set PE bit to 0
                    break;

                case 4:
                    // MOV to CR4
                    // All valid cases of accessing CR4 are controlled by the CR4 guest/host mask
                    // and CR4 read shadow fields of the TD VMCS, and do not cause a VM exit.

                    // Modification of any bit owned by L1 causes an L2->L1 exit
                    if (is_any_host_owned_bit_modified(value, tdvps_p->management.shadow_cr4_guest_host_mask[vm_id],
                                                       tdvps_p->management.shadow_cr4_read_shadow[vm_id]))
                    {
                        return CR_L2_TO_L1_EXIT; // L2->L1 exit
                    }

                    status = write_guest_cr4(value, tdcs_p, tdvps_p);
                    break;

                default:
                    // VM exits due to other CR accesses cause L2->L1 exit or #VE
                    return CR_ACCESS_NON_ARCH;
            } // switch (vm_exit_qualification.cr_access.cr_num)

            break;
        } // case VMEXIT_CR_ACCESS_MOV_TO_CR

        case VMEXIT_CR_ACCESS_LMSW:
        {
            // Architecturally, LMSW can only write CR0[3:1] (TS, EM, MP); write to CR0[0] (PE)
            // is ignored in protected mode.
            // Because of the setting of TD VMCS CR0 guest/host mask, guest TD attempts to
            // clear CR0.NE or CR0.PE to 0, or set CR0.CD, CR0.NW or any of the CR0 reserved bits
            // to 1 cause a VM exit.

            value = vm_exit_qualification.cr_access.lmsw_src_data & CR0_L2_LMSW_MASK;

            // Modification of any bit owned by L1 causes an L2->L1 exit
            if (is_any_host_owned_bit_modified(value, tdvps_p->management.shadow_cr0_guest_host_mask[vm_id] & CR0_L2_LMSW_MASK,
                                               tdvps_p->management.shadow_cr0_read_shadow[vm_id] & CR0_L2_LMSW_MASK))
            {
                return CR_L2_TO_L1_EXIT; // L2->L1 exit
            }

            ia32_cr0_t new_cr0 = { .raw = value };

            ia32_vmread(VMX_GUEST_CR0_ENCODE, &cr0.raw);

            // If running in protected mode, ignore attempts to clear PE
            if (cr0.pe && !new_cr0.pe)
            {
                new_cr0.pe = 1;
            }

            ia32_vmwrite(VMX_GUEST_CR0_ENCODE, new_cr0.raw | (cr0.raw & ~CR0_L2_LMSW_MASK));

            break;
        } // case VMEXIT_CR_ACCESS_LMSW

        case VMEXIT_CR_ACCESS_CLTS:
        {
            // The L1 VMM may set L2’s CR0_GUEST_HOST_MASK.TS.
            // In this case, if the L2 VM executes CLTS, we arrive here.
            // Since we don't set TDVPS.SHADOW_CR0_GUEST_HOST_MASK.TS, we implicitly need to do an L2->L1 exit.
            return CR_L2_TO_L1_EXIT; // L2->L1 exit
        }

        default:
            // VM exits due to other access types cause L2->L1 exit or #VE
            return CR_ACCESS_NON_ARCH;
    }

    return status;
}

void td_l2_exception_or_nmi_exit(vm_vmexit_exit_reason_t vm_exit_reason,
                                 vmx_exit_qualification_t vm_exit_qualification,
                                 vmx_exit_inter_info_t vm_exit_inter_info)
{
    if (vm_exit_inter_info.interruption_type == VMEXIT_INTER_INFO_TYPE_NMI)
    {
        // This exit was due to an NMI
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason,
                            vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }
    else if (vm_exit_inter_info.vector == E_MC)
    {
        // This exit was due to a #MC, disable the TD
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_TD_NON_ACCESSIBLE, vm_exit_reason,
                            vm_exit_qualification.raw, 0, 0, vm_exit_inter_info.raw);
    }
    else
    {
        // Other cases are handled by the L1 VMM
        td_l2_to_l1_exit(vm_exit_reason, vm_exit_qualification, 0, vm_exit_inter_info);
    }
}

