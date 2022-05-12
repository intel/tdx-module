// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_vmm_dispatcher.c
 * @brief VMM dispatcher and return sequence
 */
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_vmm_api_handlers.h"
#include "debug/tdx_debug.h"
#include "helpers/helpers.h"

void tdx_vmm_dispatcher(void)
{
    // Must be first thing to do before accessing local/global data or sysinfo table
    tdx_module_local_t* local_data = init_data_fast_ref_ptrs();

    TDX_LOG("Module entry start\n");

    tdx_module_global_t * global_data = get_global_data();
    uint64_t leaf_opcode;
    ia32_core_capabilities_t core_capabilities;

    // Execute the BHB defense sequence.
    if (global_data->rtm_supported)
    {
        tsx_abort_sequence();             
    }
    else
    {
        // BHB draining sequence
        // There are 6 taken branches in each iteration (one CALL, four JMPs, and one JNZ), 
        // so for GLC (194 branch stews in BHB), NUM_ITERS = round-up(194 / 6) = 32.
        uint64_t num_iters = NUM_OF_BHB_CLEARING_ITERATIONS;
        uint64_t num_iters_multi_8 = 8*num_iters;

        _ASM_VOLATILE_ (
            "movq %0, %%rcx\n"
            "1:  call 2f\n"
            "lfence\n" 
            "2:  jmp 3f\n"
            "nop\n"
            "3:  jmp 4f\n"
            "nop\n"
            "4:  jmp 5f\n"
            "nop\n"
            "5:  jmp 6f\n"
            "nop\n"
            "6:  dec %%rcx\n"
            "jnz 1b\n"
            "add %1, %%rsp\n"
            "lfence\n"
            : : "a"(num_iters), "b"(num_iters_multi_8) : "memory", "rcx");
    }    

    // Save IA32_SPEC_CTRL and set speculative execution variant 4 defense
    // using Speculative Store Bypass Disable (SSBD), which delays speculative
    // execution of a load until the addresses for all older stores are known.
    local_data->vmm_non_extended_state.ia32_spec_ctrl = ia32_rdmsr(IA32_SPEC_CTRL_MSR_ADDR);
    ia32_spec_ctrl_t spec_ctrl;
    spec_ctrl.raw = 0ULL;
    spec_ctrl.ssbd = 1ULL;
    wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR, spec_ctrl.raw, local_data->vmm_non_extended_state.ia32_spec_ctrl);

    // All IA32_DEBGCTL bits have been cleared by SEAMCALL.
    // Set IA32_DEBUGCTL.ENABLE_UNCORE_PMI to the VMM's value, all other bits remain 0.
    ia32_debugctl_t debugctl;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &debugctl.raw);
    local_data->ia32_debugctl_value.raw = 0;
    local_data->ia32_debugctl_value.en_uncore_pmi = debugctl.en_uncore_pmi;
    wrmsr_opt(IA32_DEBUGCTL_MSR_ADDR, local_data->ia32_debugctl_value.raw, debugctl.raw);

    // Get leaf code from RAX in local data (saved on entry)
    leaf_opcode = local_data->vmm_regs.rax;
    
    TDX_LOG("leaf_opcode = 0x%llx\n", leaf_opcode);

    // If simplified LAM is supported, save & disable its state
    if (local_data->lp_is_init)
    {
        core_capabilities.raw = global_data->plt_common_config.ia32_core_capabilities.raw;
    }
    else
    {
        core_capabilities.raw = ia32_rdmsr(IA32_CORE_CAPABILITIES);
    }

    local_data->vmm_non_extended_state.ia32_lam_enable = 0;
    if (core_capabilities.lam_supported != 0)
    {
        local_data->vmm_non_extended_state.ia32_lam_enable = ia32_rdmsr(IA32_LAM_ENABLE_MSR_ADDR);
        if (local_data->vmm_non_extended_state.ia32_lam_enable != 0)
        {
            ia32_wrmsr(IA32_LAM_ENABLE_MSR_ADDR, 0);
        }
    }

    // Check if module state is in SHUTDOWN
    if ((SYS_SHUTDOWN == global_data->global_state.sys_state) && (leaf_opcode != TDH_SYS_LP_SHUTDOWN_LEAF))
    {
        TDX_ERROR("Module in shutdown state\n");
        // update RAX in local data with error code
        local_data->vmm_regs.rax = TDX_SYS_SHUTDOWN;
        goto EXIT;
    }

    // Check if module is in ready state, if not
    // only some leaf functions are allowed to run
    if ((global_data->global_state.sys_state != SYS_READY)     &&
        (leaf_opcode != TDH_SYS_INFO_LEAF)                        &&
        (leaf_opcode != TDH_SYS_INIT_LEAF)                        &&
        (leaf_opcode != TDH_SYS_LP_INIT_LEAF)                      &&
        (leaf_opcode != TDH_SYS_CONFIG_LEAF)                      &&
        (leaf_opcode != TDH_SYS_KEY_CONFIG_LEAF)                   &&
        (leaf_opcode != TDH_SYS_LP_SHUTDOWN_LEAF)
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
        && (leaf_opcode != TDDEBUGCONFIG_LEAF)
#endif
        )
    {
        TDX_ERROR("Module system not ready, can't execute leaf 0x%llx\n", leaf_opcode);
        // update RAX in local data with error code
        local_data->vmm_regs.rax = TDX_SYS_NOT_READY;
        goto EXIT;
    }

    // switch over leaf opcodes
    switch (leaf_opcode)
    {
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    case TDDEBUGCONFIG_LEAF:
    {
        local_data->vmm_regs.rax = td_debug_config(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx,
                                                   local_data->vmm_regs.r8);
        break;
    }
#endif
    case TDH_MNG_ADDCX_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_add_cx(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MEM_PAGE_ADD_LEAF:
    {
        page_info_api_input_t gpa_page_info;
        gpa_page_info.raw = local_data->vmm_regs.rcx;
        local_data->vmm_regs.rax = tdh_mem_page_add(gpa_page_info,
                                               local_data->vmm_regs.rdx,
                                               local_data->vmm_regs.r8,
                                               local_data->vmm_regs.r9);
        break;
    }
    case TDH_MEM_SEPT_ADD_LEAF:
    {
        page_info_api_input_t sept_level_and_gpa;
        sept_level_and_gpa.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_sept_add(sept_level_and_gpa,
                                               local_data->vmm_regs.rdx,
                                               local_data->vmm_regs.r8);
        break;
    }
    case TDH_VP_ADDCX_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_addcx(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MEM_PAGE_RELOCATE:
    {
        local_data->vmm_regs.rax = tdh_mem_page_relocate(local_data->vmm_regs.rcx,
                local_data->vmm_regs.rdx, local_data->vmm_regs.r8);

        break;
    }
    case TDH_MEM_PAGE_AUG_LEAF:
    {
        page_info_api_input_t gpa_page_info;
        gpa_page_info.raw = local_data->vmm_regs.rcx;
        local_data->vmm_regs.rax = tdh_mem_page_aug(gpa_page_info,
                                               local_data->vmm_regs.rdx,
                                               local_data->vmm_regs.r8);
        break;
    }
    case TDH_MEM_RANGE_BLOCK_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_range_block(page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_KEY_CONFIG_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_key_config(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MNG_CREATE_LEAF:
    {
        hkid_api_input_t hkid_info;
        hkid_info.raw = local_data->vmm_regs.rdx;

        local_data->vmm_regs.rax = tdh_mng_create(local_data->vmm_regs.rcx, hkid_info);
        break;
    }
    case TDH_VP_CREATE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_create(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_init(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_VP_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_init(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_RD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_rd(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MEM_RD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_rd(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MNG_WR_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_wr(local_data->vmm_regs.rcx,
                                             local_data->vmm_regs.rdx,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9);
        break;
    }
    case TDH_MEM_WR_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_wr(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx,
                                                    local_data->vmm_regs.r8);
        break;
    }
    case TDH_MEM_PAGE_DEMOTE_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_page_demote(page_info,
                                                  local_data->vmm_regs.rdx,
                                                  local_data->vmm_regs.r8);
        break;
    }
    case TDH_VP_ENTER_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_enter(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MR_EXTEND_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mr_extend(local_data->vmm_regs.rcx, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MR_FINALIZE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mr_finalize(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_VP_FLUSH_LEAF:
    {
        local_data->vmm_regs.rax = tdh_vp_flush(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MNG_VPFLUSHDONE_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_vpflushdone(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MNG_KEY_FREEID_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_key_freeid(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_PAGE_PROMOTE_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_page_promote(page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_PHYMEM_PAGE_RDMD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_page_rdmd(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_SEPT_RD_LEAF:
    {
        page_info_api_input_t sept_page_info;
        sept_page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_sept_rd(sept_page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_VP_RD_LEAF:
    {
        td_ctrl_struct_field_code_t field_code = {.raw = local_data->vmm_regs.rdx};
        local_data->vmm_regs.rax = tdh_vp_rd(local_data->vmm_regs.rcx, field_code);
        break;
    }
    case TDH_MNG_KEY_RECLAIMID_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mng_key_reclaimid(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_PHYMEM_PAGE_RECLAIM_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_page_reclaim(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_PAGE_REMOVE_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_page_remove(page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_MEM_SEPT_REMOVE_LEAF:
    {
        page_info_api_input_t sept_page_info;
        sept_page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_sept_remove(sept_page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_SYS_CONFIG_LEAF:
    {
        hkid_api_input_t global_private_hkid;
        global_private_hkid.raw = local_data->vmm_regs.r8;

        local_data->vmm_regs.rax = tdh_sys_config(local_data->vmm_regs.rcx,
                                                 local_data->vmm_regs.rdx,
                                                 global_private_hkid);
        break;
    }
    case TDH_SYS_KEY_CONFIG_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_key_config();
        break;
    }
    case TDH_SYS_INFO_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_info(local_data->vmm_regs.rcx,
                                               local_data->vmm_regs.rdx,
                                               local_data->vmm_regs.r8,
                                               local_data->vmm_regs.r9);
        break;
    }
    case TDH_SYS_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_init((sys_attributes_t)local_data->vmm_regs.rcx);
        break;
    }
    case TDH_SYS_LP_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_lp_init();
        break;
    }
    case TDH_SYS_TDMR_INIT_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_tdmr_init(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_SYS_LP_SHUTDOWN_LEAF:
    {
        local_data->vmm_regs.rax = tdh_sys_lp_shutdown();
        break;
    }
    case TDH_MEM_TRACK_LEAF:
    {
        local_data->vmm_regs.rax = tdh_mem_track(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_MEM_RANGE_UNBLOCK_LEAF:
    {
        page_info_api_input_t page_info;
        page_info.raw = local_data->vmm_regs.rcx;

        local_data->vmm_regs.rax = tdh_mem_range_unblock(page_info, local_data->vmm_regs.rdx);
        break;
    }
    case TDH_PHYMEM_CACHE_WB_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_cache_wb(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_PHYMEM_PAGE_WBINVD_LEAF:
    {
        local_data->vmm_regs.rax = tdh_phymem_page_wbinvd(local_data->vmm_regs.rcx);
        break;
    }
    case TDH_VP_WR_LEAF:
    {
        td_ctrl_struct_field_code_t field_code = {.raw = local_data->vmm_regs.rdx};
        local_data->vmm_regs.rax = tdh_vp_wr(local_data->vmm_regs.rcx,
                                             field_code,
                                             local_data->vmm_regs.r8,
                                             local_data->vmm_regs.r9);
        break;
    }
    default:
    {
        TDX_ERROR("tdx_vmm_dispatcher - TDX_OPERAND_INVALID - invalid leaf = %d\n", leaf_opcode);
        local_data->vmm_regs.rax = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
        break;
    }
    }

    tdx_sanity_check(local_data->vmm_regs.rax != UNINITIALIZE_ERROR, SCEC_VMM_DISPATCHER_SOURCE, 1);

EXIT:
    // No return after calling the post dispatching operations
    // Eventually call SEAMRET
    tdx_vmm_post_dispatching();
}


void tdx_vmm_post_dispatching(void)
{

    advance_guest_rip();

    tdx_module_local_t* local_data_ptr = get_local_data();

    // Restore IA32_SPEC_CTRL
    ia32_spec_ctrl_t current_spec_ctrl = { .raw = 0 };
    current_spec_ctrl.ssbd = 1;
    wrmsr_opt(IA32_SPEC_CTRL_MSR_ADDR, local_data_ptr->vmm_non_extended_state.ia32_spec_ctrl,
                                       current_spec_ctrl.raw);

    // If simplified LAM was saved & disabled, restore its state
    if (local_data_ptr->vmm_non_extended_state.ia32_lam_enable != 0)
    {
        ia32_wrmsr(IA32_LAM_ENABLE_MSR_ADDR, local_data_ptr->vmm_non_extended_state.ia32_lam_enable);
    }

#ifdef DEBUG
    // Check that we have no mapped keyholes left
    tdx_debug_assert(local_data_ptr->keyhole_state.total_ref_count == 0);
#endif

    TDX_LOG("tdx_vmm_post_dispatching - preparing to do SEAMRET\n");

    tdx_seamret_to_vmm(); // Restore GPRs and SEAMRET

    // Shouldn't reach here:
    tdx_sanity_check(0, SCEC_VMM_DISPATCHER_SOURCE, 0);
}
