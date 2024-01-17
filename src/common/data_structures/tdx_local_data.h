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
 * @file tdx_local_data.h
 * @brief TDX local data (per LP) definitions
 */
#ifndef __TDX_LOCAL_DATA_H_INCLUDED__
#define __TDX_LOCAL_DATA_H_INCLUDED__


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "data_structures/tdx_local_data_offsets.h"
#include "data_structures/td_control_structures.h"
#include "data_structures/tdx_tdvps.h"
#include "memory_handlers/pamt_manager.h"

/**
 * @struct lp_info_t
 *
 * @brief Holds logical processor information
 */
typedef struct PACKED lp_info_s
{
    uint32_t  lp;     /**< number of lp in package and core context */
    uint32_t  core;   /**< number of core in package context */
    uint32_t  pkg;    /**< number of package */
    uint32_t  lp_id;  /**< The unique sequential index of the current lp in the platform */
} lp_info_t;


/**
 * @struct non_extended_state_t
 *
 * @brief Holds the non extended state registers and MSRs
 */
typedef struct PACKED non_extended_state_s
{
    uint64_t ia32_spec_ctrl;
    uint64_t ia32_lam_enable;
    uint64_t ia32_ds_area;
    uint64_t ia32_tsx_ctrl;
} non_extended_state_t;



#define KH_ENTRY_FREE           0
#define KH_ENTRY_MAPPED         1
#define KH_ENTRY_CAN_BE_REMOVED 2
/**
 * @struct keyhole_entry_t
 *
 * @brief Holds physical to linear PTE mappings
 *
 * It implements an LRU list and a hash list entry.
 */
typedef struct PACKED keyhole_entry_s
{
    uint64_t  mapped_pa;  /**< mapped physical address of this keyhole entry */
    /**
     * lru_next and lru_prev present an LRU doubly linked-list.
     */
    uint16_t  lru_next;
    uint16_t  lru_prev;
    uint16_t  hash_list_next;  /**< next element in hash list */
    /**
     * state can be KH_ENTRY_FREE or KH_ENTRY_MAPPED or KH_ENTRY_CAN_BE_REMOVED.
     */
    uint8_t   state;
    bool_t    is_writable;  /**< is PTE set to be Read-only or RW */
    bool_t    is_wb_memtype; /**< is PTE should be with WB or UC memtype */

    uint64_t  ref_count; /** reference count of pages mapped in keyhole manager */
} keyhole_entry_t;


#define MAX_KEYHOLE_PER_LP 128
/**
 * @struct keyhole_state_t
 *
 * @brief Holds the state of the keyhole mappings for this lp
 *
 * It implements an LRU list and a hash list.
 */
typedef struct PACKED keyhole_state_s
{
    /**
     * Each index in the keyhole_array presents an offset of the mapped linear address.
     * The array also implement and LRU doubly linked-list.
     */
    keyhole_entry_t keyhole_array[MAX_KEYHOLE_PER_LP];
    /**
     * A hash table, its index represents the index in the keyhole_array
     * that it is mapped to.
     */
    uint16_t  hash_table[MAX_KEYHOLE_PER_LP];
    /**
     * lru_head and lru_tail present the index of the keyhole_array LRU
     * doubly linked-list.
     */
    uint16_t  lru_head;
    uint16_t  lru_tail;

    /**
     * total_ref_count counts the total amount of non-statically mapped linear addresses.
     * Incremented on map_pa and decremented on free_la
     */
    uint64_t  total_ref_count;
} keyhole_state_t;

#define ACTIVE_VMCS_NONE        ((uint16_t)(~0U))

/**
 * @struct vp_ctx_t
 *
 * @brief stores the context of the current running VP after VMEXIT
 */
typedef struct PACKED vp_ctx_s
{
    /**
     * TDR structure context, physical address, linear address and linear address of PAMT entry
     * It is set before each TD entry
     */
    tdr_t *               tdr;
    pamt_entry_t *        tdr_pamt_entry;
    pa_t                  tdr_pa;

    /**
     * TDVPR structure context, physical address, linear address and linear address of PAMT entry
     * It is set before each TD entry
     */
    tdvps_t *             tdvps;
    pamt_entry_t *        tdvpr_pamt_entry;
    pamt_block_t          tdvpr_pamt_block;
    pa_t                  tdvpr_pa;

    /**
     * TDCS structure context, linear address.
     * It is set before each TD entry
     */
    tdcs_t *              tdcs;
    /**
     * TDVPR PA of the last VCPU that ran on this LP
     */
    pa_t                  last_tdvpr_pa;

    /**
     * TD states to avoid accessing TDCS and TDVPS in case of a memory integrity error
     */
    td_param_attributes_t attributes;
    uint64_t              xfam;
    bool_t                xfd_supported;
    uint64_t              ia32_perf_global_status;

    /**
     *  Indicates that a bus lock as been reported on VM exit from a TD VCPU, as part of
     *  another exit reason, but the information has not yet been delivered to the host VMM in a TD exit.
     */
    bool_t                bus_lock_preempted;

    /**
     * Currently active VMCS (L1 or any of L2)
     */
    uint16_t              active_vmcs;

} vp_ctx_t;

#define LFSR_INIT_VALUE 0xFEEDBEAF

typedef struct PACKED stepping_s
{
    // Stepping data
    bool_t            in_inst_step_mode;    // Indicates that the TDX module is stepping through instructions in a TD vCPU
    uint32_t          num_inst_step;        // In instr step mode - number of TD vCPUs instructions left to execute until exiting to VMM
    uint64_t          saved_cr8;            // Saved value of LP's CR8 during stepping
    bool_t            nmi_exit_occured;     // Indicates that stepping has started due to NMI
    bool_t            init_exit_occured;    // Indicates that stepping has started due to INIT
    uint32_t          lfsr_value;           // Random number
    uint64_t          last_entry_tsc;       // TSC at which this TD vCPU has been entered last time (or 0, if not yet entered)
    uint64_t          guest_rip_on_tdentry; // RIP with which this TD vCPU has been entered last time (or -1, if not yet entered)
} stepping_t;

/**
 * @struct tdx_module_local_t
 *
 * @brief Per logical processor (lp) local data
 */
typedef struct PACKED tdx_module_local_s
{
    gprs_state_t          vmm_regs; /**< vmm host saved GPRs */
    gprs_state_t          td_regs;  /**< td guest saved GPRs */
    uint64_t              current_td_vm_id;
    lp_info_t             lp_info;
    bool_t                lp_is_init;  /**< is lp initialized */
    bool_t                lp_is_busy;
    ia32_debugctl_t       ia32_debugctl_value;
    uint64_t              non_faulting_msr_value;
    bool_t                reset_avx_state; /**< flag is set to true by invoking AES-GCM flows */

    vp_ctx_t              vp_ctx;

    stepping_t            single_step_def_state;

    non_extended_state_t  vmm_non_extended_state;
    keyhole_state_t       keyhole_state;

    void*                 local_data_fast_ref_ptr;
    void*                 global_data_fast_ref_ptr;
    void*                 sysinfo_fast_ref_ptr;

    uint64_t              host_rsp;
    uint64_t              host_ssp;
    uint64_t              host_gs_base;

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    uint32_t              local_dbg_msg_num;
#endif

} tdx_module_local_t;
tdx_static_assert(offsetof(tdx_module_local_t, vmm_regs) == TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET, tdx_module_local_t);
tdx_static_assert(offsetof(tdx_module_local_t, td_regs) == TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET, tdx_module_local_t);
tdx_static_assert(offsetof(tdx_module_local_t, current_td_vm_id) == TDX_LOCAL_DATA_CURRENT_TD_VM_ID_OFFSET, tdx_module_local_t);


#endif // __TDX_LOCAL_DATA_H_INCLUDED__

