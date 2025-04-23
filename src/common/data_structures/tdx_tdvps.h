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
 * @file tdx_tdvps.h
 * @brief TDVPS definitions
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDX_TDVPS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDX_TDVPS_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "tdx_api_defs.h"

#include "x86_defs/x86_defs.h"
#include "x86_defs/msr_defs.h"

#include "helpers/error_reporting.h"
#include "debug/tdx_debug.h"

#define MAX_VCPUS           0xFFFF

typedef enum
{
    TDVPS_VE_INFO_PAGE_INDEX = 0,
    TDVPS_VMCS_PAGE_INDEX    = 1,
    TDVPS_VAPIC_PAGE_INDEX   = 2,

    L2_VMCS_BASE_INDEX        = 6,
    L2_MSR_BITMAPS_BASE_INDEX = 7,
    L2_MSR_REQUEST_BASE_INDEX = 8,
    TDVPS_PAGES_PER_L2_VM     = 3,    // Number of TDVPS pages per L2 VM

    L2_VMCS_1_INDEX           = 6,
    L2_MSR_BITMAPS_1_INDEX    = 7,
    L2_MSR_REQUEST_1_INDEX    = 8,
    L2_VMCS_2_INDEX           = 9,
    L2_MSR_BITMAPS_2_INDEX    = 10,
    L2_MSR_REQUEST_2_INDEX    = 11,
    L2_VMCS_3_INDEX           = 12,
    L2_MSR_BITMAPS_3_INDEX    = 13,
    L2_MSR_REQUEST_3_INDEX    = 14,

    MIN_TDVPS_PAGES           = 6,
    MAX_TDVPS_PAGES          = 15

} tdvps_pages_e;

typedef enum
{
    HOST_ROUTED_NONE     = 0, // L2 TD exit not routed to L1
    HOST_ROUTED_ASYNC    = 1, // L2 async TD exit routed to L1 (TDH.VP.ENTER with RESUME_L1 set)
    HOST_ROUTED_TDVMCALL = 2  // L2 sync (TDG.VP.VMCALL) TD exit routed to L1 (TDH.VP.ENTER with RESUME_L1 set)
} l2_exit_host_routing_e;

#define MAX_VMS           4
#define MAX_L2_VMS        (MAX_VMS - 1)

typedef union l2_vcpu_ctrl_u
{
    struct
    {
        uint64_t enable_shared_eptp : 1,   // Bit 0
                 enable_tdvmcall    : 1,   // Bit 1
                 enable_extended_ve : 1,   // Bit 2
                 reserved           : 61;  // Bits 63:3
    };
    uint64_t raw;
} l2_vcpu_ctrl_t;
tdx_static_assert(sizeof(l2_vcpu_ctrl_t) == 8, l2_vcpu_ctrl_t);

#define ALLOWED_L2_VCPU_CTLS            (BIT(0) | BIT(1))

typedef union l2_vm_debug_ctls_u
{
    struct
    {
        uint64_t td_exit_on_l1_to_l2   : 1,   // Bit 0: If set, TDG.VP.ENTER will TD - exit instead of entering an L2 VM
                 td_exit_on_l2_to_l1   : 1,   // Bit 1: If set, VM exit from L2 which results in an L2->L1 exit is mutated into a TD exit
                 td_exit_on_l2_vm_exit : 1,   // Bit 2: All L2 VM exits (except fatal errors) will result in a TD exit
                 reserved              : 61;  // Bits 63:1
    };
    uint64_t raw;
} l2_vm_debug_ctls_t;
tdx_static_assert(sizeof(l2_vm_debug_ctls_t) == 8, l2_vm_debug_ctls_t);

#define ALLOWED_L2_VM_DEBUG_CTLS            (BIT(0) | BIT(1) | BIT(2))

_STATIC_INLINE_ uint32_t get_tdvps_vmcs_page_index(uint16_t vm_id)
{
    tdx_debug_assert(vm_id < MAX_VMS);

    uint32_t index = (vm_id == 0) ? TDVPS_VMCS_PAGE_INDEX :
                     L2_VMCS_BASE_INDEX + ((vm_id - 1) * TDVPS_PAGES_PER_L2_VM);

    tdx_debug_assert(index < MAX_TDVPS_PAGES);

    return index;
}

_STATIC_INLINE_ uint32_t get_tdvps_msr_bitmap_index(const uint16_t vm_id)
{
    tdx_debug_assert(vm_id < MAX_VMS && vm_id > 0);
    const uint32_t index = L2_MSR_BITMAPS_1_INDEX + ((vm_id - 1) * TDVPS_PAGES_PER_L2_VM);
    tdx_debug_assert(index < MAX_TDVPS_PAGES);
    return index;
}

_STATIC_INLINE_ bool_t is_l2_msr_bitmap_page_index(uint64_t tdcx_index_num)
{
    return ((tdcx_index_num == L2_MSR_BITMAPS_1_INDEX) ||
            (tdcx_index_num == L2_MSR_BITMAPS_2_INDEX) ||
            (tdcx_index_num == L2_MSR_BITMAPS_3_INDEX) ||
            (tdcx_index_num == L2_MSR_REQUEST_1_INDEX) ||
            (tdcx_index_num == L2_MSR_REQUEST_2_INDEX) ||
            (tdcx_index_num == L2_MSR_REQUEST_3_INDEX));
}

#define VCPU_UNINITIALIZED  0x0
#define VCPU_READY          0x2
#define VCPU_ACTIVE         0x4
#define VCPU_DISABLED       0x8
#define VCPU_IMPORT         0x10

#define LAST_EXIT_ASYNC_FAULT 0x0
#define LAST_EXIT_ASYNC_TRAP  0x1
#define LAST_EXIT_TDVMCALL    0x2

#define SIZE_OF_VE_INFO_STRUCT_IN_BYTES 128
#define OFFSET_OF_VE_INFO_STRUCT_IN_BYTES 0
#define TDVPS_VE_INFO_VALID_CONTENT     0xFFFFFFFF // a 32-bit value
#define TDVPS_VE_INFO_NOT_VALID         0

#define VE_INFO_CONTENTS_VALID          0xFFFFFFFF

#pragma pack(push, 1)

/**
 * @struct tdvps_ve_info_t
 *
 * @brief Holds the ve info
 */
typedef struct tdvps_ve_info_s
{
    uint32_t  exit_reason;
    uint32_t  valid; /**< 0xFFFFFFFF:  valid, 0x00000000:  not valid */
    uint64_t  exit_qualification;
    uint64_t  gla;
    uint64_t  gpa;
    uint16_t  eptp_index;

    // Non-Architectural Fields

    uint8_t              reserved0[2];
    union
    {
        struct
        {
            uint32_t instruction_length;
            uint32_t instruction_info;
        };
        uint64_t inst_len_and_info;
    };
    uint8_t              reserved1[84];
} tdvps_ve_info_t;
tdx_static_assert(sizeof(tdvps_ve_info_t) == SIZE_OF_VE_INFO_STRUCT_IN_BYTES, tdvps_ve_info_t);

/**
 * @struct vcpu_state__t
 *
 * @brief vcpu state details is a virtual TDVPS field. It is calculated on read
 */
typedef union vcpu_state_s
{
    struct
    {
        uint64_t vmxip    : 1;
        uint64_t reserved : 63;
    };
    uint64_t raw;
}vcpu_state_t;

#define SIZE_OF_TDVPS_MANAGEMENT_STRUCT_IN_BYTES 1536
#define EPF_GPA_LIST_SIZE 32
#define OFFSET_OF_TDVPS_MANAGEMENT_IN_BYTES      0x100

/**
 * @struct tdvps_management_t
 *
 * @brief Holds the TDVPS management fields
 */
typedef struct tdvps_management_s
{
    uint8_t   state; /**< The activity state of the VCPU */
    uint8_t   last_td_exit; /** Type of the last TD exit **/

    /**
     * Sequential index of the VCPU in the parent TD. VCPU_INDEX indicates the order
     * of VCPU initialization (by TDHVPINIT), starting from 0, and is made available to
     * the TD via TDINFO. VCPU_INDEX is in the range 0 to (MAX_VCPUS_PER_TD - 1)
     */
    uint32_t  vcpu_index;

    uint8_t   reserved_0;

    uint8_t   num_tdvps_pages; /**< A counter of the number of child TDCX pages associated with this TDVPR */

    /**
     * An array of (TDVPS_PAGES) physical address pointers to the TDCX pages
     *
     * PA is without HKID bits
     * Page 0 is the PA of the TDVPR page
     * Pages 1,2,... are PAs of the TDCX pages
    */
    uint64_t  tdvps_pa[MAX_TDVPS_PAGES];
    uint8_t   reserved_1[72];
    /**
     * The (unique hardware-derived identifier) of the logical processor on which this VCPU
     * is currently associated (either by TDHVPENTER or by other VCPU-specific SEAMCALL flow).
     * A value of 0xffffffff (-1 in signed) indicates that VCPU is not associated with any LP.
     * Initialized by TDHVPINIT to the LP_ID on which it ran
     */
    uint32_t  assoc_lpid;
    uint8_t   reserved_2[4];

    /**
     * The value of TDCS.TD_EPOCH, sampled at the time this VCPU entered TDX non-root mode
     */
    uint64_t  vcpu_epoch;

    bool_t    cpuid_supervisor_ve;
    bool_t    cpuid_user_ve;
    uint8_t   reserved_3[2]; /**< Reserved for aligning the next field */

    uint32_t  export_count;
    uint64_t  last_exit_tsc;

    bool_t    pend_nmi;

    // Flags that on the last VM exit NMI unblocking due to IRET was indicated
    bool_t    nmi_unblocking_due_to_iret;
    uint8_t   reserved_4[6]; /**< Reserved for aligning the next field */

    uint64_t  xfam;
    uint8_t   last_epf_gpa_list_idx;
    uint8_t   possibly_epf_stepping;

    uint8_t   reserved_5[6];

    uint64_t  hp_lock_busy_start;
    bool_t    hp_lock_busy;

    uint8_t   reserved_6[5]; /**< Reserved for aligning the next field */

    uint64_t  last_seamdb_index;
    uint16_t  curr_vm;
    uint8_t    l2_exit_host_routed;
    uint8_t   reserved_7[1];

    bool_t    vm_launched[MAX_VMS];
    bool_t    lp_dependent_hpa_updated[MAX_VMS];
    bool_t    module_dependent_hpa_updated[MAX_VMS];

    uint8_t   reserved_8[2];

    l2_vcpu_ctrl_t  l2_ctls[MAX_VMS];
    l2_vm_debug_ctls_t  l2_debug_ctls[MAX_VMS];

    uint64_t  tsc_deadline[MAX_VMS];

    uint64_t  shadow_tsc_deadline[MAX_VMS];

    // Base values of CR0/4 controls
    uint64_t  base_l2_cr0_guest_host_mask;
    uint64_t  base_l2_cr0_read_shadow;
    uint64_t  base_l2_cr4_guest_host_mask;
    uint64_t  base_l2_cr4_read_shadow;

    uint64_t  shadow_cr0_guest_host_mask[MAX_VMS]; // Index 0 is not used - L2 only
    uint64_t  shadow_cr0_read_shadow[MAX_VMS];     // Index 0 is not used - L2 only
    uint64_t  shadow_cr4_guest_host_mask[MAX_VMS]; // Index 0 is not used - L2 only
    uint64_t  shadow_cr4_read_shadow[MAX_VMS];     // Index 0 is not used - L2 only
    uint32_t  shadow_notify_window[MAX_VMS];
    uint64_t  shadow_pid_hpa;

    uint8_t   reserved_9[24];

    uint32_t  shadow_pinbased_exec_ctls;

    uint8_t   reserved_10[12];

    uint32_t  shadow_ple_gap[MAX_VMS];
    uint32_t  shadow_ple_window[MAX_VMS];
    uint16_t  shadow_posted_int_notification_vector;

    uint8_t   reserved_11[6];

    uint32_t  shadow_procbased_exec_ctls2[MAX_VMS];
    uint64_t  shadow_shared_eptp[MAX_VMS];

    uint64_t  l2_enter_guest_state_gpa[MAX_VMS];
    uint64_t  l2_enter_guest_state_hpa[MAX_VMS];

    uint64_t  ve_info_gpa[MAX_VMS];
    uint64_t  ve_info_hpa[MAX_VMS];

    uint64_t  l2_vapic_gpa[MAX_VMS];
    uint64_t  l2_vapic_hpa[MAX_VMS];

    uint8_t   reserved_12[608]; /**< Reserved for aligning the next field */
} tdvps_management_t;
tdx_static_assert(sizeof(tdvps_management_t) == SIZE_OF_TDVPS_MANAGEMENT_STRUCT_IN_BYTES, tdvps_management_t);

#define OFFSET_OF_CPUID_CTRL_IN_BYTES       0x900
#define NUM_OF_CPUID_CTRL_ENTRIES           128

/**
 * @struct cpuid_control_t
 *
 * @brief Bit 0: When set, the Intel TDX module injects #VE on guest TD execution of CPUID in CPL = 0.
 *        Bit 1: When set, the Intel TDX module injects #VE on guest TD execution of CPUID in CPL > 0.
 *        Other:  Reserved, must be 0.
 */
typedef union cpuid_control_s
{
    struct
    {
        uint8_t supervisor_ve : 1;
        uint8_t user_ve       : 1;
        uint8_t reserved      : 6;
    };
    uint8_t raw;
} cpuid_control_t;

#define SIZE_OF_TDVPS_GUEST_STATE_IN_BYTES 256 // Include Guest state & Guest GPR state (each 128 Byte)
#define OFFSET_OF_TDVPS_GUEST_STATE_IN_BYTES (OFFSET_OF_CPUID_CTRL_IN_BYTES + NUM_OF_CPUID_CTRL_ENTRIES)

/**
 * @struct tdvps_guest_state_t
 *
 * @brief Holds the state of the guests registers
 */
typedef struct tdvps_guest_state_s
{
    gprs_state_t gpr_state;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t xcr0;
    uint64_t cr2;
    uint8_t  reserved[8]; /**< Reserved for aligning the next field */
    uint128_t  iwk_enckey[2]; /**< Last KeyLocker IWK loader.  Cache line aligned */
    uint128_t  iwk_intkey;
    loadiwkey_ctl_t iwk_flags;
    uint8_t  reserved_2[4]; /**< Reserved for aligning the next field */
    vcpu_state_t vcpu_state_details;
} tdvps_guest_state_t;
tdx_static_assert(sizeof(tdvps_guest_state_t) == SIZE_OF_TDVPS_GUEST_STATE_IN_BYTES, tdvps_guest_state_t);

#define SIZE_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES   560
#define OFFSET_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES (OFFSET_OF_TDVPS_GUEST_STATE_IN_BYTES+SIZE_OF_TDVPS_GUEST_STATE_IN_BYTES)

/**
 * @struct tdvps_guest_msr_state_t
 *
 * @brief Holds the MSRs
 */
typedef struct tdvps_guest_msr_state_s
{
    uint64_t ia32_spec_ctrl;
    uint64_t ia32_umwait_control;
    uint64_t ia32_tsx_ctrl;
    uint64_t ia32_perfevtsel[NUM_PMC];
    uint64_t ia32_offcore_rsp[2];
    uint64_t ia32_xfd;
    uint64_t ia32_xfd_err;
    uint64_t ia32_fixed_ctr[MAX_FIXED_CTR];
    uint64_t ia32_perf_metrics;
    uint64_t ia32_fixed_ctr_ctrl;
    uint64_t ia32_perf_global_status;
    uint64_t ia32_pebs_enable;
    uint64_t ia32_pebs_data_cfg;
    uint64_t ia32_pebs_ld_lat;
    uint64_t ia32_pebs_frontend;
    uint64_t ia32_a_pmc[NUM_PMC];
    uint64_t ia32_ds_area;
    uint64_t ia32_fixed_ctr_reload_cfg[4];
    uint64_t ia32_fixed_ctr_ext[4];
    uint64_t ia32_a_pmc_reload_cfg[NUM_PMC];
    uint64_t ia32_a_pmc_ext[NUM_PMC];
    uint64_t ia32_xss;
    uint64_t ia32_lbr_depth;
    uint64_t ia32_uarch_misc_ctl;
    uint64_t ia32_star;
    uint64_t ia32_lstar;
    uint64_t ia32_fmask;
    uint64_t ia32_kernel_gs_base;
    uint64_t ia32_tsc_aux;
} tdvps_guest_msr_state_t;
tdx_static_assert(sizeof(tdvps_guest_msr_state_t) == SIZE_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES, tdvps_guest_msr_state_t);


#define SIZE_OF_TD_VMCS_IN_BYTES   (TDX_PAGE_SIZE_IN_BYTES/2)
#define OFFSET_OF_TDVPS_TD_VMCS_IN_BYTES 0x1000

/**
 * @struct tdvps_td_vmcs_t
 *
 * @brief Holds the TD VMCS page
 */
typedef struct tdvps_td_vmcs_s
{
    uint8_t td_vmcs[SIZE_OF_TD_VMCS_IN_BYTES]; /**< Not mapped in TDX-SEAM LA, access by VMREAD/VMWRITE.*/
} tdvps_td_vmcs_t;
tdx_static_assert(sizeof(tdvps_td_vmcs_t) == SIZE_OF_TD_VMCS_IN_BYTES, tdvps_td_vmcs_t);


#define SIZE_OF_TDVPS_VAPIC_STRUCT_IN_BYTES TDX_PAGE_SIZE_IN_BYTES
#define OFFSET_OF_TDVPS_VAPIC_STRUCT              0x2000
#define APIC_T_SIZE _1KB

#define PPR_INDEX 0xA0

/**
 * @struct tdvps_vapic_t
 *
 * @brief Holds the Virtual APIC Page
 */
typedef union  tdvps_vapic_s
{
    struct
    {
        uint8_t apic[APIC_T_SIZE]; /**< Virtual APIC Page */
        uint8_t reserved[TDX_PAGE_SIZE_IN_BYTES - APIC_T_SIZE];
    };
    uint8_t raw[TDX_PAGE_SIZE_IN_BYTES];
} tdvps_vapic_t;
tdx_static_assert(sizeof(tdvps_vapic_t) == SIZE_OF_TDVPS_VAPIC_STRUCT_IN_BYTES, tdvps_vapic_t);


#define SIZE_OF_TDVPS_GUEST_EXT_STATE_IN_BYTES (3*TDX_PAGE_SIZE_IN_BYTES)
#define OFFSET_OF_TDVPS_GUEST_EXT_STATE     0x3000

/**
 * @struct tdvps_guest_extension_state_t
 *
 * @brief Holds the xbuf
 */
typedef struct tdvps_guest_extension_state_s
{
    union
    {
        xsave_area_t xbuf; /**< XSAVES buffer */
        uint8_t max_size[SIZE_OF_TDVPS_GUEST_EXT_STATE_IN_BYTES];
    };
} tdvps_guest_extension_state_t;
tdx_static_assert(sizeof(tdvps_guest_extension_state_t) == SIZE_OF_TDVPS_GUEST_EXT_STATE_IN_BYTES, tdvps_guest_extension_state_t);

#define SIZE_OF_TDVPS_L2_CONTROL_IN_BYTES (3*TDX_PAGE_SIZE_IN_BYTES)
#define OFFSET_OF_TDVPS_L2_CONTROL (3*TDX_PAGE_SIZE_IN_BYTES)
/**
 * @struct l2_vm_ctrl_t
 *
 * @brief Holds:
 *          1) VMCS for controling the VCPU operation in L2 VM
 *          2) MSR exit bitmaps page, controling L2 VM RDMSR/WRMSR VM exit
 *          3) Shadow MSR exit bitmaps page, defining the L2 VM policy for handling MSR access, set by the L1 VMM
 */
typedef struct l2_vm_ctrl_s
{
    uint8_t  l2_vmcs[SIZE_OF_TD_VMCS_IN_BYTES];
    uint8_t  reserved[SIZE_OF_TD_VMCS_IN_BYTES];
    uint64_t l2_msr_bitmaps[512];
    uint64_t l2_shadow_msr_bitmaps[512];
} l2_vm_ctrl_t;
tdx_static_assert(sizeof(l2_vm_ctrl_t) == SIZE_OF_TDVPS_L2_CONTROL_IN_BYTES, l2_vm_ctrl_t);

/**
 * @struct tdvps_t
 *
 * @brief Holds the 6 pages of TDVPS. The pages need to be contiguous in physical memory
 */
typedef struct ALIGN(TDX_PAGE_SIZE_IN_BYTES) tdvps_s
{
    tdvps_ve_info_t                ve_info;
    uint8_t                        reserved_0[128]; /**< Reserved for aligning the next field */
    tdvps_management_t             management;
    uint64_t                       last_epf_gpa_list[EPF_GPA_LIST_SIZE];  // Array of GPAs that caused EPF at this TD vCPU instruction

    uint8_t                        reserved_1[256]; /**< Reserved for aligning the next field */

    cpuid_control_t                cpuid_control[NUM_OF_CPUID_CTRL_ENTRIES];
    tdvps_guest_state_t            guest_state;
    tdvps_guest_msr_state_t        guest_msr_state;
    uint8_t                        reserved_2[848]; /**< Reserved for aligning the next field */

    tdvps_td_vmcs_t                td_vmcs;
    uint8_t                        reserved_3[TDX_PAGE_SIZE_IN_BYTES - SIZE_OF_TD_VMCS_IN_BYTES]; /**< Reserved for aligning the next field */

    tdvps_vapic_t                  vapic;
    tdvps_guest_extension_state_t  guest_extension_state;

    l2_vm_ctrl_t                   l2_vm_ctrl[MAX_L2_VMS];
} tdvps_t;
tdx_static_assert(sizeof(tdvps_t) == (MAX_TDVPS_PAGES*TDX_PAGE_SIZE_IN_BYTES), tdvps_t);
tdx_static_assert(offsetof(tdvps_t, ve_info) == OFFSET_OF_VE_INFO_STRUCT_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, management) == OFFSET_OF_TDVPS_MANAGEMENT_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, cpuid_control) == OFFSET_OF_CPUID_CTRL_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, guest_state) == OFFSET_OF_TDVPS_GUEST_STATE_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, guest_msr_state) == OFFSET_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, td_vmcs) == OFFSET_OF_TDVPS_TD_VMCS_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, vapic) == OFFSET_OF_TDVPS_VAPIC_STRUCT, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, guest_extension_state) == OFFSET_OF_TDVPS_GUEST_EXT_STATE, tdvps_t);


typedef union attr_flags_u
{
    struct
    {
        uint16_t reserved  : 15;
        uint16_t do_invept : 1;
    } vm_arr[MAX_VMS];
    uint16_t raw_vm[MAX_VMS];
    gpa_attr_t gpa_attr;
    uint64_t raw;
} attr_flags_t;
tdx_static_assert(sizeof(attr_flags_t) == 8, attr_flags_t);

#pragma pack(pop)

#endif /* SRC_COMMON_DATA_STRUCTURES_TDX_TDVPS_H_ */
