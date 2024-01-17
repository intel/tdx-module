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
 * @file tdx_control_structure.h
 * @brief TDR & TDCS definitions
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TD_CONTROL_STRUCTURES_H_
#define SRC_COMMON_DATA_STRUCTURES_TD_CONTROL_STRUCTURES_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "helpers/tdx_locks.h"
#include "helpers/migration.h"
#include "helpers/service_td.h"
#include "crypto/sha384.h"
#include "crypto/aes_gcm.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_tdvps.h"
#include "auto_gen/op_state_lookup.h"
#include "memory_handlers/pamt_manager.h"

#define NUM_RTMRS          4

/* MIN_MIGS: 1 forward and 1 backward migration streams */
#define MIN_MIGS   2

/* MAX_MIGS: Maximum total number of migration streams */
#define MAX_MIGS   512

// MAX_F_MIGS: Maximum forward migration streams
#define MAX_F_MIGS 511

/**
 * TD Life Cycle State
 */
typedef enum
{
    TD_HKID_ASSIGNED      = 0x0,
    TD_KEYS_CONFIGURED    = 0x1,
    TD_BLOCKED            = 0x2,
    TD_TEARDOWN           = 0x3
} td_lifecycle_state_t;
tdx_static_assert(sizeof(td_lifecycle_state_t) == 4, td_lifecycle_state_t);

/**
 * @brief Indices of TDCS pages
 */
typedef enum
{
    MSR_BITMAPS_PAGE_INDEX = 2,
    SEPT_ROOT_PAGE_INDEX   = 3,
    ZERO_PAGE_INDEX        = 4,
    MIGSC_LINKS_PAGE_INDEX = 5,

    L2_SEPT_ROOT_PAGE_BASE_INDEX = 6,  // First L2 SEPT Root page
    L2_SEPT_ROOT_PAGE_BASE_INC   = 1,  // How much the base index is incremented for each VM

    L2_SEPT_ROOT_1_PAGE_INDEX    = 6,
    L2_SEPT_ROOT_2_PAGE_INDEX    = 7,
    L2_SEPT_ROOT_3_PAGE_INDEX    = 8,

    TDCS_PAGES_PER_L2_VM         = 1,  // Additional TDCS pages per L2 VM

    MAX_NUM_TDCS_PAGES           = 9,  // Maximum total number of TDCS pages

    MIN_NUM_TDCS_PAGES           = 6,  // Minimum total number of TDCS pages

    MAX_MAPPED_TDCS_PAGES  = MAX_NUM_TDCS_PAGES

} tdcs_page_index_t;

_STATIC_INLINE_ uint32_t get_tdcs_sept_root_page_index(uint16_t vm_id)
{
    uint32_t index = (vm_id == 0) ? SEPT_ROOT_PAGE_INDEX :
                     L2_SEPT_ROOT_PAGE_BASE_INDEX + ((vm_id - 1) * L2_SEPT_ROOT_PAGE_BASE_INC);

    tdx_debug_assert(index < MAX_NUM_TDCS_PAGES);

    return index;
}

/**
 * @struct tdr_td_management_fields_t
 *
 * @brief Holds the management fields of TD
 */
typedef struct tdr_td_management_fields_s
{
    bool_t    fatal; /**< Indicates a fatal error */

    ALIGN(4) uint32_t  num_tdcx; /**< Number of TDCX pages that have been added by TDHMNGADDCX */
    /**
     * The number of child 4KB pages (including opaque control structure pages)
     * associated with this TDR
     */
    ALIGN(8) uint64_t  chldcnt;
    ALIGN(4) td_lifecycle_state_t  lifecycle_state;
    ALIGN(8) uint64_t  tdcx_pa[MAX_NUM_TDCS_PAGES]; /**< Physical addresses of the TDCX pages */

    ALIGN(32) uint256_t td_uuid;

    uint8_t   reserved_2[128];
} tdr_td_management_fields_t;
tdx_static_assert(sizeof(tdr_td_management_fields_t) == 256, tdr_td_management_fields_t);


/**
 * @struct tdr_key_managment_fields_t
 *
 * @brief Holds the key management fields of TD
 */
typedef struct tdr_key_managment_fields_s
{
    uint16_t hkid;      /**< Holds private key hkid */
    /**
     * Bitmap that indicates on which package TDHKEYCONFIG was
     * executed successfully using this private key entry.
     */
    ALIGN(8) uint64_t pkg_config_bitmap;

    uint8_t reserved[48];
} tdr_key_managment_fields_t;
tdx_static_assert(sizeof(tdr_key_managment_fields_t) == 64, tdr_key_managment_fields_t);

/**
 * @struct tdr_td_preserving_fields_t
 *
 * @brief Holds the TD preserving fields of TD
 */
typedef struct tdr_td_preserving_fields_s
{
    uint16_t handoff_version;
    ALIGN(8) uint64_t seamdb_index;
    uint256_t seamdb_nonce;

    uint8_t reserved[16];
} tdr_td_preserving_fields_t;
tdx_static_assert(sizeof(tdr_td_preserving_fields_t) == 64, tdr_td_preserving_fields_t);

#define TDX_SIZE_OF_TDR_STRUCTS (sizeof(tdr_td_management_fields_t) + \
                                 sizeof(tdr_key_managment_fields_t) + \
                                 sizeof(tdr_td_preserving_fields_t))

/**
 * @struct tdr_t
 *
 * @brief TDR is the root control structure of a guest TD.
 *
 * TDR occupies a single 4KB naturally aligned page of memory.
 * It is the first TD page to be allocated and the last to be removed.
 */
typedef struct ALIGN(TDX_PAGE_SIZE_IN_BYTES) tdr_s
{
    tdr_td_management_fields_t        management_fields;
    tdr_key_managment_fields_t        key_management_fields;
    tdr_td_preserving_fields_t        td_preserving_fields;

    uint8_t reserved[TDX_PAGE_SIZE_IN_BYTES - TDX_SIZE_OF_TDR_STRUCTS];

} tdr_t;
tdx_static_assert(sizeof(tdr_t) == TDX_PAGE_SIZE_IN_BYTES, tdr_t);


/**
 * @struct tdcs_management_fields_t
 *
 * @brief Holds the management fields of TDCS
 */
typedef struct tdcs_management_fields_s
{
    /**
     * The number of VCPUs that are either in TDX non-root mode (TDVPS.STATE == VCPU_ACTIVE)
     * or are ready to run (TDVPS.STATE == VCPU_READY).
     * This includes VCPUs that have been successfully initialized (by TDHVPINIT) and
     * have not since started teardown (due to a Triple Fault
     */
    uint32_t num_vcpus;
    /**
     * The number of VCPUS associated with LPs, i.e., the LPs might hold TLB
     * translations and/or cached TD VMCS
     */
    uint32_t num_assoc_vcpus;

    op_state_e         op_state;
    sharex_hp_lock_t   op_state_lock;
    uint8_t            reserved_0[2];

    // Number of L2 VMs
    uint16_t num_l2_vms;
    uint8_t reserved_1[110];

} tdcs_management_fields_t;
tdx_static_assert(sizeof(op_state_e) == 4, op_state_e);
tdx_static_assert(sizeof(tdcs_management_fields_t) == 128, tdcs_management_fields_t);

#define TDX_ATTRIBUTES_SEPT_VE_DIS_SUPPORT BIT(28)

#define TDX_ATTRIBUTES_MIGRATABLE_SUPPORT  BIT(29)

#define TDX_ATTRIBUTES_PKS_SUPPORT   BIT(30)

#define TDX_ATTRIBUTES_PERFMON_SUPPORT   BIT(63)

//  Supported ATTRIBUTES bits depend on the supported features - bits 0 (DEBUG), 29 (migratable), 30 (PKS),
//  63 (PERFMON) and 28 (SEPT VE DISABLE)
#define TDX_ATTRIBUTES_FIXED0 (0x1 | TDX_ATTRIBUTES_MIGRATABLE_SUPPORT | TDX_ATTRIBUTES_PKS_SUPPORT |\
                               TDX_ATTRIBUTES_PERFMON_SUPPORT | TDX_ATTRIBUTES_SEPT_VE_DIS_SUPPORT)
#define TDX_ATTRIBUTES_FIXED1 0x0


#define CONFIG_FLAGS_FIXED0   (BIT(0) | BIT(1) | BIT(2))
#define CONFIG_FLAGS_FIXED1   0x0



#define VIRT_CRYSTAL_CLOCK_FREQUENCY   25000000ULL // Nominal frequency of the core crystal clock in Hz, in CPUID(0x15).ECX = 25MHz
#define VIRT_TSC_FREQUENCY_UNIT        25000000ULL // Virtual TSC frequency is specified in units of 25MHz
#define VIRT_TSC_FREQUENCY_MIN         4           // 100MHz
#define VIRT_TSC_FREQUENCY_MAX         400         // 10 GHz

// The TSC params calculation goes as follows:
//
// 1)  TSC Multiplier Calculation:
//     Goal is to virtualize the TSC frequency as requested.
//     tmp_128b = virt_tsc_frequency * VIRT_TSC_FREQUENCY_UNIT * (1ULL < 48);
//     tsc_multiplier = tmp_128b / native_tsc_frequency;
//
// 2)  TSC Offset Calculation:
//     Goal is to make the virtual TSC start from 0
//     tmp_128b = current_tsc * tsc_multiplier;
//     tsc_offset = -(tmp_128b / (1ULL < 48));
//     The division above is best done as simple shifts:
//         virt_tsc_64b = (tmp_128b_tsc.upper << 16) | (tmp_128b_tsc.lower >> 48);
// Note that we do not care about overflow in this division, since TSC rolls over naturally.
//
// In order to ensure that the first div result won't cause #DE and its result will fit into 64-bit
// we must ensure the following:
//
// virt_tsc_frequency * 25000000 <= VIRT_TSC_FREQUENCY_MAX(400) * 25000000 == 10000000000
// tmp_128b == virt_tsc_frequency * (1ULL < 48) <= 0x2540be400000000000000
//
// Which means that the divisor (native_tsc_frequency) should be:
//
// 0x2540be400000000000000 / native_tsc_freq <= 0xFFFFFFFFFFFFFFFF
// 0x2540be400000000000000 <= 0xFFFFFFFFFFFFFFFF * native_tsc_freq
// native_tsc_freq >= 0x2540be400000000000000 / 0xFFFFFFFFFFFFFFFF
// native_tsc_freq >= 0x2540b + 1 == 0x2540c

#define NATIVE_TSC_FREQUENCY_MIN       0x2540c

#define TDX_SIZE_OF_EPOCH_REFCOUNT_RESERVED_IN_BYTES 4

/**
 * @struct epoch_and_refcount_t
 *
 * @brief Holds the epoch and refcount in a 128bit structure
 */
typedef struct epoch_and_refcount_s
{
    union
    {
        struct
        {
            /**
             * The TD epoch counter. This counter is incremented by the host VMM using the TDHMEMTRACK function
             */
            uint64_t       td_epoch;
            /**
             * Each REFCOUNT counts the number of LPs which may have TLB entries created
             * during a specific TD_EPOCH, and that are currently executing in TDX non-root mode
             */
            uint16_t       refcount[2];
            uint8_t        reserved[TDX_SIZE_OF_EPOCH_REFCOUNT_RESERVED_IN_BYTES];
        };
        uint128_t raw;
    };

} epoch_and_refcount_t;
tdx_static_assert(sizeof(epoch_and_refcount_t) == 16, epoch_and_refcount_t);

/**
 * @struct tdcs_epoch_tracking_fields_t
 *
 * @brief Holds the epoch tracking fields of TDCS
 */
typedef struct tdcs_epoch_tracking_fields_s
{
    epoch_and_refcount_t epoch_and_refcount;

    sharex_lock_t epoch_lock; /**< Protects the update of epoch tracking fields above as a critical region */

    uint8_t  reserved[46];

} tdcs_epoch_tracking_fields_t;
tdx_static_assert(sizeof(tdcs_epoch_tracking_fields_t) == 64, tdcs_epoch_tracking_fields_t);

#define TDX_XFAM_FIXED0 0x0006DBE7ULL
#define TDX_XFAM_FIXED1 0x00000003ULL

#define XBUFF_OFFSETS_NUM   (XCR0_MAX_VALID_BIT+1)

/**
 * @struct cpuid_flags_t
 *
 * @brief Virtual CPUID flags:  save searching CPUID_VALUES during MSR virtualization and TD entry/exit
 */
typedef struct cpuid_flags_s
{
    bool_t monitor_mwait_supported; // virtual CPUID(0x1).ECX[3] (MONITOR)
    bool_t dca_supported;           // virtual CPUID(0x1).ECX[18]
    bool_t tsc_deadline_supported;  // virtual CPUID(0x1).ECX[24] (TSC Deadline)
    bool_t tsx_supported;           // virtual CPUID(0x7, 0x0).EBX[4] && virtual CPUID(0x7, 0x0).EBX[11]
    bool_t waitpkg_supported;       // virtual CPUID(0x7, 0x0).ECX[5]
    bool_t tme_supported;           // virtual CPUID(0x7, 0x0).ECX[13]
    bool_t mktme_supported;         // virtual CPUID(0x7, 0x0).EDX[18]
    bool_t xfd_supported;           // virtual CPUID(0xD, 0x1).EAX[4]
    bool_t ddpd_supported;          // virtual CPUID(0x7, 0x2).EDX[3]
    bool_t la57_supported;          // virtual CPUID(0x7, 0x0).ECX[16]
    uint8_t reserved[22];
} cpuid_flags_t;
tdx_static_assert(sizeof(cpuid_flags_t) == 32, cpuid_flags_t);

typedef union
{
    struct
    {
        uint64_t  notify_ept_faults : 1; // 0 - notify when zero-step attack is suspected
        uint64_t  reserved_63_1     : 63;
    };
    uint64_t  raw;
} notify_enables_t;
tdx_static_assert(sizeof(notify_enables_t) == 8, notify_enables_t);

typedef union
{
    struct
    {
        uint64_t ept_violation_on_l2_sept_walk_failure : 1; // bit 0:  ept violation td exit if a tdcall flow fails l2 ept walk
        uint64_t reserved                              : 63;
    };
    uint64_t  raw;
} vm_ctls_t;
tdx_static_assert(sizeof(vm_ctls_t) == 8, vm_ctls_t);

#define ALLOWED_VM_CTLS             (BIT(0))

typedef union
{
    struct
    {
        uint64_t pending_ve_disable : 1; // Bit 0:  Control the way guest TD access to a PENDING page is processed
        uint64_t reserved           : 63;
    };
    uint64_t raw;
} td_ctls_t;
tdx_static_assert(sizeof(td_ctls_t) == 8, td_ctls_t);

// Limits of HP_LOCK_TIMEOUT, in usec units
#define MIN_HP_LOCK_TIMEOUT_USEC      10000UL      // 10 msec
#define MAX_HP_LOCK_TIMEOUT_USEC      100000000UL  // 100 sec
#define DEFAULT_HP_LOCK_TIMEOUT_USEC  1000000UL    // 1 sec

/**
 * @struct tdcs_execution_control_fields_t
 *
 * @brief Holds the execution fields of TDCS
 */
typedef struct tdcs_execution_control_fields_s
{
    td_param_attributes_t        attributes; /**< TD attributes */
    /**
     * xfam is Extended Features Available Mask.
     * Indicates the extended user and system features which are available for the TD
     */
    ALIGN(8) uint64_t            xfam;
    ALIGN(4) uint32_t            max_vcpus; /**< Maximum number of VCPUs. In practice, limited to 0xFFFF */
    ALIGN(1) bool_t              gpaw; /**< This bit has the same meaning as the TDCS GPAW execution control */
    /**
     * TD-scope Secure EPT pointer. Format is the same as the VMCS EPTP execution control.
     * Copied to each TD VMCS EPTP on TDVPINIT.
     */
    ALIGN(8) ia32e_eptp_t        eptp;
    ALIGN(2) sharex_lock_t       secure_ept_lock; /**< Protects Secure EPT updates */

    /**
     * TD-scope TSC offset execution control.
     * Copied to each TD VMCS TSC-offset execution control on TDHVPINIT
     */
    ALIGN(8) uint64_t            tsc_offset;

    /**
     * TD-scope TSC multiplier execution control.
     * Copied to each TD VMCS TSC-multiplier execution control on TDHVPINIT
     */
    ALIGN(8) uint64_t            tsc_multiplier;
    ALIGN(2) uint16_t            tsc_frequency;
    ALIGN(1) cpuid_flags_t       cpuid_flags;
    ALIGN(4) uint32_t            xbuff_size;
    ALIGN(8) notify_enables_t    notify_enables;
    ALIGN(8) uint64_t            hp_lock_timeout;
    ALIGN(8) vm_ctls_t           vm_ctls[MAX_VMS]; // vm controls, applicable only for l2 vms
    ALIGN(8) uint64_t            ia32_spec_ctrl_mask;
    ALIGN(8) config_flags_t      config_flags;
    ALIGN(8) td_ctls_t           td_ctls;
    uint8_t                      reserved_1[12];
    uint8_t                      cpuid_valid[80];
    ALIGN(16) uint32_t           xbuff_offsets[XBUFF_OFFSETS_NUM];
    uint8_t                      reserved_2[36];
} tdcs_execution_control_fields_t;
tdx_static_assert(sizeof(tdcs_execution_control_fields_t) == 384, tdcs_execution_control_fields_t);
// Validate that the size of gpaw (bool_t) is 1 byte
tdx_static_assert(sizeof(bool_t) == 1, gpaw);

#define TDCS_MEASUREMEMNT_MRTD_CTX_SIZE         352

/**
 * @struct tdcs_measurement_fields_t
 *
 * @brief Holds TDCSs measurement fields
 */
typedef struct tdcs_measurement_fields_s
{
    measurement_t  mr_td; /**< Measurement of the initial contents of the TD */
    measurement_t  mr_config_id; /**< Software defined ID for additional configuration for the SW in the TD */
    measurement_t  mr_owner; /**< Software defined ID for TD's owner */
    /**
     * Software defined ID for owner-defined configuration of the guest TD,
     * e.g., specific to the workload rather than the runtime or OS.
     */

    measurement_t  mr_owner_config; /**< Software defined ID for TD's owner */
    measurement_t  rtmr [NUM_RTMRS]; /**< Array of NUM_RTMRS runtime extendable measurement registers */

    measurement_t  last_teeinfo_hash;

    sharex_hp_lock_t rtmr_lock; /**< Controls concurrent access to the RTMR array */

    bool_t         last_teeinfo_hash_valid;

    uint8_t        reserved_0[45];
    /**
     * Holds the context of an incremental SHA384 calculation on this TD
     */
    sha384_ctx_t   td_sha_ctx;

    uint8_t        reserved_1[TDCS_MEASUREMEMNT_MRTD_CTX_SIZE - sizeof(sha384_ctx_t)];
} tdcs_measurement_fields_t;
tdx_static_assert(sizeof(tdcs_measurement_fields_t) == 832, tdcs_measurement_fields_t);

#define TDX_SIZE_OF_TDCS_MGMT_STRUCTS (sizeof(tdcs_management_fields_t) + \
                                       sizeof(tdcs_execution_control_fields_t) + \
                                       sizeof(tdcs_measurement_fields_t))

/**
 * @struct tdcs_migration_fields_t
 *
 * @brief Holds TDCSs migration fields
 */
typedef struct tdcs_migration_fields_s
{
    bool_t            mig_dec_key_set;
    uint32_t          export_count;
    uint32_t          import_count;
    uint32_t          mig_epoch;
    bepoch_t          bw_epoch;
    uint64_t          total_mb_count;
    key256_t          mig_dec_key;
    key256_t          mig_dec_working_key;
    key256_t          mig_enc_key;
    key256_t          mig_enc_working_key;
    uint16_t          mig_version;
    uint16_t          mig_working_version;
    uint64_t          dirty_count;
    uint64_t          mig_count;
    uint16_t          num_migs;
    uint8_t           reserved_0[2];
    uint32_t          num_migrated_vcpus;
    uint256_t         preimport_uuid;
    sharex_lock_t     mig_lock;

    uint8_t           reserved_1[158];
} tdcs_migration_fields_t;
tdx_static_assert(sizeof(tdcs_migration_fields_t) == 384, tdcs_migration_fields_t);

/**
 * @struct tdcs_virt_msrs_t
 *
 * @brief   Virtual values of VMX enumeration MSRs
 *          These values are calculated on TDH.MNG.INIT and TDH.IMPORT.STATE.IMMUTABLE.
 */
typedef struct tdcs_virt_msrs_s
{
    ia32_vmx_basic_t                virt_ia32_vmx_basic;
    ia32_vmx_misc_t                 virt_ia32_vmx_misc;
    ia32_cr0_t                      virt_ia32_vmx_cr0_fixed0;
    ia32_cr0_t                      virt_ia32_vmx_cr0_fixed1;
    ia32_cr4_t                      virt_ia32_vmx_cr4_fixed0;
    ia32_cr4_t                      virt_ia32_vmx_cr4_fixed1;
    ia32_vmx_allowed_bits_t         virt_ia32_vmx_procbased_ctls2;
    ia32_vmx_ept_vpid_cap_t         virt_ia32_vmx_ept_vpid_cap;
    ia32_vmx_allowed_bits_t         virt_ia32_vmx_true_pinbased_ctls;
    ia32_vmx_allowed_bits_t         virt_ia32_vmx_true_procbased_ctls;
    ia32_vmx_allowed_bits_t         virt_ia32_vmx_true_exit_ctls;
    ia32_vmx_allowed_bits_t         virt_ia32_vmx_true_entry_ctls;
    uint64_t                        virt_ia32_vmx_vmfunc;
    uint64_t                        virt_ia32_vmx_procbased_ctls3;
    uint64_t                        virt_ia32_vmx_exit_ctls2;
    uint64_t                        virt_ia32_arch_capabilities;

    uint8_t                         reserved[128];
} tdcs_virt_msrs_t;
tdx_static_assert(sizeof(tdcs_virt_msrs_t) == 256, tdcs_virt_msrs_t);


/**
 * @struct servtd_binding_t
 *
 * @brief Holds SERVTD binding state
 */
typedef struct PACKED servtd_binding_s
{
    uint8_t             state;
    uint8_t             reserved_0;
    uint16_t            type;
    uint32_t            reserved_1;
    servtd_attributes_t attributes;
    uint256_t           uuid;
    measurement_t       info_hash;
    uint8_t             reserved_2[32];
} servtd_binding_t;
tdx_static_assert(sizeof(servtd_binding_t) == 128, servtd_binding_t);

/**
 * @struct tdcs_service_td_fields_t
 *
 * @brief Holds TDCSs service td fields
 */
typedef struct tdcs_service_td_fields_s
{
    measurement_t              servtd_hash;
    uint16_t                   servtd_num;
    ALIGN(2) sharex_hp_lock_t  servtd_bindings_lock;   // Not in the TDR TDCS spreadsheet

    uint8_t                    reserved_0[80];
    /* Service TD Binding Table
       The table is built as a set of arrays to ease metadata definition and access based
       on the TDR_TDCS spreadsheet.
    */
    ALIGN(16) servtd_binding_t servtd_bindings_table[MAX_SERV_TDS];

    uint8_t                    reserved_1[752];
} tdcs_service_td_fields_t;
tdx_static_assert(sizeof(tdcs_service_td_fields_t) == 1024, tdcs_service_td_fields_t);

#define MAX_POSSIBLE_CPUID_LOOKUP           80

#if (MAX_POSSIBLE_CPUID_LOOKUP < MAX_NUM_CPUID_LOOKUP)
#error "Invalid number of MAX_POSSIBLE_CPUID_LOOKUP"
#endif

/**
 * @struct tdcs_t
 *
 * @brief TDCS is the root control structure of a TD.
 *
 * It controls the operation and holds the state that is global to all the TD’s VCPUs.
 * TDCS must be resident in memory as long any other TD page or control structure is resident in memory.
 * The TDCS occupies a 4KB naturally aligned region of memory.
 *
 */
typedef struct ALIGN(TDX_PAGE_SIZE_IN_BYTES) tdcs_s
{
    /**
     * TDCX First page - Management structures
     */
    tdcs_management_fields_t               management_fields;
    tdcs_execution_control_fields_t        executions_ctl_fields;

    tdcs_epoch_tracking_fields_t           epoch_tracking;
    tdcs_measurement_fields_t              measurement_fields;

    /**
     * Migration Fields
     */
    tdcs_migration_fields_t                migration_fields;

    tdcs_virt_msrs_t                       virt_msrs;

    /**
     * Values returned by the matching configurable CPUID leaf and sub-leaf.
     */
    cpuid_config_return_values_t           cpuid_config_vals[MAX_POSSIBLE_CPUID_LOOKUP];

    /**
     * Service TD Fields
     */
    tdcs_service_td_fields_t               service_td_fields;

    uint8_t                                reserved_io[1280];

    /**
     * TDCX 3rd page - MSR Bitmaps
     */
    ALIGN(4096) uint8_t MSR_BITMAPS[TDX_PAGE_SIZE_IN_BYTES]; /**< TD-scope RDMSR/WRMSR exit control bitmaps */

    /**
     * TDCX 4th page - Secure EPT Root Page
     */
    uint8_t sept_root_page[TDX_PAGE_SIZE_IN_BYTES];

    /**
     * TDCX 5th page - Zero Page
     */
    uint8_t zero_page[TDX_PAGE_SIZE_IN_BYTES];

    /**
     * TDCX 6th page - MIGSC links page
     */
    union
    {
         uint8_t migsc_links_page[TDX_PAGE_SIZE_IN_BYTES];
         migsc_link_t migsc_links[MAX_MIGS];
         struct {
             migsc_link_t b_migsc_link;
             migsc_link_t f_migsc_links[MAX_F_MIGS];
         };
    };

    /**
     * TDCX 7th-9th page - L2 Secure EPT Root
     */
    uint8_t L2_SEPT_ROOT_1[TDX_PAGE_SIZE_IN_BYTES];
    uint8_t L2_SEPT_ROOT_2[TDX_PAGE_SIZE_IN_BYTES];
    uint8_t L2_SEPT_ROOT_3[TDX_PAGE_SIZE_IN_BYTES];

} tdcs_t;
tdx_static_assert(sizeof(tdcs_t) == TDX_PAGE_SIZE_IN_BYTES*MAX_NUM_TDCS_PAGES, tdcs_t);
tdx_static_assert(sizeof_field(tdcs_t, cpuid_config_vals) == 1280, cpuid_config_vals);
tdx_static_assert(offsetof(tdcs_t, cpuid_config_vals) == 0x800, cpuid_config_vals_offset);
tdx_static_assert(offsetof(tdcs_t, MSR_BITMAPS)      == TDX_PAGE_SIZE_IN_BYTES*MSR_BITMAPS_PAGE_INDEX, tdcs_t);
tdx_static_assert(offsetof(tdcs_t, sept_root_page)   == TDX_PAGE_SIZE_IN_BYTES*SEPT_ROOT_PAGE_INDEX, tdcs_t);
tdx_static_assert(offsetof(tdcs_t, zero_page)        == TDX_PAGE_SIZE_IN_BYTES*ZERO_PAGE_INDEX, tdcs_t);
tdx_static_assert(offsetof(tdcs_t, migsc_links_page) == TDX_PAGE_SIZE_IN_BYTES*MIGSC_LINKS_PAGE_INDEX, tdcs_t);



_STATIC_INLINE_ bool_t is_required_tdcs_allocated(tdr_t *tdr_p, uint16_t num_l2_vms)
{
    return (tdr_p->management_fields.num_tdcx >=
            (uint32_t)(MIN_NUM_TDCS_PAGES + (TDCS_PAGES_PER_L2_VM * num_l2_vms)));
}

#endif /* SRC_COMMON_DATA_STRUCTURES_TD_CONTROL_STRUCTURES_H_ */
