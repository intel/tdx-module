// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_control_structure.h
 * @brief TDR & TDCS definitions
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TD_CONTROL_STRUCTURES_H_
#define SRC_COMMON_DATA_STRUCTURES_TD_CONTROL_STRUCTURES_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "helpers/tdx_locks.h"
#include "crypto/sha384.h"
#include "data_structures/tdx_global_data.h"

#define NUM_RTMRS          4


#define TD_HKID_ASSIGNED      0x0
#define TD_KEYS_CONFIGURED    0x1
#define TD_BLOCKED            0x2
#define TD_TEARDOWN           0x3

/**
 * @brief Indices of TDCS pages
 */
typedef enum
{
    MSR_BITMAPS_PAGE_INDEX = 1,
    SEPT_ROOT_PAGE_INDEX   = 2,
    ZERO_PAGE_INDEX        = 3,
    MAX_NUM_TDCS_PAGES     = 4   /**< Total number of TDCS pages */
} tdcs_page_index_t;


/**
 * @struct tdr_td_management_fields_t
 *
 * @brief Holds the management fields of TD
 */
typedef struct tdr_td_management_fields_s
{
    bool_t    init; /**< Indicates that the TDCS has been initialized by TDHMNGINIT */
    bool_t    fatal; /**< Indicates a fatal error */
    uint32_t  num_tdcx; /**< Number of TDCX pages that have been added by TDHMNGADDCX */
    uint64_t  tdcx_pa[MAX_NUM_TDCS_PAGES]; /**< Physical addresses of the TDCX pages */
    /**
     * The number of child 4KB pages (including opaque control structure pages)
     * associated with this TDR
     */
    uint64_t  chldcnt;

    uint8_t   lifecycle_state; /**< The key management state of this TD */
} tdr_td_management_fields_t;


/**
 * @struct tdr_key_managment_fields_t
 *
 * @brief Holds the key management fields of TD
 */
typedef struct tdr_key_managment_fields_s
{
    uint16_t       hkid;      /**< Holds private key hkid */
    /**
     * Bitmap that indicates on which package TDHKEYCONFIG was
     * executed successfully using this private key entry.
     */
    uint64_t       pkg_config_bitmap;
} tdr_key_managment_fields_t;


#define TDX_SIZE_OF_TDR_STRUCTS (sizeof(tdr_td_management_fields_t) + \
                                 sizeof(tdr_key_managment_fields_t))

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

    uint8_t reserved[TDX_PAGE_SIZE_IN_BYTES - sizeof(tdr_td_management_fields_t) -
                     sizeof(tdr_key_managment_fields_t)];
} tdr_t;
tdx_static_assert(sizeof(tdr_t) <= TDX_PAGE_SIZE_IN_BYTES, tdr_t);


/**
 * @struct tdcs_management_fields_t
 *
 * @brief Holds the management fields of TDCS
 */
typedef struct tdcs_management_fields_s
{
    bool_t   finalized; /**< Flags that TD build & measurement has been finalized */
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
} tdcs_management_fields_t;

#define TDX_ATTRIBUTES_SEPT_VE_DIS_SUPPORT BIT(28)

#define TDX_ATTRIBUTES_PKS_SUPPORT   BIT(30)

#define TDX_ATTRIBUTES_PERFMON_SUPPORT   BIT(63)

//  Supported ATTRIBUTES bits depend on the supported features - bits 0 (DEBUG), 30 (PKS), 63 (PERFMON)
//  and 28 (SEPT VE DISABLE)
#define TDX_ATTRIBUTES_FIXED0 (0x1 | TDX_ATTRIBUTES_PKS_SUPPORT | TDX_ATTRIBUTES_PERFMON_SUPPORT |\
                               TDX_ATTRIBUTES_SEPT_VE_DIS_SUPPORT)
#define TDX_ATTRIBUTES_FIXED1 0x0

#define VIRT_TSC_FREQUENCY_UNIT        25000000ULL   // Virtual TSC frequency is specified in units of 25MHz
#define VIRT_TSC_FREQUENCY_MIN         4          // 100MHz
#define VIRT_TSC_FREQUENCY_MAX         400        // 10 GHz

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
    epoch_and_refcount_t      epoch_and_refcount;
    sharex_lock_t             epoch_lock; /**< Protects the update of epoch tracking fields above as a critical region */
} tdcs_epoch_tracking_fields_t;


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
    bool_t dca_supported;       // virtual CPUID(0x1).ECX[18]    
    bool_t waitpkg_supported;   // virtual CPUID(0x7, 0x0).ECX[5]
    bool_t tme_supported;       // virtual CPUID(0x7, 0x0).ECX[13]
    bool_t mktme_supported;     // virtual CPUID(0x7, 0x0).EDX[18]
    bool_t xfd_supported;       // virtual CPUID(0xD, 0x1).EAX[4]
} cpuid_flags_t;

/**
 * @struct tdcs_execution_control_fields_t
 *
 * @brief Holds the execution fields of TDCS
 */
typedef struct tdcs_execution_control_fields_s
{
    td_param_attributes_t attributes; /**< TD attributes */
    /**
     * xfam is Extended Features Available Mask.
     * Indicates the extended user and system features which are available for the TD
     */
    uint64_t                     xfam;
    uint32_t                     max_vcpus; /**< Maximum number of VCPUs. In practice, limited to 0xFFFF */
    bool_t                       gpaw; /**< This bit has the same meaning as the TDCS GPAW execution control */
    /**
     * TD-scope Secure EPT pointer. Format is the same as the VMCS EPTP execution control.
     * Copied to each TD VMCS EPTP on TDVPINIT.
     */
    ia32e_eptp_t                 eptp;
    sharex_lock_t                secure_ept_lock; /**< Protects Secure EPT updates */

    uint16_t                     tsc_frequency;

    /**
     * TD-scope TSC offset execution control.
     * Copied to each TD VMCS TSC-offset execution control on TDHVPINIT
     */
    uint64_t                     tsc_offset;
    /**
     * TD-scope TSC multiplier execution control.
     * Copied to each TD VMCS TSC-multiplier execution control on TDHVPINIT
     */
    uint64_t                     tsc_multiplier;

    /**
     * Values returned by the matching configurable CPUID leaf and sub-leaf.
     */
    cpuid_config_return_values_t cpuid_config_vals[MAX_NUM_CPUID_LOOKUP];

    cpuid_flags_t                cpuid_flags;

    uint32_t                     xbuff_offsets[XBUFF_OFFSETS_NUM];
} tdcs_execution_control_fields_t;


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
    uint32_t       mr_tdblocks; /**< Counter of the number of times MRTD was updated */
    /**
     * Holds the context of an incremental SHA384 calculation on this TD
     */
    sha384_ctx_t   td_sha_ctx;
    sharex_lock_t  rtmr_lock; /**< Controls concurrent access to the RTMR array */
} tdcs_measurement_fields_t;


#define TDX_SIZE_OF_TDCS_MGMT_STRUCTS (sizeof(tdcs_management_fields_t) + \
                                       sizeof(tdcs_execution_control_fields_t) + \
                                       sizeof(tdcs_measurement_fields_t))

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
    /**
     * Needs to be 128bit (16 byte) aligned for atomic cmpxchg
     */
    tdcs_epoch_tracking_fields_t ALIGN(16) epoch_tracking;
    tdcs_measurement_fields_t              measurement_fields;

    uint64_t                     notify_enables; // Enable guest notification of events

    /**
     * TDCX 2nd page - MSR Bitmaps
     */
    uint8_t ALIGN(TDX_PAGE_SIZE_IN_BYTES)                          MSR_BITMAPS[TDX_PAGE_SIZE_IN_BYTES]; /**< TD-scope RDMSR/WRMSR exit control bitmaps */

    /**
     * TDCX 3rd page - Secure EPT Root Page
     */
    uint8_t ALIGN(TDX_PAGE_SIZE_IN_BYTES)                          sept_root_page[TDX_PAGE_SIZE_IN_BYTES];

    /**
     * TDCX 4th page - Zero Page
     */
    uint8_t ALIGN(TDX_PAGE_SIZE_IN_BYTES)                          zero_page[TDX_PAGE_SIZE_IN_BYTES];
} tdcs_t;
tdx_static_assert((offsetof(tdcs_t, epoch_tracking)%16) == 0, tdcs_t); // Required Alignment = 16
tdx_static_assert(offsetof(tdcs_t, MSR_BITMAPS) == TDX_PAGE_SIZE_IN_BYTES, tdcs_t);
tdx_static_assert(offsetof(tdcs_t, sept_root_page) == TDX_PAGE_SIZE_IN_BYTES*2, tdcs_t);
tdx_static_assert(offsetof(tdcs_t, zero_page) == TDX_PAGE_SIZE_IN_BYTES*3, tdcs_t);
tdx_static_assert(sizeof(tdcs_t) == TDX_PAGE_SIZE_IN_BYTES*MAX_NUM_TDCS_PAGES, tdcs_t);



#endif /* SRC_COMMON_DATA_STRUCTURES_TD_CONTROL_STRUCTURES_H_ */
