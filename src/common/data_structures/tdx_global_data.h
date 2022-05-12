// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_global_data.h
 * @brief TDX global data
 */
#ifndef __TDX_GLOBAL_DATA_H_INCLUDED__
#define __TDX_GLOBAL_DATA_H_INCLUDED__

#include "helpers/tdx_locks.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "helpers/smrrs.h"
#include "debug/tdx_debug.h"
#include "tdx_api_defs.h"
#include "x86_defs/msr_defs.h"
#include "auto_gen/cpuid_configurations_defines.h"
#include "crypto/sha384.h"

#define AES_XTS_128                BIT(0)
#define AES_XTS_128_WITH_INTEGRITY BIT(1)
#define AES_XTS_256                BIT(2)

typedef enum
{
    SYSINIT_PENDING = 0,
    SYSINIT_DONE    = 1,
    SYSCONFIG_DONE  = 2,
    SYS_READY       = 3,
    SYS_SHUTDOWN    = 4
} sysinit_state_e;

/**
 * @struct xsave_area_no_extended_t
 *
 * @brief Holds xsave legacy region and headers
 */
typedef struct ALIGN(0x1000) PACKED xsave_area_no_extended_s
{
    xsave_legacy_region_t legacy_region;
    xsave_header_t xsave_header;
} xsave_area_no_extended_t;

/**
 * @struct tdx_global_state_t
 *
 * @brief Holds the global key assignment and system init states
 */
typedef struct tdx_global_state_s
{
    /**
     * system init state: SYSINIT_PENDING = 0, SYSINIT_RUNNING,
     *                    SYSINIT_DONE, SYS_READY, SYS_SHUTDOWN
     */
    uint8_t sys_state;
} tdx_global_state_t;

#define KOT_STATE_HKID_FREE      0
#define KOT_STATE_HKID_ASSIGNED  1
#define KOT_STATE_HKID_FLUSHED   2
#define KOT_STATE_HKID_RESERVED  3
/**
 * @struct kot_entry_t
 *
 * @brief Holds the entry definition of the KOT
 */
typedef struct kot_entry_s
{
    /**
     * kot entry state state: KOT_STATE_HKID_FREE = 0, KOT_STATE_HKID_ASSIGNED, KOT_STATE_HKID_RECLAIMED,
     *                        KOT_STATE_HKID_FLUSHED, KOT_STATE_HKID_RESERVED
     */
    uint8_t state;
    /**
     * Bitmap of packages indicating a TDWBINVD is required before the HKID can be freed.
     * If WBINVD_BITMAP[n] is 1, then the entry’s HKID has been reclaimed
     * (by TDHMNGKEYRECLAIMID), but TDWBINVD has not been completed yet on package n.
     *
     */
    uint32_t wbinvd_bitmap;
} kot_entry_t;

#define MAX_HKIDS 128
/**
 * @struct kot_t
 *
 * @brief KOT = Key Ownership Table
 *
 * KOT is used to manage HKIDs state and ownership by TDs
 */
typedef struct kot_s
{
    sharex_lock_t lock; /**< shared exclusve lock to access the kot */
    /**
     * A table of MAX_HKIDS entries, indexed by HKID
     */
    kot_entry_t entries[MAX_HKIDS];
} kot_t;

/**
 * @struct wbt_entry_t
 *
 * @brief WBT is a table which controls the operation of TDWBINVD.
 *
 *  WBT holds an entry WBINVD scope per package.
 */
typedef struct wbt_entry_s
{
    uint64_t intr_point; /**< WBINDP handle */
    /**
     * Array of HKIDs, indicating which HKID was in the HKID_FLUSHED state
     * throughout the TDWBINVD cycle.
     * If HKID_FLUSHED[k] is 1, then when TDWBINVD was initiated
     * (not as a resumption of a previously-interrupted TDWBINVD),
     * KOT.ENTRIES[k].STATE was HKID_FLUSHED.
     * This bitmap is only applicable during a TDBWINVD cycle of all HKIDs,
     * from the initial TDWBINVD until a successful TDWBINVD completion.
     */
    uint8_t hkid_flushed[MAX_HKIDS];
    mutex_lock_t entry_lock; /**< mutex to control concurrent execution of TDWBINVD */
} wbt_entry_t;

#define MAX_PKGS  8
#define MAX_TDMRS 64
/**
 * @struct tdmr_entry_t
 *
 * @brief Holds a TDMR region representation and its PAMTs
 *
 */
typedef struct tdmr_entry_s
{
    uint64_t base; /**< base physical address of TDMR */
    uint64_t size; /**< size of TDMR in bytes */
    uint64_t last_initialized; /**< last initialized address of the TDMR region */

    uint64_t pamt_1g_base; /**< Base address of the PAMT_1G range */
    uint64_t pamt_2m_base; /**< Base address of the PAMT_2M range */
    uint64_t pamt_4k_base; /**< Base address of the PAMT_4K range */

    uint32_t num_of_pamt_blocks; /**< number of PAMT blocks in this TDMR region */

    struct
    {
        uint64_t offset; /**< Offset of reserved range 0 within the TDMR. 4K aligned. */
        uint64_t size;   /**< Size of reserved range 0 within the TDMR. A size of 0 indicates a null entry. 4K aligned. */
    } rsvd_areas[MAX_RESERVED_AREAS];

    uint32_t num_of_rsvd_areas;

    mutex_lock_t lock; /**< mutex for the initialization process of this TDMR region */
} tdmr_entry_t;

typedef struct
{

    uint64_t                        ia32_tsc_adjust;

    //MSRs
    ia32_vmx_basic_t                ia32_vmx_basic;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_pinbased_ctls;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_procbased_ctls;
    ia32_vmx_allowed_bits_t         ia32_vmx_procbased_ctls2;
    uint64_t                        ia32_vmx_procbased_ctls3;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_exit_ctls;
    ia32_vmx_allowed_bits_t         ia32_vmx_true_entry_ctls;
    uint64_t                        ia32_vmx_ept_vpid_cap;

    ia32_cr0_t                      ia32_vmx_cr0_fixed0;
    ia32_cr0_t                      ia32_vmx_cr0_fixed1;
    ia32_cr4_t                      ia32_vmx_cr4_fixed0;
    ia32_cr4_t                      ia32_vmx_cr4_fixed1;

    ia32_mtrrcap_t                  ia32_mtrrcap;

    ia32_arch_capabilities_t        ia32_arch_capabilities;
    ia32_tsx_ctrl_t                 ia32_tsx_ctrl;
    ia32_core_capabilities_t        ia32_core_capabilities;

    ia32_tme_capability_t           ia32_tme_capability;
    ia32_tme_activate_t             ia32_tme_activate;
    ia32_tme_keyid_partitioning_t   ia32_tme_keyid_partitioning;

    smrr_range_t smrr[2];
} platform_common_config_t;

/* TD VMCS field values computed by TDHSYSINIT
*/
typedef struct
{
    uint32_t pinbased_ctls;
    uint32_t procbased_ctls;
    uint32_t procbased_ctls2;
    uint64_t procbased_ctls3;
    uint32_t exit_ctls;
    uint32_t entry_ctls;
} td_vmcs_values_t;

typedef struct xsave_component_info_s
{
    uint32_t size;
    bool_t   align;
} xsave_component_info_t;

/**
 * @struct tdx_module_local_t
 *
 * @brief Holds the global per-package data
 *
 */
typedef struct tdx_module_global_s
{
    xsave_area_no_extended_t xbuf;

    /**
     * shared exclusive lock to access the global data per-package
     */
    sharex_lock_t global_lock;
    sys_attributes_t sys_attributes;
    uint64_t hkid_mask; /**< mask hkid bits from physical address */
    uint32_t hkid_start_bit;
    uint64_t max_mktme_hkids; /**< Number of activated keys available to TME and MK-TME */
    uint64_t max_pa; /**< Maximum PA bits supported by the platform */
    uint32_t num_of_lps; /**< total number of logical processors */
    uint32_t num_of_pkgs; /**< total number of packages */
    uint32_t num_of_init_lps; /**< number of initialized lps */
    uint32_t num_of_init_pkgs; /**< number of initialized packages */
    // Taken from the SEAM Loader SYS_INFO_TABLE
    uint64_t shutdown_host_rip;
    /**
     * Bitmap that indicates on which package the global private key has been configured.
     */
    uint32_t pkg_config_bitmap;
    uint32_t private_hkid_min; /**< minimum value for a private tdx hkid */
    uint32_t private_hkid_max; /**< maximum ... */
    uint16_t hkid;
    tdx_global_state_t global_state;
    kot_t kot;
    wbt_entry_t wbt_entries[MAX_PKGS];
    tdmr_entry_t tdmr_table[MAX_TDMRS];
    uint32_t num_of_tdmr_entries;
    platform_common_config_t plt_common_config;
    uint64_t seamrr_base; /**< SEAMRR base physical address */
    uint64_t seamrr_size; /**< SEAMRR size in bytes */
    /**
     * Indicates the number of blocks that need to be invalidated when running a WBINVD cycle.
     */
    uint64_t num_of_cached_sub_blocks;
    uint32_t max_x2apic_id;               // Maximum value of x2APIC ID across all LPs
    uint32_t x2apic_core_id_shift_count;  // # of bits to shift to get Core ID
    uint32_t x2apic_core_id_mask;
    uint32_t x2apic_pkg_id_shift_count;   // # of bits to shift to get Package ID

    bool_t waitpkg_supported;
    bool_t kl_loadiwk_no_backup;
    bool_t xfd_supported;
    bool_t hle_supported;
    bool_t rtm_supported;

    uint64_t native_tsc_frequency;


    uint32_t xcr0_supported_mask;
    uint32_t ia32_xss_supported_mask;
    uint32_t xfd_faulting_mask;

    xsave_component_info_t xsave_comp[XCR0_MAX_VALID_BIT+1];

    // Values of CPUID, sampled @ TDHSYSINIT and verified @ TDHSYSINITLP
    cpuid_config_t cpuid_values[MAX_NUM_CPUID_LOOKUP];
    uint32_t cpuid_last_base_leaf;      // Calculated on TDH.SYS.INIT, based on CPUID(0).EAX (may be higher)
    uint32_t cpuid_last_extended_leaf;  // Calculated on TDH.SYS.INIT, based on CPUID(0x80000000).EAX


    // Values of TD VMCS fields, computed @ TDHSYSINIT
    td_vmcs_values_t td_vmcs_values;

    /* Max LBR depth */
    uint32_t max_lbr_depth;

    // ATTRIBUTES fixed bits masks
    uint64_t     attributes_fixed0;   // Bit value of 0 means ATTRIBUTES bit must be 0
    uint64_t     attributes_fixed1;   // Bit value of 1 means ATTRIBUTES bit must be 1

    // Hash method buffers for IPP crypto lib - should be initialized before usage
    hash_method_t sha384_method;

    // Array of TDMR info
    tdmr_info_entry_t tdmr_info_copy[MAX_TDMRS];

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    debug_control_t debug_control;
    debug_message_t trace_buffer[TRACE_BUFFER_SIZE];
#endif

} tdx_module_global_t;

#endif // __TDX_GLOBAL_DATA_H_INCLUDED__
