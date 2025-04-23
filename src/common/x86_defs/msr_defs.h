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
 * @file msr_defs.h
 * @brief msr definitions
 */


#ifndef SRC_COMMON_X86_DEFS_MSR_DEFS_H_
#define SRC_COMMON_X86_DEFS_MSR_DEFS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "x86_defs.h"

#define MSR_RANGE_SIZE                                   0x2000

#define IA32_SEAMRR_BASE_MSR_ADDR                        0x1400
#define IA32_SEAMRR_MASK_MSR_ADDR                        0x1401
#define IA32_TME_CAPABILITY_MSR_ADDR                     0x981
#define IA32_TME_ACTIVATE_MSR_ADDR                       0x982
#define IA32_TME_EXCLUDE_MASK                            0x983
#define IA32_TME_EXCLUDE_BASE                            0x984
#define IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR           0x87
#define IA32_XSS_MSR_ADDR                                0xDA0
#define IA32_EFER_MSR_ADDR                               0xC0000080
#define IA32_STAR_MSR_ADDR                               0xC0000081
#define IA32_LSTAR_MSR_ADDR                              0xC0000082
#define IA32_FMASK_MSR_ADDR                              0xC0000084
#define IA32_XFD_MSR_ADDR                                0x1C4
#define IA32_XFD_ERROR_MSR_ADDR                          0x1C5
#define IA32_KERNEL_GS_BASE_MSR_ADDR                     0xC0000102
#define IA32_SPEC_CTRL_MSR_ADDR                          0x48
#define IA32_LBR_DEPTH_MSR_ADDR                          0x14CF
#define IA32_DS_AREA_MSR_ADDR                            0x600
#define IA32_PKRS_MSR_ADDR                               0x6E1
#define IA32_X2APIC_START                                0x800
#define IA32_X2APIC_APICID                               0x802
#define IA32_X2APIC_ICR                                  0x830
#define IA32_X2APIC_EOI                                  0x80B
#define IA32_X2APIC_END                                  0x8FF
#define IA32_APIC_BASE_MSR_ADDR                          0x1B
#define IA32_TSC_ADJ_MSR_ADDR                            0x3B
#define IA32_TSC_AUX_MSR_ADDR                            0xC0000103
#define IA32_TSC_DEADLINE_MSR_ADDR                       0x6E0
#define IA32_FIXED_CTR_CTRL_MSR_ADDR                     0x38D
#define IA32_FIXED_CTR0_MSR_ADDR                         0x309
#define IA32_A_PMC0_MSR_ADDR                             0x4C1
#define IA32_PERFEVTSEL0_MSR_ADDR                        0x186
#define IA32_PERF_METRICS_MSR_ADDR                       0x329
#define IA32_PEBS_ENABLE_MSR_ADDR                        0x3F1
#define IA32_PEBS_DATA_CFG_MSR_ADDR                      0x3F2
#define IA32_PERF_GLOBAL_STATUS_MSR_ADDR                 0x38E
#define IA32_PERF_GLOBAL_STATUS_RESET_MSR_ADDR           0x390
#define IA32_PERF_GLOBAL_STATUS_SET_MSR_ADDR             0x391
#define IA32_DEBUGCTL_MSR_ADDR                           0x1D9
#define IA32_ARCH_CAPABILITIES_MSR_ADDR                  0x10A
#define IA32_TSX_CTRL_MSR_ADDR                           0x122
#define IA32_OFFCORE_RSPx_MSR_ADDR                       0x1A6
#define IA32_PERF_GLOBAL_CTRL_MSR_ADDR                   0x38F
#define IA32_PEBS_LD_LAT_MSR_ADDR                        0x3F6
#define IA32_PEBS_FRONTEND_MSR_ADDR                      0x3F7
#define IA32_UMWAIT_CONTROL                              0xE1
#define IA32_PLATFORM_DCA_CAP                            0x1F8
#define IA32_CPU_DCA_CAP                                 0x1F9
#define IA32_DCA_CAP                                     0x1FA
#define IA32_CORE_CAPABILITIES                           0xCF
#define IA32_LAM_ENABLE_MSR_ADDR                         0x276
#define IA32_MISC_PACKAGE_CTLS_MSR_ADDR                  0xBC
#define IA32_UARCH_MISC_CTL_MSR_ADDR                     0x1B01
#define IA32_XAPIC_DISABLE_STATUS_MSR_ADDR               0xBD
// Partial WBINVD related MSRs
#define IA32_WBINVDP_MSR_ADDR                            0x98
#define IA32_WBNOINVDP_MSR_ADDR                          0x99
#define IA32_INTR_PENDING_MSR_ADDR                       0x9A
#define IA32_MISC_ENABLES_MSR_ADDR                       0x1A0
// Perf related MSRs
#define IA32_PERF_CAPABILITIES_MSR_ADDR                  0x345
#define IA32_PRED_CMD_MSR_ADDR                           0x49
#define IA32_RTIT_CTL_MSR_ADDR                           0x570
#define IA32_LBR_CTL_MSR_ADDR                            0x14CE


#define IA32_SEAMRR_BASE_AND_MASK_MASK           BITS((MAX_PA-1), 25)
#define MISC_EN_LIMIT_CPUID_MAXVAL_BIT           BIT(22)
#define IA32_FMASK_MSR_RESET_STATE               0x20200ULL
#define IA32_LBR_DEPTH_MSR_RESET_STATE           0x20ULL

#define NUM_PMC                      8
#define MAX_FIXED_CTR                7ULL // Max supported by TDX module

#define IA32_PERF_GLOBAL_CTRL_FIXED_CTR12_EN_MASK           (BIT(33) | BIT(34))

typedef union
{
    struct
    {
        uint64_t syscall_enabled :1; // Bit 0
        uint64_t reserved_0 :7;      // Bits 1:7
        uint64_t lme :1;             // Bit 8
        uint64_t reserved_1 :1;      // Bit 9
        uint64_t lma :1;             // Bit 10
        uint64_t nxe :1;             // Bit 11
        uint64_t reserved_2 :52;
    };
    uint64_t raw;
} ia32_efer_t;

typedef union {
    struct
    {
        uint64_t
            lbr             : 1, // 0
            btf             : 1, // 1
            bus_lock_detect : 1, // 2
            reserved_0      : 3, // 3-5
            tr              : 1, // 6
            bts             : 1, // 7
            btint           : 1, // 8
            bts_off_os      : 1, // 9
            bts_off_usr     : 1, // 10
            frz_lbr_pmi     : 1, // 11
            frz_perfmon_pmi : 1, // 12
            en_uncore_pmi   : 1, // 13
            frz_while_smm   : 1, // 14
            rtm_debug       : 1, // 15
            reserved_1      : 48; // 16-63

    };
    uint64_t raw;
} ia32_debugctl_t;
tdx_static_assert(sizeof(ia32_debugctl_t) == 8, ia32_debugctl_t);

typedef union
{
    struct
    {
        uint64_t lock                            : 1 , //0
                 tme_enable                      : 1,  //1
                 key_select                      : 1,  //2
                 save_key_for_standby            : 1,  //3
                 tme_policy                      : 4,  //4-7
                 sgx_tem_enable                  : 1,  //8
                 rsvd                            : 22, //9-30
                 tme_enc_bypass_enable           : 1,  //31
                 mk_tme_keyid_bits               : 4,  //32-35
                 tdx_reserved_keyid_bits         : 4,  //36-39
                 rsvd1                           : 8,  //40-47
                 algs_aes_xts_128                : 1,  //48
                 algs_aes_xts_128_with_integrity : 1,  //49
                 algs_aes_xts_256                : 1,  //50
                 algs_aes_xts_256_with_integrity : 1,  //51
                 algs_rsvd                       : 12;
    };
    uint64_t raw;
} ia32_tme_activate_t;
tdx_static_assert(sizeof(ia32_tme_activate_t) == 8, ia32_tme_activate_t);

typedef union
{
    struct
    {
        uint64_t aes_xts_128 : 1;                // Bit 0
        uint64_t aes_xts_128_with_integrity : 1; // Bit 1
        uint64_t aes_xts_256 : 1;                // Bit 2
        uint64_t aes_xts_256_with_integrity : 1; // Bit 3
        uint64_t rsvd : 27;                      // Bits 30:4
        uint64_t tme_enc_bypass_supported   : 1; // Bit 31
        uint64_t mk_tme_max_keyid_bits : 4;      // Bits 35:32
        uint64_t mk_tme_max_keys : 15;           // Bits 50:36
        uint64_t nm_encryption_disable : 1;      // Bit 51
        uint64_t rsvd2 : 11;                     // Bits 62:52
        uint64_t implicit_bit_mask : 1;          // Bit 63
    };
    uint64_t raw;
} ia32_tme_capability_t;
tdx_static_assert(sizeof(ia32_tme_capability_t) == 8, ia32_tme_capability_t);

typedef union
{
    struct
    {
        uint32_t num_mktme_kids;
        uint32_t num_tdx_priv_kids;
    };
    uint64_t raw;
} ia32_tme_keyid_partitioning_t;
tdx_static_assert(sizeof(ia32_tme_keyid_partitioning_t) == 8, ia32_tme_keyid_partitioning_t);

typedef union ia32_seamrr_base_u {
    struct {
        uint64_t
            rsvd0       : 3,                   // [2:0]
            configured  : 1,                   // [3]
            rsvd1       : 21,                  // [24:4]
            base        : ((MAX_PA - 1) - 24), // [MAX_PA-1:25]
            rsvd2       : ((63 - MAX_PA) + 1);   // [63:MAX_PA]
    };

    uint64_t raw;
} ia32_seamrr_base_t;
tdx_static_assert(sizeof(ia32_seamrr_base_t) == 8, ia32_seamrr_base_t);

typedef union ia32_seamrr_mask_u {
    struct {
        uint64_t
            rsvd0       : 10,                  // [9:0]
            lock        : 1,                   // [10]
            valid       : 1,                   // [11]
            rsvd1       : 13,                  // [24:12]
            mask        : ((MAX_PA - 1) - 24), // [MAX_PA-1:25]
            rsvd2       : ((63 - MAX_PA) + 1);   // [63:MAX_PA]
    };

    uint64_t raw;
} ia32_seamrr_mask_t;
tdx_static_assert(sizeof(ia32_seamrr_mask_t) == 8, ia32_seamrr_mask_t);

typedef union
{
    struct
    {
        uint64_t lbr_format                  : 6, //0-5
                 pebs_trap_indicator         : 1, //6
                 pebs_save_arch_regs         : 1, //7
                 pebs_records_encoding       : 4, //8-11
                 freeze_while_smm_supported  : 1, //12
                 full_write                  : 1, //13
                 rsvd1                       : 1, //14
                 perf_metrics_available      : 1, //15
                 pebs_output_pt_avail        : 1, //16
                 rsvd2                       : 47;//17-63
    };
    uint64_t raw;
} ia32_perf_capabilities_t;

typedef union
{
    struct
    {
        uint64_t vmcs_revision_id         : 31; // bits 30:0
        uint64_t rsvd0                    : 1;  // bit 31
        uint64_t vmcs_region_size         : 13; // bits 44:32
        uint64_t rsvd1                    : 3;  // bits 47:45
        uint64_t vmxon_pa_width           : 1;  // bit 48 
        uint64_t dual_monitor             : 1;  // bit 49
        uint64_t vmcs_mt                  : 4;  // bits 53:50
        uint64_t vmexit_info_on_ios       : 1;  // bit 54
        uint64_t ia32_vmx_true_available  : 1;  // bit 55
        uint64_t voe_without_err_code     : 1;  // bit 56
        uint64_t rsvd2                    : 7;  // bits 63:57
    };
    uint64_t raw;
} ia32_vmx_basic_t;
tdx_static_assert(sizeof(ia32_vmx_basic_t) == 8, ia32_vmx_basic_t);

typedef union ia32_vmx_misc_u
{
    struct
    {
        uint64_t vmx_preempt_timer_tsc_factor   : 5;   // Bits 4:0
        uint64_t unrestricted_guest             : 1;   // bit 5
        uint64_t activity_hlt                   : 1;   // bit 6
        uint64_t activity_shutdown              : 1;   // bit 7
        uint64_t activity_wait_for_sipi         : 1;   // bit 8
        uint64_t reserved                       : 5;   // bits 13:9
        uint64_t pt_in_vmx                      : 1;   // bit 14
        uint64_t ia32_smbase                    : 1;   // bit 15
        uint64_t max_cr3_targets                : 9;   // bits 24:16
        uint64_t max_msr_list_size              : 3;   // bits 27:25
        uint64_t ia32_smm_monitor_ctl           : 1;   // bit 28
        uint64_t vmwrite_any_vmcs_field         : 1;   // bit 29
        uint64_t voe_with_0_instr_length        : 1;   // bit 30
        uint64_t reserved_1                     : 1;   // bit 31
        uint64_t mseg_rev_id                    : 32;  // bits 63:32
    };
    uint64_t raw;
} ia32_vmx_misc_t;
tdx_static_assert(sizeof(ia32_vmx_misc_t) == 8, ia32_vmx_misc_t);


typedef union ia32_vmx_ept_vpid_cap_u
{
    struct
    {
        uint64_t exe_only_supported                             : 1;   // bit 0
        uint64_t reserved_1                                     : 5;   // bits 5:1
        uint64_t pml4_supported                                 : 1;   // bit 6
        uint64_t pml5_supported                                 : 1;   // bit 7
        uint64_t uc_supported                                   : 1;   // bit 8
        uint64_t reserved_2                                     : 5;   // bits 13:9
        uint64_t wb_supported                                   : 1;   // bit 14
        uint64_t reserved_3                                     : 1;   // bit 15
        uint64_t ps_2m_supported                                : 1;   // bit 16
        uint64_t ps_1g_supported                                : 1;   // bit 17
        uint64_t reserved_4                                     : 2;   // bits 19:18
        uint64_t invept_supported                               : 1;   // bit 20
        uint64_t ad_supported                                   : 1;   // bit 21
        uint64_t advanced_vmexit_info_supported                 : 1;   // bit 22
        uint64_t sss_support                                    : 1;   // bit 23
        uint64_t reserved_5                                     : 1;   // bit 24
        uint64_t single_context_invept_supported                : 1;   // bit 25
        uint64_t all_context_invept_supported                   : 1;   // bit 26
        uint64_t reserved_6                                     : 5;   // bit 31:27
        uint64_t invvpid_supported                              : 1;   // bit 32
        uint64_t reserved_7                                     : 7;   // bits 39:33
        uint64_t individual_addr_invvpid_supported              : 1;   // bit 40
        uint64_t single_context_invvpid_supported               : 1;   // bit 41
        uint64_t all_context_invvpid_supported                  : 1;   // bit 42
        uint64_t single_contx_retaining_globals_invvpid_supp    : 1;   // bit 43
        uint64_t reserved_8                                     : 4;   // bits 47:44
        uint64_t hlat_prefix_size                               : 6;   // Bits 53:48
        uint64_t reserved_9                                     : 10;  // Bits 63:54
    };
    uint64_t raw;
} ia32_vmx_ept_vpid_cap_t;
tdx_static_assert(sizeof(ia32_vmx_ept_vpid_cap_t) == 8, ia32_vmx_ept_vpid_cap_t);

typedef union
{
    struct
    {
        uint32_t not_allowed0;
        uint32_t allowed1;
    };
    uint64_t raw;
} ia32_vmx_allowed_bits_t;

typedef union ia32_pred_cmd_u
{
    struct
    {
        uint64_t ibpb     : 1;
        uint64_t reserved : 63;
    };
    uint64_t raw;
} ia32_pred_cmd_t;

typedef union ia32_core_capabilities_u
{
    struct
    {
        uint64_t stlb_qos_supported           : 1;   // Bit 0
        uint64_t rar_supported                : 1;   // Bit 1
        uint64_t fusa_supported               : 1;   // Bit 2
        uint64_t rsm_in_cpl0_only             : 1;   // Bit 3
        uint64_t uc_lock_disable_supported    : 1;   // Bit 4
        uint64_t split_lock_disable_supported : 1;   // Bit 5
        uint64_t snoop_filter_qos_supported   : 1;   // Bit 6
        uint64_t uc_store_throttlin_supported : 1;   // Bit 7
        uint64_t lam_supported                : 1;   // Bit 8
        uint64_t reserved_2                   : 55;  // Bits 63-9
    };
    uint64_t raw;
} ia32_core_capabilities_t;
tdx_static_assert(sizeof(ia32_core_capabilities_t) == 8, ia32_core_capabilities_t);

typedef union ia32_spec_ctrl_u
{
    struct
    {
        uint64_t ibrs           : 1;  // Bit 0
        uint64_t stibp          : 1;  // Bit 1
        uint64_t ssbd           : 1;  // Bit 2
        uint64_t ipred_dis_u    : 1;  // Bit 3
        uint64_t ipred_dis_s    : 1;  // Bit 4
        uint64_t rrsba_dis_u    : 1;  // Bit 5
        uint64_t rrsba_dis_s    : 1;  // Bit 6
        uint64_t psfd           : 1;  // Bit 7
        uint64_t ddpd_u         : 1;  // Bit 8
        uint64_t reserved_0     : 1;  // Bit 9
        uint64_t bhi_dis_s      : 1;  // Bit 10
        uint64_t reserved_1     : 53; // Bits 63:11
    };
    uint64_t raw;
} ia32_spec_ctrl_t;
tdx_static_assert(sizeof(ia32_spec_ctrl_t) == 8, ia32_spec_ctrl_t);

#define IA32_SPEC_CTRL_SSBD_BIT         BIT(2)
#define IA32_SPEC_CTRL_IPRED_DIS_S_BIT  BIT(4)

#define TDX_MODULE_IA32_SPEC_CTRL       (IA32_SPEC_CTRL_SSBD_BIT | IA32_SPEC_CTRL_IPRED_DIS_S_BIT)

#define IA32_ARCH_CAPABILITIES_CONFIG_MASK  (BIT(4) | BIT(19) | BIT(20) | BIT(24))

typedef union ia32_arch_capabilities_u
{
    struct
    {
        uint64_t rdcl_no              : 1;  // Bit 0
        uint64_t irbs_all             : 1;  // Bit 1
        uint64_t rsba                 : 1;  // Bit 2
        uint64_t skip_l1dfl_vmentry   : 1;  // Bit 3
        uint64_t ssb_no               : 1;  // Bit 4
        uint64_t mds_no               : 1;  // Bit 5
        uint64_t if_pschange_mc_no    : 1;  // Bit 6
        uint64_t tsx_ctrl             : 1;  // Bit 7
        uint64_t taa_no               : 1;  // Bit 8
        uint64_t mcu_ctls             : 1;  // Bit 9
        uint64_t misc_package_ctls    : 1;  // Bit 10
        uint64_t energy_filtering_ctl : 1;  // Bit 11
        uint64_t doitm                : 1;  // Bit 12
        uint64_t sbdr_ssdp_no         : 1;  // Bit 13
        uint64_t fbsdp_no             : 1;  // Bit 14
        uint64_t psdp_no              : 1;  // Bit 15
        uint64_t reserved_1           : 1;  // Bit 16
        uint64_t fb_clear             : 1;  // Bit 17
        uint64_t fb_clear_ctrl        : 1;  // Bit 18
        uint64_t rrsba                : 1;  // Bit 19
        uint64_t bhi_no               : 1;  // Bit 20
        uint64_t xapic_disable_status : 1;  // Bit 21
        uint64_t reserved_2           : 1;  // Bit 22
        uint64_t overclocking_status  : 1;  // Bit 23
        uint64_t pbrsb_no             : 1;  // Bit 24
        uint64_t reserved_3           : 39; // BITS 25:63
    };
    uint64_t raw;
} ia32_arch_capabilities_t;
tdx_static_assert(sizeof(ia32_arch_capabilities_t) == 8, ia32_arch_capabilities_t);

typedef union ia32_tsx_ctrl_u
{
    struct
    {
        uint64_t rtm_disable      : 1;  // Bit  0
        uint64_t tsx_cpuid_clear  : 1;  // Bit  1
        uint64_t rsvd             : 62; // Bits 2:63
    };
    uint64_t raw;
} ia32_tsx_ctrl_t;

#define IA32_TSX_CTRL_DISABLE_VALUE 0x3ULL

typedef union ia32_misc_enable_u
{
    struct
    {
        uint64_t fast_strings           : 1;  // 0
        uint64_t rsvd1                  : 2;  // 1-2
        uint64_t thermal_monitor_enable : 1;  // 3
        uint64_t rsvd2                  : 3;  // 6:4
        uint64_t perfmon_available      : 1;  // 7
        uint64_t rsvd3                  : 3;  // 10:8
        uint64_t bts_unavailable        : 1;  // 11
        uint64_t pebs_unavailable       : 1;  // 12
        uint64_t rsvd4                  : 3;  // 15:13
        uint64_t enable_gv3             : 1;  // 16
        uint64_t rsvd5                  : 1;  // 17
        uint64_t enable_monitor_fsm     : 1;  // 18
        uint64_t rsvd6                  : 3;  // 21:19
        uint64_t limit_cpuid_maxval     : 1;  // 22
        uint64_t tpr_message_disable    : 1;  // 23
        uint64_t rsvd7                  : 3;  // 26:24
        uint64_t rsvd8                  : 1;  // 27
        uint64_t hlep_disable           : 1;  // 28
        uint64_t rsvd9                  : 9;  // 37:29
        uint64_t turbo_mode_disable     : 1;  // 38
        uint64_t rsvd10                 : 25; // 63:39
    };
    uint64_t raw;
} ia32_misc_enable_t;

typedef union ia32_misc_package_ctls_u
{
    struct
    {
        uint64_t energy_filtering_enable   : 1;   // Bit 0
        uint64_t reserved                  : 63;  // Bits 63-1
    };
    uint64_t raw;
} ia32_misc_package_ctls_t;

typedef union ia32_msr_intr_pending_u
{
    struct
    {
        uint64_t intr  : 1;   // Bit 0: INTR is pending
        uint64_t nmi   : 1;   // Bit 1: NMI is pending
        uint64_t smi   : 1;   // Bit 2: SMI is pending
        uint64_t other : 61;  // Bits 63:3: Other events are pending
    };
    uint64_t raw;
} ia32_msr_intr_pending_t;

typedef union ia32_xapic_disable_status_u
{
    struct
    {
        uint64_t legacy_xapic_disabled : 1;   // Bit 0
        uint64_t reserved              : 63;  // Bits 63-1
    };
    uint64_t raw;
} ia32_xapic_disable_status_t;

#endif /* SRC_COMMON_X86_DEFS_MSR_DEFS_H_ */
