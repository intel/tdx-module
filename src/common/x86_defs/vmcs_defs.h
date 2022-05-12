// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file vmcs_defs.h
 * @brief VMCS x86 definitions
 */
#ifndef SRC_COMMON_X86_DEFS_VMCS_DEFS_H_
#define SRC_COMMON_X86_DEFS_VMCS_DEFS_H_


#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"


#define TD_VMCS_SIZE _2KB

typedef enum
{
    /* TD VMCS Controls:
       INIT:     Initial value
       VARIABLE: Mask of bits that can be set to 0 or 1
       UNKNOWN:  Mask of "Fixed" and "Reserved" bits, whos values are
                 set during TDHSYSINIT
    */
    PINBASED_CTLS_INIT       = 0x00000029,
    PINBASED_CTLS_VARIABLE   = 0x00000080,
    PINBASED_CTLS_UNKNOWN    = 0xFFFFFF16,

    PROCBASED_CTLS_INIT      = 0xB1220488,
    PROCBASED_CTLS_VARIABLE  = 0x00400800,
    PROCBASED_CTLS_UNKNOWN   = 0x04046173,

    PROCBASED_CTLS2_INIT     = 0x133CB3FA,
    PROCBASED_CTLS2_VARIABLE = 0xCC000400,
    PROCBASED_CTLS2_UNKNOWN  = 0x00000000,

    // Note that PROCBASED_CTLS3 enumerates 64 bits
    PROCBASED_CTLS3_INIT     = 0x0000000000000000,
    PROCBASED_CTLS3_VARIABLE = 0x0000000000000020,
    PROCBASED_CTLS3_UNKNOWN  = 0xFFFFFFFFFFFFFFC0,

    EXIT_CTLS_INIT           = 0x1F3C8204,
    EXIT_CTLS_VARIABLE       = 0x40001000,
    EXIT_CTLS_UNKNOWN        = 0x80036DFB,

    ENTRY_CTLS_INIT          = 0x003EC004,
    ENTRY_CTLS_VARIABLE      = 0x00402200,
    ENTRY_CTLS_UNKNOWN       = 0xFF8011FB,

    /* TD VMCS Guest CR0 and CR4
    */
    GUEST_CR0_INIT           = 0x00000021,
    CR0_READ_SHADOW          = 0x0000000000000021,

    GUEST_CR4_INIT           = 0x00002040,
    CR4_READ_SHADOW          = 0x0000000000000040,
} td_vmcs_ctl_values_e;

// additional td_vmcs_ctl_values - 64bit
static const uint64_t IA32_VMX_EPT_VPID_CAP_MASK = 0x061340C0;

typedef union vmcs_revision_u
{
    struct
    {
        uint32_t
            vmcs_revision_identifier       : 31,             // [30:0]
            shadow_vmcs_indicator          : 1;             //  [31]
    };
    uint32_t raw;
} vmcs_revision_t;
tdx_static_assert(sizeof(vmcs_revision_t) == 4, vmcs_revision_t);


typedef struct vmcs_header_s
{
    vmcs_revision_t revision;
    uint32_t        vmx_abort_indicator;
} vmcs_header_t;
tdx_static_assert(sizeof(vmcs_header_t) == 8, vmcs_header_t);



#define IA32_VMX_BASIC_MSR_ADDR               0x480
#define IA32_VMX_PINBASED_CTLS_MSR_ADDR       0x481
#define IA32_VMX_PROCBASED_CTLS_MSR_ADDR      0x482
#define IA32_VMX_EXIT_CTLS_MSR_ADDR           0x483
#define IA32_VMX_ENTRY_CTLS_MSR_ADDR          0x484
#define IA32_VMX_EPT_VPID_CAP_MSR_ADDR        0x48C
#define IA32_VMX_CR0_FIXED0_MSR_ADDR          0x486
#define IA32_VMX_CR0_FIXED1_MSR_ADDR          0x487
#define IA32_VMX_CR4_FIXED0_MSR_ADDR          0x488
#define IA32_VMX_CR4_FIXED1_MSR_ADDR          0x489
#define IA32_VMX_PROCBASED_CTLS2_MSR_ADDR     0x48B
#define IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR  0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR 0x48E
#define IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR      0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR     0x490
#define IA32_VMX_PROCBASED_CTLS3_MSR_ADDR     0x492

#define EPT_VPID_CAP_ALLOW_EXECUTE_ONLY       0x1


typedef struct ALIGN(16) ept_descriptor_s
{
    uint64_t ept;
    uint64_t reserved; /**< Must be 0 */
} ept_descriptor_t;
tdx_static_assert(sizeof(ept_descriptor_t) == 16, ept_descriptor_t);

#define INVEPT_TYPE_1 1
#define INVEPT_TYPE_2 2

typedef union
{
    struct
    {
        uint32_t reserved_0                      : 1;  // bit 0
        uint32_t reserved_1                      : 1;  // bit 1
        uint32_t interrupt_window_exiting        : 1;  // bit 2
        uint32_t use_tsc_offsetting              : 1;  // bit 3
        uint32_t reserved_2                      : 1;  // bit 4
        uint32_t reserved_3                      : 1;  // bit 5
        uint32_t reserved_4                      : 1;  // bit 6
        uint32_t hlt_exiting                     : 1;  // bit 7
        uint32_t reserved_5                      : 1;  // bit 8
        uint32_t invlpg_exiting                  : 1;  // bit 9
        uint32_t mwait_exiting                   : 1;  // bit 10
        uint32_t rdpmc_exiting                   : 1;  // bit 11
        uint32_t rdtsc_exiting                   : 1;  // bit 12
        uint32_t reserved_6                      : 1;  // bit 13
        uint32_t reserved_7                      : 1;  // bit 14
        uint32_t cr3_load_exiting                : 1;  // bit 15
        uint32_t cr3_store_exiting               : 1;  // bit 16
        uint32_t activate_tertiary_controls      : 1;  // bit 17
        uint32_t reserved_8                      : 1;  // bit 18
        uint32_t cr8_load_exiting                : 1;  // bit 19
        uint32_t cr8_store_exiting               : 1;  // bit 20
        uint32_t use_tpr_shadow                  : 1;  // bit 21
        uint32_t nmi_window_exiting              : 1;  // bit 22
        uint32_t mov_dr_exiting                  : 1;  // bit 23
        uint32_t uncondditional_io_exiting       : 1;  // bit 24
        uint32_t use_io_bitmaps                  : 1;  // bit 25
        uint32_t reserved_9                      : 1;  // bit 26
        uint32_t monitor_trap_flag               : 1;  // bit 27
        uint32_t use_msr_bitmaps                 : 1;  // bit 28
        uint32_t monitor_exiting                 : 1;  // bit 29
        uint32_t pause_exiting                   : 1;  // bit 30
        uint32_t activate_secondary_controls     : 1;  // bit 31
    };
    uint64_t raw;
} vmcs_procbased_ctls_t;
tdx_static_assert(sizeof(vmcs_procbased_ctls_t) == 8, vmcs_procbased_ctls_t);

typedef union
{
    struct
    {
        uint32_t virt_apic                       : 1;  // Bit 0
        uint32_t en_ept                          : 1;  // Bit 1
        uint32_t descriptor_table_exit           : 1;  // Bit 2
        uint32_t en_rdtscp                       : 1;  // Bit 3
        uint32_t virt_2apic_mode                 : 1;  // Bit 4
        uint32_t en_vpid                         : 1;  // Bit 5
        uint32_t wbinvd_exiting                  : 1;  // Bit 6
        uint32_t unrestricted_guest              : 1;  // Bit 7
        uint32_t apic_reg_virtualization         : 1;  // Bit 8
        uint32_t virtual_interrupt               : 1;  // Bit 9
        uint32_t pause_loop                      : 1;  // Bit 10
        uint32_t rdrand                          : 1;  // Bit 11
        uint32_t en_invpcid                      : 1;  // Bit 12
        uint32_t en_vm_func                      : 1;  // Bit 13
        uint32_t vmcs_shadowing                  : 1;  // Bit 14
        uint32_t en_encls                        : 1;  // Bit 15
        uint32_t rdseed                          : 1;  // Bit 16
        uint32_t en_pml                          : 1;  // Bit 17
        uint32_t ept_vaiolation_ve               : 1;  // Bit 18
        uint32_t conceal_vmx                     : 1;  // Bit 19
        uint32_t en_xsaves_xstors                : 1;  // Bit 20
        uint32_t pasid_translation               : 1;  // Bit 21
        uint32_t execute_control_ept             : 1;  // Bit 22
        uint32_t en_spp                          : 1;  // Bit 23
        uint32_t pt2gpa                          : 1;  // Bit 24
        uint32_t tsc_scaling                     : 1;  // Bit 25
        uint32_t en_guest_wait_pause             : 1;  // Bit 26
        uint32_t en_pconfig                      : 1;  // Bit 27
        uint32_t en_enclv_exiting                : 1;  // Bit 28
        uint32_t en_epc_virt                     : 1;  // Bit 29
        uint32_t buslock_detect                  : 1;  // Bit 30
        uint32_t en_no_commit                    : 1;  // Bit 31
    };
    uint32_t raw;
} vmcs_procbased_ctls2_t;

typedef union
{
    struct
    {
        uint64_t loadiwkey_exiting              : 1;  // Bit 0
        uint64_t enable_hlat                    : 1;  // Bit 1
        uint64_t ept_paging_write_control       : 1;  // Bit 2
        uint64_t guest_paging_verification      : 1;  // Bit 3
        uint64_t ipi_virtualization             : 1;  // Bit 4
        uint64_t gpaw                           : 1;  // Bit 5
        uint64_t reserved                       : 58; // Bits 6-63
    };
    uint64_t raw;
} vmcs_procbased_ctls3_t;

typedef union
{
    struct
    {
        uint64_t b0          : 1; // Bit 0
        uint64_t b1          : 1; // Bit 1
        uint64_t b2          : 1; // Bit 2
        uint64_t b3          : 1; // Bit 3
        uint64_t rsvd_0      : 8; // Bits 4-11
        uint64_t enable      : 1; // Bit 12
        uint64_t rsvd_1      : 1; // Bits 13
        uint64_t bs          : 1; // Bits 14
        uint64_t rsvd_2      : 1; // Bits 15
        uint64_t rtm         : 1; // Bits 16
        uint64_t rsvd_3      : 47;// Bits 17-63
    };
    uint64_t raw;
} pending_debug_exception_t;

typedef enum {
    VMEXIT_REASON_EXCEPTION_OR_NMI                       = 0,
    VMEXIT_REASON_INTERRUPT                              = 1,
    VMEXIT_REASON_TRIPLE_FAULT                           = 2,
    VMEXIT_REASON_INIT_EVENT                             = 3,
    VMEXIT_REASON_SIPI_EVENT                             = 4,
    VMEXIT_REASON_SMI_IO_EVENT                           = 5,
    VMEXIT_REASON_SMI_OTHER_EVENT                        = 6,
    VMEXIT_REASON_INTERRUPT_WINDOW                       = 7,
    VMEXIT_REASON_NMI_WINDOW                             = 8,
    VMEXIT_REASON_TASK_SWITCH                            = 9,
    VMEXIT_REASON_CPUID_INSTRUCTION                      = 10,
    VMEXIT_REASON_GETSEC_INSTRUCTION                     = 11,
    VMEXIT_REASON_HLT_INSTRUCTION                        = 12,
    VMEXIT_REASON_INVD_INSTRUCTION                       = 13,
    VMEXIT_REASON_INVLPG_INSTRUCTION                     = 14,
    VMEXIT_REASON_RDPMC_INSTRUCTION                      = 15,
    VMEXIT_REASON_RDTSC_INSTRUCTION                      = 16,
    VMEXIT_REASON_RSM_INSTRUCTION                        = 17,
    VMEXIT_REASON_VMCALL_INSTRUCTION                     = 18,
    VMEXIT_REASON_VMCLEAR_INSTRUCTION                    = 19,
    VMEXIT_REASON_VMLAUNCH_INSTRUCTION                   = 20,
    VMEXIT_REASON_VMPTRLD_INSTRUCTION                    = 21,
    VMEXIT_REASON_VMPTRST_INSTRUCTION                    = 22,
    VMEXIT_REASON_VMREAD_INSTRUCTION                     = 23,
    VMEXIT_REASON_VMRESUME_INSTRUCTION                   = 24,
    VMEXIT_REASON_VMWRITE_INSTRUCTION                    = 25,
    VMEXIT_REASON_VMXOFF_INSTRUCTION                     = 26,
    VMEXIT_REASON_VMXON_INSTRUCTION                      = 27,
    VMEXIT_REASON_CR_ACCESS                              = 28,
    VMEXIT_REASON_DR_ACCESS                              = 29,
    VMEXIT_REASON_IO_INSTRUCTION                         = 30,
    VMEXIT_REASON_MSR_READ                               = 31,
    VMEXIT_REASON_MSR_WRITE                              = 32,
    VMEXIT_REASON_FAILED_VMENTER_GS                      = 33,
    VMEXIT_REASON_FAILED_VMENTER_MSR                     = 34,
    VMEXIT_REASON_VMEXIT_FAILURE                         = 35,
    VMEXIT_REASON_MWAIT_INSTRUCTION                      = 36,
    VMEXIT_REASON_MTF                                    = 37,
    VMEXIT_REASON_MONITOR_INSTRUCTION                    = 39,
    VMEXIT_REASON_PAUSE_INSTRUCTION                      = 40,
    VMEXIT_REASON_FAILED_VMENTER_MC                      = 41,
    VMEXIT_REASON_C_STATE_SMI                            = 42,
    VMEXIT_REASON_TPR_BELOW_THRESHOLD                    = 43,
    VMEXIT_REASON_APIC_ACCESS                            = 44,
    VMEXIT_REASON_VIRTUALIZED_EOI                        = 45,
    VMEXIT_REASON_GDTR_IDTR_ACCESS                       = 46,
    VMEXIT_REASON_LDTR_TR_ACCESS                         = 47,
    VMEXIT_REASON_EPT_VIOLATION                          = 48,
    VMEXIT_REASON_EPT_MISCONFIGURATION                   = 49,
    VMEXIT_REASON_INVLEPT                                = 50,
    VMEXIT_REASON_RDTSCP                                 = 51,
    VMEXIT_REASON_PREEMPTION_TIMER_EXPIRED               = 52,
    VMEXIT_REASON_INVLVPID                               = 53,
    VMEXIT_REASON_WBINVD_INSTRUCTION                     = 54,
    VMEXIT_REASON_XSETBV_INSTRUCTION                     = 55,
    VMEXIT_REASON_APIC_WRITE                             = 56,
    VMEXIT_REASON_RDRAND_INSTRUCTION                     = 57,
    VMEXIT_REASON_INVPCID_INSTRUCTION                    = 58,
    VMEXIT_REASON_VMFUNC_INSTRUCTION                     = 59,
    VMEXIT_REASON_ENCLS_INSTRUCTION                      = 60,
    VMEXIT_REASON_RDSEED_INSTRUCTION                     = 61,
    VMEXIT_REASON_EPT_PML_FULL                           = 62,
    VMEXIT_REASON_XSAVES_INSTRUCTION                     = 63,
    VMEXIT_REASON_XRSTORS_INSTRUCTION                    = 64,
    VMEXIT_REASON_PCONFIG                                = 65,
    VMEXIT_REASON_LOADIWK_INSTRUCTION                    = 69,
    VMEXIT_REASON_ENCLV_INSTRUCTION                      = 70,
    VMEXIT_REASON_ENQCMD_PASID_TRANSLATION_FAILURE       = 72,
    VMEXIT_REASON_ENQCMDS_PASID_TRANSLATION_FAILURE      = 73,
    VMEXIT_REASON_BUS_LOCK                               = 74,
    VMEXIT_REASON_NOTIFICATION                           = 75,
    VMEXIT_REASON_SEAMCALL                               = 76,
    VMEXIT_REASON_TDCALL                                 = 77
} vm_exit_basic_reason_e;

typedef union vm_vmexit_exit_reason_s {
    struct
    {
        uint64_t basic_reason         : 16; // Bits 0-15
        uint64_t reserved_0           : 10; // Bits 16-25
        uint64_t bus_lock_preempted   : 1;  // Bit  26
        uint64_t enclave_interruption : 1;  // Bit  27
        uint64_t pending_mtf          : 1;  // Bit  28
        uint64_t parallel             : 1;  // Bit  29
        uint64_t reserved_1           : 1;  // Bit  30
        uint64_t vmenter_fail         : 1;  // Bit  31
        uint64_t reserved_2           : 32; // Bits 32-63
    };

    uint64_t raw;
} vm_vmexit_exit_reason_t;
tdx_static_assert(sizeof(vm_vmexit_exit_reason_t) == 8, vm_vmexit_exit_reason_t);

typedef union vm_vmexit_interruption_info_s {
    struct
    {
        uint64_t vector               : 8;  // 0-7
        uint64_t interruption_type    : 3;  // 8-10
        uint64_t error_code_valid     : 1;  // 11
        uint64_t nmi_unblocking       : 1;  // 12
        uint64_t reserved_0           : 18; // 13-30
        uint64_t valid                : 1;  // 31
        uint64_t reserved_1           : 32;
    };

    uint64_t raw;
} vm_vmexit_interruption_info_t;
tdx_static_assert(sizeof(vm_vmexit_interruption_info_t) == 8, vm_vmexit_interruption_info_t);

typedef enum
{
    VMEXIT_INTER_INFO_TYPE_EXTERNAL_INTERRUPT             = 0,
    VMEXIT_INTER_INFO_TYPE_NMI                            = 2,
    VMEXIT_INTER_INFO_TYPE_HARDWARE_EXCEPTION             = 3,
    VMEXIT_INTER_INFO_TYPE_SOFTWARE_INTERRUPT             = 4,
    VMEXIT_INTER_INFO_TYPE_PRIV_SOFT_EXCEPTION            = 5,
    VMEXIT_INTER_INFO_TYPE_SOFTWARE_EXCEPTION             = 6,
    VMEXIT_INTER_INFO_TYPE_OTHER_EVENT                    = 7
} vmexit_inter_info_inter_type_t;

typedef union vmx_exit_qualification_s {
    struct
    {
        uint64_t data_read                  : 1; // 0 - Data read failed
        uint64_t data_write                 : 1; // 1 - Data write failed
        uint64_t insn_fetch                 : 1; // 2 - Instruction fetch failed
        uint64_t gpa_readable               : 1; // 3 - GPA is not readable
        uint64_t gpa_writeable              : 1; // 4 - GPA is not writeable
        uint64_t gpa_executable             : 1; // 5 - GPA is not executable
        uint64_t gpa_exec_for_ring3_lin     : 1; // 6
        uint64_t gla_valid                  : 1; // 7 - Linear address is not valid
        uint64_t page_walk_fault            : 1; // 8 - Page walk fault
        uint64_t user_mode_lin_addr         : 1; // 9
        uint64_t writable_lin_addr          : 1; // 10
        uint64_t execute_dis_lin_addr       : 1; // 11
        uint64_t nmi_unblocking_due_to_iret : 1; // 12
        uint64_t ss                         : 1; // 13
        uint64_t reserved                   : 50;
    } ept_violation;

    struct
    {
        uint64_t msmi     : 1;
        uint64_t reserved : 63;
    } smi;

    struct
    {
        uint64_t cr_num         : 4;
        uint64_t access_type    : 2;
        uint64_t lmsw_op_type   : 1;
        uint64_t reserved0      : 1;
        uint64_t mov_cr_gpr     : 4;
        uint64_t reserved1      : 4;
        uint64_t lmsw_src_data  : 16;
        uint64_t reserved2      : 32;
    } cr_access;

    struct
    {
        uint64_t vm_context_invalid         : 1;  // Bit 0
        uint64_t reserved0                  : 11; // Bits 1-11
        uint64_t nmi_unblocking_due_to_iret : 1;  // Bit 12
        uint64_t reserved1                  : 51; // Bits 13-63
    } notification;

    uint64_t  raw;

} vmx_exit_qualification_t;
tdx_static_assert(sizeof(vmx_exit_qualification_t) == 8, vmx_exit_qualification_t);

#define VMEXIT_CR_ACCESS_MOV_TO_CR          0
#define VMEXIT_CR_ACCESS_MOV_FROM_CR        1
#define VMEXIT_CR_ACCESS_CLTS               2
#define VMEXIT_CR_ACCESS_LMSW               3

typedef enum vmx_eeq_type_e
{
    VMX_EEQ_NONE = 0,
    VMX_EEQ_ACCEPT = 1
} vmx_eeq_type_t;

typedef union vmx_ext_exit_qual_u
{
    struct
    {
        uint64_t    type : 4;
        uint64_t    rsvd : 28;
        uint64_t    info : 32;
    };

    uint64_t raw;

} vmx_ext_exit_qual_t;
tdx_static_assert(sizeof(vmx_ext_exit_qual_t) == 8, vmx_ext_exit_qual_t);

typedef union seam_ops_capabilities_s {
    struct
    {
        uint64_t capabilities  : 1; // 0
        uint64_t seamreport    : 1; // 1
        uint64_t reserved      : 62; // 2-63
    };
    uint64_t  raw;
} seam_ops_capabilities_t;
tdx_static_assert(sizeof(seam_ops_capabilities_t) == 8, seam_ops_capabilities_t);

typedef union vmx_entry_inter_info_s {
    struct
    {
        uint32_t vector             : 8;
        uint32_t interruption_type  : 3;
        uint32_t deliver_error_code : 1;
        uint32_t reserved           : 19;
        uint32_t valid              : 1;
    };
    uint64_t raw;

} vmx_entry_inter_info_t;
tdx_static_assert(sizeof(vmx_entry_inter_info_t) == 8, vmx_entry_inter_info_t);

typedef union vmx_exit_inter_info_s {

    struct
    {
        uint32_t vector                     : 8;
        uint32_t interruption_type          : 3;
        uint32_t error_code_valid           : 1;
        uint32_t nmi_unblocking_due_to_iret : 1;
        uint32_t reserved                   : 18;
        uint32_t valid                      : 1;
    };
    uint64_t raw;

} vmx_exit_inter_info_t;
tdx_static_assert(sizeof(vmx_exit_inter_info_t) == 8, vmx_exit_inter_info_t);

typedef union vmx_idt_vectoring_info_s {
    struct
    {
        uint32_t vector             : 8;
        uint32_t interruption_type  : 3;
        uint32_t error_code_valid   : 1;
        uint32_t undefined          : 1;
        uint32_t reserved           : 18;
        uint32_t valid              : 1;
    };
    uint64_t raw;

} vmx_idt_vectoring_info_t;
tdx_static_assert(sizeof(vmx_idt_vectoring_info_t) == 8, vmx_idt_vectoring_info_t);

typedef union
{
    struct
    {
        uint32_t external_int_exiting            : 1;
        uint32_t reserved_0                      : 2;
        uint32_t nmi_exiting                     : 1;
        uint32_t resrved_1                       : 1;
        uint32_t virtual_nmis                    : 1;
        uint32_t activate_vmx_preemption_timer   : 1;
        uint32_t process_posted_interrupts       : 1;
        uint32_t reserved_2                      : 24;
    };
    uint32_t raw;
} vmx_pinbased_ctls_t;
tdx_static_assert(sizeof(vmx_pinbased_ctls_t) == 4, vmx_pinbased_ctls_t);

typedef union
{
    struct
    {
        uint64_t virtualize_apic_access          : 1;  // bit 0
        uint64_t enable_ept                      : 1;  // bit 1
        uint64_t descriptor_table_exiting        : 1;  // bit 2
        uint64_t enable_rdtscp                   : 1;  // bit 3
        uint64_t virtualize_x2apic_mode          : 1;  // bit 4
        uint64_t enable_vpid                     : 1;  // bit 5
        uint64_t wbinvd_exiting                  : 1;  // bit 6
        uint64_t unrestricted_guest              : 1;  // bit 7
        uint64_t apic_register_virtualization    : 1;  // bit 8
        uint64_t virtual_interrupt_delivery      : 1;  // bit 9
        uint64_t pause_loop_exiting              : 1;  // bit 10
        uint64_t rdrand_exiting                  : 1;  // bit 11
        uint64_t enable_invpcid                  : 1;  // bit 12
        uint64_t enable_vm_functions             : 1;  // bit 13
        uint64_t vmcs_shadowing                  : 1;  // bit 14
        uint64_t enable_encls_exiting            : 1;  // bit 15
        uint64_t rdseed_exiting                  : 1;  // bit 16
        uint64_t enable_pml                      : 1;  // bit 17
        uint64_t ept_violation_ve                : 1;  // bit 18
        uint64_t conceal_vmx_fmpt                : 1;  // bit 19
        uint64_t enable_xsaves_xrstors           : 1;  // bit 20
        uint64_t reserved_0                      : 1;  // bit 21
        uint64_t ept_mode_based_execution_control: 1;  // bit 22
        uint64_t ept_sub_page_write_permissions  : 1;  // bit 23
        uint64_t intel_pt_uses_gpa               : 1;  // bit 24
        uint64_t use_tsc_scaling                 : 1;  // bit 25
        uint64_t enable_user_wait_and_pause      : 1;  // bit 26
        uint64_t reserved_1                      : 1;  // bit 27
        uint64_t enable_enclv_exiting            : 1;  // bit 28
        uint64_t reserved_2                      : 35;  // bits 29-63
    };
    uint64_t raw;
} vmx_procbased_ctls2_t;
tdx_static_assert(sizeof(vmx_procbased_ctls2_t) == 8, vmx_pinbased_ctls_t);

typedef union vmx_guest_inter_state_u
{
    struct
    {
        uint32_t blocking_by_sti      : 1;   // 0
        uint32_t blocking_by_mov_ss   : 1;   // 1
        uint32_t blocking_by_smi      : 1;   // 2
        uint32_t blocking_by_nmi      : 1;   // 3
        uint32_t enclave_interruption : 1;   // 4
        uint32_t reserved             : 27;  // 31:5
    };
    uint64_t raw;
} vmx_guest_inter_state_t;
tdx_static_assert(sizeof(vmx_guest_inter_state_t) == 8, vmx_guest_inter_state_t);

typedef union guest_interrupt_status_u
{
    struct
    {
        uint8_t rvi;
        uint8_t svi;
    };
    uint16_t raw;
}guest_interrupt_status_t;


typedef union vmx_instruction_info_u
{
    struct
    {
        uint32_t na1        : 3;  // Bits 2:0
        uint32_t xmm1_index : 4;  // Bits 6:3
        uint32_t na2        : 21; // Bits 27:18
        uint32_t xmm2_index : 4;  // Bits 31:28
    } loadiwk;

    uint64_t raw;
} vmx_instruction_info_t;

#define MSR_BITMAP_SIZE                  _1KB

#define READ_BITMAP_FOR_LOW_MSR_OFFSET   0
#define READ_BITMAP_FOR_HIGH_MSR_OFFSET  (_1KB*8)   // 1024 bytes in bits
#define WRITE_BITMAP_FOR_LOW_MSR_OFFSET  (_1KB*2*8) // 2048 bytes in bits
#define WRITE_BITMAP_FOR_HIGH_MSR_OFFSET (_1KB*3*8) // 3072 bytes in bits

#define HIGH_MSR_START                   (BITS(31,30))       // 0xC000000
#define HIGH_MSR_MASK                    (~(HIGH_MSR_START)) // ~0xC000000


#define POSTED_INTERRUPT_NOTFICATION_VECTOR_INIT    0xFFFF  // Initial (illegal) value
#define POSTED_INTERRUPT_NOTFICATION_VECTOR_MIN     0
#define POSTED_INTERRUPT_NOTFICATION_VECTOR_MAX     255

#define VMX_GUEST_ES_SELECTOR_ENCODE  0x0800ULL
#define VMX_GUEST_ES_ARBYTE_ENCODE  0x4814ULL
#define VMX_GUEST_ES_LIMIT_ENCODE  0x4800ULL
#define VMX_GUEST_ES_BASE_ENCODE  0x6806ULL
#define VMX_GUEST_CS_SELECTOR_ENCODE  0x0802ULL
#define VMX_GUEST_CS_ARBYTE_ENCODE  0x4816ULL
#define VMX_GUEST_CS_LIMIT_ENCODE  0x4802ULL
#define VMX_GUEST_CS_BASE_ENCODE  0x6808ULL
#define VMX_GUEST_SS_SELECTOR_ENCODE  0x0804ULL
#define VMX_GUEST_SS_ARBYTE_ENCODE  0x4818ULL
#define VMX_GUEST_SS_LIMIT_ENCODE  0x4804ULL
#define VMX_GUEST_SS_BASE_ENCODE  0x680AULL
#define VMX_GUEST_DS_SELECTOR_ENCODE  0x0806ULL
#define VMX_GUEST_DS_ARBYTE_ENCODE  0x481AULL
#define VMX_GUEST_DS_LIMIT_ENCODE  0x4806ULL
#define VMX_GUEST_DS_BASE_ENCODE  0x680CULL
#define VMX_GUEST_LDTR_SELECTOR_ENCODE  0x080CULL
#define VMX_GUEST_LDTR_ARBYTE_ENCODE  0x4820ULL
#define VMX_GUEST_LDTR_LIMIT_ENCODE  0x480CULL
#define VMX_GUEST_LDTR_BASE_ENCODE  0x6812ULL
#define VMX_GUEST_TR_SELECTOR_ENCODE  0x080EULL
#define VMX_GUEST_TR_ARBYTE_ENCODE  0x4822ULL
#define VMX_GUEST_TR_LIMIT_ENCODE  0x480EULL
#define VMX_GUEST_TR_BASE_ENCODE  0x6814ULL
#define VMX_GUEST_FS_SELECTOR_ENCODE  0x0808ULL
#define VMX_GUEST_FS_ARBYTE_ENCODE  0x481CULL
#define VMX_GUEST_FS_LIMIT_ENCODE  0x4808ULL
#define VMX_GUEST_FS_BASE_ENCODE  0x680EULL
#define VMX_GUEST_GS_SELECTOR_ENCODE  0x080AULL
#define VMX_GUEST_GS_ARBYTE_ENCODE  0x481EULL
#define VMX_GUEST_GS_LIMIT_ENCODE  0x480AULL
#define VMX_GUEST_GS_BASE_ENCODE  0x6810ULL
#define VMX_RSVD_32_BIT_CONTROL_ENCODE  0x4024ULL
#define VMX_GUEST_GDTR_LIMIT_ENCODE  0x4810ULL
#define VMX_GUEST_GDTR_BASE_ENCODE  0x6816ULL
#define VMX_RSVD_32_BIT_GUEST_STATE_ENCODE  0x4830ULL
#define VMX_GUEST_IDTR_LIMIT_ENCODE  0x4812ULL
#define VMX_GUEST_IDTR_BASE_ENCODE  0x6818ULL
#define VMX_HOST_ES_SELECTOR_ENCODE  0x0C00ULL
#define VMX_HOST_CS_SELECTOR_ENCODE  0x0C02ULL
#define VMX_HOST_SS_SELECTOR_ENCODE  0x0C04ULL
#define VMX_HOST_DS_SELECTOR_ENCODE  0x0C06ULL
#define VMX_HOST_FS_SELECTOR_ENCODE  0x0C08ULL
#define VMX_HOST_GS_SELECTOR_ENCODE  0x0C0AULL
#define VMX_HOST_TR_SELECTOR_ENCODE  0x0C0CULL
#define VMX_GUEST_VPID_ENCODE  0x0000ULL
#define VMX_OSV_CVP_FULL_ENCODE  0x200CULL
#define VMX_OSV_CVP_HIGH_ENCODE  0x200dULL
#define VMX_VM_INSTRUCTION_ERRORCODE_ENCODE  0x4400ULL
#define VMX_PAUSE_LOOP_EXITING_GAP_ENCODE  0x4020ULL
#define VMX_PAUSE_LOOP_EXITING_WINDOW_ENCODE  0x4022ULL
#define VMX_GUEST_SAVED_WORKING_VMCS_POINTER_FULL_ENCODE  0x2800ULL
#define VMX_GUEST_SAVED_WORKING_VMCS_POINTER_HIGH_ENCODE  0x2801ULL
#define VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE  0x2802ULL
#define VMX_GUEST_IA32_DEBUGCTLMSR_HIGH_ENCODE  0x2803ULL
#define VMX_GUEST_IA32_PAT_FULL_ENCODE  0x2804ULL
#define VMX_GUEST_IA32_PAT_HIGH_ENCODE  0x2805ULL
#define VMX_GUEST_IA32_EFER_FULL_ENCODE  0x2806ULL
#define VMX_GUEST_IA32_EFER_HIGH_ENCODE  0x2807ULL
#define VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE  0x2808ULL
#define VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_HIGH_ENCODE  0x2809ULL
#define VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE  0x4002ULL
#define VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE  0x401EULL
#define VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE  0x4000ULL
#define VMX_TPR_THRESHOLD_ENCODE  0x401CULL
#define VMX_PAGEFAULT_ERRORCODE_MASK_ENCODE  0x4006ULL
#define VMX_PAGEFAULT_ERRORCODE_MATCH_ENCODE  0x4008ULL
#define VMX_GUEST_INTERRUPTIBILITY_ENCODE  0x4824ULL
#define VMX_GUEST_SLEEP_STATE_ENCODE  0x4826ULL
#define VMX_GUEST_EPT_POINTER_FULL_ENCODE  0x201AULL
#define VMX_GUEST_EPT_POINTER_HIGH_ENCODE  0x201bULL
#define VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE  0x2400ULL
#define VMX_GUEST_PHYSICAL_ADDRESS_INFO_HIGH_ENCODE  0x2401ULL
#define VMX_VM_ENTRY_INTR_INFO_ENCODE  0x4016ULL
#define VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE  0x4018ULL
#define VMX_VM_ENTRY_INSTRUCTION_LENGTH_ENCODE  0x401AULL
#define VMX_VM_EXIT_CONTROL_ENCODE  0x400CULL
#define VMX_GUEST_PREEMPTION_TIMER_COUNT_ENCODE  0x482EULL
#define VMX_VM_EXIT_MSR_STORE_COUNT_ENCODE  0x400EULL
#define VMX_VM_EXIT_MSR_LOAD_COUNT_ENCODE  0x4010ULL
#define VMX_VM_EXIT_REASON_ENCODE  0x4402ULL
#define VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE  0x4404ULL
#define VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE  0x4406ULL
#define VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE  0x4408ULL
#define VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE  0x440AULL
#define VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE  0x440CULL
#define VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE  0x440EULL
#define VMX_TSC_OFFSET_FULL_ENCODE  0x2010ULL
#define VMX_TSC_OFFSET_HIGH_ENCODE  0x2011ULL
#define VMX_VM_EXIT_QUALIFICATION_ENCODE  0x6400ULL
#define VMX_VM_EXIT_IO_RCX_ENCODE  0x6402ULL
#define VMX_VM_EXIT_IO_RSI_ENCODE  0x6404ULL
#define VMX_VM_EXIT_IO_RDI_ENCODE  0x6406ULL
#define VMX_VM_EXIT_IO_RIP_ENCODE  0x6408ULL
#define VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE  0x640AULL
#define VMX_GUEST_DR7_ENCODE  0x681AULL
#define VMX_GUEST_RSP_ENCODE  0x681CULL
#define VMX_GUEST_RIP_ENCODE  0x681EULL
#define VMX_GUEST_RFLAGS_ENCODE  0x6820ULL
#define VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE  0x6822ULL
#define VMX_GUEST_IA32_SYSENTER_ESP_ENCODE  0x6824ULL
#define VMX_GUEST_IA32_SYSENTER_EIP_ENCODE  0x6826ULL
#define VMX_GUEST_IA32_SYSENTER_CS_ENCODE  0x482AULL
#define VMX_EPTP_INDEX_ENCODE  0x0004ULL
#define VMX_GUEST_CR0_ENCODE  0x6800ULL
#define VMX_GUEST_CR3_ENCODE  0x6802ULL
#define VMX_GUEST_CR4_ENCODE  0x6804ULL
#define VMX_GUEST_PDPTR0_FULL_ENCODE  0x280AULL
#define VMX_GUEST_PDPTR0_HIGH_ENCODE  0x280bULL
#define VMX_GUEST_PDPTR1_FULL_ENCODE  0x280CULL
#define VMX_GUEST_PDPTR1_HIGH_ENCODE  0x280dULL
#define VMX_GUEST_PDPTR2_FULL_ENCODE  0x280EULL
#define VMX_GUEST_PDPTR2_HIGH_ENCODE  0x280fULL
#define VMX_GUEST_PDPTR3_FULL_ENCODE  0x2810ULL
#define VMX_GUEST_PDPTR3_HIGH_ENCODE  0x2811ULL
#define VMX_CR0_GUEST_HOST_MASK_ENCODE  0x6000ULL
#define VMX_CR4_GUEST_HOST_MASK_ENCODE  0x6002ULL
#define VMX_CR0_READ_SHADOW_ENCODE  0x6004ULL
#define VMX_CR4_READ_SHADOW_ENCODE  0x6006ULL
#define VMX_CR3_TARGET_VALUE_0_ENCODE  0x6008ULL
#define VMX_CR3_TARGET_VALUE_1_ENCODE  0x600AULL
#define VMX_CR3_TARGET_VALUE_2_ENCODE  0x600CULL
#define VMX_CR3_TARGET_VALUE_3_ENCODE  0x600EULL
#define VMX_EOI_EXIT_TABLE_0_FULL_ENCODE  0x201CULL
#define VMX_EOI_EXIT_TABLE_0_HIGH_ENCODE  0x201dULL
#define VMX_EOI_EXIT_TABLE_1_FULL_ENCODE  0x201EULL
#define VMX_EOI_EXIT_TABLE_1_HIGH_ENCODE  0x201fULL
#define VMX_EOI_EXIT_TABLE_2_FULL_ENCODE  0x2020ULL
#define VMX_EOI_EXIT_TABLE_2_HIGH_ENCODE  0x2021ULL
#define VMX_EOI_EXIT_TABLE_3_FULL_ENCODE  0x2022ULL
#define VMX_EOI_EXIT_TABLE_3_HIGH_ENCODE  0x2023ULL
#define VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE  0x2016ULL
#define VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH_ENCODE  0x2017ULL
#define VMX_GUEST_SMBASE_ENCODE  0x4828ULL
#define VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE  0x0002ULL
#define VMX_EXCEPTION_BITMAP_ENCODE  0x4004ULL
#define VMX_CR3_TARGET_COUNT_ENCODE  0x400AULL
#define VMX_VM_ENTRY_CONTROL_ENCODE  0x4012ULL
#define VMX_VM_ENTRY_MSR_LOAD_COUNT_ENCODE  0x4014ULL
#define VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE  0x2012ULL
#define VMX_VIRTUAL_APIC_PAGE_ADDRESS_HIGH_ENCODE  0x2013ULL
#define VMX_IO_BITMAP_A_PHYPTR_FULL_ENCODE  0x2000ULL
#define VMX_IO_BITMAP_A_PHYPTR_HIGH_ENCODE  0x2001ULL
#define VMX_IO_BITMAP_B_PHYPTR_FULL_ENCODE  0x2002ULL
#define VMX_IO_BITMAP_B_PHYPTR_HIGH_ENCODE  0x2003ULL
#define VMX_EXIT_MSR_STORE_PHYPTR_FULL_ENCODE  0x2006ULL
#define VMX_EXIT_MSR_STORE_PHYPTR_HIGH_ENCODE  0x2007ULL
#define VMX_EXIT_MSR_LOAD_PHYPTR_FULL_ENCODE  0x2008ULL
#define VMX_EXIT_MSR_LOAD_PHYPTR_HIGH_ENCODE  0x2009ULL
#define VMX_ENTRY_MSR_LOAD_PHYPTR_FULL_ENCODE  0x200AULL
#define VMX_ENTRY_MSR_LOAD_PHYPTR_HIGH_ENCODE  0x200bULL
#define VMX_VIRTUAL_APIC_ACCESS_PAGE_ADDRESS_FULL_ENCODE  0x2014ULL
#define VMX_VIRTUAL_APIC_ACCESS_PAGE_ADDRESS_HIGH_ENCODE  0x2015ULL
#define VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE  0x2004ULL
#define VMX_MSR_BITMAP_PHYPTR_HIGH_ENCODE  0x2005ULL
#define VMX_HOST_RSP_ENCODE  0x6C14ULL
#define VMX_HOST_RIP_ENCODE  0x6C16ULL
#define VMX_HOST_IA32_PAT_FULL_ENCODE  0x2c00ULL
#define VMX_HOST_IA32_PAT_HIGH_ENCODE  0x2c01
#define VMX_HOST_IA32_EFER_FULL_ENCODE  0x2c02
#define VMX_HOST_IA32_EFER_HIGH_ENCODE  0x2c03
#define VMX_HOST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE  0x2c04
#define VMX_HOST_IA32_PERF_GLOBAL_CONTROL_HIGH_ENCODE  0x2c05
#define VMX_HOST_CR0_ENCODE  0x6C00
#define VMX_HOST_CR3_ENCODE  0x6C02
#define VMX_HOST_CR4_ENCODE  0x6C04ULL
#define VMX_HOST_IDTR_BASE_ENCODE  0x6C0E
#define VMX_HOST_GDTR_BASE_ENCODE  0x6C0C
#define VMX_HOST_FS_BASE_ENCODE  0x6C06
#define VMX_HOST_GS_BASE_ENCODE  0x6C08
#define VMX_HOST_TR_BASE_ENCODE  0x6C0A
#define VMX_HOST_IA32_SYSENTER_ESP_ENCODE  0x6C10
#define VMX_HOST_IA32_SYSENTER_EIP_ENCODE  0x6C12
#define VMX_HOST_IA32_SYSENTER_CS_ENCODE  0x4C00
#define VMX_GUEST_INTERRUPT_STATUS_ENCODE  0x0810
#define VMX_GUEST_UINV_ENCODE  0x0814
#define VMX_PML_INDEX_ENCODE  0x0812
#define VMX_VM_FUNCTION_CONTROLS_FULL_ENCODE  0x2018
#define VMX_VM_FUNCTION_CONTROLS_HIGH_ENCODE  0x2019
#define VMX_EPTP_LIST_ADDRESS_FULL_ENCODE  0x2024
#define VMX_EPTP_LIST_ADDRESS_HIGH_ENCODE  0x2025
#define VMX_VMREAD_BITMAP_ADDRESS_FULL_ENCODE  0x2026
#define VMX_VMREAD_BITMAP_ADDRESS_HIGH_ENCODE  0x2027
#define VMX_VMWRITE_BITMAP_ADDRESS_FULL_ENCODE  0x2028
#define VMX_VMWRITE_BITMAP_ADDRESS_HIGH_ENCODE  0x2029
#define VMX_PML_LOG_ADDRESS_FULL_ENCODE  0x200E
#define VMX_PML_LOG_ADDRESS_HIGH_ENCODE  0x200f
#define VMX_XSS_EXIT_CONTROL_FULL_ENCODE  0x202C
#define VMX_XSS_EXIT_CONTROL_HIGH_ENCODE  0x202d
#define VMX_ENCLS_EXIT_CONTROL_FULL_ENCODE  0x202E
#define VMX_ENCLS_EXIT_CONTROL_HIGH_ENCODE  0x202f
#define VMX_RSVD_64_BIT_VMEXIT_DATA_FULL_ENCODE  0x2402
#define VMX_RSVD_64_BIT_VMEXIT_DATA_HIGH_ENCODE  0x2403
#define VMX_ENCLV_EXIT_CONTROL_FULL_ENCODE  0x2036
#define VMX_ENCLV_EXIT_CONTROL_HIGH_ENCODE  0x2037
#define VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE  0x202A
#define VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_HIGH_ENCODE  0x202b
#define VMX_GUEST_BNDCFGS_FULL_ENCODE  0x2812
#define VMX_GUEST_BNDCFGS_HIGH_ENCODE  0x2813
#define VMX_SPPTP_FULL_ENCODE  0x2030
#define VMX_SPPTP_HIGH_ENCODE  0x2031
#define VMX_TSC_MULTIPLIER_FULL_ENCODE  0x2032
#define VMX_TSC_MULTIPLIER_HIGH_ENCODE  0x2033
#define VMX_GUEST_RTIT_CTL_FULL_ENCODE  0x2814
#define VMX_GUEST_RTIT_CTL_HIGH_ENCODE  0x2815
#define VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE  0x2034
#define VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_HIGH_ENCODE  0x2035
#define VMX_PCONFIG_EXITING_FULL_ENCODE  0x203E
#define VMX_PCONFIG_EXITING_HIGH_ENCODE  0x203f
#define VMX_PASID_LOW_FULL_ENCODE  0x2038
#define VMX_PASID_LOW_HIGH_ENCODE  0x2039
#define VMX_PASID_HIGH_FULL_ENCODE  0x203A
#define VMX_PASID_HIGH_HIGH_ENCODE  0x203b
#define VMX_HOST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE  0x6C1C
#define VMX_GUEST_IA32_S_CET_ENCODE  0x6828
#define VMX_GUEST_SSP_ENCODE  0x682A
#define VMX_GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE  0x682C
#define VMX_HOST_IA32_S_CET_ENCODE  0x6C18
#define VMX_HOST_SSP_ENCODE  0x6C1A
#define VMX_HKID_ENCODE  0x4026
#define VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE  0x203C
#define VMX_GUEST_SHARED_EPT_POINTER_HIGH_ENCODE  0x203D
#define VMX_NO_COMMIT_THRESHOLD_ENCODE  0x4024
#define VMX_GUEST_LBR_CTL_FULL_ENCODE  0x2816
#define VMX_GUEST_PKRS_FULL_ENCODE  0x2818

#endif /* SRC_COMMON_X86_DEFS_VMCS_DEFS_H_ */
