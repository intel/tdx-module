// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_vp_rd_wr
 * @brief TDHVPRD and TDHVPWR API handlers
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "auto_gen/tdvps_fields_lookup.h"

#define VAPIC_DEBUG_RD_MASK             ((uint64_t)(-1ULL))
#define VAPIC_DEBUG_WR_MASK             0ULL
#define VAPIC_PROD_RD_MASK              0ULL
#define VAPIC_PROD_WR_MASK              0ULL
#define POSTED_INTER_DESCRIPTOR_SIZE    64   //64 Byte alignment for Posted-interrupt descriptor address


/** @brief Helper function to get TDVPS field information
 *  @note:  The return read and write masks must take into account the field size, i.e.,
 *          if a field size is 16b, the upper 48b of the masks must be 0.
 */
static bool_t get_tdvps_field_data(td_ctrl_struct_field_code_t field_code,
                                   bool_t is_debug,
                                   uint32_t* offset_in_tdvps,
                                   uint64_t* rd_mask,
                                   uint64_t* wr_mask)

{
    *offset_in_tdvps = 0ULL;
    *rd_mask = 0ULL;
    *wr_mask = 0ULL;

    // Special case for fields not mapped in the lookup table

    if (field_code.class_code == TDVPS_GUEST_EXT_STATE_CLASS_CODE)
    {
        if ((field_code.reserved != 0) || (field_code.non_arch != 0))
        {
            return false;
        }
        // Offset to the buffer
        if ((uint64_t)field_code.field_code < (SIZE_OF_TDVPS_GUEST_EXT_STATE_IN_BYTES / sizeof(uint64_t)))
        {
            if (is_debug)
            {
                *offset_in_tdvps = OFFSET_OF_TDVPS_GUEST_EXT_STATE + (field_code.field_code * sizeof(uint64_t));
                *rd_mask = -1ULL;
                *wr_mask = -1ULL;
            }
            // Zero values returned by default
            return true;
        }
        else
        {
            // Entry beyond the XBUF size doesn't exist
            return false;
        }
    }

    for (uint32_t i = 0; i < MAX_NUM_TDVPS_LOOKUP; i++)
    {
        if (tdvps_lookup[i].tdvps_field_code.raw == field_code.raw)
        {
            *offset_in_tdvps = tdvps_lookup[i].offset;

            if (is_debug)
            {
                *rd_mask = tdvps_lookup[i].dbg_rd_mask;
                *wr_mask = tdvps_lookup[i].dbg_wr_mask;
            }
            else
            {
                *rd_mask = tdvps_lookup[i].prod_rd_mask;
                *wr_mask = tdvps_lookup[i].prod_wr_mask;
            }

            return true;
        }
    }

    // Entry not found
    return false;
}

/**
 * @brief Helper function to get TD VMCS field information
 * @note  The return read and write masks must take into account the field size, i.e.,
 *         if a field size is 16b, the upper 48b of the masks must be 0.
 */
static void get_td_vmcs_field_data(td_ctrl_struct_field_code_t field_code,
                                   bool_t is_debug,
                                   uint64_t* rd_mask,
                                   uint64_t* wr_mask,
                                   bool_t* is_shared_hpa)

{
    *is_shared_hpa = false;

    if (!is_debug)
    {
        switch (field_code.vmcs_field_code.raw)
        {
            case VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE:
                *rd_mask = BIT(7);
                *wr_mask = BIT(7);
                break;
            case VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE:
                *rd_mask = BIT(30) | BIT(31);
                *wr_mask = BIT(30) | BIT(31);
                break;
            case VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE:
                *is_shared_hpa = true;
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFFFFFFC0;
                break;
            case VMX_GUEST_EPT_POINTER_FULL_ENCODE:
                *is_shared_hpa = false;
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0ULL;
                break;
            case VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE:
                *is_shared_hpa = true;
                *rd_mask = 0xFFFFFFFFFF000;
                *wr_mask = 0xFFFFFFFFFF000; // Bits 12:51 are RW and the rest are RO
                break;
            case VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE:
            case VMX_NO_COMMIT_THRESHOLD_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = BIT_MASK_64BITS;
                break;
            case VMX_PML_LOG_ADDRESS_FULL_ENCODE:
                *is_shared_hpa = true;
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0ULL;
                break;
            case VMX_PAUSE_LOOP_EXITING_GAP_ENCODE:
            case VMX_PAUSE_LOOP_EXITING_WINDOW_ENCODE:
            case VMX_TSC_OFFSET_FULL_ENCODE:
            case VMX_TSC_MULTIPLIER_FULL_ENCODE:
            case VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE:
            case VMX_HKID_ENCODE:
            case VMX_VM_FUNCTION_CONTROLS_FULL_ENCODE:
            case VMX_EPTP_LIST_ADDRESS_FULL_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0ULL;
                break;
            default:
                *rd_mask = 0ULL;
                *wr_mask = 0ULL;
        }
    }
    else // Debug
    {
        switch (field_code.vmcs_field_code.raw)
        {
            case VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE:
                *rd_mask = BIT_MASK_32BITS;
                *wr_mask = BIT(7);
                break;
            case VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE:
                *rd_mask = BIT_MASK_32BITS;
                *wr_mask = 0xC0130C04;
                break;
            case VMX_GUEST_EPT_POINTER_FULL_ENCODE:
                *is_shared_hpa = false;
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0;
                break;
            case VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE:
                *is_shared_hpa = true;
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFF000; // Bits 12:51 are RW and the rest are RO
                break;
            case VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE:
                *is_shared_hpa = true;
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFFFFFFC0;
                break;
            case VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE:
                *rd_mask = BIT_MASK_32BITS;
                *wr_mask = 0x69999A04;
                break;
            case VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0x1;
                break;
            case VMX_PML_LOG_ADDRESS_FULL_ENCODE:
                *is_shared_hpa = true;
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFFFFF000;
                break;
            case VMX_CR0_GUEST_HOST_MASK_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFF9FFFFFDE;
                break;
            case VMX_CR0_READ_SHADOW_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFFFFFFDE;
                break;
            case VMX_CR4_GUEST_HOST_MASK_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFFFF9FBF;
                break;
            case VMX_CR4_READ_SHADOW_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFFFFFFBF;
                break;
            case VMX_EXCEPTION_BITMAP_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0xFFFFFFFFFFFBFFFF;
                break;
            case VMX_GUEST_SMBASE_ENCODE:
            case VMX_GUEST_SAVED_WORKING_VMCS_POINTER_FULL_ENCODE:
            case VMX_HOST_RIP_ENCODE:
            case VMX_HOST_RSP_ENCODE:
            case VMX_HOST_SSP_ENCODE:
            case VMX_HOST_GS_BASE_ENCODE:
            case VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE:
            case VMX_OSV_CVP_FULL_ENCODE:
                *rd_mask = 0ULL;
                *wr_mask = 0ULL;
                break;
            case VMX_GUEST_BNDCFGS_FULL_ENCODE:
            case VMX_GUEST_SLEEP_STATE_ENCODE:
            case VMX_VIRTUAL_APIC_ACCESS_PAGE_ADDRESS_FULL_ENCODE:
            case VMX_TPR_THRESHOLD_ENCODE:
            case VMX_EOI_EXIT_TABLE_0_FULL_ENCODE:
            case VMX_EOI_EXIT_TABLE_1_FULL_ENCODE:
            case VMX_EOI_EXIT_TABLE_2_FULL_ENCODE:
            case VMX_EOI_EXIT_TABLE_3_FULL_ENCODE:
            case VMX_IO_BITMAP_A_PHYPTR_FULL_ENCODE:
            case VMX_IO_BITMAP_B_PHYPTR_FULL_ENCODE:
            case VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE:
            case VMX_HKID_ENCODE:
            case VMX_GUEST_VPID_ENCODE:
            case VMX_VM_FUNCTION_CONTROLS_FULL_ENCODE:
            case VMX_EPTP_LIST_ADDRESS_FULL_ENCODE:
            case VMX_VMREAD_BITMAP_ADDRESS_FULL_ENCODE:
            case VMX_VMWRITE_BITMAP_ADDRESS_FULL_ENCODE:
            case VMX_ENCLS_EXIT_CONTROL_FULL_ENCODE:
            case VMX_ENCLV_EXIT_CONTROL_FULL_ENCODE:
            case VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE:
            case VMX_EPTP_INDEX_ENCODE:
            case VMX_PASID_LOW_FULL_ENCODE:
            case VMX_PASID_HIGH_FULL_ENCODE:
            case VMX_PCONFIG_EXITING_FULL_ENCODE:
            case VMX_VM_EXIT_MSR_STORE_COUNT_ENCODE:
            case VMX_EXIT_MSR_STORE_PHYPTR_FULL_ENCODE:
            case VMX_EXIT_MSR_LOAD_PHYPTR_FULL_ENCODE:
            case VMX_VM_ENTRY_CONTROL_ENCODE:
            case VMX_VM_ENTRY_MSR_LOAD_COUNT_ENCODE:
            case VMX_ENTRY_MSR_LOAD_PHYPTR_FULL_ENCODE:
            case VMX_VM_ENTRY_INTR_INFO_ENCODE:
            case VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE:
            case VMX_VM_ENTRY_INSTRUCTION_LENGTH_ENCODE:
            case VMX_VM_EXIT_REASON_ENCODE:
            case VMX_VM_EXIT_QUALIFICATION_ENCODE:
            case VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE:
            case VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE:
            case VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE:
            case VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE:
            case VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE:
            case VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE:
            case VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE:
            case VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE:
            case VMX_VM_EXIT_IO_RCX_ENCODE:
            case VMX_VM_EXIT_IO_RSI_ENCODE:
            case VMX_VM_EXIT_IO_RDI_ENCODE:
            case VMX_VM_EXIT_IO_RIP_ENCODE:
            case VMX_VM_INSTRUCTION_ERRORCODE_ENCODE:
            case VMX_VM_EXIT_CONTROL_ENCODE:
            case VMX_GUEST_PDPTR0_FULL_ENCODE:
            case VMX_GUEST_PDPTR1_FULL_ENCODE:
            case VMX_GUEST_PDPTR2_FULL_ENCODE:
            case VMX_GUEST_PDPTR3_FULL_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = 0ULL;
                break;
            case VMX_PML_INDEX_ENCODE:
            case VMX_GUEST_CR0_ENCODE:
            case VMX_GUEST_CR3_ENCODE:
            case VMX_GUEST_CR4_ENCODE:
            case VMX_GUEST_DR7_ENCODE:
            case VMX_GUEST_RSP_ENCODE:
            case VMX_GUEST_RIP_ENCODE:
            case VMX_GUEST_RFLAGS_ENCODE:
            case VMX_GUEST_ES_SELECTOR_ENCODE:
            case VMX_GUEST_CS_SELECTOR_ENCODE:
            case VMX_GUEST_SS_SELECTOR_ENCODE:
            case VMX_GUEST_DS_SELECTOR_ENCODE:
            case VMX_GUEST_FS_SELECTOR_ENCODE:
            case VMX_GUEST_GS_SELECTOR_ENCODE:
            case VMX_GUEST_LDTR_SELECTOR_ENCODE:
            case VMX_GUEST_TR_SELECTOR_ENCODE:
            case VMX_GUEST_ES_BASE_ENCODE:
            case VMX_GUEST_CS_BASE_ENCODE:
            case VMX_GUEST_SS_BASE_ENCODE:
            case VMX_GUEST_DS_BASE_ENCODE:
            case VMX_GUEST_FS_BASE_ENCODE:
            case VMX_GUEST_GS_BASE_ENCODE:
            case VMX_GUEST_LDTR_BASE_ENCODE:
            case VMX_GUEST_TR_BASE_ENCODE:
            case VMX_GUEST_GDTR_BASE_ENCODE:
            case VMX_GUEST_IDTR_BASE_ENCODE:
            case VMX_GUEST_ES_LIMIT_ENCODE:
            case VMX_GUEST_CS_LIMIT_ENCODE:
            case VMX_GUEST_SS_LIMIT_ENCODE:
            case VMX_GUEST_DS_LIMIT_ENCODE:
            case VMX_GUEST_FS_LIMIT_ENCODE:
            case VMX_GUEST_GS_LIMIT_ENCODE:
            case VMX_GUEST_LDTR_LIMIT_ENCODE:
            case VMX_GUEST_TR_LIMIT_ENCODE:
            case VMX_GUEST_GDTR_LIMIT_ENCODE:
            case VMX_GUEST_IDTR_LIMIT_ENCODE:
            case VMX_GUEST_ES_ARBYTE_ENCODE:
            case VMX_GUEST_CS_ARBYTE_ENCODE:
            case VMX_GUEST_SS_ARBYTE_ENCODE:
            case VMX_GUEST_DS_ARBYTE_ENCODE:
            case VMX_GUEST_FS_ARBYTE_ENCODE:
            case VMX_GUEST_GS_ARBYTE_ENCODE:
            case VMX_GUEST_LDTR_ARBYTE_ENCODE:
            case VMX_GUEST_TR_ARBYTE_ENCODE:
            case VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE:
            case VMX_GUEST_IA32_SYSENTER_CS_ENCODE:
            case VMX_GUEST_IA32_SYSENTER_ESP_ENCODE:
            case VMX_GUEST_IA32_SYSENTER_EIP_ENCODE:
            case VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE:
            case VMX_GUEST_IA32_PAT_FULL_ENCODE:
            case VMX_GUEST_IA32_EFER_FULL_ENCODE:
            case VMX_GUEST_IA32_S_CET_ENCODE:
            case VMX_GUEST_SSP_ENCODE:
            case VMX_GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE:
            case VMX_GUEST_RTIT_CTL_FULL_ENCODE:
            case VMX_GUEST_LBR_CTL_FULL_ENCODE:
            case VMX_GUEST_PKRS_FULL_ENCODE:
            case VMX_GUEST_INTERRUPTIBILITY_ENCODE:
            case VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE:
            case VMX_GUEST_PREEMPTION_TIMER_COUNT_ENCODE:
            case VMX_GUEST_INTERRUPT_STATUS_ENCODE:
            case VMX_GUEST_UINV_ENCODE:
            case VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE:
            case VMX_CR3_TARGET_VALUE_0_ENCODE:
            case VMX_CR3_TARGET_VALUE_1_ENCODE:
            case VMX_CR3_TARGET_VALUE_2_ENCODE:
            case VMX_CR3_TARGET_VALUE_3_ENCODE:
            case VMX_CR3_TARGET_COUNT_ENCODE:
            case VMX_PAGEFAULT_ERRORCODE_MASK_ENCODE:
            case VMX_PAGEFAULT_ERRORCODE_MATCH_ENCODE:
            case VMX_TSC_OFFSET_FULL_ENCODE:
            case VMX_TSC_MULTIPLIER_FULL_ENCODE:
            case VMX_PAUSE_LOOP_EXITING_GAP_ENCODE:
            case VMX_PAUSE_LOOP_EXITING_WINDOW_ENCODE:
            case VMX_XSS_EXIT_CONTROL_FULL_ENCODE:
            case VMX_NO_COMMIT_THRESHOLD_ENCODE:
            case VMX_VM_EXIT_MSR_LOAD_COUNT_ENCODE:
                *rd_mask = BIT_MASK_64BITS;
                *wr_mask = BIT_MASK_64BITS;
                break;
            default:
                *rd_mask = 0;
                *wr_mask = 0;
        }
    }

    if (field_code.vmcs_field_code.width == VMCS_FIELD_WIDTH_16B)
    {
        *rd_mask &= BIT_MASK_16BITS;
        *wr_mask &= BIT_MASK_16BITS;
    }
    else if (field_code.vmcs_field_code.width == VMCS_FIELD_WIDTH_32B)
    {
        *rd_mask &= BIT_MASK_32BITS;
        *wr_mask &= BIT_MASK_32BITS;
    }
}


/**
 * @brief Read from or write to a TDVPS field
 *
 * @param tdcs_ptr Pointer to the active TDCS structure - from the debug attributes
 * @param tdvps_ptr Pointer to the active TDVPS structure
 * @param data Input (for write) Output (for read and write)
 * @param field_code TDVPS field code information
 * @param write Is write or read operation
 *
 * @return api_error_code_e Success or Error type
 */
_STATIC_INLINE_ api_error_type read_or_write_tdvps_field(tdcs_t* tdcs_ptr,
                                                           tdvps_t* tdvps_ptr,
                                                           uint64_t* data,
                                                           td_ctrl_struct_field_code_t field_code,
                                                           bool_t write,
                                                           uint64_t wr_request_mask)
{
    uint64_t wr_value = *data;
    uint64_t rd_value = 0;
    uint64_t rd_mask, wr_mask;
    uint32_t offset;
    bool_t is_shared_hpa = false;
    uint64_t* field_ptr = NULL;
    vmx_pinbased_ctls_t pinbased_exec_ctls;
    vmx_procbased_ctls2_t procbase_exec_ctls2;
    ia32_debugctl_t ia32_debugctl;
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    switch (field_code.class_code)
    {
        case TDVPS_VMCS_CLASS_CODE:
        {
            if ((field_code.reserved != 0) || (field_code.non_arch != 0))
           {
               return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
           }
            // We do not allow using the "High" access type
            if (field_code.vmcs_field_code.access_type == VMCS_FIELD_ACCESS_TYPE_HIGH)
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }

            // Read the VMCS field. VMREAD may return an error if the field code does not match
            // a real VMCS field.
            if (!ia32_try_vmread(field_code.vmcs_field_code.raw, &rd_value))
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }

            get_td_vmcs_field_data(field_code,
                                   tdcs_ptr->executions_ctl_fields.attributes.debug,
                                   &rd_mask,
                                   &wr_mask,
                                   &is_shared_hpa);

            break;
        }
        case TDVPS_VAPIC_CLASS_CODE:
            // The whole VAPIC page uses the same read and write masks
            if ((field_code.reserved != 0) || (field_code.non_arch != 0))
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }
            if (tdcs_ptr->executions_ctl_fields.attributes.debug)
            {
                rd_mask = VAPIC_DEBUG_RD_MASK;
                wr_mask = VAPIC_DEBUG_WR_MASK;
            }
            else
            {
                rd_mask = VAPIC_PROD_RD_MASK;
                wr_mask = VAPIC_PROD_WR_MASK;
            }

            // VAPIC page is just an array of 512 8B fields.  The field code
            // is an 8-byte index into the page and must be less than 4096/8
            if ((uint64_t)field_code.field_code >= (TDX_PAGE_SIZE_IN_BYTES / sizeof(uint64_t)))
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }

            field_ptr = (uint64_t*)&tdvps_ptr->vapic.raw[field_code.field_code * sizeof(uint64_t)];
            rd_value = *field_ptr;

            break;
        case TDVPS_GUEST_GPR_STATE_CLASS_CODE:
        case TDVPS_GUEST_EXT_STATE_CLASS_CODE:
        case TDVPS_GUEST_MSR_STATE_CLASS_CODE:
        case TDVPS_GUEST_OTHER_STATE_CLASS_CODE:
        case TDVPS_VE_INFO_CLASS_CODE:
        case TDVPS_MANAGEMENT_CLASS_CODE:
            if (!get_tdvps_field_data(field_code,
                                      tdcs_ptr->executions_ctl_fields.attributes.debug,
                                      &offset,
                                      &rd_mask,    // The read mask takes into account field size
                                      &wr_mask))   // The write mask takes into account field size
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }

            field_ptr = (uint64_t*)((uint8_t*)tdvps_ptr + offset);
            rd_value = *field_ptr;

            break;
        default:
        {
            // We should get here - but return an error anyway
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        }
    }

    if (write)
    {
        // Narrow down the bits to be written with the input mask
        wr_mask &= wr_request_mask;

        // Check if the requested field is writable.
        // Note that there is no check for readable; we don't have write-only
        // fields.
        if (wr_mask == 0)
        {
            return TDX_FIELD_NOT_WRITABLE;
        }

        // Insert the bits to be written
        wr_value = (rd_value & ~wr_mask) | (wr_value & wr_mask);

        // Check additional requirements on the value to be written
        if (is_shared_hpa)
        {
            api_error_code_e return_val = TDX_OPERAND_INVALID;

            /* Initial value of a shared HPA is NULL_PA (-1).
             *  When writing a new value, we need to clear bits that are not
             *  part of the write mask (e.g., to ensure alignment).
            */
            if ((rd_value & BIT(63)) != 0)
            {
                wr_value &= wr_mask;
            }

            if (field_code.class_code == TDVPS_VMCS_CLASS_CODE &&
                    field_code.vmcs_field_code.raw == VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE)
            {
                return_val = shared_hpa_check((pa_t)wr_value, POSTED_INTER_DESCRIPTOR_SIZE);
            }
            else
            {
                return_val = shared_hpa_check((pa_t)wr_value, TDX_PAGE_SIZE_IN_BYTES);
            }

            if (return_val != TDX_SUCCESS)
            {
                return api_error_with_operand_id(return_val, OPERAND_ID_R8);
            }
        }

        if (field_code.class_code == TDVPS_VMCS_CLASS_CODE)
        {
            // Handle Special Cases
            //   - These are marked as RW* in the FAS TD VMCS tables
            //   - Shared PA values and their alignments were checked above
            switch (field_code.vmcs_field_code.raw)
            {
            case VMX_GUEST_CR0_ENCODE:
                if (write_guest_cr0_from_host(wr_value) != CR_WR_SUCCESS)
                {
                    return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                }
                break;
            case VMX_GUEST_CR4_ENCODE:
                if (write_guest_cr4_from_host(wr_value, tdcs_ptr, tdvps_ptr) != CR_WR_SUCCESS)
                {
                    return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                }
                break;

            case VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE:
                // This field's writable bits is not static.  In addition to the write mask that was
                // applied above, we need to check compatibility with the value read on TDHSYSINIT from
                // the IA32_VMX_PROCBASED_CTLS2 MSR.
                if ((~(uint32_t)wr_value & tdx_global_data_ptr->plt_common_config.ia32_vmx_procbased_ctls2.not_allowed0) |
                   ((uint32_t)wr_value & ~tdx_global_data_ptr->plt_common_config.ia32_vmx_procbased_ctls2.allowed1))
                {
                   return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                }
                // PML address must have been set (as a valid shared HPA) for PML to be enabled
                procbase_exec_ctls2.raw = wr_value;
                if (procbase_exec_ctls2.enable_pml)
                {
                    uint64_t vec;

                    /*
                     * Check if a PA value is still its initial and invalid value.
                     * We indicate this by the MSB of the PA being set to 1
                     */
                    ia32_vmread(VMX_PML_LOG_ADDRESS_FULL_ENCODE, &vec);
                    if ((vec & BIT(63)) != 0)
                    {
                        return api_error_with_operand_id(TDX_TD_VMCS_FIELD_NOT_INITIALIZED,
                                VMX_PML_LOG_ADDRESS_FULL_ENCODE);
                    }
                }

                break;

            case VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE:
                // Enabling posted interrupts in only allowed if the proper fields
                // have been initialized
                pinbased_exec_ctls.raw = (uint32_t)wr_value;
                if (pinbased_exec_ctls.process_posted_interrupts == 1)
                {
                    uint64_t addr, vec;

                    ia32_vmread(VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE, &vec);

                    if ((uint16_t)vec == POSTED_INTERRUPT_NOTFICATION_VECTOR_INIT)
                    {
                        return api_error_with_operand_id(TDX_TD_VMCS_FIELD_NOT_INITIALIZED,
                                                         VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE);
                    }

                    /*
                     * Check if a PA value is still its initial and invalid value.
                     * We indicate this by the MSB of the PA being set to 1
                     */
                    ia32_vmread(VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE, &addr);
                    if ((addr & BIT(63)) != 0)
                    {
                        return api_error_with_operand_id(TDX_TD_VMCS_FIELD_NOT_INITIALIZED,
                                                         VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE);
                    }
                }

                break;

            case VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE:
                if (((uint16_t)wr_value < POSTED_INTERRUPT_NOTFICATION_VECTOR_MIN) ||
                    ((uint16_t)wr_value > POSTED_INTERRUPT_NOTFICATION_VECTOR_MAX))
                {
                    return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                }

                break;

            case VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE:
                ia32_debugctl.raw = wr_value;

                // For simplicity, we check  on TDHSYSINIT/TDHSYSINITLP that all non-reserved
                // bits are supported.  Thus, checking of unsupported bits is done by the
                // write mask and there's no need for an explicit check here.*/

                // Bits 7:6 must not be set to 01 unless the TD is in debug mode
                tdx_debug_assert(tdcs_ptr->executions_ctl_fields.attributes.debug == 1);

                if ((ia32_debugctl.bts == 0) &&
                    (ia32_debugctl.tr == 1))
                {
                    return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                }

                // Update TD VMCS with the input value, except bit 13
                ia32_debugctl.en_uncore_pmi = get_local_data()->ia32_debugctl_value.en_uncore_pmi;
                wr_value = ia32_debugctl.raw;

                break;

            case VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE:
                // If we got here, then we passed the check above that this is a valid
                // shared HPA.  Mark Shared EPTP as initialized.
                tdvps_ptr->management.is_shared_eptp_valid = true;

                break;

            default:
                break;
            }

            /* VMWRITE may fail if the field is read-only but the write mask
               allowed write.
            */
            if (!ia32_try_vmwrite(field_code.vmcs_field_code.raw, wr_value))
            {
                return TDX_FIELD_NOT_WRITABLE;
            }
        } 
        else if (field_code.class_code == TDVPS_MANAGEMENT_CLASS_CODE)
        {
            if (field_code.field_code == XFAM_FIELD_CODE)
            {
                if (!check_xfam(wr_value))
                {
                    return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
                }
            }
            *field_ptr = wr_value;
        }
        else
        {
            // Handle Special Cases

            // Currently there are not such cases for TDVPS fields (not in TD VMCS)

            // Write the value
            *field_ptr = wr_value;
        }
    }

    else // Read
    {
        if (rd_mask == 0)
        {
            return TDX_FIELD_NOT_READABLE;
        }
        vcpu_state_t vcpu_state_details;
        guest_interrupt_status_t interrupt_status;
        //  Special Handling on Read
        if (field_code.class_code == TDVPS_GUEST_OTHER_STATE_CLASS_CODE)
        {
            if(field_code.field_code == TDVPS_VCPU_STATE_DETAILS_FIELD_CODE)
            {
                // Calculate virtual interrupt pending status
                uint64_t interrupt_status_raw;
                ia32_vmread(VMX_GUEST_INTERRUPT_STATUS_ENCODE, &interrupt_status_raw);
                interrupt_status.raw = (uint16_t)interrupt_status_raw;
                vcpu_state_details.raw = 0ULL;
                if ((interrupt_status.rvi & 0xF0UL) > (tdvps_ptr->vapic.apic[PPR_INDEX] & 0xF0UL))
                {
                    vcpu_state_details.vmxip = 1ULL;
                }
                rd_value = vcpu_state_details.raw;

            }
        }
    }


    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    *data = rd_value & rd_mask;
    return TDX_SUCCESS;
}


static api_error_type tdh_vp_rd_wr(uint64_t target_tdvpr_pa,
                            td_ctrl_struct_field_code_t field_code,
                            tdx_module_local_t * local_data_ptr,
                            bool_t write,
                            uint64_t wr_data,
                            uint64_t wr_request_mask)
{
    // TDVPS related variables
    pa_t                  tdvpr_pa = {.raw = target_tdvpr_pa};  // TDVPR physical address
    tdvps_t             * tdvps_ptr = NULL;                     // Pointer to the TDVPS structure ((Multi-page linear address)
    pamt_block_t          tdvpr_pamt_block;                     // TDVPR PAMT block
    pamt_entry_t        * tdvpr_pamt_entry_ptr;                 // Pointer to the TDVPR PAMT entry
    bool_t                tdvpr_locked_flag = false;            // Indicate TDVPR is locked
    page_size_t           tdvpr_leaf_size = PT_4KB;

    // TDR related variables
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    td_ctrl_struct_field_code_t    requested_field_code = field_code;

    uint16_t              curr_hkid;
    bool_t                td_vmcs_loaded = false;               // Indicates whether TD VMCS was loaded

    uint64_t              rd_wr_data = wr_data;

    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Initialize output registers to default values
    local_data_ptr->vmm_regs.r8 = 0ULL;

    // Check and lock the parent TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RCX,
                                                         TDX_LOCK_SHARED,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_block,
                                                         &tdvpr_pamt_entry_ptr,
                                                         &tdvpr_leaf_size,
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

    // Check the TD state
    if ((return_val = check_td_in_correct_build_state(tdr_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("TD is not in build state - error = %lld\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    // Get the TD's ephemeral HKID
    curr_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the multi-page TDVPS structure
    tdvps_ptr = map_tdvps(tdvpr_pa, curr_hkid, TDX_RANGE_RW);

    if (tdvps_ptr == NULL)
    {
        TDX_ERROR("TDVPS mapping failed\n");
        return_val = TDX_TDVPX_NUM_INCORRECT;
        goto EXIT;
    }

    /**
     *  Associate the VCPU. On read, allow association even if the VCPU is disabled
     */
    bool_t associate_flag = false;
    if ((return_val = associate_vcpu(tdvps_ptr, tdcs_ptr, tdr_ptr, !write, &associate_flag)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to associate VCPU - error = %llx\n", return_val);
        goto EXIT;
    }
    td_vmcs_loaded = true;

    /**
     *  Read or Write the data
     */
    if ((return_val = read_or_write_tdvps_field(tdcs_ptr,
                                                tdvps_ptr,
                                                &rd_wr_data,
                                                requested_field_code,
                                                write,
                                                wr_request_mask)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to Read or Write data to a TDVPS field - error = %llx\n", return_val);
        goto EXIT;
    }

    // Write data to r8
    local_data_ptr->vmm_regs.r8 = rd_wr_data;

EXIT:
    // Check if we need to load the SEAM VMCS
    if (td_vmcs_loaded)
    {
        set_seam_vmcs_as_active();
    }
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }
    return return_val;
}


api_error_type tdh_vp_wr(uint64_t tdvpr_pa,
                         td_ctrl_struct_field_code_t field_code,
                         uint64_t wr_data,
                         uint64_t wr_mask)
{
    tdx_module_local_t * local_data_ptr = get_local_data();

    return tdh_vp_rd_wr(tdvpr_pa, field_code, local_data_ptr, true, wr_data, wr_mask);
}


api_error_type tdh_vp_rd(uint64_t tdvpr_pa, td_ctrl_struct_field_code_t field_code)
{
    tdx_module_local_t * local_data_ptr = get_local_data();

    return tdh_vp_rd_wr(tdvpr_pa, field_code, local_data_ptr, false, 0, 0);
}



