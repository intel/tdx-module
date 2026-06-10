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
 * @file error_reporting.c
 * @brief Runtime error reporting features for TDX module
 */

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "error_reporting.h"
#include "helpers/helpers.h"

void tdx_report_error_and_halt(uint32_t source_id, uint32_t code)
{
    uint64_t error_code = ERROR_CODE(source_id, code);
    TDX_ERROR("Error 0x%llx reported by the TDX Module\n", error_code);
    TDX_ERROR("Module shutdown initiated\n");

    UNUSED(error_code);

    tdx_arch_fatal_error();
}

void tdx_arch_fatal_error( void )
{
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    TDX_ERROR("!!!!!!!!!!!!!!!!!! - Module critical error - !!!!!!!!!!!!!!!!!!\n");
    TDX_ERROR("!!!!!!!!!!!!!!!!!!      - LAST MESSAGE -     !!!!!!!!!!!!!!!!!!\n");
    debug_control_t* p_ctl = &(get_global_data()->debug_control);
    dump_print_buffer_to_vmm_memory(p_ctl->emergency_buffer, 0);

    while (1) {};
#else // DEBUGFEATURE_TDX_DBG_TRACE
    induce_shutdown();
#endif // DEBUGFEATURE_TDX_DBG_TRACE
}

_STATIC_INLINE_ uint64_t filter_and_get_gpa_bits(uint64_t gpa)
{
    return ((gpa & BITS(51, 12)) >> 12);
}

extended_fatal_info_t prepare_extended_fatal_info_td_handle(uint64_t hpa)
{
    extended_fatal_info_t extended_fatal_info = { .raw = 0 };

    extended_fatal_info.td_handle.tdr_hpa_51_12 = hpa;

    return extended_fatal_info;
}

extended_fatal_info_t prepare_extended_fatal_info_sept_td_handle(uint64_t hpa, uint64_t vm_index, uint64_t offending_sept_level, uint64_t offending_gpa, ia32e_sept_t sept_entry)
{
    extended_fatal_info_t extended_fatal_info = { .raw = 0 };

    extended_fatal_info.td_and_vm.tdr_hpa = hpa;
    extended_fatal_info.td_and_vm.vm_index = vm_index;
    extended_fatal_info.gpa_and_level.offending_sept_entry_level = offending_sept_level;
    extended_fatal_info.gpa_and_level.offending_gpa = filter_and_get_gpa_bits(offending_gpa);
    extended_fatal_info.sept_entry = sept_entry;

    return extended_fatal_info;
}

extended_fatal_info_t prepare_extended_fatal_info_sept_eptp(uint64_t eptp, uint8_t offending_level, uint64_t offending_gpa, ia32e_sept_t sept_entry)
{
    extended_fatal_info_t extended_fatal_info = { .raw = 0 };

    extended_fatal_info.eptp = eptp;
    extended_fatal_info.gpa_and_level_0.offending_sept_entry_level = offending_level;
    extended_fatal_info.gpa_and_level_0.offending_gpa = filter_and_get_gpa_bits(offending_gpa);
    extended_fatal_info.sept_entry_0 = sept_entry;

    return extended_fatal_info;
}

extended_fatal_info_t prepare_extended_fatal_info_page_hpa(uint64_t hpa, uint8_t size)
{
    extended_fatal_info_t extended_fatal_info = { .raw = 0 };

    extended_fatal_info.hpa = hpa;
    extended_fatal_info.size = size;

    return extended_fatal_info;
}

//extended_fatal_info_t prepare_extended_fatal_info_pamt(pamt_entry_t pamt_entry, uint64_t hpa, uint8_t level, uint64_t pamt_page)
//{
//    extended_fatal_info_t extended_fatal_info = { .raw = 0 };
//
//    extended_fatal_info.pamt_entry = pamt_entry;
//    extended_fatal_info.hpa_0 = hpa;
//    extended_fatal_info.level = level;
//    extended_fatal_info.pamt_page = pamt_page;
//
//    return extended_fatal_info;
//}

extended_fatal_info_t prepare_extended_fatal_info_unexpected_exception(uint8_t vector)
{
    extended_fatal_info_t extended_fatal_info = { .raw = 0 };

    extended_fatal_info.vector = vector;

    return extended_fatal_info;
}

extended_fatal_info_t prepare_extended_fatal_info_unexpected_vm_exit(uint64_t hpa, uint64_t vm_index, uint32_t exit_reason, uint32_t extended_info)
{
    extended_fatal_info_t extended_fatal_info = { .raw = 0 };

    extended_fatal_info.td_and_vm_0.tdr_hpa = hpa;
    extended_fatal_info.td_and_vm_0.vm_index = vm_index;
    extended_fatal_info.exit_reason = exit_reason;
    extended_fatal_info.extended_info = extended_info;

    return extended_fatal_info;
}

void fatal_error(fatal_error_id_e error_id, fatal_info_format_e format, extended_fatal_info_t* extended_info)
{
    tdx_module_global_t* global_data = get_global_data();

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    TDX_ERROR("!!!!!!!!!!!!!!!!!!  - FATAL ERROR INFO - BASIC -  !!!!!!!!!!!!!!!!!!!\n");
    // TDX_ERROR("state = 0x%lx\n", (uint64_t)fatal_info_p->basic_info.state); - irrelevant if fatal_info_p isnt mapped
    TDX_ERROR("format = 0x%lx\n", (uint64_t)format);
    TDX_ERROR("x2apic_id = 0x%lx\n", (uint32_t)ia32_rdmsr(IA32_X2APIC_APICID));
    TDX_ERROR("error_id = %d\n", error_id);

    if (FATAL_INFO_FORMAT_BASIC_INFO != format)
    {
        TDX_ERROR("!!!!!!!!!!!!!!!!!! - FATAL ERROR INFO - EXTENDED - !!!!!!!!!!!!!!!!!!\n");
        switch (format)
        {
        case FATAL_INFO_FORMAT_TD_HANDLE_INFO:
        {
            TDX_ERROR("td_handle = 0x%lx\n", extended_info->td_handle.raw);
            break;
        }
        case FATAL_INFO_FORMAT_SEPT_TD_HANDLE_INFO:
        {
            TDX_ERROR("td_handle = 0x%lx\n", extended_info->td_and_vm.raw);
            TDX_ERROR("gpa_and_level = 0x%lx\n", extended_info->gpa_and_level.raw);
            TDX_ERROR("sept_entry = 0x%lx\n", extended_info->sept_entry.raw);
            break;
        }
        case FATAL_INFO_FORMAT_SEPT_EPTP_INFO:
        {
            TDX_ERROR("eptp = 0x%lx\n", extended_info->eptp);
            TDX_ERROR("gpa_and_level = 0x%lx\n", extended_info->gpa_and_level_0.raw);
            TDX_ERROR("sept_entry = 0x%lx\n", extended_info->sept_entry_0.raw);
            break;
        }
        case FATAL_INFO_FORMAT_PAGE_HPA_INFO:
        {
            TDX_ERROR("hpa = 0x%lx\n", extended_info->hpa);
            TDX_ERROR("size = 0x%lx\n", extended_info->size);
            break;
        }
        /*case FATAL_INFO_FORMAT_PAMT_INFO:
        {
            TDX_ERROR("hpa = 0x%lx\n", extended_info->hpa_0);
            TDX_ERROR("level = 0x%lx\n", extended_info->level);
            TDX_ERROR("pamt_page = 0x%lx\n", extended_info->pamt_page);
            break;
        }*/
        case FATAL_INFO_FORMAT_UNEXPECTED_EXCEPTION_INFO:
        {
            TDX_ERROR("vector = 0x%lx\n", extended_info->vector);
            break;
        }
        case FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO:
        {
            TDX_ERROR("td_and_vm = 0x%lx\n", extended_info->td_and_vm_0.raw);
            TDX_ERROR("exit_reason = 0x%lx\n", extended_info->exit_reason);
            TDX_ERROR("extended_info = 0x%lx\n", extended_info->extended_info);
            break;
        }
        default:
        {
            TDX_ERROR("Unexpected format (0x%lx)\n", (uint64_t)format);
        }
        } // switch (format)

        TDX_ERROR("!!!!!!!!!!!!!!!!!!       - FATAL ERROR ICR -       !!!!!!!!!!!!!!!!!!\n");
        TDX_ERROR("fatal_info_icr - 0x%llx\n", global_data->fatal_info_icr);
    } //if (FATAL_INFO_FORMAT_BASIC_INFO != format)
#endif // DEBUGFEATURE_TDX_DBG_TRACE

    // check if fatal error diagnostics logging was configured
    if (global_data->fatal_info_p)
    {
        fatal_info_t* fatal_info_p = (fatal_info_t*)global_data->fatal_info_p;

        // check that fatal info does not contain any valid info
        if (FATAL_INFO_STATE_NO_INFO != _lock_cmpxchg_8bit(FATAL_INFO_STATE_NO_INFO, FATAL_INFO_STATE_WRITING_IN_PROGRESS, (uint8_t*)&fatal_info_p->basic_info.state))
        {
            TDX_ERROR("Failed to lock fatal info. Fatal info logging skipped.\n");
            goto EXIT;
        }

        // prepare basic info diagnostics
        fatal_info_p->basic_info.error_id = error_id;
        fatal_info_p->basic_info.format = format;
        fatal_info_p->basic_info.x2apic_id = (uint32_t)ia32_rdmsr(IA32_X2APIC_APICID);

        if ((FATAL_INFO_FORMAT_BASIC_INFO != format) && (extended_info != NULL))
        {
            tdx_memcpy(&fatal_info_p->extended_info, sizeof(extended_fatal_info_t), extended_info, sizeof(extended_fatal_info_t));
        }

        ia32_clflushopt((void*)global_data->fatal_info_p);
        mfence();
        
        // update the state and release the state lock
        (void)_xchg_8_bit((uint8_t*)&fatal_info_p->basic_info.state, FATAL_INFO_STATE_TDX_VALID_INFO);
    }

EXIT:
    // check if fatal error notification interrupt was configured
    if (global_data->fatal_info_icr)
    {
        ia32_wrmsr(IA32_X2APIC_ICR, global_data->fatal_info_icr);
    }

    tdx_arch_fatal_error();
}
