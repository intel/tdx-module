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
 * @file tdg_mr_report.c
 * @brief TDGMRREPORT API handler
 */
#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "crypto/sha384.h"
#include "helpers/service_td.h"
#include "td_transitions/td_exit.h"


api_error_type tdg_mr_report(uint64_t report_struct_gpa, uint64_t additional_data_gpa, uint64_t sub_type, bool_t* interrupt_occurred)
{
    // Local data and TD's structures
    tdx_module_local_t  * local_data_ptr = get_local_data();
    tdr_t               * tdr_p = local_data_ptr->vp_ctx.tdr;
    tdcs_t              * tdcs_p = local_data_ptr->vp_ctx.tdcs;
    tdvps_t             * tdvps_p = local_data_ptr->vp_ctx.tdvps;

    bool_t                interrupt_pending = false;

    tdx_sanity_check(tdr_p != NULL, SCEC_TDCALL_SOURCE(TDG_MR_REPORT_LEAF), 0);
    tdx_sanity_check(tdcs_p != NULL, SCEC_TDCALL_SOURCE(TDG_MR_REPORT_LEAF), 1);
    tdx_sanity_check(tdvps_p != NULL, SCEC_TDCALL_SOURCE(TDG_MR_REPORT_LEAF), 2);

    /**
     * GPA of newly created tdg_mr_report_t and report_data - given as input
     */
    pa_t                  tdg_mr_report_gpa = {.raw = report_struct_gpa};
    pa_t                  report_data_gpa = {.raw = additional_data_gpa};
    uint8_t               report_subtype = (uint8_t)sub_type;  // Subtype of the report (input)
    td_report_t         * tdg_mr_report_ptr = NULL;                // Pointer to the TDREPORT_STRUCT
    td_report_data_t    * tdg_mr_report_data_ptr = NULL;           // Pointer to the REPORTDATA_STRUCT
    td_report_type_t      tdg_mr_report_type = {.raw = 0};         // REPORTTYPE STRUCT
    ALIGN(1024) td_report_t temp_tdg_mr_report;                    // To generate the report before copying
    ALIGN(64) measurement_t tee_info_hash = { 0 };

    bool_t async_exit_needed = false;

    basic_memset_to_zero(&temp_tdg_mr_report, sizeof(temp_tdg_mr_report));

    api_error_type        return_val = TDX_OPERAND_INVALID;

    // Check TDG_MR_REPORT_LEAF GPA alignment
    if (!is_addr_aligned_pwr_of_2(tdg_mr_report_gpa.raw, SIZE_OF_TD_REPORT_STRUCT_IN_BYTES))
    {
        TDX_ERROR("TDREPORT_STRUCT is gpa (%llx) is not aligned to %d\n",
                  tdg_mr_report_gpa.raw,
                  SIZE_OF_TD_REPORT_STRUCT_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check REPORTDATA GPA alignment
    if (!is_addr_aligned_pwr_of_2(report_data_gpa.raw, SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES))
    {
        TDX_ERROR("REPORTDATA_STRUCT is gpa (%llx) is not aligned to %d\n",
                   report_data_gpa.raw,
                   SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }
    return_val = check_walk_and_map_guest_side_gpa(tdcs_p,
                                                   tdvps_p,
                                                   report_data_gpa,
                                                   tdr_p->key_management_fields.hkid,
                                                   TDX_RANGE_RO,
                                                   PRIVATE_OR_SHARED,
                                                   (void **)&tdg_mr_report_data_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on checking GPA (=%llx) error = %llx\n", report_data_gpa.raw, return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Verify subtype is legal
    if (sub_type != TDX_REPORT_SUBTYPE)
    {
        TDX_ERROR("Report subtype is illegal (=%d)\n", report_subtype);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Assemble REPORTTYPE
    tdg_mr_report_type.type = (uint8_t)TDX_REPORT_TYPE;
    tdg_mr_report_type.subtype = report_subtype;

    if (tdcs_p->service_td_fields.servtd_num > 0)
    {
        tdg_mr_report_type.version = (uint8_t)TDX_REPORT_VERSION_WITH_SERVTDS;
    }
    else
    {
        tdg_mr_report_type.version = (uint8_t)TDX_REPORT_VERSION_NO_SERVTDS;
    }

    bool_t is_cached_teeinfohash_used = tdcs_p->measurement_fields.last_teeinfo_hash_valid;

    // Create TDREPORT in a temporary buffer and compute TEE_INFO_HASH
    ignore_tdinfo_bitmap_t ignore = { .raw = 0 };
    if ((return_val = get_tdinfo_and_teeinfohash(tdcs_p, ignore,
                          &temp_tdg_mr_report.td_info, &tee_info_hash, true)) != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RTMR);
        goto EXIT;
    }

    // Interruption Point: only if TEEINFOHASH was not cached (so its calculation took a long time)
    if (!is_cached_teeinfohash_used && is_interrupt_pending_guest_side())
    {
        // An interrupt is pending. Resume the guest without updating CPU state
        // TDG.MR.REPORT will be called again after the interrupt is serviced.
        // get_tdinfo_and_teeinfohash() is optimized to avoid recalculation if used with the same inputs,
        // so some progress should happen.
        interrupt_pending = true;
        goto EXIT;
    }

    // Use SEAMDB_REPORT to create REPORTMACSTRUCT & SEAM measurements (if applicable)
    // for the TD's index/nonce
    uint64_t result = ia32_seamops_seamdb_report(&temp_tdg_mr_report, tdg_mr_report_data_ptr,
            tee_info_hash.qwords, tdg_mr_report_type.raw, tdr_p->td_preserving_fields.seamdb_index,
            &tdr_p->td_preserving_fields.seamdb_nonce);

    // If SEAMDB_REPORT failed due to TDR corruption (contained bad index/nonce),
    // go to non-recoverable asynchronous TDEXIT
    if (result != SEAMOPS_SUCCESS)
    {
        TDX_ERROR("SEADB_REPORT failure due to TDR corruption\n");
        async_exit_needed = true;
        goto EXIT;
    }
	
    // Free keyhole mappings
    if (tdg_mr_report_data_ptr != NULL)
    {
        free_la(tdg_mr_report_data_ptr);
        tdg_mr_report_data_ptr = NULL;
    }

    return_val = check_walk_and_map_guest_side_gpa(tdcs_p,
                                                   tdvps_p,
                                                   tdg_mr_report_gpa,
                                                   tdr_p->key_management_fields.hkid,
                                                   TDX_RANGE_RW,
                                                   PRIVATE_OR_SHARED,
                                                   (void **)&tdg_mr_report_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on checking GPA (=%llx) error = %llx\n", tdg_mr_report_gpa.raw, return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Copy report to TD memory
    tdx_memcpy(tdg_mr_report_ptr, SIZE_OF_TD_REPORT_STRUCT_IN_BYTES, &temp_tdg_mr_report, SIZE_OF_TD_REPORT_STRUCT_IN_BYTES);

    return_val = TDX_SUCCESS;

EXIT:

    *interrupt_occurred = interrupt_pending;

    // Free keyhole mappings
    if (tdg_mr_report_data_ptr != NULL)
    {
        free_la(tdg_mr_report_data_ptr);
    }
    if (tdg_mr_report_ptr != NULL)
    {
        free_la(tdg_mr_report_ptr);
    }
    if (async_exit_needed)
    {
        async_tdexit_empty_reason(TDX_NON_RECOVERABLE_TD_CORRUPTED_MD);
    }

    return return_val;
}
