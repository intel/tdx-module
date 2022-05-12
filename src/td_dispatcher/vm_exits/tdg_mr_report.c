// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

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


api_error_type tdg_mr_report(uint64_t report_struct_gpa, uint64_t additional_data_gpa, uint64_t sub_type)
{
    // Local data and TD's structures
    tdx_module_local_t  * local_data_ptr = get_local_data();
    tdr_t               * tdr_p = local_data_ptr->vp_ctx.tdr;
    tdcs_t              * tdcs_p = local_data_ptr->vp_ctx.tdcs;
    tdvps_t             * tdvps_p = local_data_ptr->vp_ctx.tdvps;

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
    ALIGN(64) uint64_t    tee_info_hash[SIZE_OF_SHA384_HASH_IN_QWORDS] = { 0 };

    uint128_t             xmms[16];                  // SSE state backup for crypto
    crypto_api_error      sha_error_code;

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

    // Acquire shared access to TDCS.RTMR
    if (acquire_sharex_lock_sh(&tdcs_p->measurement_fields.rtmr_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire shared lock on RTMR\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RTMR);
        goto EXIT;
    }

    // Assemble REPORTTYPE
    tdg_mr_report_type.type = (uint8_t)TDX_REPORT_TYPE;
    tdg_mr_report_type.subtype = report_subtype;
    tdg_mr_report_type.version = (uint8_t)TDX_REPORT_VERSION;

    // Create TDG_MR_REPORT_LEAF in a temporary buffer
    // Zero the report (reserve fields are zero'd)
    basic_memset_to_zero(&temp_tdg_mr_report, sizeof(td_report_t));
    temp_tdg_mr_report.td_info.attributes = tdcs_p->executions_ctl_fields.attributes.raw;
    temp_tdg_mr_report.td_info.xfam = tdcs_p->executions_ctl_fields.xfam;
    tdx_memcpy(temp_tdg_mr_report.td_info.mr_td.bytes, sizeof(measurement_t),
               tdcs_p->measurement_fields.mr_td.bytes,
               sizeof(measurement_t));
    tdx_memcpy(temp_tdg_mr_report.td_info.mr_config_id.bytes, sizeof(measurement_t),
               tdcs_p->measurement_fields.mr_config_id.bytes,
               sizeof(measurement_t));
    tdx_memcpy(temp_tdg_mr_report.td_info.mr_owner.bytes, sizeof(measurement_t),
               tdcs_p->measurement_fields.mr_owner.bytes,
               sizeof(measurement_t));
    tdx_memcpy(temp_tdg_mr_report.td_info.mr_owner_config.bytes, sizeof(measurement_t),
               tdcs_p->measurement_fields.mr_owner_config.bytes,
               sizeof(measurement_t));
    for (uint32_t i = 0; i < NUM_OF_RTMRS; i++)
    {
        tdx_memcpy(temp_tdg_mr_report.td_info.rtmr[i].bytes, sizeof(measurement_t),
                   tdcs_p->measurement_fields.rtmr[i].bytes,
                   sizeof(measurement_t));
    }

    // Compute TEE_INFO_HASH

    store_xmms_in_buffer(xmms);

    if ((sha_error_code = sha384_generate_hash((const uint8_t *)&temp_tdg_mr_report.td_info,
                                                sizeof(td_info_t),
                                                (void *)&tee_info_hash[0])))
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        FATAL_ERROR();
    }

    load_xmms_from_buffer(xmms);
    basic_memset_to_zero(xmms, sizeof(xmms));

    // Use SEAMREPORT to create REPORTMACSTRUCT & SEAM measurements (if applicable)
    ia32_seamops_seamreport(&temp_tdg_mr_report,
                            tdg_mr_report_data_ptr,
                            &tee_info_hash[0],
                            tdg_mr_report_type.raw);

    // Release all acquired locks and free keyhole mappings
    release_sharex_lock_sh(&tdcs_p->measurement_fields.rtmr_lock);  
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
    // Free keyhole mappings
    if (tdg_mr_report_data_ptr != NULL)
    {
        free_la(tdg_mr_report_data_ptr);
    }
    if (tdg_mr_report_ptr != NULL)
    {
        free_la(tdg_mr_report_ptr);
    }

    return return_val;
}
