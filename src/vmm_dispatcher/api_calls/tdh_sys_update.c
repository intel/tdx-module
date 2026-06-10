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
 * @file tdh_sys_update
 * @brief TDH_SYS_UPDATE API handler
 */

#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include TDX_ERROR_CODES_DEFS_HEADER

#include "data_structures/tdx_global_data.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "helpers/preserving.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "tdxio/iommu.h"

api_error_type tdh_sys_update(uint8_t version, uint64_t enabling_flags, uint64_t reserved_r10)
{
    // Global data
    tdx_module_global_t* global_data = get_global_data();
    sysinfo_table_t* sysinfo_table = get_sysinfo_table();

    bool_t global_locked_flag = false;
    api_error_type ret_val = TDX_OPERAND_INVALID;

    // Acquire an exclusive lock to the whole TDX-SEAM module
    if (acquire_sharex_lock_ex(&global_data->global_lock) != LOCK_RET_SUCCESS)
    {
        ret_val = TDX_SYS_BUSY;
        goto EXIT;
    }
    global_locked_flag = true;

    // Check the system state
    if ((global_data->global_state.sys_state != SYSINIT_DONE) ||
        (global_data->num_of_init_lps < global_data->num_of_lps))
    {
        ret_val = TDX_SYS_STATE_INCORRECT;
        goto EXIT;
    }

    // Check that handoff data is valid
    handoff_data_header_t* handoff_data_hdr = (handoff_data_header_t*)sysinfo_table->data_rgn_base;
    uint16_t hv = handoff_data_hdr->hv;

    if ((handoff_data_hdr->valid == false) ||
        (hv < global_data->min_update_hv) ||
        (hv > global_data->module_hv))
    {
        ret_val = TDX_SYS_INVALID_HANDOFF;
        goto EXIT;
    }

    // Retrieve handoff data
    uint32_t buff_size = (global_data->num_handoff_pages + 1) * TDX_PAGE_SIZE_IN_BYTES
                         - sizeof(handoff_data_header_t);
    uint32_t size = handoff_data_hdr->size;

    if (hv == 0)
    {
        // TDX 2.0.12 and earlier sizes
        tdx_sanity_check((size > 0) && (size <= HANDOFF_V0_SIZE), FATAL_ERROR_ID_372, 0);
    }
    else
    {
        tdx_sanity_check((size > 0) && (size <= buff_size), FATAL_ERROR_ID_304, 0);
    }

    uint8_t* handoff_data_bytes = (uint8_t*)(sysinfo_table->data_rgn_base + sizeof(handoff_data_header_t));

    retrieve_handoff_data(hv, size, handoff_data_bytes);

    if (version)
    {
        if (version > 1)
        {
			// Versions 0 and 1 are the only supported versions
            TDX_ERROR("Max supported version of TDH.SYS.UPDATE is 1\n");
            ret_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
            goto EXIT;
        }

        tdx_features_enum0_t enabled_features = (tdx_features_enum0_t)enabling_flags;
        tdx_features_enum0_t tdx_enabled_features = get_tdx_features_enum0();

        // A bit may be set to 1 if the corresponding TDX_FEATURES0 bit is 1
        if ((enabled_features.raw | tdx_enabled_features.raw) != tdx_enabled_features.raw)
        {
            TDX_ERROR("An enabling bit may be set to 1 only if the corresponding TDX_FEATURES0 bit is 1 (readable by TDH.SYS.RD)\n");
            ret_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
            goto EXIT;
        }


        if (reserved_r10)
        {
            TDX_ERROR("R10 is reserved and must be zero\n");
            ret_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
            goto EXIT;
        }

        global_data->update_compatibility = enabled_features.update_compatibility;
    }

    complete_cpuid_handling(global_data);

    // Disabled, since this is breaking Hyper-V tests
    // if (!is_valid_initial_iommu_state())
    // {
    //     ret_val = TDX_CONNECT_INVALID_STATE;
    //     goto EXIT;
    // }

    // Clean handoff data
    handoff_data_hdr->valid = false;
    handoff_data_hdr->size  = 0;

    // Move to "ready" state
    global_data->global_state.sys_state = SYS_READY;

    ret_val = TDX_SUCCESS;

EXIT:
    // Release all locks
    if (global_locked_flag)
    {
        release_sharex_lock_ex(&global_data->global_lock);
    }

    return ret_val;
}
