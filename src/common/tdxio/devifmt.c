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
 * @file devifmt.c
 * @brief
 */

#include "devifmt.h"
#include "devif.h"
#include "helpers/mt_walk_helpers.h"

api_error_code_e devifmt_walk(
    const devifmt_idx_t devifmt_idx,
    const bool_t lock_entry,
    const bool_t lock_mode,
    const bool_t is_guest,
    bool_t *const is_devifmt_walked_ptr,
    devifmt_walk_res_t *const devifmt_walk_result_ptr)
{
    api_error_code_e return_val = UNINITIALIZE_ERROR;
    mapping_type_t mapping_type;
    pa_t child_pa = {.raw = 0};
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();

    // Start with root table level
    devifmt_walk_result_ptr->devifmt_idx.raw = devifmt_idx.raw;
    devifmt_walk_result_ptr->devifmt_idx.level = DEVIFMT_ROOT_L;
    uint32_t current_level = devifmt_walk_result_ptr->devifmt_idx.level;

    // Root level entry points to global entry pointer where we save the pa of the first level table
    devifmt_walk_result_ptr->devifmt_path_arr[DEVIFMT_ROOT_L] = (devifmt_entry_t *)&tdx_global_data_ptr->devifmt_root_node;
    uint32_t entry_idx_arr[] = {devifmt_idx.l0_idx, devifmt_idx.l1_idx, devifmt_idx.l2_idx, devifmt_idx.l3_idx};

    /**
     * @note the loop will not be entered if the desired level is root level
     *       Also, DEVIFMT_L0 will always terminate the loop execution so child_level will never underflow
     *
     */
    while (current_level != devifmt_idx.level)
    {
        tdx_sanity_check(current_level != DEVIFMT_L0, FATAL_ERROR_ID_241, 0);

        // Check that the current level present bit is on
        if (devifmt_walk_result_ptr->devifmt_path_arr[current_level]->p != 1)
        {
            TDX_ERROR("DEVIFMT at entry level %u is not present\n", current_level);
            return_val = TDX_DEVIFMT_NOT_PRESENT;
            goto EXIT;
        }
        uint8_t child_level = devifmt_walk_result_ptr->devifmt_idx.level - 1;
        mapping_type = (child_level == devifmt_idx.level) ? TDX_RANGE_RW : TDX_RANGE_RO;

        // Get the page address that point to the child level
        child_pa.page_4k_num = devifmt_walk_result_ptr->devifmt_path_arr[current_level]->pa;

        // Get and lock the PAMT entry and the linear address of the child level
        return_val = mt_lock_pamt_and_map_la(
            child_pa,
            entry_idx_arr[child_level],
            sizeof(devifmt_entry_t),
            is_guest,
            &devifmt_walk_result_ptr->pamt_walk_result_arr[child_level],
            PT_DEVIF_MT,
            mapping_type,
            (void **)&devifmt_walk_result_ptr->devifmt_path_arr[child_level]);
        if (return_val != TDX_SUCCESS)
        {
            goto EXIT;
        }

        // Move to the next level
        current_level = child_level;
        // Set current level reached
        devifmt_walk_result_ptr->devifmt_idx.level = current_level;
    }

    // Acquire lock on last entry only
    if (lock_entry)
    {
        if (lock_mode == DEVIFMT_HP_LOCK_MODE)
        {
            return_val = devifmt_acquire_host_lock(devifmt_walk_result_ptr->devifmt_path_arr[current_level]);
            if (return_val != TDX_SUCCESS)
            {
                TDX_ERROR("Failed to acquire host lock on devifmt entry at level %u\n", current_level);
                goto EXIT;
            }
        }
        else // DEVIFMT_GUEST_LOCK_MODE
        {
            return_val = devifmt_acquire_guest_lock(devifmt_walk_result_ptr->devifmt_path_arr[current_level]);
            if (return_val != TDX_SUCCESS)
            {
                TDX_ERROR("Failed to acquire guest lock on devifmt entry at level %u\n", current_level);
                goto EXIT;
            }
        }
    }
    devifmt_walk_result_ptr->is_entry_locked = lock_entry;

    return_val = TDX_SUCCESS;

EXIT:
    if (return_val != TDX_SUCCESS)
    {
        devifmt_unwalk(devifmt_walk_result_ptr);
    }

    *is_devifmt_walked_ptr = return_val == TDX_SUCCESS;

    return return_val;
}

api_error_type tdg_devifmt_get_devifcs(
    const function_id_reg_t function_id_reg,
    const mapping_type_t mapping_type,
    const uint64_t operand_id,
    const bool_t is_check_devifcs_validity,
    devif_verify_param_t *const devif_verify_param_ptr,
    tdx_module_local_t *local_data)
{
    api_error_type  return_val = devifmt_get_devifcs(
        function_id_reg,
        mapping_type,
        DEVIFMT_GUEST_LOCK_MODE,
        devif_verify_param_ptr,
        true);
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(return_val, operand_id);
        goto EXIT;
    }

    if (is_check_devifcs_validity && !devif_verify_param_ptr->devifcs_ptr->valid)
    {
        TDX_ERROR("DEVIFCS not valid\n");
        return_val = api_error_with_operand_id(TDX_DEVIF_INVALID_STATE, operand_id);
        goto EXIT;
    }

    if (local_data == NULL)
    {
        local_data = get_local_data();
    }

    if (devif_verify_param_ptr->devifcs_ptr->tdr_pa.raw != local_data->vp_ctx.tdr_pa.raw)
    {
        return_val = api_error_with_operand_id(TDX_DEVIF_INVALID_METADATA, operand_id);
    }

EXIT:
    return return_val;
}

api_error_type tdh_devifmt_get_devifcs(
    const function_id_reg_t function_id_reg,
    const mapping_type_t mapping_type,
    const uint64_t function_id_operand_id,
    devif_verify_param_t *const devif_verify_param_ptr)
{
    api_error_type return_val = devifmt_get_devifcs(
        function_id_reg,
        mapping_type,
        DEVIFMT_HP_LOCK_MODE,
        devif_verify_param_ptr,
        false);
    return return_val == TDX_SUCCESS ? return_val : api_error_with_operand_id(return_val, function_id_operand_id);
}

api_error_type devifmt_get_devifcs(
    const function_id_reg_t function_id_reg,
    const mapping_type_t mapping_type,
    const bool_t lock_mode,
    devif_verify_param_t *const devif_verify_param_ptr,
    const bool_t is_guest)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    // DEVIFMT parameters
    devifmt_entry_t *devifmt_leaf_entry_ptr = NULL;

    if (function_id_reg.reserved != 0 ||
        !verify_function_id(function_id_reg.function_id))
    {
        TDX_ERROR("Invalid function id 0x%llx\n", function_id_reg.raw);
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    devif_verify_param_ptr->devifmt_idx.function_id = function_id_reg.function_id;
    devif_verify_param_ptr->devifmt_idx.level = DEVIFMT_L0;

    return_val = devifmt_walk(
        devif_verify_param_ptr->devifmt_idx,
        true,
        lock_mode,
        is_guest,
        &devif_verify_param_ptr->is_devifmt_walked,
        &devif_verify_param_ptr->devifmt_walk_res);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    devifmt_leaf_entry_ptr = devif_verify_param_ptr->devifmt_walk_res.devifmt_path_arr[DEVIFMT_L0];

    if (devifmt_leaf_entry_ptr->p != 1)
    {
        return_val = TDX_DEVIFMT_NOT_PRESENT;
        goto EXIT;
    }

    // Get DEVIFCS PA
    pa_t devifcs_pa = {.raw = 0};
    devifcs_pa.page_4k_num = devifmt_leaf_entry_ptr->pa;

    devif_verify_param_ptr->devifcs_ptr = (devifcs_t *)map_pa_with_global_hkid(
        devifcs_pa.raw_void,
        mapping_type);
    devif_verify_param_ptr->is_devifcs_mapped = true;

EXIT:
    return return_val;
}

_STATIC_INLINE_ void devifmt_release_lock(devifmt_entry_t *const devifmt_entry_ptr)
{
    tdx_sanity_check(devifmt_entry_ptr->raw & BIT(DEVIFMT_LOCK_BIT_IDX), FATAL_ERROR_ID_242, 8);

    // Lock is already taken. Release it by resetting the lock bit
    (void)_lock_btr_64b(&devifmt_entry_ptr->raw, DEVIFMT_LOCK_BIT_IDX);
}

void devifmt_unwalk(devifmt_walk_res_t *const devifmt_walk_result_ptr)
{
    if (devifmt_walk_result_ptr == NULL)
    {
        return;
    }

    if (devifmt_walk_result_ptr->is_entry_locked)
    {
        devifmt_release_lock(devifmt_walk_result_ptr->devifmt_path_arr[devifmt_walk_result_ptr->devifmt_idx.level]);
    }

    /**
     * @note DEVIFMT_ROOT_L won't get inside this for loop
     *
     */
    for (uint8_t level_idx = devifmt_walk_result_ptr->devifmt_idx.level; level_idx <= DEVIFMT_L3; level_idx++)
    {
        pa_t devifmt_pa = {.raw = 0};
        // The current level PA is extracted from the parent node
        devifmt_pa.page_4k_num = devifmt_walk_result_ptr->devifmt_path_arr[level_idx + 1]->pa;

        pamt_unwalk(&devifmt_walk_result_ptr->pamt_walk_result_arr[level_idx]);
        free_la(devifmt_walk_result_ptr->devifmt_path_arr[level_idx]);
    }
}

api_error_type devifmt_acquire_host_lock(devifmt_entry_t *const devifmt_entry_ptr)
{
    bool_t ret_val = _lock_bts_64b(&devifmt_entry_ptr->raw, DEVIFMT_LOCK_BIT_IDX) == 0;
    if (!ret_val)
    {
        // The lock is already taken. Just set (no need to check return value) the HP bit and return BUSY_HOST PRIORITY
        (void)_lock_bts_64b(&devifmt_entry_ptr->raw, DEVIFMT_HP_BIT_IDX);
        return TDX_OPERAND_BUSY;
    }

    // IF lock successfully acquired, reset the HP bit.
    (void)_lock_btr_64b(&devifmt_entry_ptr->raw, DEVIFMT_HP_BIT_IDX);

    return TDX_SUCCESS;
}

api_error_type devifmt_acquire_guest_lock(devifmt_entry_t *const devifmt_entry_ptr)
{
    bool_t ret_val = _lock_bts_64b(&devifmt_entry_ptr->raw, DEVIFMT_LOCK_BIT_IDX) == 0;
    if (!ret_val)
    {
        return TDX_OPERAND_BUSY;
    }

    // Lock was successfully acquired. Check if the HP bit is set
    // No need for atomic operations since the DEVIFMT entry is locked
    if (devifmt_entry_ptr->hp)
    {
        // If the HP bit is set, release the lock and return BUSY_HOAT_PRORITY
        (void)_lock_btr_64b(&devifmt_entry_ptr->raw, DEVIFMT_LOCK_BIT_IDX);

        return TDX_OPERAND_BUSY_HOST_PRIORITY;
    }

    return TDX_SUCCESS;
}
