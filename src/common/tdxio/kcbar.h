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
 * @file kcbar.h
 * @brief
 */

#ifndef SRC_COMMON_TDXIO_KCBAR_H_
#define SRC_COMMON_TDXIO_KCBAR_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "helpers/helpers.h"

#include "data_structures/tdxio/kcbar_defs.h"
#include "data_structures/tdxio/iommu_defs.h"

_STATIC_INLINE_ uint64_t get_kcbar_pa(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr)
{
    pa_t kcbar_addr_reg_pa = {.raw = hiop_info_ptr->hiop_mmcfg_base + (uint64_t)socket_io_info_ptr->hiop_kcbar_offset};
    return pci_64bit_read(kcbar_addr_reg_pa) & ~BIT(KCBAR_ENABLE_BIT);
}

_STATIC_INLINE_ kcbar_t *map_kcbar(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr)
{
    uint64_t kcbar_pa = get_kcbar_pa(socket_io_info_ptr, hiop_info_ptr);
    return (kcbar_t *)map_pa_with_global_hkid_uncached((void *)kcbar_pa, TDX_RANGE_RW);
}

_STATIC_INLINE_ stream_config_reg_block_t *get_stream_cfg_reg_block(
    kcbar_t *const kcbar_ptr,
    const uint16_t key_id)
{
    tdx_debug_assert(key_id < NUM_OF_STREAM_CFG_BLOCKS_IN_KEY_CONFIG);
    return (&kcbar_ptr->stream_config_reg_block) + key_id;
}

_STATIC_INLINE_ void initialize_kcbar_registers(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const stream_id_t stream_id,
    const bool_t enabled)
{
    stream_config_reg_block_t *stream_config_reg_block = get_stream_cfg_reg_block(
        kcbar_ptr,
        key_id);

    vol_write_reg32(&stream_config_reg_block->tx_ctrl, 0);
    vol_write_reg32(&stream_config_reg_block->rx_ctrl, 0);
    vol_write_reg32(&stream_config_reg_block->tx_key_set_0, (uint32_t)-1);
    vol_write_reg32(&stream_config_reg_block->tx_key_set_1, (uint32_t)-1);
    vol_write_reg32(&stream_config_reg_block->rx_key_set_0, (uint32_t)-1);
    vol_write_reg32(&stream_config_reg_block->rx_key_set_1, (uint32_t)-1);

    stream_control_t stream_control = {.raw = 0};
    stream_control.stream_id = stream_id;
    stream_control.en = enabled;
    vol_write_reg32(&stream_config_reg_block->control, stream_control.raw);
}

_STATIC_INLINE_ void kcbar_set_key_slot(
    kcbar_t *const kcbar_ptr,
    const uint8_t direction,
    const uint8_t slot_id,
    key_slot_t *const key_val_ptr)
{
    iv_slot_t default_iv_val = {0};
    key_slot_t *key_slot_ptr = NULL;
    iv_slot_t *iv_slot_ptr = NULL;
    io_module_stream_cap_t kcbar_capabilities = {.raw = vol_read_reg32(&kcbar_ptr->capabilities)};
    stream_config_reg_block_t *stream_config_reg_block = get_stream_cfg_reg_block(kcbar_ptr, 0);

    // Set default value
    default_iv_val.bytes[0] = IDE_IV_INIT_VALUE;
    // Jump to Tx key_slots[0]
    key_slot_ptr = (key_slot_t *)(stream_config_reg_block + kcbar_capabilities.num_stream_supported + 1);
    // Jump to Tx iv_slots[0]
    iv_slot_ptr = (iv_slot_t *)(key_slot_ptr + kcbar_capabilities.num_tx_key_slots + 1);

    if (direction == DEV_TX)
    {
        // Jump to rx key_slots[0]
        key_slot_ptr = (key_slot_t *)(iv_slot_ptr + kcbar_capabilities.num_tx_key_slots + 1);
        // Jump to rx iv_slots[0]
        iv_slot_ptr = (iv_slot_t *)(key_slot_ptr + kcbar_capabilities.num_rx_key_slots + 1);
    }

    tdx_debug_assert(slot_id < NUM_OF_KEYSLOT_IN_KEY_CONFIG);
    // Jump to correct key slot
    key_slot_ptr += slot_id;
    // Jump to correct iv slot
    iv_slot_ptr += slot_id;

    tdx_memcpy_dw(key_slot_ptr, sizeof(key_slot_t), key_val_ptr, sizeof(key_slot_t));
    tdx_memcpy_dw(iv_slot_ptr, sizeof(iv_slot_t), &default_iv_val, sizeof(iv_slot_t));
}

_STATIC_INLINE_ bool_t is_kcbar_disabled(kcbar_t *const kcbar_ptr)
{
    io_module_stream_cap_t kcbar_capabilities = {.raw = vol_read_reg32(&kcbar_ptr->capabilities)};
    uint16_t max_kcbar_idx = kcbar_capabilities.num_stream_supported + 1;

    for (uint16_t kcbar_idx = 0; kcbar_idx < max_kcbar_idx; kcbar_idx++)
    {
        stream_config_reg_block_t *stream_config_reg_block = get_stream_cfg_reg_block(
            kcbar_ptr,
            kcbar_idx);

        stream_control_t stream_control = {.raw = vol_read_reg32(&stream_config_reg_block->control)};
        if (stream_control.en)
        {
            TDX_ERROR("Found enabled stream ctrl in KCBAR\n");
            return false;
        }
    }
    return true;
}

#endif /* SRC_COMMON_TDXIO_KCBAR_H_ */
