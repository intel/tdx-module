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
 * @file ide_stream.c
 */

#include "tdxio/ide_stream.h"
#include "helpers/helpers.h"

#include "tdxio/aead.h"
#include "tdxio/tdisp.h"
#include "tdxio/spdm.h"
#include "tdxio/rp_cfg_page.h"
#include "tdxio/kcbar.h"

api_error_code_e verify_stream_config_reg_and_map_rp_cfg(
    const socket_io_info_t *const socket_io_info_ptr,
    const hiop_info_t *const hiop_info_ptr,
    const ide_stream_cfg_reg_t ide_stream_cfg_reg,
    kcbar_t *const kcbar_ptr,
    rp_cfg_page_t **rp_cfg_page_ptr)
{
    api_error_code_e return_val = UNINITIALIZE_ERROR;

    // Verify reserved bits
    if (ide_stream_cfg_reg.rsvd ||
        ide_stream_cfg_reg.ide_stream_cfg.rsvd)
    {
        TDX_ERROR("Reserved bits in ide stream configuration register are not equal to zero (ide_stream_cfg_reg: 0x%llx)\n", ide_stream_cfg_reg.raw);
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    ide_stream_cfg_t ide_stream_cfg = ide_stream_cfg_reg.ide_stream_cfg;

    // Verify root port is valid
    uint8_t rp_idx = 0;

    for (rp_idx = 0; rp_idx < NUM_OF_RP; rp_idx++)
    {
        if ((((uint64_t)hiop_info_ptr->hiop_rp_bit_vector & BIT(rp_idx)) != 0) &&
            socket_io_info_ptr->hiop_rp_df[rp_idx] == ide_stream_cfg.rp_df_num)
        {
            break;
        }
    }
    if (rp_idx == NUM_OF_RP)
    {
        TDX_ERROR("No root ports are configured\n");
        return_val = TDX_IOMMU_RP_NOT_CONFIGURED;
        goto EXIT;
    }

    // Verify Key ID index is valid
    io_module_stream_cap_t kcbar_capabilities = {.raw = vol_read_reg32(&kcbar_ptr->capabilities)};
    if (ide_stream_cfg.key_id > kcbar_capabilities.num_stream_supported)
    {
        TDX_ERROR("Invalid key_id(=%u) is greater than max IDE streams supperted in KCBAR(=%u)\n", ide_stream_cfg.key_id, kcbar_capabilities.num_stream_supported);
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    // Verify Root port has IDE-Stream support
    *rp_cfg_page_ptr = map_rp_mmcfg(
        hiop_info_ptr,
        ide_stream_cfg.rp_df_num);

    ide_ecap_t *ide_ecap_ptr = get_rp_ide_ecap_regaddr(socket_io_info_ptr, *rp_cfg_page_ptr);
    if (ide_ecap_ptr == NULL)
    {
        TDX_ERROR("IDE not supported\n");
        return_val = TDX_IDE_STREAM_NOT_SUPPORTED;
        goto EXIT;
    }

    // IDE ID is a valid index in IDE-ECAP
    ide_cap_t ide_cap = ide_ecap_ptr->ide_cap;
    // Valid Link IDE id is [0 .. (num_lnk_ide - 1)]. The value is dummy if ide_cap_reg_p->lnk_ide_sup==false, must check it first!
    // Valid Selective IDE id is [num_lnk_ide .. (num_lnk_ide + num_sel_ide -1)]. The value is dummy if ide_cap_reg_p->sel_ide_sup==false, check it first!
    const uint8_t num_lnk_ide = ide_cap.lnk_ide_supported ? ide_cap.num_lnk_ide + 1 : 0;
    const uint8_t num_sel_ide = ide_cap.sel_ide_supported ? ide_cap.num_sel_ide + 1 : 0;

    if (ide_stream_cfg.stream_type == IDE_STREAM_LINK_IDE)
    {
        if ((!ide_cap.lnk_ide_supported) ||
            ide_stream_cfg.ide_id >= num_lnk_ide)
        {
            TDX_ERROR("Link IDE stream not supported or IDE id(=%u) is greater than max number of link ide supported(=%u)\n", ide_stream_cfg.ide_id, num_lnk_ide);
            return_val = TDX_OPERAND_INVALID;
            goto EXIT;
        }
    }
    else if ((!ide_cap.sel_ide_supported) || // type == IDE_STREAM_SEL_IDE
             ide_stream_cfg.ide_id >= (num_lnk_ide + num_sel_ide) ||
             ide_stream_cfg.ide_id < num_lnk_ide)
    {
        TDX_ERROR("Selective IDE stream not supported or Invalid IDE id: IDE id = %u, max id of supported selective ide stream = %u\n, is link IDE stream supperted: %s, max id of supported link ide stream = %u\n",
                  ide_stream_cfg.ide_id, num_sel_ide, ide_cap.lnk_ide_supported ? "True" : "False", num_lnk_ide);
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    // Added to prevent SpectreV1 in the context of ide_stream_cfg.ide_id
    lfence();

    void *ide_reg_block_ptr = get_ide_reg_block(
        socket_io_info_ptr,
        *rp_cfg_page_ptr,
        ide_stream_cfg.ide_id,
        ide_stream_cfg.stream_type);
    if (ide_reg_block_ptr == NULL)
    {
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    bool_t stream_ctr_enabled = false;

    if (ide_stream_cfg.stream_type == IDE_STREAM_SEL_IDE)
    {
        ide_stream_ctrl_t stream_control = {.raw = vol_read_reg32(&((sel_ide_stream_reg_block_t *)ide_reg_block_ptr)->control)};
        stream_ctr_enabled = stream_control.enabled;
    }
    else
    {
        lnk_ide_stream_control_reg_t stream_control = {.raw = vol_read_reg32(&((lnk_ide_stream_reg_block_t *)ide_reg_block_ptr)->control)};
        stream_ctr_enabled = stream_control.en;
    }

    // Stream at IDE ID index is not already configured in IDE-ECAP
    if (stream_ctr_enabled)
    {
        TDX_ERROR("Stream at IDE ID index is already configured in IDE-ECAP\n");
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    stream_config_reg_block_t *stream_config_reg_block = get_stream_cfg_reg_block(
        kcbar_ptr,
        ide_stream_cfg_reg.ide_stream_cfg.key_id);

    stream_control_t stream_control = {.raw = vol_read_reg32(&stream_config_reg_block->control)};
    // Stream control register in Key ID is not already configured
    if (stream_control.en)
    {
        TDX_ERROR("Stream control register in Key ID is already configured\n");
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }
    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}

api_error_code_e verify_stream_control_reg(
    const ide_stream_cfg_t ide_stream_cfg,
    const ide_stream_ctrl_reg_t stream_ctrl_reg,
    const stream_info_t *const stream_info_ptr)
{
    api_error_code_e return_val = UNINITIALIZE_ERROR;

    // Reserved bits must be 0
    if (stream_ctrl_reg.rsvd ||
        stream_ctrl_reg.ide_stream_ctrl.reserved0 ||
        stream_ctrl_reg.ide_stream_ctrl.reserved1 ||
        stream_ctrl_reg.ide_stream_ctrl.reserved2 ||
        stream_ctrl_reg.ide_stream_ctrl.algorithm != STREAM_ALGO_AES_GCM_256_96B_MAC ||
        stream_ctrl_reg.ide_stream_ctrl.enabled != 0 ||
        stream_ctrl_reg.ide_stream_ctrl.cfg_sel_ide != 0 ||
        stream_ctrl_reg.ide_stream_ctrl.default_stream != 0 ||
        // Aggregation mode can be enabled only for link IDE streams
        (ide_stream_cfg.stream_type == IDE_STREAM_SEL_IDE &&
         (stream_ctrl_reg.ide_stream_ctrl.tx_aggr_mode_npr != 0 ||
          stream_ctrl_reg.ide_stream_ctrl.tx_aggr_mode_pr != 0 ||
          stream_ctrl_reg.ide_stream_ctrl.tx_aggr_mode_cpl != 0)))
    {
        TDX_ERROR("Invalid stream_ctrl_reg (=0x%llx)\n", stream_ctrl_reg.raw);
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    // Verify Stream ID is not already configured
    if (stream_info_ptr->stream_sts.config_lock)
    {
        TDX_ERROR("Stream ID already configured\n");
        return_val = TDX_IDE_STREAM_NOT_FREE;
        goto EXIT;
    }

    return_val = TDX_SUCCESS;
EXIT:

    return return_val;
}

api_error_type verify_rid_assoc_regs(
    const hiop_info_t *const hiop_info_ptr,
    const ide_stream_cfg_t ide_stream_cfg,
    const rid_assoc_1_reg_t rid_assoc_1_reg,
    const rid_assoc_2_reg_t rid_assoc_2_reg)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    // Reserved bits must be 0
    if (ide_stream_cfg.stream_type == IDE_STREAM_LINK_IDE)
    {
        if (rid_assoc_1_reg.raw != 0)
        {
            TDX_ERROR("rid_assoc_1 register for link ide stream should be zero, but value is set to 0x%llx\n", rid_assoc_1_reg.raw);
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
            goto EXIT;
        }
        if (rid_assoc_2_reg.raw != 0)
        {
            TDX_ERROR("rid_assoc_2 register for link ide stream should be zero, but value is set to 0x%llx\n", rid_assoc_2_reg.raw);
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R11);
            goto EXIT;
        }
        // No more checks reuqired for link IDE Streams
        goto EXIT_SUCCESS;
    }

    // stream_type == IDE_STREAM_SEL_IDE

    if (rid_assoc_1_reg.rsvd ||
        rid_assoc_1_reg.rid_assoc_1.rsvd0 ||
        rid_assoc_1_reg.rid_assoc_1.rsvd1)
    {
        TDX_ERROR("Reserved bytes for rid_assoc_1 register for selective ide stream are not set to zero (register value: 0x%llx)\n", rid_assoc_1_reg.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }
    if (!rid_assoc_2_reg.rid_assoc_2.valid ||
        rid_assoc_2_reg.rsvd ||
        rid_assoc_2_reg.rid_assoc_2.rsvd0 ||
        rid_assoc_2_reg.rid_assoc_2.rsvd1)
    {
        TDX_ERROR("Reserved bytes for rid_assoc_2 register for selective ide stream are not set to zero (register value: 0x%llx)\n", rid_assoc_2_reg.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R11);
        goto EXIT;
    }

    rid_range_t rid_range =
        {
            .base = rid_assoc_2_reg.rid_assoc_2.rid_base,
            .limit = rid_assoc_1_reg.rid_assoc_1.rid_limit};

    // Verify the RID base and RID limit are within the range of bus numbers decoded by this HIOP
    // Verify that the RID limit is below RID base
    // Note, there are 256 device functions on each bus
    uint64_t iommu_base = (uint64_t)(hiop_info_ptr->hiop_bus_base * NUM_DF_PER_BUS);
    uint64_t iommu_limit = (uint64_t)((hiop_info_ptr->hiop_bus_limit + 1) * NUM_DF_PER_BUS);
    if (rid_range.base < iommu_base ||
        rid_range.limit >= iommu_limit ||
        rid_range.limit < rid_range.base)
    {

        TDX_ERROR("Invalid RID range: (RID base = 0x%llx, RID limit = 0x%llx, IOMMU base = 0x%llx, IOMMU limit = 0x%llx)\n",
                  rid_range.base, rid_range.limit, iommu_base, iommu_limit);

        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

EXIT_SUCCESS:
    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}

api_error_type verify_addr_assoc_regs(
    const hiop_info_t *const hiop_info_ptr,
    const ide_stream_cfg_t ide_stream_cfg,
    const ide_addr_assoc_1_reg_t ide_addr_assoc_1_reg,
    const ide_addr_assoc_2_reg_t ide_addr_assoc_2_reg,
    const ide_addr_assoc_3_reg_t ide_addr_assoc_3_reg)

{
    api_error_type return_val = UNINITIALIZE_ERROR;
    uint64_t operand_id = OPERAND_ID_RAX;

    // Reserved bits must be 0
    if (ide_stream_cfg.stream_type == IDE_STREAM_LINK_IDE)
    {
        if (ide_addr_assoc_1_reg.raw != 0)
        {
            TDX_ERROR("ide_addr_assoc_1 register for link ide stream should be zero, but value is set to 0x%llx\n", ide_addr_assoc_1_reg.raw);
            operand_id = OPERAND_ID_R12;
            goto EXIT;
        }
        if (ide_addr_assoc_2_reg.raw != 0)
        {
            TDX_ERROR("ide_addr_assoc_2 register for link ide stream should be zero, but value is set to 0x%llx\n", ide_addr_assoc_2_reg.raw);
            operand_id = OPERAND_ID_R13;
            goto EXIT;
        }
        if (ide_addr_assoc_3_reg.raw != 0)
        {
            TDX_ERROR("ide_addr_assoc_3 register for link ide stream should be zero, but value is set to 0x%llx\n", ide_addr_assoc_3_reg.raw);
            operand_id = OPERAND_ID_R14;
            goto EXIT;
        }
        // No more checks reuqired for link IDE Streams
        goto EXIT_SUCCESS;
    }

    // stream_type == IDE_STREAM_SEL_IDE

    if (ide_addr_assoc_1_reg.rsvd ||
        ide_addr_assoc_1_reg.ide_addr_assoc_1.rsvd ||
        ide_addr_assoc_1_reg.ide_addr_assoc_1.valid != 1)
    {
        TDX_ERROR("ide_addr_assoc_1 valid bit is not set to 1. Register value 0x%llx\n", ide_addr_assoc_1_reg.raw);
        operand_id = OPERAND_ID_R12;
        goto EXIT;
    }

    if (ide_addr_assoc_2_reg.rsvd)
    {
        TDX_ERROR("ide_addr_assoc_2 register reserved bits are not set to zero. Register value 0x%llx\n", ide_addr_assoc_2_reg.raw);
        operand_id = OPERAND_ID_R13;
        goto EXIT;
    }

    if (ide_addr_assoc_3_reg.rsvd)
    {
        TDX_ERROR("ide_addr_assoc_3 register reserved bits are not set to zero. Register value 0x%llx\n", ide_addr_assoc_3_reg.raw);
        operand_id = OPERAND_ID_R14;
        goto EXIT;
    }

    // Extract address range from the association registers
    uint64_t addr_assoc_base, addr_assoc_limit;
    transform_assoc_reg_to_range(
        ide_addr_assoc_1_reg.ide_addr_assoc_1,
        ide_addr_assoc_2_reg.ide_addr_assoc_2,
        ide_addr_assoc_3_reg.ide_addr_assoc_3,
        &addr_assoc_base,
        &addr_assoc_limit);

    // Address assocation range must be valid
    // Verify there are no bits beyond MAX_PA-1 and no HKID set in address
    // and that base address is less than limit address + _1GB
    // Base must be within the HIOP decoded MMIO range
    // Limit must be within the HIOP decoded MMIO range + _1GB
    if ((!is_pa_smaller_than_max_pa(addr_assoc_limit)) ||
        get_hkid_from_pa((pa_t)addr_assoc_limit) != 0 ||
        get_hkid_from_pa((pa_t)addr_assoc_base) != 0 ||
        addr_assoc_limit >= hiop_info_ptr->hiop_mmioh_limit + _1GB ||
        addr_assoc_limit <= addr_assoc_base ||
        addr_assoc_base < hiop_info_ptr->hiop_mmioh_base ||
        addr_assoc_base >= hiop_info_ptr->hiop_mmioh_limit + _1GB)
    {
        TDX_ERROR("Invalid assoc address range: address base: 0x%llx, address limit: 0x%llx,\n HIOP decoded MMIO range base: 0x%llx, HIOP decoded MMIO range limit: 0x%llx,\n base address hkid 0x%llx, limit address hkid 0x%llx\n",
                  addr_assoc_base, addr_assoc_limit, hiop_info_ptr->hiop_mmioh_base, hiop_info_ptr->hiop_mmioh_limit + _1GB,
                  get_hkid_from_pa((pa_t)addr_assoc_base), get_hkid_from_pa((pa_t)addr_assoc_limit));
        operand_id = OPERAND_ID_R12;
        goto EXIT;
    }

EXIT_SUCCESS:
    return_val = TDX_SUCCESS;

EXIT:
    if (return_val != TDX_SUCCESS)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
    }

    return return_val;
}

api_error_type verify_no_stream_overlaps(
    void *stinfo_0_ptr,
    void *stinfo_1_ptr,
    const rid_assoc_1_t rid_assoc_1,
    const rid_assoc_2_t rid_assoc_2,
    const ide_addr_assoc_1_t ide_addr_assoc_1,
    const ide_addr_assoc_2_t ide_addr_assoc_2,
    const ide_addr_assoc_3_t ide_addr_assoc_3)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    stream_info_t *stream_info_base_ptr = NULL;

    uint64_t addr_assoc_base, addr_assoc_limit;
    transform_assoc_reg_to_range(
        ide_addr_assoc_1,
        ide_addr_assoc_2,
        ide_addr_assoc_3,
        &addr_assoc_base,
        &addr_assoc_limit);

    for (uint16_t i = 0; i < MAX_IDE_STREAM_ID; i++)
    {
        stream_info_base_ptr = i < (MAX_IDE_STREAM_ID / 2) ? stinfo_1_ptr : stinfo_0_ptr;
        stream_info_t *stream_info_ptr = &stream_info_base_ptr[i % (MAX_IDE_STREAM_ID / 2)];

        // Skip non-configured streams
        if (stream_info_ptr->stream_sts.config_lock == 0 ||
            stream_info_ptr->stream_sts.stream_type == IDE_STREAM_LINK_IDE)
        {
            continue;
        }

        // No Rid overlap
        rid_range_t curr_rid_range = stream_info_ptr->ide_rid_assoc_reg;
        bool_t no_rid_overlaps =
            (rid_assoc_2.rid_base > curr_rid_range.limit) ||
            (rid_assoc_1.rid_limit < curr_rid_range.base);

        if (!no_rid_overlaps)
        {
            TDX_ERROR("RID range for current ide stream (0x%llx - 0x%llx) overlap with ide stream #%u RID range (0x%llx - 0x%llx)\n",
                      rid_assoc_2.rid_base, rid_assoc_1.rid_limit,
                      i, curr_rid_range.base, curr_rid_range.limit);

            return_val = TDX_IDE_STREAM_RID_OVERLAP;
            goto EXIT;
        }

        // No address overlap
        uint64_t curr_addr_assoc_base, curr_addr_assoc_limit;
        transform_assoc_reg_to_range(
            stream_info_ptr->ide_addr_assoc_reg1,
            stream_info_ptr->ide_addr_assoc_reg2,
            stream_info_ptr->ide_addr_assoc_reg3,
            &curr_addr_assoc_base,
            &curr_addr_assoc_limit);

        bool_t no_addr_overlaps =
            (addr_assoc_base > curr_addr_assoc_limit) ||
            (addr_assoc_limit < curr_addr_assoc_base);

        if (!no_addr_overlaps)
        {
            TDX_ERROR("Address range for current ide stream #%d (0x%llx - 0x%llx) overlap with ide stream #%d Address range (0x%llx - 0x%llx)\n",
                      stream_info_ptr->ide_stream_ctrl.stream_id, addr_assoc_base, addr_assoc_limit,
                      i, curr_addr_assoc_base, curr_addr_assoc_limit);
            return_val = TDX_IDE_STREAM_ADDR_OVERLAP;
            goto EXIT;
        }
    }
    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}

api_error_type setup_ide_ecap_regs(
    const socket_io_info_t *const socket_io_info_ptr,
    const rp_cfg_page_t *const rp_cfg_page_ptr,
    void *ide_reg_block_ptr,
    const uint8_t ide_id,
    const ide_stream_type_t ide_stream_type,
    const ide_stream_ctrl_t ide_stream_ctrl,
    const rid_assoc_1_t rid_assoc_1,
    const rid_assoc_2_t rid_assoc_2,
    const ide_addr_assoc_1_t ide_addr_assoc_1,
    const ide_addr_assoc_2_t ide_addr_assoc_2,
    const ide_addr_assoc_3_t ide_addr_assoc_3)
{
    api_error_type return_val = UNINITIALIZE_ERROR;

    lnk_ide_stream_reg_block_t *lnk_ide_stream_reg_block = NULL;
    sel_ide_stream_reg_block_t *sel_ide_stream_reg_block = NULL;

    // In case the reg_block wasn't provided by the caller fetch it from the RP config page
    if (ide_reg_block_ptr == NULL)
    {
        ide_reg_block_ptr = get_ide_reg_block(
            socket_io_info_ptr,
            rp_cfg_page_ptr,
            ide_id,
            ide_stream_type);

        // Fail in case the reg_block wasn't found
        if (ide_reg_block_ptr == NULL)
        {
            TDX_ERROR("IDE not supported\n");
            return_val = api_error_with_operand_id(TDX_IDE_STREAM_NOT_SUPPORTED, OPERAND_ID_R8);
            goto EXIT;
        }
    }

    if (ide_stream_type == IDE_STREAM_SEL_IDE)
    {
        sel_ide_stream_reg_block = (sel_ide_stream_reg_block_t *)ide_reg_block_ptr;
        vol_write_reg32(&sel_ide_stream_reg_block->rid_assoc1, rid_assoc_1.raw);
        vol_write_reg32(&sel_ide_stream_reg_block->rid_assoc2, rid_assoc_2.raw);

        ide_addr_assoc_reg_block_t *addr_assoc_block = get_addr_assoc_block(sel_ide_stream_reg_block);
        vol_write_reg32(&addr_assoc_block->addr_assoc1, ide_addr_assoc_1.raw);
        vol_write_reg32(&addr_assoc_block->addr_assoc2, ide_addr_assoc_2.raw);
        vol_write_reg32(&addr_assoc_block->addr_assoc3, ide_addr_assoc_3.raw);
        // Control register enable bit must be set last
        // In this case the ide cap is being programmed, set the control as the input param ide_stream_ctrl
        vol_write_reg32(&sel_ide_stream_reg_block->control, ide_stream_ctrl.raw);
    }
    else
    {
        lnk_ide_stream_reg_block = (lnk_ide_stream_reg_block_t *)ide_reg_block_ptr;
        // In this case the ide cap is being programmed, set the control as the input param ide_stream_ctrl
        vol_write_reg32(&lnk_ide_stream_reg_block->control, ide_stream_ctrl.raw);
    }

    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}

void transform_assoc_reg_to_range(
    const ide_addr_assoc_1_t reg1,
    const ide_addr_assoc_2_t reg2,
    const ide_addr_assoc_3_t reg3,
    uint64_t *const base,
    uint64_t *const limit)
{
    *base = ((uint64_t)reg3.mem_base_upper) << 32;
    *base |= (uint64_t)reg1.mem_base_lower << 20;

    *limit = ((uint64_t)reg2.mem_limit_upper) << 32;
    *limit |= (uint64_t)reg1.mem_limit_lower << 20 | 0xFFFFF; // 0xFFFFF sets bits [0..19]
}

void cfg_rc_ide_keys(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const uint8_t direction,
    const uint8_t key_set_select,
    const uint8_t sub_stream,
    const uint8_t slot_id,
    key_slot_t *const key_val_ptr)
{
    kcbar_set_key_slot(
        kcbar_ptr,
        direction,
        slot_id,
        key_val_ptr);

    stream_config_reg_block_t *stream_cfg_reg_block = get_stream_cfg_reg_block(
        kcbar_ptr,
        key_id);

    stream_keyset_slot_id_t *keyset_slot_id_ptr = NULL;
    if (direction == DEV_TX)
    {
        keyset_slot_id_ptr = key_set_select == KS0 ? &stream_cfg_reg_block->rx_key_set_0 : &stream_cfg_reg_block->rx_key_set_1;
    }
    else if (direction == DEV_RX)
    {
        keyset_slot_id_ptr = key_set_select == KS0 ? &stream_cfg_reg_block->tx_key_set_0 : &stream_cfg_reg_block->tx_key_set_1;
    }
    else
    {
        FATAL_ERROR();
    }

    // Replace the SLOT_ID for the specified SUB_STREAM
    stream_keyset_slot_id_t stream_keyset_slot_id = {.raw = vol_read_reg32(keyset_slot_id_ptr)};
    if (sub_stream == IDE_SUB_STREAM_PR)
    {
        stream_keyset_slot_id.pr = slot_id;
    }
    else if (sub_stream == IDE_SUB_STREAM_NPR)
    {
        stream_keyset_slot_id.npr = slot_id;
    }
    else if (sub_stream == IDE_SUB_STREAM_CPL)
    {
        stream_keyset_slot_id.cpl = slot_id;
    }
    else
    {
        FATAL_ERROR();
    }
    vol_write_reg32(keyset_slot_id_ptr, stream_keyset_slot_id.raw);
}

void prime_rc_ide_keys(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const ide_stream_direction_t direction,
    const ide_stream_key_set_sel_t key_set_select)
{
    stream_config_reg_block_t *stream_cfg_reg_block = get_stream_cfg_reg_block(kcbar_ptr, key_id);
    stream_txrx_control_t *ctrl_reg_ptr = (direction == DEV_RX) ? &stream_cfg_reg_block->tx_ctrl : &stream_cfg_reg_block->rx_ctrl;

    stream_txrx_control_t stream_txrx_control = {.raw = vol_read_reg32(ctrl_reg_ptr)};
    if (key_set_select == KS0)
    {
        stream_txrx_control.common.prime_key_set_0 = 1;
    }
    else if (key_set_select == KS1)
    {
        stream_txrx_control.common.prime_key_set_1 = 1;
    }
    else
    {
        FATAL_ERROR();
    }
    vol_write_reg32(ctrl_reg_ptr, stream_txrx_control.raw);
}

bool_t is_ide_ks_ready(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const ide_stream_key_set_sel_t key_set_select)
{
    stream_config_reg_block_t *stream_cfg_reg_block = get_stream_cfg_reg_block(kcbar_ptr, key_id);
    stream_txrx_status_t *rx_ctrl_reg_ptr = &stream_cfg_reg_block->tx_status;
    stream_txrx_status_t *tx_ctrl_reg_ptr = &stream_cfg_reg_block->rx_status;
    uint8_t rx_ks_status = 0;
    uint8_t tx_ks_status = 0;

    if (key_set_select == KS0)
    {
        rx_ks_status = rx_ctrl_reg_ptr->ready_key_set_0;
        tx_ks_status = tx_ctrl_reg_ptr->ready_key_set_0;
    }
    else if (key_set_select == KS1)
    {
        rx_ks_status = rx_ctrl_reg_ptr->ready_key_set_1;
        tx_ks_status = tx_ctrl_reg_ptr->ready_key_set_1;
    }
    else
    {
        FATAL_ERROR();
    }

    return (rx_ks_status > 0) && (tx_ks_status > 0);
}

void set_rc_tx_ide_key_set(
    kcbar_t *const kcbar_ptr,
    const uint8_t key_id,
    const ide_stream_key_set_sel_t key_set)
{
    stream_config_reg_block_t *stream_cfg_reg_block = get_stream_cfg_reg_block(kcbar_ptr, key_id);

    stream_txrx_control_t stream_txrx_control = {.raw = vol_read_reg32(&stream_cfg_reg_block->tx_ctrl)};
    if (key_set == KS0)
    {
        stream_txrx_control.stream_tx_control.key_set_select = 0b01;
    }
    else if (key_set == KS1)
    {
        stream_txrx_control.stream_tx_control.key_set_select = 0b10;
    }
    else
    {
        FATAL_ERROR();
    }
    vol_write_reg32(&stream_cfg_reg_block->tx_ctrl, stream_txrx_control.raw);
}

void generate_idekm_payload(
    const ide_object_id_t object_id,
    const stream_id_t stream_id,
    const ide_km_param_t ide_km_param,
    const key_slot_t *const key_val_ptr,
    void *const payload_ptr,
    uint16_t *const payload_len_ptr)
{
    // Always treat message as if it were keyprog. Fill relevant info only
    keyprog_obj_t *keyprog_obj_ptr = (keyprog_obj_t *)payload_ptr;

    keyprog_obj_ptr->k_gostop_ack_obj.protocol_id = IDE_KM_MSG_PROTOCOL_ID; //  Payload[0]
    keyprog_obj_ptr->k_gostop_ack_obj.object_id = object_id;
    keyprog_obj_ptr->k_gostop_ack_obj.rsvd0 = 0;
    keyprog_obj_ptr->k_gostop_ack_obj.stream_id.raw = stream_id.raw;
    keyprog_obj_ptr->k_gostop_ack_obj.rsvd1 = 0;
    keyprog_obj_ptr->k_gostop_ack_obj.ide_km_param.raw = ide_km_param.raw;
    keyprog_obj_ptr->k_gostop_ack_obj.rsvd2 = 0;

    // Fill payload_len accordingly to the message type
    *payload_len_ptr = object_id == IDE_OBJECT_ID_KEY_PROG ? IDE_KM_KEYPROG_OBJ_SIZE : IDE_KM_DEFUALT_OBJ_SIZE;

    if (object_id == IDE_OBJECT_ID_KEY_PROG)
    {
        for (uint8_t idx = 0; idx < IDE_KEY_SIZE_IN_DWORDS; idx++)
        {
            keyprog_obj_ptr->ide_key.dwords[idx] = key_val_ptr->dwords[IDE_KEY_SIZE_IN_DWORDS - idx - 1];
        }
        // Init iv value
        basic_memset_to_zero(
            (void *)&keyprog_obj_ptr->iv,
            (uint64_t)IDE_IV_SIZE_IN_BYTES);
        keyprog_obj_ptr->iv.bytes[IDE_IV_INIT_BYTE_IDX] = IDE_IV_INIT_VALUE;
    }
}

api_error_type generate_ide_km_req_msg(
    stream_exinfo_t *const stream_exinfo_ptr,
    const stream_id_t stream_id,
    spdm_info_t *const spdm_info_ptr,
    const ide_object_id_t object_id,
    const ide_km_param_t ide_km_param,
    const key_slot_t *const key_val_ptr,
    idekm_msg_t *const message_ptr)
{
    idekm_msg_t *idekm_msg_ptr = (idekm_msg_t *)stream_exinfo_ptr->idekm_msg_buffer;
    uint16_t payload_len = 0;

    // Generate IDEKM payload
    generate_idekm_payload(
        object_id,
        stream_id,
        ide_km_param,
        key_val_ptr,
        (void *)&idekm_msg_ptr->payload,
        &payload_len);

    // Fill all SPDM vendor defined message header fields
    generate_spdm_vendor_defined_msg_header(
        &idekm_msg_ptr->spdm_doe_headers.spdm_vendor_defined_msg_header,
        spdm_info_ptr->binding_info.spdm_version,
        payload_len);

    // Fill message with constant secure spdm header values
    uint32_t session_id = 0;
    session_id = spdm_info_ptr->binding_info.spdm_session_id;

    // Fill all secure SPDM header fields
    generate_secure_spdm_header(
        &idekm_msg_ptr->spdm_doe_headers.secure_spdm_header,
        session_id,
        payload_len);

    // Fill all DOE header fields + zero padded bytes in message buffer
    generate_doe_header(
        idekm_msg_ptr,
        &idekm_msg_ptr->spdm_doe_headers.doe_header,
        idekm_msg_ptr->spdm_doe_headers.secure_spdm_header.length,
        (uint32_t)SIZE_OF_IDE_KM_MSG_BUFFER_IN_BYTES);

    // Zero out unused section bytes in message buffer
    basic_memset_to_zero(
        (void *)((uint64_t)idekm_msg_ptr + idekm_msg_ptr->spdm_doe_headers.doe_header.doe_length.length * DOE_LENGTH_GRANULARITY),
        (uint64_t)SIZE_OF_IDE_KM_MSG_BUFFER_IN_BYTES - idekm_msg_ptr->spdm_doe_headers.doe_header.doe_length.length * DOE_LENGTH_GRANULARITY);

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    const uint32_t *const msg_in_dwords = (uint32_t *)idekm_msg_ptr;
    uint32_t msg_length = idekm_msg_ptr->spdm_doe_headers.doe_header.doe_length.length;
    TDX_LOG("Printing IDEKM plaintext message before encryption:\n");

    for (uint32_t idx = 0; idx < msg_length; idx++)
    {
        TDX_LOG("0x%lx\n", msg_in_dwords[idx]);
    }
#endif // DEBUGFEATURE_TDX_DBG_TRACE

    const uint64_t encrypted_data_len = idekm_msg_ptr->spdm_doe_headers.secure_spdm_header.length - SECURE_SPDM_MAC_SIZE;
    api_error_type return_val = tdx_io_aead_encrypt(
        spdm_info_ptr,
        (void *)&idekm_msg_ptr->spdm_doe_headers.secure_spdm_header,                 // Start of AAD ptr
        (void *)&idekm_msg_ptr->spdm_doe_headers.secure_spdm_header.app_data_length, // Start of plain text ptr
        encrypted_data_len,                                                          // Size of plain text ptr
        ((uint8_t *)&idekm_msg_ptr->spdm_doe_headers.secure_spdm_header.app_data_length) + encrypted_data_len);
    if (return_val != TDX_SUCCESS)
    {
        return return_val;
    }

    // Copy entire message from buffer to pointer
    tdx_memcpy(
        (void *)message_ptr,
        TDX_PAGE_SIZE_IN_BYTES,
        (void *)idekm_msg_ptr,
        idekm_msg_ptr->spdm_doe_headers.doe_header.doe_length.length * DOE_LENGTH_GRANULARITY);

    return TDX_SUCCESS;
}

bool_t verify_idekm_message_content(
    const stream_exinfo_t *const stream_exinfo_ptr,
    const stream_id_t stream_id,
    const spdm_info_t *const spdm_info_ptr)
{
    idekm_msg_t *idekm_msg_ptr = (idekm_msg_t *)stream_exinfo_ptr->idekm_msg_buffer;

    if (!is_valid_doe_header(&idekm_msg_ptr->spdm_doe_headers.doe_header, IDE_KM_DEFUALT_OBJ_SIZE))
    {
        return false;
    }

    uint32_t expected_spdm_session_id = spdm_info_ptr->binding_info.spdm_session_id;

    if (!is_valid_secure_spdm_header(&idekm_msg_ptr->spdm_doe_headers.secure_spdm_header, IDE_KM_DEFUALT_OBJ_SIZE, expected_spdm_session_id))
    {
        return false;
    }

    uint32_t expected_spdm_version = spdm_info_ptr->binding_info.spdm_version;

    if (!is_valid_spdm_vendor_defined_msg_header(
            &idekm_msg_ptr->spdm_doe_headers.spdm_vendor_defined_msg_header,
            IDE_KM_DEFUALT_LEN,
            expected_spdm_version))
    {
        return false;
    }

    ide_object_id_t expected_object_id = stream_exinfo_ptr->outstanding_req_object_id == IDE_OBJECT_ID_KEY_PROG ? IDE_OBJECT_ID_KP_ACK : IDE_OBJECT_ID_K_GOSTOP_ACK;
    k_gostop_ack_obj_t *k_gostop_ack_obj_ptr = (k_gostop_ack_obj_t *)&idekm_msg_ptr->payload;

    if (k_gostop_ack_obj_ptr->protocol_id != IDE_KM_MSG_PROTOCOL_ID ||
        k_gostop_ack_obj_ptr->object_id != expected_object_id ||
        k_gostop_ack_obj_ptr->rsvd0 != 0 ||
        k_gostop_ack_obj_ptr->stream_id.raw != stream_id.raw ||
        k_gostop_ack_obj_ptr->rsvd1 != 0 ||
        k_gostop_ack_obj_ptr->ide_km_param.raw != stream_exinfo_ptr->outstanding_req_km_param.raw ||
        k_gostop_ack_obj_ptr->rsvd2 != 0)
    {
        TDX_ERROR("Invalid k_gostop_ack_obj_ptr -\n");
        TDX_ERROR("protocol_id = 0x%x, expected protocol_id = 0x%x\n", k_gostop_ack_obj_ptr->protocol_id, IDE_KM_MSG_PROTOCOL_ID);
        TDX_ERROR("object_id = 0x%x, expected object_id = 0x%x\n", k_gostop_ack_obj_ptr->object_id, expected_object_id);
        TDX_ERROR("rsvd0 = 0x%x\n", k_gostop_ack_obj_ptr->rsvd0);
        TDX_ERROR("stream_id = 0x%x, expectd stream_id = 0x%x\n", k_gostop_ack_obj_ptr->stream_id.raw, stream_id.raw);
        TDX_ERROR("rsvd1 = 0x%x\n", k_gostop_ack_obj_ptr->rsvd1);
        TDX_ERROR("ide_km_param = 0x%x, expected ide_km_param: 0x%x\n", k_gostop_ack_obj_ptr->ide_km_param.raw, stream_exinfo_ptr->outstanding_req_km_param.raw);
        TDX_ERROR("rsvd2 = 0x%x\n", k_gostop_ack_obj_ptr->rsvd2);
        return false;
    }

    return true;
}

bool_t is_ide_disabled(
    const socket_io_info_t *const socket_io_info_ptr,
    const rp_cfg_page_t *const rp_cfg_page_ptr)
{
    bool_t res = false;

    ide_ecap_t *ide_ecap_ptr = get_rp_ide_ecap_regaddr(socket_io_info_ptr, rp_cfg_page_ptr);

    // If IDE-Stream is not supported by this RP, reutrn true immidiatly
    if (ide_ecap_ptr == NULL)
    {
        res = true;
        goto EXIT;
    }

    ide_cap_t ide_cap = ide_ecap_ptr->ide_cap;
    uint8_t num_lnk_ide = ide_cap.lnk_ide_supported ? ide_cap.num_lnk_ide + 1 : 0;
    uint8_t num_sel_ide = ide_cap.sel_ide_supported ? ide_cap.num_sel_ide + 1 : 0;
    // Check the numbers of link and selective streams are as expected
    if ((is_not_gnr_a0_stepping()) &&
        (num_lnk_ide != socket_io_info_ptr->ide_ecap_num_lnk_ide_regs ||
         num_sel_ide > socket_io_info_ptr->ide_ecap_num_sel_ide_regs))
    {
        TDX_ERROR("num_lnk_ide (%u) != socket_io_info_ptr->ide_ecap_num_lnk_ide_regs (%u) OR\n",
                  num_lnk_ide, socket_io_info_ptr->ide_ecap_num_lnk_ide_regs);
        TDX_ERROR("num_sel_ide (%u) > socket_io_info_ptr->ide_ecap_num_sel_ide_regs (%u)\n",
                  num_sel_ide, socket_io_info_ptr->ide_ecap_num_sel_ide_regs);
        res = false;
        goto EXIT;
    }

    // Check Link IDE streams are disabled
    for (uint8_t ide_idx = 0; ide_idx < num_lnk_ide; ide_idx++)
    {
        void *ide_reg_block_ptr = get_ide_reg_block(
            socket_io_info_ptr,
            rp_cfg_page_ptr,
            ide_idx,
            IDE_STREAM_LINK_IDE);
        if (ide_reg_block_ptr == NULL)
        {
            res = false;
            goto EXIT;
        }

        lnk_ide_stream_control_reg_t stream_control = {.raw = vol_read_reg32(&((lnk_ide_stream_reg_block_t *)ide_reg_block_ptr)->control)};
        if (stream_control.en)
        {
            TDX_ERROR("Stream ctrl enabled with link IDE stream %u\n", ide_idx);
            res = false;
            goto EXIT;
        }
    }

    for (uint8_t ide_idx = num_lnk_ide; ide_idx < (num_lnk_ide + num_sel_ide); ide_idx++)
    {
        void *ide_reg_block_ptr = get_ide_reg_block(
            socket_io_info_ptr,
            rp_cfg_page_ptr,
            ide_idx,
            IDE_STREAM_SEL_IDE);
        if (ide_reg_block_ptr == NULL)
        {
            res = false;
            goto EXIT;
        }

        lnk_ide_stream_control_reg_t stream_control = {.raw = vol_read_reg32(&((sel_ide_stream_reg_block_t *)ide_reg_block_ptr)->control)};
        if (stream_control.en)
        {
            TDX_ERROR("Stream ctrl enabled with selective IDE stream %u\n", ide_idx);
            res = false;
            goto EXIT;
        }
    }

    res = true;

EXIT:
    return res;
}

