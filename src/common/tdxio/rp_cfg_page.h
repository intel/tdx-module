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
 * @file rp_cfg_page.h
 * @brief
 */

#ifndef SRC_COMMON_TDXIO_RP_CFG_PAGE_H_
#define SRC_COMMON_TDXIO_RP_CFG_PAGE_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "accessors/data_accessors.h"
#include "data_structures/tdxio/vtbar_defs.h"
#include "data_structures/tdxio/iommu_defs.h"

_STATIC_INLINE_ rp_cfg_page_t *map_rp_mmcfg(
    const hiop_info_t *const hiop_info,
    const uint8_t rp_df)
{
    pa_t rp_mmcfg_pa = {.raw = hiop_info->hiop_mmcfg_base + _4KB * rp_df};
    return (rp_cfg_page_t *)map_pa_with_global_hkid_uncached(rp_mmcfg_pa.raw_void, TDX_RANGE_RW);
}


_STATIC_INLINE_ ide_ecap_t *get_rp_ide_ecap_regaddr(
    const socket_io_info_t *const socket_io_info_ptr,
    const rp_cfg_page_t *const rp_cfg_page_ptr)
{
    pcie_cap_id_t *pci_cap_id = (pcie_cap_id_t *)((uint64_t)rp_cfg_page_ptr + (uint64_t)socket_io_info_ptr->ide_ecap_ofst);

    if (pci_cap_id->id == PCIE_ECAP_IDE_ID)
    {
        return (ide_ecap_t *)pci_cap_id;
    }

    TDX_ERROR("Failed to find rp_ide_ecap_regaddr\n");
    return NULL;
}

/**
 * @brief Locate relevant IDE block, depending on the stream type (link/selective)
 *
 * @param rp_cfg_page_ptr
 * @param ide_id
 * @param stream_type
 *
 * @return _STATIC_INLINE_*
 */
_STATIC_INLINE_ void *get_ide_reg_block(
    const socket_io_info_t *const socket_io_info_ptr,
    const rp_cfg_page_t *const rp_cfg_page_ptr,
    const uint8_t ide_id,
    const ide_stream_type_t stream_type)
{
    ide_ecap_t *ide_ecap_ptr = (ide_ecap_t *)get_rp_ide_ecap_regaddr(socket_io_info_ptr, rp_cfg_page_ptr);
    if (ide_ecap_ptr == NULL)
    {
        TDX_ERROR("Failed to find ide_ecap_regaddr\n")
        return NULL;
    }
    ide_cap_t ide_cap = ide_ecap_ptr->ide_cap;
    // 0 link IDEs mean one TC is supported
    uint8_t num_lnk_ide = ide_cap.lnk_ide_supported? ide_cap.num_lnk_ide + 1: 0;

    // Beginning of lnk IDE reg blocks
    uint64_t ide_reg_block_ptr = (uint64_t)&ide_ecap_ptr->ide_ctrl + sizeof(ide_ecap_ptr->ide_ctrl);

    if (stream_type == IDE_STREAM_LINK_IDE)
    {
        tdx_debug_assert(ide_cap.lnk_ide_supported);
        tdx_debug_assert(ide_id < num_lnk_ide);

        ide_reg_block_ptr += ide_id * sizeof(lnk_ide_stream_reg_block_t);
    }
    else // stream_type == IDE_STREAM_SEL_IDE
    {
        tdx_debug_assert(ide_cap.sel_ide_supported);
        tdx_debug_assert(ide_id + 1 > num_lnk_ide && ide_id <= ide_cap.num_sel_ide + num_lnk_ide);

        // Skip all link ide stream reg blocks
        ide_reg_block_ptr += num_lnk_ide * sizeof(lnk_ide_stream_reg_block_t);

        // Walking the selective IDE reg block.
        // Start with the first block after the link block
        for (uint8_t i = num_lnk_ide; i < ide_id; i++)
        {
            // Calculate size of Assoc ADDR blocks
            uint64_t size_of_assoc_block = sizeof(ide_addr_assoc_reg_block_t) *
                                           ((sel_ide_stream_reg_block_t *)ide_reg_block_ptr)->capability.num_addr_assoc_reg_blocks;

            // Advance to next ide_reg_block
            ide_reg_block_ptr += sizeof(sel_ide_stream_reg_block_t);
            ide_reg_block_ptr += size_of_assoc_block;
        }
    }
    return (void *)ide_reg_block_ptr;
}

_STATIC_INLINE_ ide_addr_assoc_reg_block_t *get_addr_assoc_block(const sel_ide_stream_reg_block_t *const sel_ide_block)
{
    uint64_t addr = (uint64_t)&sel_ide_block->rid_assoc2 + sizeof(sel_ide_block->rid_assoc2);
    return (ide_addr_assoc_reg_block_t *)addr;
}

#endif /* SRC_COMMON_TDXIO_RP_CFG_PAGE_H_ */
