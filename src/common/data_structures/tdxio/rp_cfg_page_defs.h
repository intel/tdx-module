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
 * @file rp_cfg_page_defs.h
 * @brief
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDXIO_RP_CFG_PAGE_DEFS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDXIO_RP_CFG_PAGE_DEFS_H_

#include "tdx_basic_types.h"

#pragma pack(push, 1)

typedef struct
{
    uint8_t pad[_4KB];
} rp_cfg_page_t;
tdx_static_assert(sizeof(rp_cfg_page_t) == _4KB, rp_cfg_page_t);

// Taken from PCI Express Base rev 6.2
// 7.6.3 PCI Express Extended Capability Header

#define PCIE_ECAP_IDE_ID (0x30)

typedef union
{
    struct
    {
        // PCI Express Extended Capability ID—Set to 0030h
        // to indicate IDE Extended Capability
        uint16_t id;
        // Capability Version—This field is a PCI-SIG defined
        // version number that indicates the version of the
        // Capability structure present.
        // Must be 1h for this version of the specification.
        uint16_t version : 4;
        // Next Capability Offset—This field contains the
        // offset to the next PCI Express Extended Capability
        // structure or 000h if no other items exist in the linked
        // list of Capabilities
        uint16_t next_cap_offset : 12;
    };
    uint32_t raw;
} pcie_cap_id_t;
tdx_static_assert(sizeof(pcie_cap_id_t) == 4, pcie_cap_id_t);

// 7.5.12 Type 1 Configuration Space Header
// 7.5.13 Type 0 Configuration Space Header

#define PCIE_PCICMD_OFFSET (0x4)
#define PCIE_PFBAR_OFFSET (0x10)
#define PCIE_SECBUS_OFFSET (0x19)
#define PCIE_SUBBUS_OFFSET (0x1A)
#define PCIE_PFMEM_BASE_OFFSET (0x24)
#define PCIE_PFMEM_LIMIT_OFFSET (0x26)
#define PCIE_PFBASEU_OFFSET (0x28)
#define PCIE_PFLIMITU_OFFSET (0x2C)

#pragma pack(pop)

#endif /* SRC_COMMON_DATA_STRUCTURES_TDXIO_RP_CFG_PAGE_DEFS_H_ */
