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


#ifndef IO_ACCESSORS_H_
#define IO_ACCESSORS_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "helpers/helpers.h"

/**
 * @brief Volatile uint8_t register read
 *
 * @param reg_ptr
 *
 * @return register value
 */
_STATIC_INLINE_ uint8_t vol_read_reg8(const void *const reg_ptr)
{
    return *(volatile uint8_t *)reg_ptr;
}

/**
 * @brief Volatile uint16_t register read
 *
 * @param reg_ptr
 *
 * @return register value
 */
_STATIC_INLINE_ uint16_t vol_read_reg16(const void *const reg_ptr)
{
    return *(volatile uint16_t *)reg_ptr;
}

/**
 * @brief Volatile uint32_t register read
 *
 * @param reg_ptr
 *
 * @return register value
 */
_STATIC_INLINE_ uint32_t vol_read_reg32(const void *const reg_ptr)
{
    return *(volatile uint32_t *)reg_ptr;
}

/**
 * @brief Volatile uint32_t register write
 *
 * @param reg_ptr
 * @param reg_val
 */
_STATIC_INLINE_ void vol_write_reg32(
    void *const reg_ptr,
    const uint32_t reg_val)
{
    *(volatile uint32_t *)reg_ptr = reg_val;
}

/**
 * @brief Volatile uint64_t register read using 2 volatile uint32_t read operations
 *
 * @param reg_ptr
 *
 * @return register value
 */
_STATIC_INLINE_ uint64_t vol_read_reg64_with_32(const void *const reg_ptr)
{
    uint32_t *reg_32_ptr = (uint32_t *)reg_ptr;
    uint32_t lowDW = vol_read_reg32(reg_32_ptr);

    reg_32_ptr++;
    uint64_t highDW = vol_read_reg32(reg_32_ptr);

    return (uint64_t)((highDW << 32) | lowDW);
}

/**
 * @brief Volatile uint64_t register write using 2 volatile uint32_t write operations
 *
 * @param reg_ptr
 * @param reg_val
 */
_STATIC_INLINE_ void vol_write_reg64_with_32(
    void *const reg_ptr,
    const uint64_t reg_val)
{
    uint32_t *reg_32_ptr = (uint32_t *)reg_ptr;
    uint32_t lowDW = (uint32_t)reg_val;
    vol_write_reg32(reg_32_ptr, lowDW);

    reg_32_ptr++;
    uint32_t highDW = reg_val >> 32;
    vol_write_reg32(reg_32_ptr, highDW);
}

/**
 * @brief Volatile uint64_t register read
 *
 * @param reg_ptr
 *
 * @return register value
 */
_STATIC_INLINE_ uint64_t vol_read_reg64(const void *const reg_ptr)
{
    return *(volatile uint64_t *)reg_ptr;
}

/**
 * @brief Volatile uint64_t register write
 *
 * @param reg_ptr
 * @param reg_val
 */
_STATIC_INLINE_ void vol_write_reg64(
    void *const reg_ptr,
    const uint64_t reg_val)
{
    *(volatile uint64_t *)reg_ptr = reg_val;
}

/**
 * @brief Write to the PCI space
 *
 * @param pci_reg_pa
 * @param val
 */
_STATIC_INLINE_ void pci_64bit_write(
    pa_t pci_reg_pa,
    const uint64_t val)
{
    uint32_t *pci_reg_ptr = (uint32_t *)map_pa_with_global_hkid_uncached(
        pci_reg_pa.raw_void,
        TDX_RANGE_RW);

    vol_write_reg32(pci_reg_ptr, (uint32_t)val);

    // Check if moving the pointer would cross the page boundary the LA resides in
    if (((uint64_t)pci_reg_ptr / TDX_PAGE_SIZE_IN_BYTES) != (((uint64_t)pci_reg_ptr + sizeof(uint32_t)) / TDX_PAGE_SIZE_IN_BYTES))
    {
        // Forwarding the original pointer crosses the page boundary
        // Free the LA and remap it with the modified PA
        free_la(pci_reg_ptr);
        pci_reg_pa.raw += sizeof(uint32_t);
        pci_reg_ptr = (uint32_t *)map_pa_with_global_hkid_uncached(
            pci_reg_pa.raw_void,
            TDX_RANGE_RW);
    }
    else
    {
        // Forwarding the original pointer doesn't crosses the page boundary
        pci_reg_ptr++;
    }

    vol_write_reg32(pci_reg_ptr, (uint32_t)(val >> 32));

    free_la((void *)pci_reg_ptr);
}

/**
 * @brief Reaf from the PCI space
 *
 * @param pci_reg_pa
 *
 * @return register value
 */
_STATIC_INLINE_ uint64_t pci_64bit_read(pa_t pci_reg_pa)
{
    uint32_t *pci_reg_ptr = (uint32_t *)map_pa_with_global_hkid_uncached(
        pci_reg_pa.raw_void,
        TDX_RANGE_RO);

    uint32_t pci_reg_l = vol_read_reg32(pci_reg_ptr);

    // Check if moving the pointer would cross the page boundary the LA resides in
    if (((uint64_t)pci_reg_ptr / TDX_PAGE_SIZE_IN_BYTES) != (((uint64_t)pci_reg_ptr + sizeof(uint32_t)) / TDX_PAGE_SIZE_IN_BYTES))
    {
        // Forwarding the original pointer crosses the page boundary
        // Free the LA and remap it with the modified PA
        free_la(pci_reg_ptr);
        pci_reg_pa.raw += sizeof(uint32_t);
        pci_reg_ptr = (uint32_t *)map_pa_with_global_hkid_uncached(
            pci_reg_pa.raw_void,
            TDX_RANGE_RO);
    }
    else
    {
        // Forwarding the original pointer doesn't crosses the page boundary
        pci_reg_ptr++;
    }

    uint64_t pci_reg_h = vol_read_reg32(pci_reg_ptr);

    free_la(pci_reg_ptr);

    return (uint64_t)((pci_reg_h << 32) | pci_reg_l);
}


#endif // IO_ACCESSORS_H_
