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
 * @file inv_queue.h
 * @brief
 */

#ifndef SRC_COMMON_TDXIO_INVQUEUE_H_
#define SRC_COMMON_TDXIO_INVQUEUE_H_

#include "helpers/helpers.h"
#include "data_structures/tdxio/inv_queue_defs.h"
#include "data_structures/tdxio/iommu_defs.h"

/**
 * @brief Map trusted invalidation queue entry or IQ context entry
 *
 * @param base
 * @param idx
 *
 * @return linear address
 */
_STATIC_INLINE_ void *map_iq_entry(
    const iq_buffer_t invq_page,
    const uint64_t idx)
{
    pa_t target_pa = {.raw = 0};
    target_pa.page_4k_num = invq_page.page_4k_num;
    target_pa.raw += idx * IQ_ENTRY_SIZE_IN_BYTES;
    return map_pa_with_global_hkid(target_pa.raw_void, TDX_RANGE_RW);
}

_STATIC_INLINE_ void iq_enqueue(
    const iommu_config_t *const iommu_config_ptr, // IN: Pointer to IOMMU config entry
    const inv_desc_t *const inv_dsc_val_ptr,      // IN: Invalidation descriptor value
    const iq_ctx_entry_t *const iq_ctx_val_ptr,   // IN: IQCTX entry value
    inv_desc_t **t_iq_ptr,                        // IN/OUT: Current/Next trusted IQ pointer
    iq_ctx_entry_t **iq_ctx_ptr,                  // IN/OUT: Current/Next IQCTX pointer
    uint64_t *const t_iqt_idx)                    // IN/OUT: Current/Next trusted IQ tail index
{
    uint64_t prev_t_iqt_index = *t_iqt_idx;

    (*t_iq_ptr)->raw.qwords[0] = inv_dsc_val_ptr->raw.qwords[0];
    (*t_iq_ptr)->raw.qwords[1] = inv_dsc_val_ptr->raw.qwords[1];
    (*t_iq_ptr)->raw.qwords[2] = inv_dsc_val_ptr->raw.qwords[2];
    (*t_iq_ptr)->raw.qwords[3] = inv_dsc_val_ptr->raw.qwords[3];
    (*iq_ctx_ptr)->raw.qwords[0] = iq_ctx_val_ptr->raw.qwords[0];
    (*iq_ctx_ptr)->raw.qwords[1] = iq_ctx_val_ptr->raw.qwords[1];
    (*iq_ctx_ptr)->raw.qwords[2] = iq_ctx_val_ptr->raw.qwords[2];
    (*iq_ctx_ptr)->raw.qwords[3] = iq_ctx_val_ptr->raw.qwords[3];

    // Advance the tail and wrap around if needed to the head of the queue
    *t_iqt_idx = (*t_iqt_idx + 1) % (iommu_config_ptr->t_iqaddr.size * NUM_IQ_ENTRIES_IN_PAGE);

    // Each page of IQ has NUM_IQ_ENTRIES_IN_PAGE IQ descriptors
    if ((*t_iqt_idx / NUM_IQ_ENTRIES_IN_PAGE) != (prev_t_iqt_index / NUM_IQ_ENTRIES_IN_PAGE))
    {
        // Page crossing occurred
        free_la(*t_iq_ptr);
        free_la(*iq_ctx_ptr);
        *t_iq_ptr = (inv_desc_t *)map_iq_entry(iommu_config_ptr->t_iqaddr, *t_iqt_idx);
        *iq_ctx_ptr = (iq_ctx_entry_t *)map_iq_entry(iommu_config_ptr->iqctxaddr, *t_iqt_idx);
    }
    else if ((iommu_config_ptr->t_iqaddr.size == 1) &&
             (*t_iqt_idx == 0))
    {
        // edge case where the IQ size is 1 and the last index is already occupied
        // The new index should start at zero without mapping a new page
        *t_iq_ptr -= prev_t_iqt_index;
        *iq_ctx_ptr -= prev_t_iqt_index;
    }
    else
    {
        (*t_iq_ptr)++;
        (*iq_ctx_ptr)++;
    }
}

#endif // SRC_COMMON_TDXIO_INVQUEUE_H_
