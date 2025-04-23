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
 * @file sept_manager.h
 * @brief SEPT manager headers
 */

#ifndef SRC_COMMON_MEMORY_HANDLERS_SEPT_MANAGER_H_
#define SRC_COMMON_MEMORY_HANDLERS_SEPT_MANAGER_H_

#include "x86_defs/x86_defs.h"
#include "auto_gen/sept_state_lookup.h"
#include "data_structures/tdx_local_data.h"
#include "helpers/helpers.h"


///////////////////////////////////////////////////////////////////////////////////
/// SEPT state masks
///////////////////////////////////////////////////////////////////////////////////
#define SEPT_STATE_ENCODING_MASK         (BIT(SEPT_ENTRY_D_BIT_POSITION)    | \
                                          BIT(SEPT_ENTRY_IPAT_BIT_POSITION) | \
                                          BIT(SEPT_ENTRY_PS_BIT_POSITION)   | \
                                          BIT(SEPT_ENTRY_TDP_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_TDB_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_TDBW_BIT_POSITION) | \
                                          BIT(SEPT_ENTRY_TDEX_BIT_POSITION))

#define SEPT_STATE_ENCODING_WO_D_MASK    (SEPT_STATE_ENCODING_MASK & ~(BIT(SEPT_ENTRY_D_BIT_POSITION)))

#define SEPT_STATE_ENCODING_WO_TDP_MASK  (SEPT_STATE_ENCODING_MASK & ~(BIT(SEPT_ENTRY_TDP_BIT_POSITION)))

#define SEPT_HPA_MASK                    (0x000FFFFFFFFFF000ULL)

#define SEPT_PERMISSIONS_MASK            (BIT(SEPT_ENTRY_R_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_W_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_X_BIT_POSITION))

#define L2_SEPT_PERMISSIONS_MASK         (BIT(SEPT_ENTRY_R_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_W_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_X_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_XU_BIT_POSITION))

#define SEPT_PERMISSIONS_NONE             0

#define SEPT_PERMISSIONS_RWX             (BIT(SEPT_ENTRY_R_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_W_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_X_BIT_POSITION))

#define SEPT_PERMISSIONS_RW_XS_XU        (BIT(SEPT_ENTRY_R_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_W_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_X_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_XU_BIT_POSITION))

#define SEPT_MIGRATABLE_ATTRIBUTES_MASK  (BIT(SEPT_ENTRY_R_BIT_POSITION)   | \
                                          BIT(SEPT_ENTRY_W_BIT_POSITION)   | \
                                          BIT(SEPT_ENTRY_XS_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_XU_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_VPW_BIT_POSITION) | \
                                          BIT(SEPT_ENTRY_PW_BIT_POSITION)  | \
                                          BIT(SEPT_ENTRY_SSS_BIT_POSITION))

#define L2_SEPT_MIGRATABLE_ATTRIBUTES_MASK  (BIT(SEPT_ENTRY_R_BIT_POSITION)   | \
                                             BIT(SEPT_ENTRY_W_BIT_POSITION)   | \
                                             BIT(SEPT_ENTRY_XS_BIT_POSITION)  | \
                                             BIT(SEPT_ENTRY_XU_BIT_POSITION)  | \
                                             BIT(SEPT_ENTRY_VPW_BIT_POSITION) | \
                                             BIT(SEPT_ENTRY_PW_BIT_POSITION)  | \
                                             BIT(SEPT_ENTRY_SSS_BIT_POSITION) | \
                                             BIT(SEPT_ENTRY_SVE_BIT_POSITION))

// Memory Type mask
#define MT_MASK                          (BIT(SEPT_ENTRY_MT0_BIT_POSITION) | \
                                          BIT(SEPT_ENTRY_MT1_BIT_POSITION) | \
                                          BIT(SEPT_ENTRY_MT2_BIT_POSITION))

#define SEPT_ARCH_ENTRY_LEAF_MASK        (SEPT_PERMISSIONS_MASK             | \
                                          MT_MASK                           | \
                                          SEPT_HPA_MASK                     | \
                                          BIT(SEPT_ENTRY_IPAT_BIT_POSITION) | \
                                          BIT(SEPT_ENTRY_PS_BIT_POSITION)   | \
                                          BIT(SEPT_ENTRY_SVE_BIT_POSITION))

#define SEPT_ARCH_ENTRY_NON_LEAF_MASK    (SEPT_PERMISSIONS_MASK             | \
                                          BIT(SEPT_ENTRY_PS_BIT_POSITION))

// Architectural L2 SEPT entry as provided to users - see the FAS document
// For non-debug TDs, VGP, PWA and SSS are cleared to 0
#define L2_SEPT_ARCH_ENTRY_LEAF_MASK      (MT_MASK                           | \
                                           SEPT_HPA_MASK                     | \
                                           BIT(SEPT_ENTRY_IPAT_BIT_POSITION) | \
                                           BIT(SEPT_ENTRY_PS_BIT_POSITION)   | \
                                           BIT(SEPT_ENTRY_SVE_BIT_POSITION))

// For debug TDs, the real values of RWXsXu and of VGP, PWA and SSS are returned
#define L2_SEPT_ARCH_ENTRY_LEAF_DEBUG_MASK   (L2_SEPT_MIGRATABLE_ATTRIBUTES_MASK | \
                                              MT_MASK                            | \
                                              SEPT_HPA_MASK                      | \
                                              BIT(SEPT_ENTRY_IPAT_BIT_POSITION)  | \
                                              BIT(SEPT_ENTRY_PS_BIT_POSITION)    | \
                                              BIT(SEPT_ENTRY_SVE_BIT_POSITION))

#define L2_SEPT_ARCH_ENTRY_NON_LEAF_MASK     (L2_SEPT_PERMISSIONS_MASK   | \
                                              BIT(SEPT_ENTRY_PS_BIT_POSITION))


#define L2_SEPT_STATE_ENCODING_MASK       (BIT(SEPT_ENTRY_R_BIT_POSITION)    | \
                                          BIT(SEPT_ENTRY_IPAT_BIT_POSITION) | \
                                          BIT(SEPT_ENTRY_PS_BIT_POSITION)   | \
                                          BIT(SEPT_ENTRY_TDB_BIT_POSITION))

#define L2_SEPT_STATE_ENCODING_WO_R_MASK  (L2_SEPT_STATE_ENCODING_MASK & ~(BIT(SEPT_ENTRY_R_BIT_POSITION)))

#define SEPT_CONVERT_TO_ENCODING(ept_entry)  ( ((uint64_t)(ept_entry).state_encoding.state_encoding_0) |   \
                                               (((uint64_t)(ept_entry).state_encoding.state_encoding_1_4) << 1ULL) |  \
                                               (((uint64_t)(ept_entry).state_encoding.state_encoding_5_6) << 5ULL) )

#define SEPT_STATE_ENC_TO_MASK(e)            ( ((BIT(0) & (e)) << SEPT_ENTRY_D_BIT_POSITION) | \
                                               (((BITS(4,1) & (e)) >> 1) << SEPT_ENTRY_TDEX_BIT_POSITION) |\
                                               (((BITS(6,5) & (e)) >> 5) << SEPT_ENTRY_IPAT_BIT_POSITION))

#define L2_SEPT_STATE_ENC_TO_MASK(e)         ( ((BIT(0) & (e)) << SEPT_ENTRY_TDB_BIT_POSITION) | \
                                               (((BITS(2, 1) & (e)) >> 1) << SEPT_ENTRY_IPAT_BIT_POSITION))

#define L2_SEPT_CONVERT_TO_ENCODING(l2_ept_entry)  ( ((uint64_t)(l2_ept_entry).l2_encoding.tdb) |   \
                                                    (((uint64_t)(l2_ept_entry).l2_encoding.ipat_tdmem) << 1ULL) |  \
                                                    (((uint64_t)(l2_ept_entry).l2_encoding.ps) << 2ULL) | \
                                                    (((uint64_t)(l2_ept_entry).l2_encoding.r) << 3ULL) )

typedef enum sept_state_mask_e
{
    SEPT_STATE_FREE_MASK                       = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_FREE_ENCODING),
    SEPT_STATE_NL_MAPPED_MASK                  = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_NL_MAPPED_ENCODING),
    SEPT_STATE_NL_BLOCKED_MASK                 = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_NL_BLOCKED_ENCODING),
    SEPT_STATE_MAPPED_MASK                     = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_MAPPED_ENCODING),
    SEPT_STATE_BLOCKED_MASK                    = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_BLOCKED_ENCODING),
    SEPT_STATE_REMOVED_MASK                    = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_REMOVED_ENCODING),
    SEPT_STATE_BLOCKEDW_MASK                   = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_BLOCKEDW_ENCODING),
    SEPT_STATE_EXP_BLOCKEDW_MASK               = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_EXPORTED_BLOCKEDW_ENCODING),
    SEPT_STATE_EXP_DIRTY_MASK                  = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_EXPORTED_DIRTY_ENCODING),
    SEPT_STATE_EXP_DIRTY_BLOCKEDW_MASK         = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_EXPORTED_DIRTY_BLOCKEDW_ENCODING),
    SEPT_STATE_PEND_BLOCKEDW_MASK              = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_PENDING_BLOCKEDW_ENCODING),
    SEPT_STATE_PEND_EXP_BLOCKEDW_MASK          = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_PENDING_EXPORTED_BLOCKEDW_ENCODING),
    SEPT_STATE_PEND_EXP_DIRTY_MASK             = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_PENDING_EXPORTED_DIRTY_ENCODING),
    SEPT_STATE_PEND_EXP_DIRTY_BLOCKEDW_MASK    = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_PENDING_EXPORTED_DIRTY_BLOCKEDW_ENCODING),
    SEPT_STATE_PEND_MASK                       = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_PENDING_ENCODING),
    SEPT_STATE_PEND_BLOCKED_MASK               = SEPT_STATE_ENC_TO_MASK(SEPT_STATE_PENDING_BLOCKED_ENCODING),
    SEPT_STATE_L2_FREE_MASK                    = L2_SEPT_STATE_ENC_TO_MASK(SEPT_STATE_L2_FREE_ENCODING),
    SEPT_STATE_L2_NL_MAPPED_MASK               = L2_SEPT_STATE_ENC_TO_MASK(SEPT_STATE_L2_NL_MAPPED_ENCODING),
    SEPT_STATE_L2_NL_BLOCKED_MASK              = L2_SEPT_STATE_ENC_TO_MASK(SEPT_STATE_L2_NL_BLOCKED_ENCODING),
    SEPT_STATE_L2_MAPPED_MASK                  = L2_SEPT_STATE_ENC_TO_MASK(SEPT_STATE_L2_MAPPED_ENCODING),
    SEPT_STATE_L2_BLOCKED_MASK                 = L2_SEPT_STATE_ENC_TO_MASK(SEPT_STATE_L2_BLOCKED_ENCODING)
} sept_state_mask_t;

// Clearing the TDP bit relies of specific encoding of the SEPT entry state.
// The following assertions verify this.
tdx_static_assert((SEPT_STATE_PEND_MASK == (SEPT_STATE_MAPPED_MASK | BIT(SEPT_ENTRY_TDP_BIT_POSITION))), sept_state_mapped_mask);
tdx_static_assert((SEPT_STATE_PEND_EXP_DIRTY_MASK == (SEPT_STATE_EXP_DIRTY_MASK | BIT(SEPT_ENTRY_TDP_BIT_POSITION))), sept_state_mapped_mask);

// A free Secure-EPT init value with suppress VE set (bit 63)
#define SEPTE_INIT_VALUE        (SEPT_STATE_FREE_MASK | BIT(SEPT_ENTRY_SVE_BIT_POSITION))
#define SEPTE_L2_INIT_VALUE     (SEPT_STATE_L2_FREE_MASK)

///////////////////////////////////////////////////////////////////////////////////
/// SEPT state queries
///////////////////////////////////////////////////////////////////////////////////
_STATIC_INLINE_ bool_t is_sept_free(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_MASK) == SEPT_STATE_FREE_MASK);
}

_STATIC_INLINE_ bool_t is_sept_mapped(const ia32e_sept_t* ept_entry)
{
    // Bit D is X
    return ((ept_entry->raw & SEPT_STATE_ENCODING_WO_D_MASK) == SEPT_STATE_MAPPED_MASK);
}

_STATIC_INLINE_ bool_t is_sept_pending(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_MASK) == SEPT_STATE_PEND_MASK);
}

_STATIC_INLINE_ bool_t is_sept_blocked(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_WO_TDP_MASK) == SEPT_STATE_BLOCKED_MASK);
}

_STATIC_INLINE_ bool_t is_sept_exp_dirty(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_MASK) == SEPT_STATE_EXP_DIRTY_MASK);
}

_STATIC_INLINE_ bool_t is_sept_pending_exp_dirty(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_MASK) == SEPT_STATE_PEND_EXP_DIRTY_MASK);
}

_STATIC_INLINE_ bool_t is_sept_blockedw(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_WO_TDP_MASK) == SEPT_STATE_BLOCKEDW_MASK);
}

_STATIC_INLINE_ bool_t is_sept_exported_blocked(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_WO_TDP_MASK) == SEPT_STATE_EXP_BLOCKEDW_MASK);
}

_STATIC_INLINE_ bool_t is_sept_removed(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_MASK) == SEPT_STATE_REMOVED_MASK);
}

_STATIC_INLINE_ bool_t is_sept_nl_mapped(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & SEPT_STATE_ENCODING_MASK) == SEPT_STATE_NL_MAPPED_MASK);
}

_STATIC_INLINE_ bool_t is_l2_sept_nl_blocked(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & L2_SEPT_STATE_ENCODING_MASK) == SEPT_STATE_L2_NL_BLOCKED_MASK);
}

_STATIC_INLINE_ bool_t is_l2_sept_blocked(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & L2_SEPT_STATE_ENCODING_WO_R_MASK) == SEPT_STATE_L2_BLOCKED_MASK);
}

_STATIC_INLINE_ bool_t is_l2_sept_mapped(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & L2_SEPT_STATE_ENCODING_WO_R_MASK) == SEPT_STATE_L2_MAPPED_MASK);
}

_STATIC_INLINE_ bool_t is_l2_sept_free(const ia32e_sept_t* ept_entry)
{
    return ((ept_entry->raw & L2_SEPT_STATE_ENCODING_MASK) == SEPT_STATE_L2_FREE_MASK);
}

/**
 * @brief Helper functions that establish if a specific operation allowed or required
 *        for a given SEPT State
 */

_STATIC_INLINE_ bool_t sept_state_is_live_export_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].live_export_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_paused_export_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].paused_export_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_re_export_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].re_export_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_re_import_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].re_import_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_export_cancel_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].export_cancel_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_import_cancel_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].import_cancel_allowed;
}


_STATIC_INLINE_ bool_t sept_state_is_first_time_export_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].first_time_export_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_first_time_import_allowed(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].first_time_import_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_any_exported(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].any_exported;
}

_STATIC_INLINE_ bool_t sept_state_is_any_exported_and_dirty(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].any_exported_and_dirty;
}

_STATIC_INLINE_ bool_t sept_state_is_any_exported_and_non_dirty(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].any_exported_and_non_dirty;
}

_STATIC_INLINE_ bool_t sept_state_is_any_blockedw(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].any_blockedw;
}

_STATIC_INLINE_ bool_t sept_state_is_mapped_or_pending(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].mapped_or_pending;
}

_STATIC_INLINE_ bool_t sept_state_is_any_pending(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].any_pending;
}

_STATIC_INLINE_ bool_t sept_state_is_any_pending_and_guest_acceptable(const ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].any_pending_and_guest_acceptable;
}

_STATIC_INLINE_ bool_t sept_state_is_any_blocked(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].any_blocked;
}

_STATIC_INLINE_ bool_t sept_state_is_tlb_tracking_required(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].tlb_tracking_required;
}

_STATIC_INLINE_ bool_t sept_state_is_guest_accessible_leaf(ia32e_sept_t ept_entry)
{
    uint64_t idx = SEPT_CONVERT_TO_ENCODING(ept_entry);
    tdx_debug_assert(idx < MAX_SEPT_STATE_ENC);
    return sept_special_flags_lookup[idx].guest_accessible_leaf;
}

_STATIC_INLINE_ bool_t septe_state_encoding_is_seamcall_allowed(uint64_t septe_state_enc, seamcall_leaf_opcode_t leaf_number)
{
    tdx_debug_assert(septe_state_enc < (MAX_SEPT_STATE_ENC));
    tdx_debug_assert((uint64_t)leaf_number < MAX_SEAMCALL_LEAF);

    uint32_t septe_state_enc_index = sept_special_flags_lookup[septe_state_enc].index;
    tdx_debug_assert(septe_state_enc_index < NUM_SEPT_STATES);

    bool_t is_seamcall_allowed = seamcall_sept_state_lookup[leaf_number][septe_state_enc_index];

    return is_seamcall_allowed;
}

_STATIC_INLINE_ bool_t septe_state_encoding_is_tdcall_allowed(uint64_t septe_state_enc, tdcall_leaf_opcode_t leaf_number)
{
    tdx_debug_assert(septe_state_enc < (MAX_SEPT_STATE_ENC));
    tdx_debug_assert((uint64_t)leaf_number < MAX_TDCALL_LEAF);

    uint32_t septe_state_enc_index = sept_special_flags_lookup[septe_state_enc].index;
    tdx_debug_assert(septe_state_enc_index < NUM_SEPT_STATES);

    bool_t is_tdcall_allowed = tdcall_sept_state_lookup[leaf_number][septe_state_enc_index];

    return is_tdcall_allowed;
}

_STATIC_INLINE_ bool_t sept_state_is_seamcall_leaf_allowed(seamcall_leaf_opcode_t current_leaf, ia32e_sept_t ept_entry)
{
    uint64_t sept_state_enc = SEPT_CONVERT_TO_ENCODING(ept_entry);
    return septe_state_encoding_is_seamcall_allowed(sept_state_enc, current_leaf);
}

_STATIC_INLINE_ bool_t sept_state_is_tdcall_leaf_allowed(tdcall_leaf_opcode_t current_leaf, ia32e_sept_t ept_entry)
{
    uint64_t sept_state_enc = SEPT_CONVERT_TO_ENCODING(ept_entry);
    return septe_state_encoding_is_tdcall_allowed(sept_state_enc, current_leaf);
}

_STATIC_INLINE_ uint32_t sept_get_arch_state(ia32e_sept_t ept_entry)
{
    return sept_special_flags_lookup[SEPT_CONVERT_TO_ENCODING(ept_entry)].public_state;
}

_STATIC_INLINE_ uint32_t l2_sept_get_arch_state(ia32e_sept_t l2_ept_entry)
{
    return l2_sept_special_flags_lookup[L2_SEPT_CONVERT_TO_ENCODING(l2_ept_entry)].public_state;
}

_STATIC_INLINE_ void sept_update_state(ia32e_sept_t* ept_entry, sept_state_mask_t state)
{
    ia32e_sept_t new_septe;

    new_septe.raw = (ept_entry->raw & ~SEPT_STATE_ENCODING_MASK) | (state & SEPT_STATE_ENCODING_MASK);
    new_septe.supp_ve = 1;

    // Write the new value in a single 64-bit write
    atomic_mem_write_64b(&ept_entry->raw, new_septe.raw);
}

_STATIC_INLINE_ void sept_l2_update_state(ia32e_sept_t* ept_entry, sept_state_mask_t state)
{
    ia32e_sept_t new_septe;

    uint64_t final_mask = L2_SEPT_STATE_ENCODING_MASK;

    if ((state == SEPT_STATE_L2_MAPPED_MASK) || (state == SEPT_STATE_L2_BLOCKED_MASK))
    {
        final_mask = L2_SEPT_STATE_ENCODING_WO_R_MASK;
    }

    new_septe.raw = (ept_entry->raw & ~final_mask) | (state & final_mask);

    // Write the new value in a single 64-bit write
    atomic_mem_write_64b(&ept_entry->raw, new_septe.raw);
}

// Reserved for future expansion
_STATIC_INLINE_ gpa_attr_single_vm_t sept_get_gpa_attr(const ia32e_sept_t ept_entry)
{
    UNUSED(ept_entry);
    gpa_attr_single_vm_t gpa_attr_single_vm = {.raw = 0};
    return gpa_attr_single_vm;
}

_STATIC_INLINE_ void l2_sept_update_gpa_attr(
    ia32e_sept_t *const l2_sept_entry_ptr,
    const gpa_attr_single_vm_t gpa_attr_single_vm)
{
    l2_sept_entry_ptr->l2_encoding.r = gpa_attr_single_vm.r;
    l2_sept_entry_ptr->l2_encoding.w = gpa_attr_single_vm.w;
    l2_sept_entry_ptr->l2_encoding.x = gpa_attr_single_vm.xs;
    l2_sept_entry_ptr->l2_encoding.xu = gpa_attr_single_vm.xu;
    l2_sept_entry_ptr->l2_encoding.vgp = gpa_attr_single_vm.vgp;
    l2_sept_entry_ptr->l2_encoding.pwa = gpa_attr_single_vm.pwa;
    l2_sept_entry_ptr->l2_encoding.sss = gpa_attr_single_vm.sss;
    l2_sept_entry_ptr->l2_encoding.sve = gpa_attr_single_vm.sve;

    if (is_l2_sept_blocked(l2_sept_entry_ptr))
    {
        l2_sept_entry_ptr->l2_encoding.mt0_tdrd = l2_sept_entry_ptr->l2_encoding.r;
        l2_sept_entry_ptr->l2_encoding.r = 0;
        l2_sept_entry_ptr->l2_encoding.tdwr = l2_sept_entry_ptr->l2_encoding.w;
        l2_sept_entry_ptr->l2_encoding.w = 0;
        l2_sept_entry_ptr->l2_encoding.mt1_tdxs = l2_sept_entry_ptr->l2_encoding.x;
        l2_sept_entry_ptr->l2_encoding.x = 0;
        l2_sept_entry_ptr->l2_encoding.mt2_tdxu = l2_sept_entry_ptr->l2_encoding.xu;
        l2_sept_entry_ptr->l2_encoding.xu = 0;
    }
}

/**
 * @brief
 * Get the architectural GPA attributes of the L2 SEPT entry.
 *  - If the entry is free, return only SVE.  Return VALID as 0.
 *  - Else if the entry is a leaf, return all attributes.  Return VALID as 1.
 *    - If the entry is a blocked leaf, return saved W bit (if is_blockedw) or saved RWXsXu bits (if !is_blockedw)
 *  - Else (non-leaf), return RWXsXu as all-1 (even if they are 0 since the entry is blocked).  Return VALID as 1.
 *
 *  @param l2_sept_entry_ptr - pointer to the L2 sept entry
 *  @param is_blockedw - BLOCKEDW state of the parent L1 entry
 */
_STATIC_INLINE_ gpa_attr_single_vm_t l2_sept_get_gpa_attr(
    const ia32e_sept_t *const l2_sept_entry_ptr,
    const bool_t is_blockedw)
{
    gpa_attr_single_vm_t gpa_attr_single_vm = {.raw = 0};

    if (is_l2_sept_free(l2_sept_entry_ptr))
    {
        gpa_attr_single_vm.sve = l2_sept_entry_ptr->l2_encoding.sve;
        gpa_attr_single_vm.valid = 0;
    }
    else
    {
        if (l2_sept_entry_ptr->leaf)
        {
            gpa_attr_single_vm.vgp = l2_sept_entry_ptr->l2_encoding.vgp;
            gpa_attr_single_vm.pwa = l2_sept_entry_ptr->l2_encoding.pwa;
            gpa_attr_single_vm.sss = l2_sept_entry_ptr->l2_encoding.sss;
            gpa_attr_single_vm.sve = l2_sept_entry_ptr->l2_encoding.sve;

            gpa_attr_single_vm.w  = l2_sept_entry_ptr->l2_encoding.w;
            gpa_attr_single_vm.r  = l2_sept_entry_ptr->l2_encoding.r;
            gpa_attr_single_vm.xs = l2_sept_entry_ptr->l2_encoding.x;
            gpa_attr_single_vm.xu = l2_sept_entry_ptr->l2_encoding.xu;

            if (is_l2_sept_blocked(l2_sept_entry_ptr))
            {
                // Saved W bit returned either way
                gpa_attr_single_vm.w = l2_sept_entry_ptr->l2_encoding.tdwr;
                if (!is_blockedw)
                {
                    gpa_attr_single_vm.r = l2_sept_entry_ptr->l2_encoding.mt0_tdrd;
                    gpa_attr_single_vm.xs = l2_sept_entry_ptr->l2_encoding.mt1_tdxs;
                    gpa_attr_single_vm.xu = l2_sept_entry_ptr->l2_encoding.mt2_tdxu;
                }
            }
        }
        else
        {
            gpa_attr_single_vm.r = 1;
            gpa_attr_single_vm.w = 1;
            gpa_attr_single_vm.xs = 1;
            gpa_attr_single_vm.xu = 1;
        }

        // Valid returned for leaf and non-leaf
        gpa_attr_single_vm.valid = 1;
    }

    return gpa_attr_single_vm;
}

/**
 * @brief Clear SEPT entry's alias indication for the specified L2 VM's SEPT
           Assumes the current SEPT entry is a non-FREE non-REMOVED leaf entry.
 *
 * @param l2_sept_entry_ptr
 * @param vm_idx
 *
 * @return _STATIC_INLINE_
 */
_STATIC_INLINE_ void sept_clear_aliased(ia32e_sept_t *const sept_entry_ptr, const uint16_t vm_idx)
{
    ia32e_sept_t tmp_sept = *sept_entry_ptr;

    tmp_sept.tdal &= ~BIT(vm_idx -1);

    atomic_mem_write_64b(&sept_entry_ptr->raw, tmp_sept.raw);
}

/**
 * @brief Set SEPT entry's alias indication for the specified L2 VM's SEPT
           Assumes the current SEPT entry is a non-FREE non-REMOVED leaf entry.
 *
 * @param l2_sept_entry_ptr
 * @param vm_idx
 *
 * @return _STATIC_INLINE_
 */
_STATIC_INLINE_ void sept_set_aliased(ia32e_sept_t *const sept_entry_ptr, const uint16_t vm_idx)
{
    ia32e_sept_t tmp_ept = *sept_entry_ptr;

    tmp_ept.tdal |= ((uint64_t)1 << (vm_idx -1));

    atomic_mem_write_64b(&sept_entry_ptr->raw, tmp_ept.raw);
}

_STATIC_INLINE_ bool_t sept_state_is_aliased(
    const ia32e_sept_t ept_entry,
    const uint16_t vm_idx)
{
    return ((ept_entry.tdal & BIT(vm_idx-1)) >> (vm_idx-1));
}

_STATIC_INLINE_ bool_t sept_state_is_any_aliased(
    const ia32e_sept_t ept_entry)
{
    return (ept_entry.tdal != 0);
}

///////////////////////////////////////////////////////////////////////////////////
/// SEPT state setters - releases all locks
///////////////////////////////////////////////////////////////////////////////////
_STATIC_INLINE_ void set_remove_and_release_locks_for_import(ia32e_sept_t *sept_entry, const tdcs_t *tdcs_p)
{
        atomic_mem_write_64b(&sept_entry->raw, SEPT_STATE_REMOVED_MASK | (1ULL << SEPT_ENTRY_SVE_BIT_POSITION));
        sept_entry->mig_epoch_valid = 1;
        sept_entry->mig_epoch = tdcs_p->migration_fields.mig_epoch;
}

_STATIC_INLINE_ void septe_set_free_or_removed_and_release_locks(ia32e_sept_t *sept_entry, const tdcs_t *tdcs_p)
{
    if (op_state_is_import_in_progress(tdcs_p->management_fields.op_state))
    {
        set_remove_and_release_locks_for_import(sept_entry, tdcs_p);
    }
    else
    {
        atomic_mem_write_64b(&sept_entry->raw, SEPT_STATE_FREE_MASK | (1ULL << SEPT_ENTRY_SVE_BIT_POSITION));
    }
}

// Secure EPT state and level as returned in RDX by many API functions
typedef union sept_entry_arch_info_u
{
    struct
    {
        uint64_t level        : 3;   // Bits 2:0
        uint64_t reserved_0   : 5;   // Bit 7:3
        uint64_t state        : 8;   // Bits 15:8
        uint64_t vm           : 2;   // Bits 17:16
        uint64_t reserved_1   : 46;  // Bits 63:18
    };
    uint64_t raw;
} sept_entry_arch_info_t;
tdx_static_assert(sizeof(sept_entry_arch_info_t) == 8, sept_entry_arch_info_t);

/**
 * @brief Check that EPT entry is a leaf - correct only for validly configured entries
 *
 * @param ept_entry Pointer to EPT entry
 * @param level The EPT entry level
 *
 * @return True if entry is a leaf, False otherwise
 */
_STATIC_INLINE_ bool_t is_ept_leaf_entry(const ia32e_ept_t * ept_entry, ept_level_t level)
{
    return ((level == LVL_PT) || (ept_entry->fields_2m.leaf == 1));
}

/**
 * @brief Check that Secure EPT entry is a leaf - correct only for non-FREE entries
 *
 * @param ept_entry Pointer to EPT entry
 *
 * @return True if entry is a leaf, False otherwise
 */
_STATIC_INLINE_ bool_t is_secure_ept_leaf_entry(const ia32e_sept_t * ept_entry)
{
    return (ept_entry->leaf == 1);
}

/**
 * @brief Map a SEPT leaf entry - releases all lock on current entry
 *
 * @param ept_entry Pointer to EPT entry to map
 * @param attributes migration attributes to use to update the ept entry
 * @param page_pa Physical address to map in entry
 * @param state_encoding the new sept entry state
 */
void sept_set_leaf_and_release_locks(ia32e_sept_t * ept_entry, uint64_t attributes,
                                     pa_t page_pa, uint64_t state_encoding);

/**
 * @brief Map a SEPT leaf entry - with a taken entry lock.
 *        Should be used only locked entries only!!!
 *
 * @param ept_entry Pointer to EPT entry to map
 * @param attributes migration attributes to use to update the ept entry
 * @param page_pa Physical address to map in entry
 * @param state_encoding the new sept entry state
 */
void sept_set_leaf_and_keep_lock(ia32e_sept_t * ept_entry, uint64_t attributes,
                                 pa_t page_pa, uint64_t state_encoding);
								 
/**
 * @brief Identical to sept_set_leaf_and_release_locks, but assumes that the current entry is unlocked
 */
void sept_set_leaf_unlocked_entry(ia32e_sept_t * ept_entry, uint64_t attributes,
                                  pa_t page_pa, uint64_t state_encoding);

/**
 * @brief Map a SEPT non-leaf entry
 *
 * @param ept_entry Pointer to EPT entry to map
 * @param page_pa Physical address to map in entry
 * @param lock Whether acquire entry lock or not
 */
void sept_set_mapped_non_leaf(ia32e_sept_t * ept_entry, pa_t page_pa, bool_t lock);

/**
 * @brief Set an L2 secure EPT leaf entry.
 *           MT bits are set to WB (110)  (Note:  this will change when TDX IO will be supported)
 *           IPAT is set to 1  (Note:  this will change when TDX IO will be supported)
 *           Attributes are set based on the provided attributes
 *           State is set to L2_MAPPED or L2_BLOCKED based on the is_l2_blocked flag.
 *           If is_l2_blocked is 1, then R, W, Xs and Xu are set to 0, and the values
 *           specified by in the provided attributes are saved in TDRD, TDW, TDXS and TDXU.
 *           Else, TDRD, TDWR, TDXS and TDXU are set to their proper values:
 *           TDRD, TDXS and TDXU are part of MT (see above) and TDWR is set to 0.
 *
 * @param l2_sept_entry_ptr
 * @param gpa_attr_single_vm
 * @param pa
 * @param is_l2_blocked
 */
void sept_l2_set_leaf(ia32e_sept_t* l2_sept_entry_ptr, gpa_attr_single_vm_t gpa_attr_single_vm,
                      pa_t pa, bool_t is_l2_blocked);

/**
 * @brief Map a L2 SEPT non-leaf entry - releases all lock on current entry
 *
 * @param ept_entry Pointer to EPT entry to map
 * @param page_pa Physical address to map in entry
 */
void sept_l2_set_mapped_non_leaf(ia32e_sept_t * ept_entry, pa_t page_pa);

/** @brief Cleanup the SEPT entry if the page is PENDING
 *         For 2MB leaf entries, zero out the INIT_COUNTER (bits 20:12)
 *
 *  @param ept_entry Pointer to EPT entry to be cleaned
 */
_STATIC_INLINE_ void sept_cleanup_if_pending(ia32e_sept_t* ept_entry, ept_level_t level)
{
    if (sept_state_is_any_pending_and_guest_acceptable(*ept_entry) && (level == LVL_PD))
    {
        tdx_debug_assert(is_secure_ept_leaf_entry(ept_entry));
        ept_entry->accept_counter = 0;
    }
}

/**
 * @brief Unblock the Secure EPT entry (non-atomic)
 *        If the SEPT entry was not blocked (NL_BLOCKED, BLOCKED, PENDING_BLOCKED), do nothing.
 *        Else:
 *          - Restore original state before blocking - releases all locks
 *          - Restore RWX
 *          - Clear SVE if PENDING
 * @param ept_entry - Pointer to SEPT entry to be unblocked
 */
_STATIC_INLINE_ void sept_unblock(ia32e_sept_t* ept_entry)
{
    switch (ept_entry->raw & SEPT_STATE_ENCODING_MASK)
    {
        case SEPT_STATE_NL_BLOCKED_MASK:
            sept_update_state(ept_entry, SEPT_STATE_NL_MAPPED_MASK);
            ept_entry->raw |= SEPT_PERMISSIONS_RWX;
            ept_entry->mt = 0;   // MT bits are reserved for non-leaf entries
            break;
        case SEPT_STATE_BLOCKED_MASK:
            sept_update_state(ept_entry, SEPT_STATE_MAPPED_MASK);
            ept_entry->r = 1;
            ept_entry->w = 1;
            ept_entry->x = 1;
            ept_entry->mt = MT_WB;
            break;
        case SEPT_STATE_PEND_BLOCKED_MASK:
            sept_update_state(ept_entry, SEPT_STATE_PEND_MASK);
            // Permission bits remain all-0
            break;
        default:
            // The SEPT entry was not blocked, do nothing
            break;
    }
}

/**
 * @brief  Unblock the L2 Secure EPT entry
 *         If the SEPT entry was not blocked (L2_NL_BLOCKED, L2_BLOCKED), do nothing.
 *         Else:
 *          - Restore the state to L2_MAPPED (if leaf) or L2_NL_MAPPED (if non-leaf).
 *          - If leaf, restore RWXsXu
 *         Set TDRD, TDWR, TDXS and TDXU are set to their proper values:
 *         TDRD, TDXS and TDXU are part of MT, and TDWR is set to 0.
 *
 * @param ept_entry - Pointer to SEPT entry to be unblocked
 */
_STATIC_INLINE_ void sept_l2_unblock(ia32e_sept_t* ept_entry)
{
    ia32e_sept_t tmp_ept_entry = { .raw = ept_entry->raw };

    if (is_l2_sept_nl_blocked(&tmp_ept_entry))
    {
        sept_l2_update_state(&tmp_ept_entry, SEPT_STATE_L2_NL_MAPPED_MASK);
        tmp_ept_entry.raw |= SEPT_PERMISSIONS_RW_XS_XU;
        tmp_ept_entry.mt = 0;   // MT bits are reserved for non-leaf entries
        tmp_ept_entry.l2_encoding.tdwr = 0;

        atomic_mem_write_64b(&ept_entry->raw, tmp_ept_entry.raw);
    }
    else if (is_l2_sept_blocked(&tmp_ept_entry))
    {
        sept_l2_update_state(&tmp_ept_entry, SEPT_STATE_L2_MAPPED_MASK);
        tmp_ept_entry.l2_encoding.r  = tmp_ept_entry.l2_encoding.mt0_tdrd;
        tmp_ept_entry.l2_encoding.w  = tmp_ept_entry.l2_encoding.tdwr;
        tmp_ept_entry.l2_encoding.x  = tmp_ept_entry.l2_encoding.mt1_tdxs;
        tmp_ept_entry.l2_encoding.xu = tmp_ept_entry.l2_encoding.mt2_tdxu;
        tmp_ept_entry.mt = MT_WB;
        tmp_ept_entry.l2_encoding.tdwr = 0;

        atomic_mem_write_64b(&ept_entry->raw, tmp_ept_entry.raw);
    }

    // Else - The SEPT entry was not blocked, do nothing
}

_STATIC_INLINE_ pa_t sept_get_pa(const ia32e_sept_t *const sept_entry)
{
    pa_t sept_pa = {.raw = 0};
    sept_pa.page_4k_num = sept_entry->base;
    return sept_pa;
}

/**
 * @brief Sets arch SEPTE details in RCX and RDX registers of the VMM
 *
 * @param ept_entry - SEPT entry from which the arch state will be extracted
 * @param level - Level of the given SEPT entry
 * @param local_data_ptr - Local data pointer
 */
void set_arch_septe_details_in_vmm_regs(ia32e_sept_t sept_entry, ept_level_t level, tdx_module_local_t* local_data_ptr);

/**
 * @brief Sets arch L2 SEPTE details in RCX and RDX registers of the VMM
 *
 * @param l2_sept_entry - L2 SEPT entry from which the arch state will be extracted
 * @param vm_id - VM id to which the L2 SEPT entry belongs
 * @param is_debug - Taken from TDCS attributes
 * @param level - Level of the given L2 SEPT entry
 * @param local_data_ptr - Local data pointer
 */
void set_arch_l2_septe_details_in_vmm_regs(ia32e_sept_t l2_sept_entry, uint16_t vm_id, bool_t is_debug,
                                           uint64_t level, tdx_module_local_t* local_data_ptr);

typedef enum
{
    EPT_WALK_SUCCESS,
    EPT_WALK_VIOLATION,
    EPT_WALK_CONVERTIBLE_VIOLATION,
    EPT_WALK_MISCONFIGURATION
} ept_walk_result_t;

/**
 * @brief Private GPA-walk will walk over SEPT, and force assign private_hkid to each HPA at each level.
 *        Return a linear pointer to Secure-EPT entry corresponding to GPA and EPT level.
 *        EPT Misconfiguration during the walk will cause module halt (fatal error).
 *
 *
 * @param septp SEPT pointer that should be used in the walk
 * @param gpa Guest Physical Address that is translated
 * @param private_hkid HKID that can be assigned to HPA of each SEPT entry during the walk
 *
 * @param level Pointer to a level parameter that the walk should reach. On return contains the level
 *              that was actually reached in the walk.
 *
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 *               User should read the SEPT entry from the cached value only,
 *
 * @param l2_sept_guest_side_walk - In L2 SEPT guest-side walk, entry presence is checked
 *                                  by L2_FREE SEPT state, instead of regular RWX bits.
 *
 *
 * @return Linear pointer to last SEPT entry that was found during the walk.
 *         Always remember to free the linear pointer after the use.
 */
ia32e_sept_t* secure_ept_walk(ia32e_eptp_t septp, pa_t gpa, uint16_t private_hkid,
                              ept_level_t* level, ia32e_sept_t* cached_sept_entry,
                              bool_t l2_sept_guest_side_walk);

/**
 * @brief Generic function used for all (private and shared) GPA translations, imitating the
 *        functionality of hardware PMH.
 *
 * @param eptp EPT pointer that should be used in the walk
 * @param gpa Guest Physical Address that is translated
 * @param private_gpa Indicated if input GPA is private or shared
 * @param private_hkid Used only if GPA is private, will be assigned on each HPA during the walk
 * @param access_rights Access rights asked for the walk (Read, Write, Execute)
 *
 * @param hpa Pointer to a HPA parameter. On return contains the translated HPA. Valid only on success.
 *
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 *               User should read the EPT entry from the cached value only,
 *
 * @param accumulated_rwx Pointer to a rwx parameter that will be accumulated during the walk
 *                        by ANDing all the rwx values of all the levels.
 *
 * @return Status of the walk, either full success, EPT violation, EPT convertible violation or EPT misconfiguration.
 *
 */
ept_walk_result_t gpa_translate(ia32e_eptp_t eptp, pa_t gpa, bool_t private_gpa,
                                uint16_t private_hkid, access_rights_t access_rights,
                                pa_t* hpa, ia32e_ept_t* cached_ept_entry, access_rights_t* accumulated_rwx);

#endif /* SRC_COMMON_MEMORY_HANDLERS_SEPT_MANAGER_H_ */
