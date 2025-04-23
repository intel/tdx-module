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
 * @file helpers.c
 * @brief Common TDX API flow helper functions
 */

#include "helpers.h"
#include "x86_defs/mktme.h"
#include "x86_defs/vmcs_defs.h"
#include "tdx_api_defs.h"
#include "auto_gen/cpuid_configurations.h"
#include "auto_gen/msr_config_lookup.h"

#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/sept_manager.h"
#include "data_structures/td_vmcs_init.h"
#include "td_transitions/td_exit.h"
#include "td_dispatcher/tdx_td_dispatcher.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "virt_msr_helpers.h"

#if (!defined(__cplusplus))
void* memset(void *str, int c, uint32_t n)
{
    basic_memset((uint64_t)str, n, (uint8_t)c, n);

    return str;
}
#endif

api_error_code_e program_mktme_keys(uint16_t hkid)
{
	mktme_key_program_t mktme_key_program;
	api_error_code_e    return_val = UNINITIALIZE_ERROR;
	uint64_t            pconfig_return_code;

	basic_memset_to_zero(&mktme_key_program, sizeof(mktme_key_program_t));

	// set the command, hkid as keyid and encryption algorithm
	mktme_key_program.keyid_ctrl.command = MKTME_KEYID_SET_KEY_RANDOM;
    mktme_key_program.keyid = hkid;

    if (get_sysinfo_table()->mcheck_fields.tdx_without_integrity)
    {
        if (get_global_data()->plt_common_config.ia32_tme_activate.algs_aes_xts_256)
        {
            mktme_key_program.keyid_ctrl.enc_algo = AES_XTS_256;
        }
        else
        {
            mktme_key_program.keyid_ctrl.enc_algo = AES_XTS_128;
        }
    }
    else
    {
        if (get_global_data()->plt_common_config.ia32_tme_activate.algs_aes_xts_256_with_integrity)
        {
            mktme_key_program.keyid_ctrl.enc_algo = AES_XTS_256_WITH_INTEGRITY;
        }
        else
        {
            mktme_key_program.keyid_ctrl.enc_algo = AES_XTS_128_WITH_INTEGRITY;
        }
    }

	// Execute the PCONFIG instruction with the updated struct and return
	pconfig_return_code = ia32_mktme_key_program(&mktme_key_program);

    if (pconfig_return_code != MKTME_PROG_SUCCESS)
    {
        TDX_ERROR("pconfig_return_code = %llx\n", pconfig_return_code);
        if (pconfig_return_code == MKTME_DEVICE_BUSY)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_KET);
            TDX_ERROR("Failed to program an MKTME key due to lock on KET\n");
            goto EXIT;
        }
        else if (pconfig_return_code == MKTME_ENTROPY_ERROR)
        {
            return_val = TDX_KEY_GENERATION_FAILED;
            TDX_ERROR("Failed to generate a key for the MKTME engine\n");
            goto EXIT;
        }
        else
        {
            // unexpected - FATAL ERROR
            FATAL_ERROR();
        }
    }

    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}

void basic_memset(uint64_t dst, uint64_t dst_bytes, uint8_t val, uint64_t nbytes)
{
    tdx_sanity_check (dst_bytes >= nbytes, SCEC_HELPERS_SOURCE, 2);

    volatile uint64_t junk;

    _ASM_VOLATILE_ ("cld\n"
                    "rep; stosb;"
                    :"=D"(junk) // marking that RDI is changing
                    :"c"(nbytes), "a"(val), "D"(dst)
                    :"memory", "cc");
}

void basic_memset_to_zero(void * dst, uint64_t nbytes)
{
    basic_memset((uint64_t)dst, nbytes, 0, nbytes);
}

void cache_aligned_copy_direct(uint64_t src, uint64_t dst, uint64_t size)
{
    uint64_t i = 0;

    tdx_debug_assert(!((src % MOVDIR64_CHUNK_SIZE) || (dst % MOVDIR64_CHUNK_SIZE) ||
                       (size % MOVDIR64_CHUNK_SIZE)));

    //To convert from size in bytes to cacheline steps (64bytes), shift by 6:
    //1 << 6 = 64;  64 >> 6 = 1
    for (i = 0; i < (size >> 6 ); i++)
    {
        movdir64b((void *)(src + (i << 6)), dst + (i << 6));
    }
    mfence();
}

api_error_code_e non_shared_hpa_metadata_check_and_lock(
        pa_t hpa,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        page_size_t*   leaf_size,
        bool_t walk_to_leaf_size,
        bool_t is_guest
        )
{
    // 1) Check that the operand’s HPA is within a TDMR (Trust Domain Memory Range) which is covered by a PAMT.
    if (!pamt_get_block(hpa, pamt_block))
    {
        TDX_ERROR("pamt_get_block error hpa = 0x%llx\n", hpa.raw);
        return TDX_OPERAND_ADDR_RANGE_ERROR;
    }

    pamt_entry_t* pamt_entry_lp;
    page_size_t requested_leaf_size = *leaf_size;

    // 2) Find the PAMT entry for the page and verify that its metadata is as expected.
    api_error_code_e errc = pamt_walk(hpa, *pamt_block, lock_type, leaf_size,
                                      walk_to_leaf_size, is_guest, &pamt_entry_lp);

    if (errc != TDX_SUCCESS)
    {
        TDX_ERROR("pamt_walk error\n");
        return errc;
    }

    if (walk_to_leaf_size && (requested_leaf_size != *leaf_size))
    {
        TDX_ERROR("PAMT entry level = %d , Expected level = %d\n", *leaf_size, requested_leaf_size);
        pamt_unwalk(hpa, *pamt_block, pamt_entry_lp, lock_type, *leaf_size);
        return TDX_PAGE_METADATA_INCORRECT;
    }

    if (pamt_entry_lp->pt != expected_pt)
    {
        TDX_ERROR("pamt_entry_lp->pt = %d , expected_pt = %d\n", pamt_entry_lp->pt, expected_pt);
        pamt_unwalk(hpa, *pamt_block, pamt_entry_lp, lock_type, *leaf_size);
        return TDX_PAGE_METADATA_INCORRECT;
    }

    *pamt_entry = pamt_entry_lp;

    return TDX_SUCCESS;
}

pa_t assign_hkid_to_hpa(tdr_t* tdr_p, pa_t hpa)
{
    uint16_t hkid;

    // 1) If the target page is TDR (given TDR pointer is NULL), then use the TDX-SEAM global private HKID.

    if (tdr_p == NULL)
    {
        hkid = get_global_data()->hkid;
    }
    // 2) Else, read the HKID value associated with the TD from the TDR page.
    else
    {
        hkid = tdr_p->key_management_fields.hkid;
    }

    return set_hkid_to_pa(hpa, hkid);
}

api_error_code_e shared_hpa_check(pa_t hpa, uint64_t size)
{
    // 1) Check that no bits above MAX_PA are set

    if (!is_pa_smaller_than_max_pa(hpa.raw))
    {
        return TDX_OPERAND_INVALID;
    }

    // 2) Check that the provided HPA is outside SEAMRR.

    uint64_t seamrr_base = get_global_data()->seamrr_base;
    uint64_t seamrr_size = get_global_data()->seamrr_size;

    // SEAMRR and HPA+page ranges are not expected cause integer overflow
    // SEAMRR base and size are both 32 bits,
    // HPA is checked to be smaller than MAX_PA in above check
    // If there's still somehow an unexpected overflow, ot will be caught by the check inside is_overlap()
    if (is_overlap(get_addr_from_pa(hpa), size, seamrr_base, seamrr_size))
    {
        return TDX_OPERAND_INVALID;
    }

    // 3) Check that HKID bits in the HPA are in the range configured for shared HKIDs (0 to MAX_MKTME_HKIDS – 1).

    if ((uint64_t)get_hkid_from_pa(hpa) >= get_global_data()->private_hkid_min)
    {
        return TDX_OPERAND_INVALID;
    }

    return TDX_SUCCESS;
}

api_error_code_e shared_hpa_check_with_pwr_2_alignment(pa_t hpa, uint64_t size)
{
    if (!is_addr_aligned_pwr_of_2(hpa.raw, size))
    {
        return TDX_OPERAND_INVALID;
    }

    return shared_hpa_check(hpa, size);
}

api_error_code_e hpa_check_with_pwr_2_alignment(pa_t hpa, uint64_t size)
{
    // 1) Check  page alignment
    if (!is_addr_aligned_pwr_of_2(hpa.raw, size))
    {
        return TDX_OPERAND_INVALID;
    }

    // 2) Check that No HKID bits are set
    if (get_hkid_from_pa(hpa) != 0)
    {
        return TDX_OPERAND_INVALID;
    }

    // 3) Check that no bits above MAX_PA are set
    if (!is_pa_smaller_than_max_pa(hpa.raw))
    {
        return TDX_OPERAND_INVALID;
    }

    return TDX_SUCCESS;
}

api_error_type check_lock_and_map_explicit_private_4k_hpa(
        pa_t hpa,
        uint64_t operand_id,
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked,
        void**         la
        )
{
    api_error_type errc;

    errc = check_and_lock_explicit_4k_private_hpa( hpa, operand_id,
             lock_type, expected_pt, pamt_block, pamt_entry, is_locked);
    if (errc != TDX_SUCCESS)
    {
        return errc;
    }

    pa_t hpa_with_hkid = assign_hkid_to_hpa(tdr_p, hpa);

    *la = map_pa((void*)hpa_with_hkid.full_pa, mapping_type);

    return TDX_SUCCESS;
}

api_error_type check_lock_and_map_explicit_tdr(
        pa_t tdr_hpa,
        uint64_t operand_id,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked,
        tdr_t** tdr_p
        )
{
    return check_lock_and_map_explicit_private_4k_hpa(tdr_hpa, operand_id, NULL, mapping_type,
            lock_type, expected_pt, pamt_block, pamt_entry, is_locked, (void**)tdr_p);
}

api_error_type othertd_check_lock_and_map_explicit_tdr(
        pa_t tdr_hpa,
        uint64_t operand_id,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked,
        tdr_t** tdr_p
        )
{
    api_error_type errc;
    page_size_t leaf_size = PT_4KB;

    errc = hpa_check_with_pwr_2_alignment(tdr_hpa, _4KB);
    if (errc != TDX_SUCCESS)
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
    }

    errc = non_shared_hpa_metadata_check_and_lock(tdr_hpa, lock_type,
            expected_pt, pamt_block, pamt_entry, &leaf_size, true, true);

    if (errc != TDX_SUCCESS)
    {
        return api_error_with_operand_id(errc, operand_id);
    }

    *is_locked = true;

    pa_t hpa_with_hkid = assign_hkid_to_hpa(NULL, tdr_hpa);

    *tdr_p = map_pa((void*)hpa_with_hkid.full_pa, mapping_type);

    return TDX_SUCCESS;
}

api_error_type check_and_lock_explicit_private_hpa(
        pa_t hpa,
        uint64_t operand_id,
        uint64_t alignment,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        page_size_t* leaf_size,
        bool_t walk_to_leaf_size,
        bool_t* is_locked
        )
{
    api_error_code_e errc;

    errc = hpa_check_with_pwr_2_alignment(hpa, alignment);
    if (errc != TDX_SUCCESS)
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
    }

    errc = non_shared_hpa_metadata_check_and_lock(hpa, lock_type,
            expected_pt, pamt_block, pamt_entry, leaf_size, walk_to_leaf_size, false);

    if (errc != TDX_SUCCESS)
    {
        return api_error_with_operand_id(errc, operand_id);
    }

    *is_locked = true;

    return TDX_SUCCESS;
}


api_error_type check_and_lock_explicit_4k_private_hpa(
        pa_t hpa,
        uint64_t operand_id,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked
        )
{
    api_error_type errc;

    page_size_t leaf_size = PT_4KB;

    errc = check_and_lock_explicit_private_hpa(hpa, operand_id, _4KB, lock_type,
              expected_pt, pamt_block, pamt_entry, &leaf_size, true, is_locked);

    if (errc != TDX_SUCCESS)
    {
        return errc;
    }

    return TDX_SUCCESS;
}

api_error_type check_and_lock_free_range_hpa(
        pa_t hpa,
        uint64_t operand_id,
        lock_type_t lock_type,
        page_size_t range_size,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked
        )
{
    tdx_debug_assert(range_size != PT_1GB);
    tdx_debug_assert(lock_type == TDX_LOCK_EXCLUSIVE);

    api_error_type errc;
    page_size_t pamt_level = range_size;
    uint64_t alignment = (range_size == PT_2MB) ? _2MB : _4KB;

    errc = check_and_lock_explicit_private_hpa(hpa, operand_id, alignment, lock_type, PT_NDA,
                                               pamt_block, pamt_entry, &pamt_level, true, is_locked);

    if (errc != TDX_SUCCESS)
    {
        return errc;
    }

    // Verify 2MB HPA range is entirely free.
    if ((range_size == PT_2MB) && !pamt_is_2mb_range_free(hpa, pamt_block))
    {
        TDX_ERROR("PAMT level (%d) is not as expected (%d) or the 2MB range isn't free\n", pamt_level, range_size);
        pamt_unwalk(hpa, *pamt_block, *pamt_entry, lock_type, pamt_level);
        *is_locked = false;
        return api_error_with_operand_id(TDX_PAGE_METADATA_INCORRECT, operand_id);
    }

    return TDX_SUCCESS;
}


api_error_type lock_and_map_implicit_tdr(
        pa_t tdr_pa,
        uint64_t operand_id,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked,
        tdr_t** tdr_p
        )
{
    api_error_code_e errc = pamt_implicit_get_and_lock(tdr_pa, PT_4KB, lock_type, pamt_entry);

    if (errc != TDX_SUCCESS)
    {
        TDX_ERROR("get_implicit_page_pamt_and_lock error\n");
        return api_error_with_operand_id(errc, operand_id);
    }

    *is_locked = true;

    uint16_t hkid = get_global_data()->hkid;
    tdr_pa = set_hkid_to_pa(tdr_pa, hkid);

    uint64_t tdr_addr = tdr_pa.full_pa;

    *tdr_p = map_continuous_pages(&tdr_addr, 1, mapping_type, STATIC_KEYHOLE_IDX_TDR);

    return TDX_SUCCESS;
}

tdcs_t* map_implicit_tdcs(
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        bool_t other_td
        )
{
    return map_continuous_pages(tdr_p->management_fields.tdcx_pa, (uint16_t)tdr_p->management_fields.num_tdcx,
                                mapping_type,
                                other_td ? STATIC_KEYHOLE_IDX_OTHERTD_TDCS : STATIC_KEYHOLE_IDX_TDCS);
}

static api_error_type check_td_in_correct_build_state(tdr_t *tdr_p)
{
    if (tdr_p->management_fields.fatal)
    {
        TDX_ERROR("TD is in fatal state\n");
        return api_error_fatal(TDX_TD_FATAL);
    }

    if (tdr_p->management_fields.lifecycle_state != TD_KEYS_CONFIGURED)
    {
        TDX_ERROR("TD key are not configured\n");
        return TDX_TD_KEYS_NOT_CONFIGURED;
    }

    if (tdr_p->management_fields.num_tdcx < MIN_NUM_TDCS_PAGES)
    {
        TDX_ERROR("TDCS minimal num of pages %d is not allocated\n", MIN_NUM_TDCS_PAGES);
        return TDX_TDCS_NOT_ALLOCATED;
    }

    return TDX_SUCCESS;
}

static api_error_type check_any_td_state_map_tdcs_and_lock(
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        lock_type_t op_state_lock_type,
        bool_t map_migsc_links,
        uint32_t current_leaf,
        bool_t other_td,
        bool_t guest_side_flow,
        tdcs_t** tdcs_p
        )
{
    UNUSED(map_migsc_links);
    api_error_code_e errc = UNINITIALIZE_ERROR;

    *tdcs_p = NULL;

    errc = check_td_in_correct_build_state(tdr_p);

    if (errc != TDX_SUCCESS)
    {
        TDX_ERROR("TD is in incorrect build state\n");
        return errc;
    }

    // Map the TDCS structure and check the state
    tdcs_t* tmp_tdcs_p = map_implicit_tdcs(tdr_p, mapping_type, other_td);

    if (op_state_lock_type != TDX_LOCK_NO_LOCK)
    {
        if ((errc = acquire_sharex_lock_hp(&(tmp_tdcs_p->management_fields.op_state_lock),
                                     op_state_lock_type, guest_side_flow)) != TDX_SUCCESS)
        {
            free_la(tmp_tdcs_p);
            TDX_ERROR("Could not lock TDCS OP state lock\n");
            return api_error_with_operand_id(errc, OPERAND_ID_OP_STATE);
        }
    }

    bool_t is_allowed = false;

    IF_COMMON (!guest_side_flow)
    {
        seamcall_leaf_opcode_t seamcall_leaf = (seamcall_leaf_opcode_t)current_leaf;
        is_allowed = op_state_is_seamcall_allowed(seamcall_leaf, tmp_tdcs_p->management_fields.op_state, other_td);
    }
    else
    {
        tdcall_leaf_opcode_t tdcall_leaf = (tdcall_leaf_opcode_t)current_leaf;
        is_allowed = op_state_is_tdcall_allowed(tdcall_leaf, tmp_tdcs_p->management_fields.op_state, other_td);
    }

    if (!is_allowed)
    {
        if (op_state_lock_type != TDX_LOCK_NO_LOCK)
        {
            release_sharex_lock_hp(&(tmp_tdcs_p->management_fields.op_state_lock), op_state_lock_type);
        }
        free_la(tmp_tdcs_p);
        TDX_ERROR("TDCS OP state is not allowed on this SEAMCALL leaf\n");
        return TDX_OP_STATE_INCORRECT;
    }

    *tdcs_p = tmp_tdcs_p;

    return TDX_SUCCESS;
}

api_error_type check_state_map_tdcs_and_lock(
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        lock_type_t op_state_lock_type,
        bool_t map_migsc_links,
        seamcall_leaf_opcode_t current_leaf,
        tdcs_t** tdcs_p
        )
{
    return check_any_td_state_map_tdcs_and_lock(tdr_p, mapping_type, op_state_lock_type,
                                                map_migsc_links, (uint32_t)current_leaf, false, false, tdcs_p);
}

api_error_type othertd_check_state_map_tdcs_and_lock(
        tdr_t* tdr_p,
        mapping_type_t mapping_type,
        lock_type_t op_state_lock_type,
        bool_t map_migsc_links,
        uint32_t current_leaf,
        bool_t guest_side_flow,
        tdcs_t** tdcs_p
        )
{
    return check_any_td_state_map_tdcs_and_lock(tdr_p, mapping_type, op_state_lock_type,
                                                map_migsc_links, current_leaf, true, guest_side_flow, tdcs_p);
}

tdvps_t* map_tdvps(
        pa_t tdvpr_pa,
        uint16_t hkid,
        uint16_t num_l2_vms,
        mapping_type_t mapping_type
        )
{
    tdvpr_pa.raw = set_hkid_to_pa(tdvpr_pa, hkid).raw;
    tdvps_t* tdvpr_lp = map_continuous_pages(&tdvpr_pa.raw, 1, mapping_type, STATIC_KEYHOLE_IDX_TDVPS);

    if ((uint32_t)tdvpr_lp->management.num_tdvps_pages < (uint32_t)(MIN_TDVPS_PAGES + (num_l2_vms * TDVPS_PAGES_PER_L2_VM)))
    {
        TDX_ERROR("Num of TDCX pages (%d) is incorrect\n", tdvpr_lp->management.num_tdvps_pages);
        free_la(tdvpr_lp);
        return NULL;
    }

    uint16_t num_of_tdvps_pages = MIN_TDVPS_PAGES + (TDVPS_PAGES_PER_L2_VM * num_l2_vms);

    // First TDVX PA is actually the PA of the TDVPR itself, since we already mapped it, it can be skipped
    (void)map_continuous_pages(&tdvpr_lp->management.tdvps_pa[1], num_of_tdvps_pages - 1, mapping_type,
                         STATIC_KEYHOLE_IDX_TDVPS + 1);

    return tdvpr_lp;
}

bool_t check_gpa_validity(pa_t gpa, bool_t gpaw, bool_t check_is_private, uint8_t virt_maxpa)
{
    uint16_t gpa_width = gpaw ? 52 : 48;
    bool_t gpa_shared_bit = get_gpa_shared_bit(gpa.raw, gpaw);

    if (check_is_private && (gpa_shared_bit == true))
    {
        return false;
    }

    if (0 == virt_maxpa)
    {
        virt_maxpa = MAX_PA;
    }
    
    uint16_t min_gpa_width = (virt_maxpa < gpa_width) ? virt_maxpa : gpa_width;

    // Create a mask with bits above min GPA width set, and shared bit removed
    uint64_t mask_to_check = BITS(63, min_gpa_width) & ~BIT(gpa_width - 1);

    // Bits higher then MAX_PA except shared bit must be zero (bits above SHARED bit must be zero)
    if ((gpa.raw & mask_to_check) != 0)
    {
        return false;
    }

    return true;
}

bool_t verify_page_info_input(page_info_api_input_t gpa_page_info, ept_level_t min_level, ept_level_t max_level)
{
    // Verify that GPA mapping input reserved fields equal zero
    if (!is_reserved_zero_in_mappings(gpa_page_info))
    {
        TDX_ERROR("Reserved fields in GPA mappings are not zero\n");
        return false;
    }

    // Verify mapping level input is valid
    if (!((gpa_page_info.level >= min_level) && (gpa_page_info.level <= max_level)))
    {
        TDX_ERROR("Input GPA level (=%d) is not valid\n", gpa_page_info.level);
        return false;
    }

    // Check the page GPA is page aligned
    if (!is_gpa_aligned(gpa_page_info))
    {
        TDX_ERROR("Page GPA 0x%llx is not page aligned\n", gpa_page_info.raw);
        return false;
    }

    return true;
}

typedef enum sept_walk_type_e
{
    SEPT_WALK_TO_LEVEL,
    SEPT_WALK_TO_LEAF,
    SEPT_WALK_TO_LEAF_LEVEL
} sept_walk_type_t;

static api_error_type lock_sept_check_and_walk_internal(
        tdcs_t* tdcs_p,
        uint64_t operand_id,
        pa_t gpa,
        uint16_t hkid,
        lock_type_t lock_type,
        bool_t check_validity,
        sept_walk_type_t walk_type,
        ia32e_sept_t** sept_entry_ptr,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry,
        bool_t* is_sept_locked
        )
{
    bool_t gpaw = tdcs_p->executions_ctl_fields.gpaw;

    *is_sept_locked = false;

    if (check_validity && !check_gpa_validity(gpa, gpaw, PRIVATE_ONLY, tdcs_p->executions_ctl_fields.virt_maxpa))
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
    }

    ia32e_eptp_t septp = tdcs_p->executions_ctl_fields.eptp;

    if (lock_type != TDX_LOCK_NO_LOCK)
    {
        if (acquire_sharex_lock(&tdcs_p->executions_ctl_fields.secure_ept_lock, lock_type) != LOCK_RET_SUCCESS)
        {
            return api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT_TREE);
        }
    }

    ept_level_t requested_level = *level;
    *sept_entry_ptr = secure_ept_walk(septp, gpa, hkid, level, cached_sept_entry, false);

    if (// When we walk to leaf we check that the final entry is a valid, existing leaf
        ((walk_type == SEPT_WALK_TO_LEAF) &&
        (!is_secure_ept_leaf_entry(cached_sept_entry) || !cached_sept_entry->rwx)) ||
        // When we walk to level, we just check that we reached requested level
        ((walk_type == SEPT_WALK_TO_LEVEL) && (*level != requested_level)) ||
        // When we walk to leaf-level, check that we reached an actual leaf
        ((walk_type == SEPT_WALK_TO_LEAF_LEVEL) && !is_secure_ept_leaf_entry(cached_sept_entry))
       )
    {
        if (lock_type != TDX_LOCK_NO_LOCK)
        {
            release_sharex_lock(&tdcs_p->executions_ctl_fields.secure_ept_lock, lock_type);
        }

        free_la(*sept_entry_ptr);
        *sept_entry_ptr = NULL;
        return api_error_with_operand_id(TDX_EPT_WALK_FAILED, operand_id);
    }

    if (lock_type != TDX_LOCK_NO_LOCK)
    {
        *is_sept_locked = true;
    }

    return TDX_SUCCESS;
}

api_error_type lock_sept_check_and_walk_private_gpa(
        tdcs_t* tdcs_p,
        uint64_t operand_id,
        pa_t gpa,
        uint16_t hkid,
        lock_type_t lock_type,
        ia32e_sept_t** sept_entry_ptr,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry,
        bool_t* is_sept_locked
        )
{
    tdx_debug_assert(lock_type != TDX_LOCK_NO_LOCK);

    return lock_sept_check_and_walk_internal(tdcs_p, operand_id, gpa, hkid,
                                             lock_type,          // Lock the SEPT tree
                                             true,               // Check private GPA validity
                                             SEPT_WALK_TO_LEVEL, // Walk to requested level
                                             sept_entry_ptr, level, cached_sept_entry, is_sept_locked);
}

api_error_type check_and_walk_private_gpa_to_leaf(
        tdcs_t* tdcs_p,
        uint64_t operand_id,
        pa_t gpa,
        uint16_t hkid,
        ia32e_sept_t** sept_entry_ptr,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry
        )
{
    bool_t is_sept_locked;
    *level = LVL_PT;

    // Don't lock SEPT, heck private GPA validity and walk to any leaf
    return lock_sept_check_and_walk_internal(tdcs_p, operand_id, gpa, hkid,
                                             TDX_LOCK_NO_LOCK,  // Do not lock SEPT tree
                                             true,              // Check private GPA validity
                                             SEPT_WALK_TO_LEAF, // Walk to any leaf
                                             sept_entry_ptr, level, cached_sept_entry, &is_sept_locked);
}

api_error_type walk_private_gpa(
        tdcs_t* tdcs_p,
        pa_t gpa,
        uint16_t hkid,
        ia32e_sept_t** sept_entry_ptr,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry
        )
{
    bool_t is_sept_locked;

    // Do not check private GPA validity and walk to requested level
    return lock_sept_check_and_walk_internal(tdcs_p, 0, gpa, hkid,
                                             TDX_LOCK_NO_LOCK,   // Do not lock SEPT tree
                                             false,              // Do not check private GPA validity
                                             SEPT_WALK_TO_LEVEL, // Walk to requested level
                                             sept_entry_ptr, level, cached_sept_entry, &is_sept_locked);
}

static void inject_ve_and_return_to_td(tdvps_t* tdvps_p, pa_t gpa, vmx_exit_qualification_t exit_qual)
{
    tdx_inject_ve(VMEXIT_REASON_EPT_VIOLATION, exit_qual.raw, tdvps_p, gpa.raw, 0);
    bus_lock_exit();
    check_pending_voe_on_debug_td_return();
    tdx_return_to_td(true, false, &tdvps_p->guest_state.gpr_state);
}

api_error_code_e check_walk_and_map_guest_side_gpa(
        tdcs_t* tdcs_p,
        tdvps_t* tdvps_p,
        pa_t gpa,
        uint16_t hkid,
        mapping_type_t mapping_type,
        bool_t check_gpa_is_private,
        void ** la
        )
{
    ia32e_eptp_t eptp;
    ia32e_ept_t ept_entry_copy = {.raw = 0};
    ept_walk_result_t walk_result;
    access_rights_t accumulated_rwx;

    bool_t gpaw = tdcs_p->executions_ctl_fields.gpaw;
    vmx_exit_qualification_t exit_qual;

    pa_t page_hpa;

    bool_t shared_bit = get_gpa_shared_bit(gpa.raw, gpaw);

    access_rights_t access_rights = { .raw = 0 };

    access_rights.r = 1;
    access_rights.w = (mapping_type == TDX_RANGE_RW) ? 1 : 0;
    access_rights.x = (uint8_t)0;

    exit_qual.raw = (uint64_t)access_rights.raw;

    if (!check_gpa_validity(gpa, gpaw, check_gpa_is_private, tdcs_p->executions_ctl_fields.virt_maxpa))
    {
        return TDX_OPERAND_INVALID;
    }

    if (shared_bit)
    {
        // read the shared EPT from the TD VMCS
        ia32_vmread(VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE, &eptp.raw);
        eptp.fields.enable_ad_bits = tdcs_p->executions_ctl_fields.eptp.fields.enable_ad_bits;
        eptp.fields.enable_sss_control = tdcs_p->executions_ctl_fields.eptp.fields.enable_sss_control;
        eptp.fields.ept_ps_mt = tdcs_p->executions_ctl_fields.eptp.fields.ept_ps_mt;
        eptp.fields.ept_pwl = tdcs_p->executions_ctl_fields.eptp.fields.ept_pwl;
    }
    else
    {
        eptp.raw = tdcs_p->executions_ctl_fields.eptp.raw;
    }

    walk_result = gpa_translate(eptp, gpa, !shared_bit, hkid, access_rights,
                                &page_hpa, &ept_entry_copy, &accumulated_rwx);

    exit_qual.ept_violation.data_read      = access_rights.r & ~accumulated_rwx.r;
    exit_qual.ept_violation.data_write     = access_rights.w & ~accumulated_rwx.w;
    exit_qual.ept_violation.insn_fetch     = access_rights.x & ~accumulated_rwx.x;
    exit_qual.ept_violation.gpa_readable   = accumulated_rwx.r;
    exit_qual.ept_violation.gpa_writeable  = accumulated_rwx.w;
    exit_qual.ept_violation.gpa_executable = accumulated_rwx.x;

    vmx_ext_exit_qual_t ext_exit_qual = { .raw = 0 };
    vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };
    vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;

    IF_RARE (!shared_bit && (walk_result != EPT_WALK_SUCCESS))
    {
        ia32e_sept_t sept_copy = { .raw = ept_entry_copy.raw };

        if (sept_state_is_any_pending_and_guest_acceptable(sept_copy))
        {
            // This is a pending page waiting for acceptable by the TD
            if (tdcs_p->executions_ctl_fields.td_ctls.pending_ve_disable)
            {
                // The TD is configured to TD exit on access to a PENDING page
                ext_exit_qual.type = VMX_EEQ_PENDING_EPT_VIOLATION;
                tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qual.raw, ext_exit_qual.raw);
            }
            else
            {
                // The TD is configured to throw a #VE on access to a PENDING page
                inject_ve_and_return_to_td(tdvps_p, gpa, exit_qual);
            }
        }
        else
        {
            // This is not a PENDING page, do an EPT Violation TD exit
            tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qual.raw, 0);
        }
    }

    IF_RARE (walk_result == EPT_WALK_MISCONFIGURATION)
    {
        tdx_ept_misconfig_exit_to_vmm(gpa);
    }
    else IF_RARE (walk_result == EPT_WALK_VIOLATION)
    {
        tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qual.raw, ext_exit_qual.raw);
    }
    else IF_RARE (walk_result == EPT_WALK_CONVERTIBLE_VIOLATION)
    {
        inject_ve_and_return_to_td(tdvps_p, gpa, exit_qual);
    }

    // Else - success

    if (shared_bit)
    {
        if (ept_entry_copy.fields_4k.mt != MT_WB)
        {
            *la = map_pa_non_wb(page_hpa.raw_void, mapping_type);
        }
        else
        {
            *la = map_pa(page_hpa.raw_void, mapping_type);
        }
    }
    else
    {
        *la = map_pa_with_hkid(page_hpa.raw_void, hkid, mapping_type);
    }

    return TDX_SUCCESS;
}

api_error_code_e associate_vcpu(tdvps_t * tdvps_ptr,
                                tdcs_t * tdcs_ptr,
                                bool_t* new_association)
{
    uint32_t         prev_assoc_lpid;  // Previous associated LPID
    uint32_t         curr_lp_id = get_local_data()->lp_info.lp_id;

    /**
     *  Atomically check that this VCPU is not associated with any LP, and
     *  associate it with the current LP.  The VCPU may already be associated
     *  with the current LP, but if it's associated with another LP this is
     *  an error.
     */
    prev_assoc_lpid = _lock_cmpxchg_32b(VCPU_NO_LP, // Expected value: no lp
                                        curr_lp_id,  // New Value
                                        &tdvps_ptr->management.assoc_lpid); // Target
    if ((prev_assoc_lpid != VCPU_NO_LP) && (prev_assoc_lpid != curr_lp_id))
    {
        return TDX_VCPU_ASSOCIATED;
    }

    // Association succeeded.  VCPU state must be VCPU_READY_*

    // Set ACTIVE_VMCS to -1 to indicate the need for VMPTRLD
    get_local_data()->vp_ctx.active_vmcs = ACTIVE_VMCS_NONE;

    uint64_t seamdb_index = get_global_data()->seamdb_index;
    if (tdvps_ptr->management.last_seamdb_index != seamdb_index)
    {
        // The TDX module has been updated since the last time this VCPU was associated.
        // The VCPU remains associated with the current LP.
        clear_module_host_state_flags(tdvps_ptr);
        clear_lp_host_state_flags(tdvps_ptr);
        tdvps_ptr->management.last_seamdb_index = seamdb_index;
    }

    // If this is a new association, update TD VMCS
    if (prev_assoc_lpid == VCPU_NO_LP)
    {
        // The current VCPU is associated with a new LP

        clear_lp_host_state_flags(tdvps_ptr);

        // Atomically increment the number of associated VCPUs
        (void)_lock_xadd_32b(&(tdcs_ptr->management_fields.num_assoc_vcpus), 1);

        *new_association = true;
    }
    else
    {
        *new_association = false;
    }

    return TDX_SUCCESS;
}

api_error_code_e check_and_associate_vcpu(tdvps_t * tdvps_ptr,
                                          tdcs_t * tdcs_ptr,
                                          bool_t* new_association,
                                          bool_t allow_disabled)
{
    uint8_t curr_vcpu_state = tdvps_ptr->management.state;

    /**
     *  Check the VCPU state to make sure it has been initialized and is not
     *  being torn down.  This may race with state changes if the VCPU is
     *  associated with another LP.  In this case the subsequent association
     *  below will fail
     */
    if (!((curr_vcpu_state == VCPU_READY) ||
          ((curr_vcpu_state == VCPU_DISABLED) && allow_disabled)))
    {
        return TDX_VCPU_STATE_INCORRECT;
    }

    return associate_vcpu(tdvps_ptr, tdcs_ptr, new_association);
}

void associate_vcpu_initial(tdvps_t * tdvps_ptr,
                            tdcs_t * tdcs_ptr)
{
    uint32_t         curr_lp_id = get_local_data()->lp_info.lp_id;

    tdvps_ptr->management.last_seamdb_index = get_global_data()->seamdb_index;

    tdvps_ptr->management.assoc_lpid = curr_lp_id;

    // Set ACTIVE_VMCS to -1 to indicate the need for VMPTRLD
    get_local_data()->vp_ctx.active_vmcs = ACTIVE_VMCS_NONE;

    clear_module_host_state_flags(tdvps_ptr);
    clear_lp_host_state_flags(tdvps_ptr);

    // Atomically increment the number of associated VCPUs
    (void)_lock_xadd_32b(&(tdcs_ptr->management_fields.num_assoc_vcpus), 1);
}

void init_tdvps_fields(tdcs_t * tdcs_ptr, tdvps_t * tdvps_ptr)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    tdvps_ptr->management.shadow_pid_hpa = NULL_PA;
    tdvps_ptr->management.shadow_pinbased_exec_ctls = tdx_global_data_ptr->td_vmcs_values.pinbased_ctls;
    tdvps_ptr->management.shadow_posted_int_notification_vector = POSTED_INTERRUPT_NOTFICATION_VECTOR_INIT;
    tdvps_ptr->management.shadow_procbased_exec_ctls2[0] = tdx_global_data_ptr->td_vmcs_values.procbased_ctls2;
    for(uint32_t indx = 0; indx <= tdcs_ptr->management_fields.num_l2_vms ; indx++)
    {
        if (indx > 0)
        {
            tdvps_ptr->management.shadow_procbased_exec_ctls2[indx] = tdx_global_data_ptr->l2_vmcs_values.procbased_ctls2; 
        }
        tdvps_ptr->management.shadow_shared_eptp[indx] = NULL_PA;
        tdvps_ptr->management.l2_enter_guest_state_gpa[indx] = NULL_PA;
        tdvps_ptr->management.l2_enter_guest_state_hpa[indx] = NULL_PA;
        tdvps_ptr->management.l2_vapic_gpa[indx] = NULL_PA;
        tdvps_ptr->management.l2_vapic_hpa[indx] = NULL_PA;
        tdvps_ptr->management.tsc_deadline[indx] = ~(0ULL);
    }

    // Base L2 CR0 Guest-Host mask:
    // The following bits are set to 1, indicating they are owned by the Intel TDX module:
    // NE (5), NW (29), CD (30)
    // Any bit set to 1 in IA32_VMX_CR0_FIXED0 except for PE (0) and PG(31) which are set to 0
    // Any bit set to 0 in IA32_VMX_CR0_FIXED1
    // Bits known to the Intel TDX module as reserved (bits 63-32, 28-19, 17 and 15-6)
    // All other bits are cleared to 0, indicating they are owned by the guest TD.
    uint64_t bitmap = 0;
    uint64_t ia32_vmx_cr0_fixed0 = get_global_data()->plt_common_config.ia32_vmx_cr0_fixed0.raw;
    uint64_t ia32_vmx_cr0_fixed1 = get_global_data()->plt_common_config.ia32_vmx_cr0_fixed1.raw;

    bitmap = (ia32_vmx_cr0_fixed0 | (~ia32_vmx_cr0_fixed1)) & (~BIT(31)) & (~BIT(0));
    bitmap = bitmap | BIT(5) | BIT(29) | BIT(30) |
             BITS(63,32) | BITS(28,19) | BIT(17) | BITS(15,6);

    tdvps_ptr->management.base_l2_cr0_guest_host_mask = bitmap;

    // Base L2 CR0 Read shadow
    // The following bits are set to 1:
    // NE (5)
    // Any bit set to 1 in IA32_VMX_CR0_FIXED0 except for PE (0) and PG(31) which are set to 0
    // All other bits are cleared to 0.
    bitmap = ia32_vmx_cr0_fixed0 & (~BIT(31)) & (~BIT(0));
    bitmap = bitmap | BIT(5);

    tdvps_ptr->management.base_l2_cr0_read_shadow = bitmap;

    // BASE_L2_CR4_GUEST_HOST_MASK = ~calc_base_l2_cr4_write_mask()
    tdvps_ptr->management.base_l2_cr4_guest_host_mask = ~(calc_base_l2_cr4_write_mask(tdcs_ptr).raw);

    uint64_t ia32_vmx_cr4_fixed0 = get_global_data()->plt_common_config.ia32_vmx_cr4_fixed0.raw;

    // Base L2 CR4 Read shadow
    // Bit MCE (6) is set to 1.
    // Bit VMXE (13) is set to 1.
    // Any other bit whose value is set to 1 in IA32_VMX_CR4_FIXED0
    // All other bits are cleared to 0.
    bitmap = (ia32_vmx_cr4_fixed0 | BIT(6) | BIT(13));

    tdvps_ptr->management.base_l2_cr4_read_shadow = bitmap;

    // Initial value of IA32_SPEC_CTRL can be calculated by calculate_real_ia32_spec_ctrl(tdcs_p, 0)
    tdvps_ptr->guest_msr_state.ia32_spec_ctrl = calculate_real_ia32_spec_ctrl(tdcs_ptr, 0);
}

uint32_t get_cpuid_lookup_entry(uint32_t leaf, uint32_t subleaf)
{
    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        if (cpuid_lookup[i].leaf_subleaf.leaf == leaf &&
            (cpuid_lookup[i].leaf_subleaf.subleaf == CPUID_SUBLEAF_NA ||
             cpuid_lookup[i].leaf_subleaf.subleaf == subleaf))
        {
            return i;
        }
    }
    return CPUID_LOOKUP_IDX_NA;
}

uint32_t get_guest_td_cpl(void)
{
    uint64_t ss_arbyte;

    ia32_vmread(VMX_GUEST_SS_ARBYTE_ENCODE, &ss_arbyte);

    seg_arbyte_t arbyte = { .raw = (uint32_t)ss_arbyte };

    return arbyte.dpl;
}

void inject_pf(uint64_t gla, pfec_t pfec)
{
    uint16_t curr_vm = get_local_data()->vp_ctx.tdvps->management.curr_vm;

    if (curr_vm != 0)
    {
        // Before we inject a #PF, reinject IDT vectoring events that happened during VM exit, if any.
        reinject_idt_vectoring_event_if_any();
    }

    vmx_entry_inter_info_t entry_info;

    //  Read the VM entry interruption information to see if there's already an event pending
    //  to be injected.
    //  Note that this field is always invalid following a VM exit.  However, it may have been
    //  set during the VM exit handling flow. At the beginning of the flow, we checked if the
    //  VM exit happened during event delivery via IDT, and may have already set up VOE. The
    //  following checks take care of such cases.
    ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &entry_info.raw);

    //  Write the GLA directly into CR2.
    //  Since TDX-SEAM does not handle #PF itself, CR2 value will remain intact
    //  until the upcoming VM entry.
    //  Note that this is done even if we later mutate into a #DF, to emulate
    //  the CPU's #PF behavior.
    ia32_load_cr2(gla);

    //  First, check if there's already a #DF waiting to be injected.  If so, we now have a
    //  triple-fault case.  In this case we do a TD exit and disable the VCPU.
    if ((entry_info.valid) &&
        (entry_info.interruption_type == VMEXIT_INTER_INFO_TYPE_HARDWARE_EXCEPTION) &&
        (entry_info.vector == E_DF))
    {
        vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };
        vm_exit_reason.basic_reason = VMEXIT_REASON_TRIPLE_FAULT;

        // For L1, we do a TD exit and disable the VCPU.  For L2, we let the L1 VMM handle this.
        if (curr_vm == 0)
        {
            async_tdexit_to_vmm(TDX_NON_RECOVERABLE_VCPU, vm_exit_reason, 0, 0, 0, 0);
        }
        else
        {
            vmx_exit_qualification_t exit_qual = { .raw = 0 };
            vmx_exit_inter_info_t exit_inter_info = { .raw = 0 };
            td_l2_to_l1_exit(vm_exit_reason, exit_qual, 0, exit_inter_info);
        }
    }

    //  Check if there's already a #PF or a #VE waiting to be injected.  If so, we have a
    //  double-fault case.  In this case we inject a #DF(0) exception.
    if ((entry_info.valid) &&
        (entry_info.interruption_type == VMEXIT_INTER_INFO_TYPE_HARDWARE_EXCEPTION) &&
        ((entry_info.vector == E_PF) || (entry_info.vector == E_VE)))
    {
        inject_df();
    }
    //  In all other cases, we inject the requested #PF
    else
    {
        ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, PF_INTERRUPTION_INFO);
        ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, (uint64_t)pfec.raw);
    }

    ia32_rflags_t rflags;

    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);
    rflags.rf = 1;
    ia32_vmwrite(VMX_GUEST_RFLAGS_ENCODE, rflags.raw);
}

uint64_t calculate_virt_tsc(uint64_t native_tsc, uint64_t tsc_multiplier, uint64_t tsc_offset)
{
    // Goal is to make the virtual TSC start from the requested virt_tsc

    // tmp_128b_virt_tsc = native_tsc * tsc_multiplier;
    uint128_t tmp_128b;

    _ASM_VOLATILE_ (
        "mulq %3\n"
        : "=a"(tmp_128b.qwords[0]), "=d"(tmp_128b.qwords[1])
        : "a"(native_tsc), "b"(tsc_multiplier)
        :);

    // tmp_virt_tsc_64b = tmp_128b_virt_tsc / (1ULL < 48);
    uint64_t tmp_64b;

    tmp_64b = (tmp_128b.qwords[1] << 16) | (tmp_128b.qwords[0] >> 48);

    // virt_tsc = tmp_virt_tsc_64b + tsc_offset;
    return (tmp_64b + tsc_offset);
}

cr_write_status_e write_guest_cr0(uint64_t value, bool_t allow_pe_disable)
{
    ia32_cr0_t cr0;
    ia32_cr4_t cr4;
    platform_common_config_t* msr_values_ptr = &get_global_data()->plt_common_config;

    cr0.raw = value;

    // If the guest attempted to write natively invalid values, inject a #GP(0)
    ia32_cr0_t cr0_fixed0;
    cr0_fixed0.raw = msr_values_ptr->ia32_vmx_cr0_fixed0.raw;
    cr0_fixed0.pe = 0;
    cr0_fixed0.pg = 0;

    if ((~value & cr0_fixed0.raw) ||
        (value & ~msr_values_ptr->ia32_vmx_cr0_fixed1.raw))
    {
        TDX_LOG("MOV to CR0 - attempt to write invalid values (0x%lx) - #GP", value);
        return CR_ACCESS_GP;
    }

    // The combination CR0.PE == 0 and CR0.PG == 1 is architecturally illegal
    if ((cr0.pe == 0) && (cr0.pg == 1))
    {
        TDX_LOG("MOV to CR0 - use illegal combination (0x%lx) - #GP", value);
        return CR_ACCESS_GP;
    }

    // If the guest attempted to clear CR0.WP while CR4.CET is 1, throw a #GP(0)
    ia32_vmread(VMX_GUEST_CR4_ENCODE, &(cr4.raw));
    if ((cr4.cet == 1) && (cr0.wp == 0))
    {
        TDX_LOG("MOV to CR0 - illegal attempt to clear bit (0x%lx) - #GP", value);
        return CR_ACCESS_GP;
    }

    // At this point, if the guest attempted to change any CR0 bit that is owned by TDX Module,
    // i.e., set to 1 in the CR0 guest/host mask, we throw a #VE.
    // An exception to this are reserved bits 28-19, 17 and 15-6, which are silently ignored
    // (this is an architectural behavior, though not well documented in the Intel SDM).
    // Reserved bits 63-32 are most likely to be caught by the fixed value checks above,
    // the check here takes care of a possible addition of non-reserved bits in the range 63-32,
    // that is not known at the time TDX Module is written.
    if ((!cr0.pe && !allow_pe_disable) || !cr0.ne || cr0.nw || cr0.cd || cr0.reserved_3)
    {
        TDX_LOG("MOV to CR0 - illegal bits set - 0x%llx\n", cr0.raw);
        return CR_ACCESS_NON_ARCH;
    }

    // Update the value of guest CR0.
    // Values of bits 28-19, 17 and 15-6 left as they were before.
    cr0.raw &= ~(uint64_t)CR0_IGNORED_MASK;
    uint64_t guest_cr0;
    ia32_vmread(VMX_GUEST_CR0_ENCODE, &guest_cr0);
    cr0.raw |= guest_cr0 & (uint64_t)CR0_IGNORED_MASK;
    ia32_vmwrite(VMX_GUEST_CR0_ENCODE, cr0.raw);

    return CR_ACCESS_SUCCESS;
}

bool_t is_guest_cr4_allowed_by_td_config(ia32_cr4_t cr4, tdcs_t* tdcs_p, ia32_xcr0_t xfam)
{
    td_param_attributes_t attributes = tdcs_p->executions_ctl_fields.attributes;

    // Check if bits for features that are not enabled by XFAM are set
    if ((!xfam.pk && cr4.pke) ||
        ((!xfam.cet_s || !xfam.cet_u) && cr4.cet) ||
        (!xfam.uli && cr4.uintr))
    {
        TDX_LOG("MOV to CR4 - attempt to write features not enabled by XFAM (0x%lx) - #GP", cr4.raw);
        return false;
    }

    // Check if bits for features that are not enabled by ATTRIBUTES are set
    if (cr4.keylocker == 1)
    {
        TDX_LOG("MOV to CR4 - keylocker not supported (0x%lx) - #GP", cr4.raw);
        return false;
    }

    if ((attributes.pks == 0) && (cr4.pks == 1))
    {
        TDX_LOG("MOV to CR4 - PKS not supported (0x%lx) - #GP", cr4.raw);
        return false;
    }

    if (!attributes.lass && cr4.lass)
    {
        TDX_LOG("MOV to CR4 - LASS not supported by the TD\n");
        return false;
    }

    return true;
}

cr_write_status_e write_guest_cr4(uint64_t value, tdcs_t* tdcs_p, tdvps_t* tdvps_p)
{
    ia32_cr0_t cr0;
    ia32_cr4_t cr4;
    platform_common_config_t* msr_values_ptr = &get_global_data()->plt_common_config;

    cr4.raw = value;

    // If the guest attempted to write natively invalid values, inject a #GP(0)
    ia32_cr4_t cr4_fixed0;
    cr4_fixed0.raw = msr_values_ptr->ia32_vmx_cr4_fixed0.raw;
    cr4_fixed0.vmxe = 0;
    if ((~value & cr4_fixed0.raw) ||
        (value & ~msr_values_ptr->ia32_vmx_cr4_fixed1.raw))
    {
        TDX_LOG("MOV to CR4 - attempt to write invalid values (0x%lx) - #GP", value);
        return CR_ACCESS_GP;
    }

    // If the guest attempted to set bits for features that are not enabled by XFAM,
    //   inject a #GP(0)
    ia32_xcr0_t cur_xfam;
    cur_xfam.raw = tdvps_p->management.xfam;

    if (!is_guest_cr4_allowed_by_td_config(cr4, tdcs_p, cur_xfam))
    {
        return CR_ACCESS_GP;
    }

    // If the guest attempted to set CR4.CET while CR0.WP is 0, throw a #GP(0)
    ia32_vmread(VMX_GUEST_CR0_ENCODE, &(cr0.raw));
    if ((cr4.cet == 1) && (cr0.wp == 0))
    {
        TDX_LOG("MOV to CR4 - illegal attempt to clear bit (0x%lx) - #GP", value);
        return CR_ACCESS_GP;
    }

    // In all other cases, there was no architectural error but there was
    // a VM exit due to bit values that are not compatible with TDX.
    // In these cases throw a #VE.
    TDX_LOG("MOV to CR4 - other case (0x%lx) - #VE", value);
    return CR_ACCESS_NON_ARCH;
}

bool_t verify_td_attributes(td_param_attributes_t attributes, bool_t is_import)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    if (((attributes.raw & ~tdx_global_data_ptr->attributes_fixed0) != 0) ||
        ((attributes.raw & tdx_global_data_ptr->attributes_fixed1) != tdx_global_data_ptr->attributes_fixed1))
    {
        return false;
    }

    if (attributes.migratable)
    {
        // A migratable TD can't be a debug TD and doesn't support PERFMON
        if (attributes.debug || attributes.perfmon)
        {
            return false;
        }
    }
    else if (is_import)
    {
        // TD must be migratable on import flow
        return false;
    }

    if (attributes.perfmon && attributes.icssd)
    {
        return false;
    }

    return true;
}

bool_t verify_td_config_flags(config_flags_t config_flags)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    if (((config_flags.raw & ~tdx_global_data_ptr->config_flags_fixed0.raw) != 0) ||
        ((config_flags.raw & tdx_global_data_ptr->config_flags_fixed1.raw) != tdx_global_data_ptr->config_flags_fixed1.raw))
    {
        return false;
    }

    return true;
}

bool_t check_xfam(ia32_xcr0_t xfam)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    // Check that all bits set to 1 are allowed
    if ((xfam.raw &
         ~(uint64_t)(TDX_XFAM_FIXED0 & (tdx_global_data_ptr->xcr0_supported_mask |
                             tdx_global_data_ptr->ia32_xss_supported_mask))) != 0)
    {
        return false;
    }

    // Check that all bits set to 0 are allowed and check that all bit combinations are allowed
    if (((xfam.raw & TDX_XFAM_FIXED1) != TDX_XFAM_FIXED1) ||
        (xfam.avx3_kmask && !xfam.avx) ||
        (xfam.avx3_kmask != xfam.avx3_zmm_hi) ||
        (xfam.avx3_kmask != xfam.avx3_zmm) ||
        (xfam.cet_s != xfam.cet_u) ||
        (xfam.amx_xtilecfg != xfam.amx_xtiledata))
    {
        return false;
    }

    return true;
}

bool_t verify_and_set_td_eptp_controls(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, bool_t gpaw, ia32e_eptp_t eptp)
{
    // Check if PML5 is supported by the platform
    uint64_t max_pwl = LVL_PML5;
    ia32_vmx_ept_vpid_cap_t vpid_cap = { .raw = get_global_data()->plt_common_config.ia32_vmx_ept_vpid_cap };

    if (!vpid_cap.pml5_supported)
    {
        max_pwl = LVL_PML4;
    }

    if ((eptp.fields.ept_ps_mt != MT_WB) ||
        (eptp.fields.ept_pwl < LVL_PML4) ||
        (eptp.fields.ept_pwl > max_pwl) ||
        (eptp.fields.enable_ad_bits != 0) ||
        (eptp.fields.enable_sss_control != 0) ||
        (eptp.fields.reserved_0 != 0) ||
        (eptp.fields.base_pa != 0) ||
        (eptp.fields.reserved_1 != 0))
    {
        return false;
    }

    uint64_t tdx_max_pa = get_global_data()->max_pa;

    if ((eptp.fields.ept_pwl == LVL_PML5) &&
        (tdx_max_pa < MIN_PA_FOR_PML5))
    {
        return false;
    }

    // Check compatibility with GPAW.  If the SHARED bit is 52 then this must be a 5-level EPT
    if (gpaw && (eptp.fields.ept_pwl < LVL_PML5))
    {
        return false;
    }

    tdcs_ptr->executions_ctl_fields.gpaw = gpaw;

    // The PA field of EPTP points to the Secure EPT root page in TDCS,
    // which has already been initialized to 0 during TDADDCX
    pa_t sept_root_pa;
    sept_root_pa.raw = tdr_ptr->management_fields.tdcx_pa[SEPT_ROOT_PAGE_INDEX];
    sept_root_pa = set_hkid_to_pa(sept_root_pa, 0);

    eptp.fields.base_pa = sept_root_pa.page_4k_num;

    tdcs_ptr->executions_ctl_fields.eptp.raw = eptp.raw;

    return true;
}

void calculate_tsc_virt_params(uint64_t tsc, uint64_t native_tsc_freq, uint16_t virt_tsc_frequency,
                               uint64_t virt_tsc, uint64_t* tsc_multiplier, uint64_t* tsc_offset)
{
    // To avoid losing accuracy, temporary results during the calculation have 128-bit accuracy.
    // This is best implemented with embedded assembly code, using:
    // - 64b*64b unsigned multiply (MUL), which produces a 128b result
    // - 128b/64b unsigned divide (DIV), which produces a 64b result

    uint64_t tmp_tsc_multiplier, tmp_tsc_offset;

    // 1. TSC Multiplier Calculation:
    // tmp_128b = virt_tsc_frequency * 25000000 * (1ULL < 48);
    // tsc_multiplier = tmp_128b / native_tsc_frequency;

    tdx_sanity_check((native_tsc_freq >= NATIVE_TSC_FREQUENCY_MIN), SCEC_SEAMCALL_SOURCE(TDH_MNG_INIT_LEAF), 0);

    _ASM_VOLATILE_ (
        "mulq %2\n"
        "divq %3\n"
        : "=a"(tmp_tsc_multiplier)
        : "a"((uint64_t)virt_tsc_frequency * VIRT_TSC_FREQUENCY_UNIT), "r"(1ULL << 48), "b"(native_tsc_freq)
        : "%rdx" );

    // 2. TSC Offset Calculation
    // tmp_128b = current_tsc * tsc_multiplier;
    // tmp_virt_tsc_64b = tmp_128b / (1ULL < 48);
    // tsc_offset = -tmp_virt_tsc_64b + virt_tsc;

    uint128_t tmp_128b;

    _ASM_VOLATILE_ (
        "mulq %3\n"
        : "=a"(tmp_128b.qwords[0]), "=d"(tmp_128b.qwords[1])
        : "a"(tsc), "b"(tmp_tsc_multiplier)
        :);

    tmp_tsc_offset = (tmp_128b.qwords[1] << 16) | (tmp_128b.qwords[0] >> 48);

    *tsc_multiplier = tmp_tsc_multiplier;
    *tsc_offset = -(tmp_tsc_offset) + virt_tsc;
}

bool_t check_guest_xcr0_value(ia32_xcr0_t xcr0, uint64_t xfam)
{
    tdx_module_global_t* global_data_ptr = get_global_data();

    // Check that any bit that is set to 1 is supported by XCR0 and XFAM.  Note that CPU
    // support has been enumerated on TDH_SYS_INIT and used to verify XFAM on TDH_MNG_INIT.
    if ((xcr0.raw & ~(global_data_ptr->xcr0_supported_mask & xfam)) != 0)
    {
        return false;
    }

    // For the following checks, see [Intel SDM, Vol. 1, 13.3]
    // XCR0[0] is always 1
    if (!xcr0.x87_fpu_mmx)
    {
        return false;
    }

    // Check that all bit combinations are allowed
    if ((xcr0.avx && !xcr0.sse)              ||    // AVX requires SSE
        (xcr0.avx3_kmask && !xcr0.avx)       ||    // AVX3 requires AVX
        (xcr0.avx3_kmask != xcr0.avx3_zmm_hi) ||   // All AVX3 bits must be the same
        (xcr0.avx3_kmask != xcr0.avx3_zmm)   ||    // All AVX3 bits must be the same
        (xcr0.amx_xtilecfg != xcr0.amx_xtiledata)) // All AMX bits must be the same
    {
        return false;
    }

    return true;
}

void send_self_ipi(apic_delivery_mode_t delivery_mode, uint32_t vector)
{
    ia32_apic_icr_t icr;

    icr.raw = 0;
    icr.delivery_mode = delivery_mode;
    icr.dest_shorthand = DEST_SHORTHAND_NONE;
    icr.vector = vector;

    // APIC works in x2APIC mode (MSR access). APIC ID is 32 bits.
    if (delivery_mode == APIC_DELIVERY_FIXED)
    {
        ia32_wrmsr(IA32_X2APIC_EOI, 0);
    }

    icr.x2apic_dest_field = ia32_rdmsr(IA32_X2APIC_APICID) & BIT_MASK_32BITS;

    ia32_wrmsr(IA32_X2APIC_ICR, icr.raw);
}

bool_t lfsr_init_seed (uint32_t* lfsr_value)
{
    uint64_t rand;

    if (!ia32_rdrand(&rand))
    {
        return false;
    }

    *lfsr_value = rand & 0xFFFFFFFF;

    return (*lfsr_value != 0);
}

uint32_t lfsr_get_random ()
{
    tdx_module_local_t* local_data_ptr = get_local_data();
    uint32_t lfsr_value = local_data_ptr->single_step_def_state.lfsr_value;

    if ((lfsr_value & 0x1) == 0x0)
    {
        lfsr_value = lfsr_value >> 1;
    }
    else
    {
        lfsr_value = (lfsr_value >> 1) ^ POLY_MASK_32;
    }

    tdx_sanity_check(lfsr_value != 0, SCEC_HELPERS_SOURCE, 2);

    local_data_ptr->single_step_def_state.lfsr_value = lfsr_value;

    return lfsr_value;
}

void initialize_extended_state(uint64_t xfam)
{
    ia32_xsetbv(0, xfam & XCR0_USER_BIT_MASK);
    ia32_wrmsr(IA32_XSS_MSR_ADDR, xfam & XCR0_SUPERVISOR_BIT_MASK);

    ia32_xrstors(&get_global_data()->xbuf, xfam);
}

void set_guest_pde_bs(void)
{
    ia32_rflags_t rflags;
    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);

    ia32_debugctl_t debugctl;
    ia32_vmread(VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &debugctl.raw);

    pending_debug_exception_t pde;
    ia32_vmread(VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE, &pde.raw);

    pde.bs = (rflags.tf == 1 && debugctl.btf == 0) ? 1 : 0;
    ia32_vmwrite(VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE, pde.raw);
}

void advance_guest_rip(void)
{
    current_vmcs_guest_rip_advance(0);

    clear_movss_sti_blocking();
    set_guest_pde_bs();
}

void increment_fixed_ctr0(tdcs_t* tdcs_p)
{
    if (!tdcs_p->executions_ctl_fields.attributes.perfmon)
    {
        ia32_wrmsr(IA32_FIXED_CTR0_MSR_ADDR, ia32_rdmsr(IA32_FIXED_CTR0_MSR_ADDR) + 1);
    }
}

void clear_movss_sti_blocking(void)
{
    vmx_guest_inter_state_t guest_inter_state;
    ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);

    if (guest_inter_state.blocking_by_mov_ss != 0 || guest_inter_state.blocking_by_sti != 0)
    {
        guest_inter_state.blocking_by_mov_ss = 0;
        guest_inter_state.blocking_by_sti = 0;
        ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
    }
}

uint32_t check_mem_enc_alg (ia32_tme_capability_t tme_capability,  // In:  IA32_TME_CAPABILITY MSR value
                            ia32_tme_activate_t   tme_activate)    // In:  IA32_TME_ACTIVATE MSR value
{
    // IA32_TME_ACTIVATE must be locked
    if (tme_activate.lock == 0)
    {
        return IA32_TME_ACTIVATE_MSR_ADDR;
    }

    /* IA32_TME_CAPABILITIES must support either 128-bit or 256-bit memory encryption, with or
       without integrity as provided by MCHECK.
       IA32_TME_ACTIVATE must have been activated to support either 128-bit or 256-bit memory encryption, with or
       without integrity as provided by MCHECK.*/
    if (get_sysinfo_table()->mcheck_fields.tdx_without_integrity)
    {
        if ((tme_capability.aes_xts_256 == 0) && (tme_capability.aes_xts_128 == 0))
        {
            return IA32_TME_CAPABILITY_MSR_ADDR;
        }

        if ((tme_activate.algs_aes_xts_256 == 0) &&
            (tme_activate.algs_aes_xts_128 == 0))
        {
            return IA32_TME_ACTIVATE_MSR_ADDR;
        }
    }
    else
    {
        if ((tme_capability.aes_xts_256_with_integrity == 0) &&
            (tme_capability.aes_xts_128_with_integrity == 0))
        {
            return IA32_TME_CAPABILITY_MSR_ADDR;
        }

        if ((tme_activate.algs_aes_xts_256_with_integrity == 0) &&
            (tme_activate.algs_aes_xts_128_with_integrity == 0))
        {
            return IA32_TME_ACTIVATE_MSR_ADDR;
        }
    }

    return 0;
}

bool_t is_msr_dynamic_bit_cleared(tdcs_t* tdcs_ptr, uint32_t msr_addr, msr_bitmap_bit_type bit_meaning)
{
    // Common dynamic cases
    if (((bit_meaning == MSR_BITMAP_DYN_PERFMON)  && is_perfmon_supported_in_tdcs(tdcs_ptr)) ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_CET) && is_cet_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_PT)  && is_pt_supported_in_tdcs(tdcs_ptr))      ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_ULI) && is_uli_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_LBR) && is_lbr_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_UMWAIT)   && is_waitpkg_supported_in_tdcs(tdcs_ptr)) ||
        ((bit_meaning == MSR_BITMAP_DYN_PKS)      && is_pks_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_XFD)      && is_xfd_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_TSX)      && is_tsx_supported_in_tdcs(tdcs_ptr)))
    {
        return true;
    }

    // Other rare dynamic cases
    if (bit_meaning == MSR_BITMAP_DYN_OTHER)
    {
        // No other MSR's are currently expected for rare case
        tdx_debug_assert((msr_addr == IA32_PERF_CAPABILITIES_MSR_ADDR) ||
                         (msr_addr == IA32_PERF_METRICS_MSR_ADDR));

        if ((msr_addr == IA32_PERF_CAPABILITIES_MSR_ADDR) &&
            (is_perfmon_supported_in_tdcs(tdcs_ptr) && is_pt_supported_in_tdcs(tdcs_ptr)))
        {
            return true;
        }

        if ((msr_addr == IA32_PERF_METRICS_MSR_ADDR) &&
            (is_perfmon_supported_in_tdcs(tdcs_ptr) &&
             get_global_data()->plt_common_config.ia32_perf_capabilities.perf_metrics_available))
        {
            return true;
        }
    }

    return false;
}

void set_msr_bitmaps(tdcs_t * tdcs_ptr)
{
    // Assuming that the whole MSR bitmap was initialized to all 1's by TDHMNGADDCX

    for (uint32_t i = 0; i < MAX_NUM_MSR_LOOKUP; i++)
    {
        uint32_t msr_addr = msr_lookup[i].start_address;

        bool_t clear_rd_bit = is_msr_dynamic_bit_cleared(tdcs_ptr, msr_addr, msr_lookup[i].rd_bit_meaning) ||
                              (msr_lookup[i].rd_bit_meaning == MSR_BITMAP_FIXED_0);
        bool_t clear_wr_bit = is_msr_dynamic_bit_cleared(tdcs_ptr, msr_addr, msr_lookup[i].wr_bit_meaning) ||
                              (msr_lookup[i].wr_bit_meaning == MSR_BITMAP_FIXED_0);

        if (!clear_rd_bit && !clear_wr_bit)
        {
            continue; // Nothing to do for whole MSR address range
        }

        for (; msr_addr <= msr_lookup[i].end_address; msr_addr++)
        {
            uint32_t byte_offset, bit_offset;
            byte_offset = (msr_addr & ~HIGH_MSR_MASK) ? MSR_BITMAP_SIZE : 0;
            byte_offset += (msr_addr & HIGH_MSR_MASK) / 8;
            bit_offset = (msr_addr & HIGH_MSR_MASK) % 8;

            uint32_t* byte_addr_rd = (uint32_t*)&tdcs_ptr->MSR_BITMAPS[byte_offset];
            uint32_t* byte_addr_wr = (uint32_t*)&tdcs_ptr->MSR_BITMAPS[byte_offset + (MSR_BITMAP_SIZE * 2)];

            if (clear_rd_bit)
            {
                btr_32b(byte_addr_rd, bit_offset);
            }

            if (clear_wr_bit)
            {
                btr_32b(byte_addr_wr, bit_offset);
            }
        }
    }
}

void set_xbuff_offsets_and_size(tdcs_t* tdcs_ptr, uint64_t xfam)
{
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    // Calculate the offsets of XSAVE components in XBUFF, which depend on XFAM.  The algorithm
    // is described in the Intel SDM, Vol. 1, - 13.4.3 "Extended Region of an XSAVE Area"
    uint32_t offset = offsetof(xsave_area_t, extended_region);
    for (uint32_t xfam_i = 2; xfam_i <= XCR0_MAX_VALID_BIT; xfam_i++)
    {
        if ((xfam & BIT(xfam_i)) != 0)
        {
            if (tdx_global_data_ptr->xsave_comp[xfam_i].align)
            {
                // Align the offset up to the next 64B boundary
                offset = ROUND_UP(offset, 64U);
            }
            tdcs_ptr->executions_ctl_fields.xbuff_offsets[xfam_i] = offset;
            offset += tdx_global_data_ptr->xsave_comp[xfam_i].size;
        }
    }

    tdcs_ptr->executions_ctl_fields.xbuff_size = offset;
}

void init_imported_td_state_mutable (tdcs_t* tdcs_ptr)
{
    UNUSED(tdcs_ptr);
    // Do nothing
}

bool_t td_immutable_state_cross_check(tdcs_t* tdcs_ptr)
{
    // A TD can't be both migratable and partitioned
    if (tdcs_ptr->executions_ctl_fields.attributes.migratable &&
        (tdcs_ptr->management_fields.num_l2_vms > 0))
    {
        TDX_ERROR("Migration of partitioned TD's is not supported\n");
        return false;
    }

    return true;
}

api_error_type check_and_init_imported_td_state_immutable (tdcs_t* tdcs_ptr)
{
    if (!td_immutable_state_cross_check(tdcs_ptr))
    {
        return api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
    }

    
    // num_vcpus sanity check (at this point num_vcpus is already set)
    if ((tdcs_ptr->management_fields.num_vcpus == 0) || (tdcs_ptr->management_fields.num_vcpus > tdcs_ptr->executions_ctl_fields.max_vcpus))
    {
        return api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_MAX_VCPUS);
    }

    /**
     * Initialize the TD Management Fields
     */
    tdcs_ptr->management_fields.num_assoc_vcpus = 0;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch = 1;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.refcount[0] = 0;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.refcount[1] = 0;

    /**
     * Execution control fields
     */
    set_xbuff_offsets_and_size(tdcs_ptr, tdcs_ptr->executions_ctl_fields.xfam);

    /** CONFIG_FLAGS is optionally imported since older TDX module versions didn't support it.  Set the GPAW bit
     *  based on the separate GPAW field that is always imported.
     */
    tdcs_ptr->executions_ctl_fields.config_flags.gpaw = (tdcs_ptr->executions_ctl_fields.gpaw != false);

    /** TD_CTLS is optionally imported (later. as part of the mutable state) since older TDX module versions didn't support it.
     *  Set the PENDING_VE_DISABLE bit based on the ATTRIBUTES field that has already been imported (as part of the immutable
     *  state). This value may be overwritten later by the immutable state import.
     */
    tdcs_ptr->executions_ctl_fields.td_ctls.pending_ve_disable = tdcs_ptr->executions_ctl_fields.attributes.sept_ve_disable;

    // Check the imported CPUID(0x1F) values and set CPUID(0xB) values

    api_error_type return_val = check_cpuid_1f_and_compute_cpuid_0b(tdcs_ptr, false);
    if (return_val != TDX_SUCCESS)
    {
        return return_val;
    }

    calculate_servtd_hash(tdcs_ptr, true);

    /**
     *  Build the MSR bitmaps
     *
     *  The MSR bitmap page was filled with all 1's during TDH_MNG_ADDCX
     */
    set_msr_bitmaps(tdcs_ptr);

    return return_val;
}

api_error_type check_imported_vp_state(tdr_t* tdr_p, tdcs_t* tdcs_p, tdvps_t* tdvps_p)
{
    UNUSED(tdr_p);

    if (tdcs_p->executions_ctl_fields.topology_enum_configured)
    {
        uint32_t x2apic_id = tdcs_p->x2apic_ids[tdvps_p->management.vcpu_index];

        for (uint32_t i = 0; i < tdcs_p->management_fields.num_vcpus; i++)
        {
            if (x2apic_id == tdcs_p->x2apic_ids[i])
            {
                if (i != tdvps_p->management.vcpu_index)
                {
                    return api_error_with_operand_id(TDX_X2APIC_ID_NOT_UNIQUE, x2apic_id);
                }
            }
        }
    }

    return TDX_SUCCESS;
}

void prepare_td_vmcs(tdvps_t *tdvps_p, uint16_t vm_id)
{
    vmcs_header_t   *td_vmcs_p;
    ia32_vmx_basic_t vmx_basic;

    pa_t tdvps_vmcs_pa = { .raw = tdvps_p->management.tdvps_pa[get_tdvps_vmcs_page_index(vm_id)] };

    // Map the TD VMCS page
    td_vmcs_p = (vmcs_header_t *)map_pa(tdvps_vmcs_pa.raw_void, TDX_RANGE_RW);

    /*
     * Initialize the version ID in the TD VMCS (first 31 bits) with the
     * VMCS version ID reported by the IA32_VMX_BASIC MSR
     */
    vmx_basic.raw = get_global_data()->plt_common_config.ia32_vmx_basic.raw;
    td_vmcs_p->revision.vmcs_revision_identifier = vmx_basic.vmcs_revision_id;
    td_vmcs_p->revision.shadow_vmcs_indicator = 0;
    td_vmcs_p->vmx_abort_indicator = 0;

    vmclear_vmcs(tdvps_p, vm_id);

    free_la(td_vmcs_p);
}

api_error_code_e get_tdinfo_and_teeinfohash(tdcs_t* tdcs_p, ignore_tdinfo_bitmap_t ignore_tdinfo,
                                            td_info_t* td_info, measurement_t* tee_info_hash, bool_t is_guest)
{
    td_info_t             td_info_local;
    ALIGN(32) uint256_t   ymms[16];                  // AVX/SSE state backup for crypto
    crypto_api_error      sha_error_code;
    api_error_code_e      retval = UNINITIALIZE_ERROR;
    bool_t                rtmr_locked_flag = true;

    if (td_info == NULL)
    {
        td_info = &td_info_local;
    }

    // Zero the TDINFO (reserve fields are zero'd)
    basic_memset_to_zero(td_info, sizeof(td_info_t));

    // Acquire shared access to TDCS.RTMR
    if ((retval = acquire_sharex_lock_hp_sh(&tdcs_p->measurement_fields.rtmr_lock, is_guest)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to acquire shared lock on RTMR\n");
        return retval;
    }

    rtmr_locked_flag = true;

    if (!ignore_tdinfo.attributes)
    {
        td_info->attributes = tdcs_p->executions_ctl_fields.attributes.raw;
    }
    if (!ignore_tdinfo.xfam)
    {
        td_info->xfam = tdcs_p->executions_ctl_fields.xfam;
    }
    if (!ignore_tdinfo.mrtd)
    {
        tdx_memcpy(td_info->mr_td.bytes, sizeof(measurement_t),
                   tdcs_p->measurement_fields.mr_td.bytes,
                   sizeof(measurement_t));
    }
    if (!ignore_tdinfo.mrconfig)
    {
        tdx_memcpy(td_info->mr_config_id.bytes, sizeof(measurement_t),
                   tdcs_p->measurement_fields.mr_config_id.bytes,
                   sizeof(measurement_t));
    }
    if (!ignore_tdinfo.mrowner)
    {
        tdx_memcpy(td_info->mr_owner.bytes, sizeof(measurement_t),
                   tdcs_p->measurement_fields.mr_owner.bytes,
                   sizeof(measurement_t));
    }
    if (!ignore_tdinfo.mrownerconfig)
    {
        tdx_memcpy(td_info->mr_owner_config.bytes, sizeof(measurement_t),
                   tdcs_p->measurement_fields.mr_owner_config.bytes,
                   sizeof(measurement_t));
    }
    for (uint32_t i = 0; i < NUM_OF_RTMRS; i++)
    {
        if (!(ignore_tdinfo.rtmr & BIT(i)))
        {
            tdx_memcpy(td_info->rtmr[i].bytes, sizeof(measurement_t),
                       tdcs_p->measurement_fields.rtmr[i].bytes,
                       SIZE_OF_SHA384_HASH_IN_BYTES);
        }
    }

    if (!ignore_tdinfo.servtd_hash)
    {
        tdx_memcpy(td_info->servtd_hash.bytes, sizeof(measurement_t),
                   tdcs_p->service_td_fields.servtd_hash.bytes,
                   sizeof(measurement_t));
    }

    /* SHA calculation is a relatively long operation.  Optimize by reusing the previously-calculated value,
       if available.  This is designed for use by TDG.MR.REPORT, which is interruptible. */
    if ((tdcs_p->measurement_fields.last_teeinfo_hash_valid) && (ignore_tdinfo.raw == 0))
    {
        // Optimize for the common case of TDG.MR.REPORT
        tdx_memcpy(tee_info_hash, sizeof(measurement_t),
                   &(tdcs_p->measurement_fields.last_teeinfo_hash), sizeof(measurement_t));
    }
    else
    {
        // Compute TEE_INFO_HASH
        store_ymms_in_buffer(ymms);

        if ((sha_error_code = sha384_generate_hash((const uint8_t *)td_info,
                                                    sizeof(td_info_t),
                                                    tee_info_hash->qwords)))
        {
            // Unexpected error - Fatal Error
            TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
            FATAL_ERROR();
        }

        load_ymms_from_buffer(ymms);
        basic_memset_to_zero(ymms, sizeof(ymms));

        if (ignore_tdinfo.raw == 0)
        {
            // Optimize for TDG.MR.REPORT: store the hash for next time
            tdx_memcpy(&(tdcs_p->measurement_fields.last_teeinfo_hash), sizeof(measurement_t),
                       tee_info_hash, sizeof(measurement_t));

            tdcs_p->measurement_fields.last_teeinfo_hash_valid = true;
        }
    }

    release_sharex_lock_hp_sh(&tdcs_p->measurement_fields.rtmr_lock);

    return TDX_SUCCESS;
}

api_error_code_e get_teeinfohash(tdcs_t* tdcs_p, ignore_tdinfo_bitmap_t ignore_tdinfo,
                                 measurement_t* tee_info_hash)
{
    td_info_t td_info;

    return get_tdinfo_and_teeinfohash(tdcs_p, ignore_tdinfo, &td_info, tee_info_hash, false);
}

api_error_type abort_import_session(
    tdcs_t                  *tdcs_p,
    api_error_type           status,
    uint32_t                 status_details)
{
    if (tdcs_p->management_fields.op_state == OP_STATE_LIVE_IMPORT)
    {
        tdcs_p->management_fields.op_state = OP_STATE_RUNNABLE;
        return api_error_with_operand_id(status, status_details);
    }
    else
    {
        tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
        status = api_error_with_operand_id(status, status_details);
        return api_error_fatal(status);
    }
}

#if 0
api_error_type abort_import_session_with_septe_details(
    tdcs_t                  *tdcs_p,
    ia32e_sept_t             septe,
    ept_level_t              level,
    api_error_type           status,
    uint32_t                 status_details)
{

    // Update output register operands
    tdx_module_local_t  * local_data_ptr = get_local_data();
    set_arch_septe_details_in_vmm_regs(septe, level, local_data_ptr);

    return abort_import_session(tdcs_p, status, status_details);
}
#endif
bool_t generate_256bit_random(uint256_t* rand)
{
    uint8_t successfull_randomizations = 0;

    for (uint8_t i = 0; i < get_global_data()->num_rdseed_retries; i++)
    {
        if (ia32_rdseed(&rand->qwords[successfull_randomizations]))
        {
            successfull_randomizations++;

            if (QUADWORDS_IN_256b == successfull_randomizations)
            {
                break;
            }
        }

        for (uint8_t j = 0; j < get_global_data()->num_rdseed_pauses; j++)
        {
            ia32_pause();
        }
    }

    if (successfull_randomizations < QUADWORDS_IN_256b)
    {
        basic_memset_to_zero(rand, sizeof(uint256_t));
        return false;
    }

    return true;
}

_STATIC_INLINE_ void copy_global_field_to_handoff(void* field_ptr, uint32_t field_size,
                                                  uint8_t** data, uint32_t* size, uint32_t* written_size)
{
    tdx_memcpy(*data, *size, field_ptr, field_size);
    *data += field_size;
    *size -= field_size;
    *written_size += field_size;
}

_STATIC_INLINE_ void copy_global_field_from_handoff(void* field_ptr, uint32_t field_size, uint8_t** data)
{
    tdx_memcpy(field_ptr, field_size, *data, field_size);
    *data += field_size;
}

uint32_t prepare_handoff_data(uint16_t hv, uint32_t size, uint8_t* data)
{
    // The function fills the handoff buffer with data variables that satisfy the following conditions:
    // 1)  Not initialized by TDH.SYS.INIT or TDH.SYS.LP.INIT
    // 2)  Persist across multiple SEAMCALLs
    // 3)  Maintained inside SEAM range
    // For hv = 0, these variables include the KOT, WBT, TDMR_TABLE, TDMR_ENTRIES, TDX_HKID, PKG_CONFIG_BITMAP

    tdx_module_global_t* g_d = get_global_data();
    uint32_t written_size = 0;

    // Currently support only HV 0
    tdx_debug_assert(hv == 0);
    UNUSED(hv);

    // All write size checks are done by tdx_memcpy inside

    // Copy KOT entries (no need to copy the lock)
    copy_global_field_to_handoff(&g_d->kot.entries, sizeof(g_d->kot.entries),
                                 &data, &size, &written_size);

    // Copy WBT entries
    copy_global_field_to_handoff(&g_d->wbt_entries, sizeof(g_d->wbt_entries),
                                 &data, &size, &written_size);

    // Copy TDMR_TABLE
    copy_global_field_to_handoff(&g_d->tdmr_table, sizeof(g_d->tdmr_table),
                                 &data, &size, &written_size);

    // Copy TDMR_ENTRIES
    copy_global_field_to_handoff(&g_d->num_of_tdmr_entries, sizeof(g_d->num_of_tdmr_entries),
                                 &data, &size, &written_size);

    // Copy TDX_HKID
    copy_global_field_to_handoff(&g_d->hkid, sizeof(g_d->hkid),
                                 &data, &size, &written_size);

    // Copy PKG_CONFIG_BITMAP
    copy_global_field_to_handoff(&g_d->pkg_config_bitmap, sizeof(g_d->pkg_config_bitmap),
                                 &data, &size, &written_size);

    return written_size;
}

void retrieve_handoff_data(uint16_t hv, uint32_t size, uint8_t* data)
{
    // The function extracts the values of some data variables from the handoff data buffer
    // For hv = 0, these variables include the KOT, WBT, TDMR_TABLE, TDMR_ENTRIES, TDX_HKID, PKG_CONFIG_BITMAP

    tdx_module_global_t* g_d = get_global_data();

    // Currently support only HV 0
    tdx_debug_assert(hv == 0);
    UNUSED(hv);

    uint32_t total_required_size = TDX_MIN_HANDOFF_SIZE;

    tdx_sanity_check(total_required_size <= size, SCEC_HELPERS_SOURCE, 5);

    // Copy KOT entries (no need to copy the lock)
    copy_global_field_from_handoff(&g_d->kot.entries, sizeof(g_d->kot.entries), &data);

    // Copy WBT entries
    copy_global_field_from_handoff(&g_d->wbt_entries, sizeof(g_d->wbt_entries), &data);

    // Copy TDMR_TABLE
    copy_global_field_from_handoff(&g_d->tdmr_table, sizeof(g_d->tdmr_table), &data);

    // Copy TDMR_ENTRIES
    copy_global_field_from_handoff(&g_d->num_of_tdmr_entries, sizeof(g_d->num_of_tdmr_entries), &data);

    // Copy TDX_HKID
    copy_global_field_from_handoff(&g_d->hkid, sizeof(g_d->hkid), &data);

    // Copy PKG_CONFIG_BITMAP
    copy_global_field_from_handoff(&g_d->pkg_config_bitmap, sizeof(g_d->pkg_config_bitmap), &data);
}

void complete_cpuid_handling(tdx_module_global_t* tdx_global_data_ptr)
{
    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        for (uint32_t j = 0; j < 4; j++)
        {
            uint32_t cpuid_value = tdx_global_data_ptr->cpuid_values[i].values.values[j];

            // Clear the bits that will be later virtualized as FIXED0 or DYNAMIC
            cpuid_value &= ~cpuid_lookup[i].fixed0_or_dynamic.values[j];

            // Set to 1 any bits that will be later virtualized as FIXED1
            cpuid_value |= cpuid_lookup[i].fixed1.values[j];

            tdx_global_data_ptr->cpuid_values[i].values.values[j] = cpuid_value;
        }
    }
}

bool_t is_voe_in_exception_bitmap( void )
{
    vmx_entry_inter_info_t entry_intr_info;

    ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &(entry_intr_info.raw));

    if (entry_intr_info.valid && entry_intr_info.interruption_type == HW_EXCEPTION)
    {
        // Check the VOE vector vs. the exception bitmap
        uint64_t exception_bitmap = 0;
        ia32_vmread(VMX_EXCEPTION_BITMAP_ENCODE, &exception_bitmap);
        if ((exception_bitmap & BIT(entry_intr_info.vector)) != 0)
        {
            if (entry_intr_info.vector == E_PF)
            {
                // #PF is a special case where we need to check the Page Fault Error Code vs.
                // the mask and match values.  See [Intel SDM Vol. 3, 25.2].
                uint64_t pfec = 0, pfec_mask = 0, pfec_match = 0;
                ia32_vmread(VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE, &pfec);
                ia32_vmread(VMX_PAGEFAULT_ERRORCODE_MASK_ENCODE, &pfec_mask);
                ia32_vmread(VMX_PAGEFAULT_ERRORCODE_MATCH_ENCODE, &pfec_match);

                return ((pfec & pfec_mask) == pfec_match);
            }
            else
            {
                return true;
            }
        }
    }

    return false;
}

void convert_l2_voe_to_l1_exit(void)
{
    vmx_entry_inter_info_t entry_intr_info;
    ia32_vmread(VMX_VM_ENTRY_INTR_INFO_ENCODE, &(entry_intr_info.raw));

    tdx_debug_assert(entry_intr_info.valid);

    vmx_exit_inter_info_t exit_inter_info;

    // Copy the VOE information to VM exit information
    exit_inter_info.raw = entry_intr_info.raw;
    ia32_vmwrite(VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE, exit_inter_info.raw);

    uint64_t error_code = 0;
    ia32_vmread(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, &error_code);
    ia32_vmwrite(VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE, error_code);

    // Invalidate the entry interruption information to avoid injecting the VOE
    entry_intr_info.valid = 0;
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, entry_intr_info.raw);

    ia32_vmwrite(VMX_VM_EXIT_REASON_ENCODE, VMEXIT_REASON_EXCEPTION_OR_NMI);
    ia32_vmwrite(VMX_VM_EXIT_QUALIFICATION_ENCODE, 0);
}

void set_vmx_preemption_timer(tdvps_t* tdvps_p, uint16_t vm_id)
{
    vmx_pinbased_ctls_t pinbased_exec_ctls;
    ia32_vmread(VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE, &pinbased_exec_ctls.raw);

    if (tdvps_p->management.tsc_deadline[vm_id] == -1ULL)
    {
        // A TSC_DEADLINE value of -1 indicates no deadline. Disable the VMX-preemption timer.
        pinbased_exec_ctls.activate_vmx_preemption_timer = 0;
    }
    else
    {
        // Calculate the TSC ticks left until preemption timeout
        uint64_t preempt_time;
        uint64_t current_time = ia32_rdtsc();

        uint64_t future_delta = tdvps_p->management.shadow_tsc_deadline[vm_id] - current_time;
        uint64_t past_delta = current_time - tdvps_p->management.shadow_tsc_deadline[vm_id];

        // Calculation may indicate a time in the past.
        // In this case set to 0, which will cause the VM to exit immediately.
        if (past_delta < future_delta)
        {
            preempt_time = 0;
        }
        else
        {
            preempt_time = tdvps_p->management.shadow_tsc_deadline[vm_id] - current_time;

            // Scale down by the factor provided in IA32_VMX_MISC
            preempt_time >>= get_global_data()->plt_common_config.ia32_vmx_misc.vmx_preempt_timer_tsc_factor;

            // Timer is 32-bit.  If value doesn't fit, set to the maximum.
            if (preempt_time >= BIT(32))
            {
                preempt_time = BIT(32) - 1;
            }
        }

        // Enable VMX-preemption timer
        pinbased_exec_ctls.activate_vmx_preemption_timer = 1;
        ia32_vmwrite(VMX_GUEST_PREEMPTION_TIMER_COUNT_ENCODE, preempt_time);
    }

    ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE, pinbased_exec_ctls.raw);
}

bool_t reinject_idt_vectoring_event_if_any(void)
{
    vmx_entry_inter_info_t entry_intr_info;
    vmx_idt_vectoring_info_t idt_vectoring_info;

    ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, &idt_vectoring_info.raw);

    // Return false if there's nothing to do.
    IF_COMMON (!idt_vectoring_info.valid)
    {
        return false;
    }

    // Copy IDT vectoring fields to VM entry exception fields.
    // On the next VM entry, the CPU will inject a VOE.

    entry_intr_info.raw = idt_vectoring_info.raw;
    entry_intr_info.reserved = 0;
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, entry_intr_info.raw);

    if (idt_vectoring_info.error_code_valid)
    {
        uint64_t idt_vectoring_error_code;
        ia32_vmread(VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE, &idt_vectoring_error_code);
        ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, idt_vectoring_error_code);
    }

    uint64_t vm_exit_instruction_length;
    ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &vm_exit_instruction_length);
    ia32_vmwrite(VMX_VM_ENTRY_INSTRUCTION_LENGTH_ENCODE, vm_exit_instruction_length);

    // Make sure the above operation is done once per VM exit
    idt_vectoring_info.valid = 0;
    ia32_vmwrite(VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE, idt_vectoring_info.raw);

    return true;
}

bool_t translate_l2_enter_guest_state_gpa(
    tdr_t *    tdr_ptr,
    tdcs_t *   tdcs_ptr,
    tdvps_t *  tdvps_ptr,
    uint16_t   vm_id,
    uint64_t * failed_gpa)
{
    uint64_t hpa;
    uint64_t gpa;

    ia32e_sept_t * sept_entry_ptr = NULL;
    ia32e_sept_t   sept_entry_copy;
    ept_level_t    sept_entry_level = LVL_PT;

    api_error_type return_val = TDX_OPERAND_INVALID;

    tdx_debug_assert(vm_id != 0);

    /*
     * Translate the GPAs of TDH.VP.ENTER output memory operands whose shadow HPA is NULL_PA,
     * using the L1 SEPT
     */
    hpa = tdvps_ptr->management.l2_enter_guest_state_hpa[vm_id];
    if (hpa == NULL_PA)
    {
        gpa = tdvps_ptr->management.l2_enter_guest_state_gpa[vm_id];

        return_val = check_and_walk_private_gpa_to_leaf(tdcs_ptr, OPERAND_ID_RCX, (pa_t)gpa,
                                          tdr_ptr->key_management_fields.hkid,
                                          &sept_entry_ptr, &sept_entry_level, &sept_entry_copy);
        if (return_val != TDX_SUCCESS)
        {
            *failed_gpa = gpa;
            goto EXIT;
        }

        if (!sept_state_is_guest_accessible_leaf(sept_entry_copy))
        {
            *failed_gpa = gpa;
            goto EXIT;
        }

        // Update the HPA
        hpa = leaf_ept_entry_to_hpa(sept_entry_copy, gpa, sept_entry_level);
        tdvps_ptr->management.l2_enter_guest_state_hpa[vm_id] = set_hkid_to_pa((pa_t)hpa, tdr_ptr->key_management_fields.hkid).raw;

        if (sept_entry_ptr != NULL)
        {
            free_la(sept_entry_ptr);
            sept_entry_ptr = NULL;
        }
    }

    return true;

EXIT:
    if (sept_entry_ptr != NULL)
    {
        free_la(sept_entry_ptr);
    }
    return false;
}

bool_t translate_gpas(
    tdr_t *    tdr_ptr,
    tdcs_t *   tdcs_ptr,
    tdvps_t *  tdvps_ptr,
    uint16_t   vm_id,
    uint64_t * failed_gpa)
{
    uint64_t hpa;
    uint64_t gpa;

    ia32e_sept_t * sept_entry_ptr = NULL;
    ia32e_sept_t   sept_entry_copy;
    ept_level_t    sept_entry_level = LVL_PT;

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Check the VMCS is the correct one
    tdx_debug_assert(vm_id != 0);
    tdx_debug_assert(get_local_data()->vp_ctx.active_vmcs == vm_id);

    /*
     * Translate the GPAs of TDH.VP.ENTER output memory operands whose shadow HPA is NULL_PA,
     * using the L1 SEPT
     */
    if (!translate_l2_enter_guest_state_gpa(tdr_ptr, tdcs_ptr, tdvps_ptr, vm_id, failed_gpa))
    {
        goto EXIT;
    }

    /*
     * Translate the soft-translated GPA L2 VMCS fields whose shadow HPA is NULL_PA,
     * using the L1 SEPT.
     */

    hpa = tdvps_ptr->management.l2_vapic_hpa[vm_id];
    if (hpa == NULL_PA)
    {
        gpa = tdvps_ptr->management.l2_vapic_gpa[vm_id];
        return_val = check_and_walk_private_gpa_to_leaf(tdcs_ptr, OPERAND_ID_RCX, (pa_t)gpa,
                                          tdr_ptr->key_management_fields.hkid,
                                          &sept_entry_ptr, &sept_entry_level, &sept_entry_copy);
        if (return_val != TDX_SUCCESS)
        {
            *failed_gpa = gpa;
            goto EXIT;
        }

        if (!sept_state_is_guest_accessible_leaf(sept_entry_copy))
        {
            *failed_gpa = gpa;
            goto EXIT;
        }

        // Update the HPA
        hpa = leaf_ept_entry_to_hpa(sept_entry_copy, gpa, sept_entry_level);
        hpa = set_hkid_to_pa((pa_t)hpa, tdr_ptr->key_management_fields.hkid).raw;
        tdvps_ptr->management.l2_vapic_hpa[vm_id] = hpa;
        ia32_vmwrite(VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE, hpa);

        if (sept_entry_ptr != NULL)
        {
            free_la(sept_entry_ptr);
        }
    }
    
    return true;

EXIT:
    if (sept_entry_ptr != NULL)
    {
        free_la(sept_entry_ptr);
    }
    return false;
}

void invalidate_gpa_translations(tdvps_t *tdvps_ptr, uint16_t vm_id)
{
    tdvps_ptr->management.l2_enter_guest_state_hpa[vm_id] = NULL_PA;
    tdvps_ptr->management.l2_vapic_hpa[vm_id] = NULL_PA;
}

void invalidate_all_gpa_translations(tdcs_t* tdcs_p, tdvps_t* tdvps_p)
{
    for (uint16_t vm_id = 0; vm_id <= tdcs_p->management_fields.num_l2_vms; vm_id++)
    {
        invalidate_gpa_translations(tdvps_p, vm_id);
    }
}

bool_t adjust_tlb_tracking_state(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr,
                                 bool_t new_association)
{
    tdcs_epoch_tracking_fields_t* epoch_tracking = &tdcs_ptr->epoch_tracking;

    // Lock the TD epoch
    if (acquire_sharex_lock_sh(&epoch_tracking->epoch_lock) != LOCK_RET_SUCCESS)
    {
        return false;
    }

    // Sample the TD epoch and atomically increment the REFCOUNT
    uint64_t vcpu_epoch = epoch_tracking->epoch_and_refcount.td_epoch;
    (void)_lock_xadd_16b(&epoch_tracking->epoch_and_refcount.refcount[vcpu_epoch & 1], 1);

    // End of critical section, release lock.
    release_sharex_lock_sh(&epoch_tracking->epoch_lock);

    if (vcpu_epoch != tdvps_ptr->management.vcpu_epoch)
    {
        if (!new_association)
        {
            /**
             *  The current VCPU was already associated with the current LP at the
             *  beginning of TDHVPENTER.
             *  Flush the TLB context and extended paging structure (EPxE) caches
             *  associated with the current TD.
             *  Else, no need to flush, since this LP is guaranteed not to hold any
             *  address translation for this VCPU
             */
            // Execute INVEPT type 1 for each Secure EPT
            flush_all_td_asids(tdr_ptr, tdcs_ptr);

            // Invalidate all soft-translated GPAs
            invalidate_all_gpa_translations(tdcs_ptr, tdvps_ptr);
        }

        // Store the sampled value of TD_EPOCH as the new value of VCPU_EPOCH
        tdvps_ptr->management.vcpu_epoch = vcpu_epoch;
    }

    return true;
}

void vmclear_vmcs(tdvps_t *tdvps_p, uint16_t vm_id)
{
    ia32_vmclear((void*)tdvps_p->management.tdvps_pa[get_tdvps_vmcs_page_index(vm_id)]);

    // Mark the guest TD as not launched.  Next VM entry will require VMLAUNCH
    tdvps_p->management.vm_launched[vm_id] = false;
}

api_error_type l2_sept_walk(tdr_t* tdr_ptr, tdcs_t* tdcs_ptr, uint16_t vm_id, pa_t page_gpa,
                            ept_level_t* level, ia32e_sept_t** l2_septe_ptr)
{
    ia32e_eptp_t septp = get_l2_septp(tdr_ptr, tdcs_ptr, vm_id);
    ia32e_sept_t cached_sept_entry = { .raw = 0 };

    ept_level_t requested_level = *level;
    *l2_septe_ptr = secure_ept_walk(septp, page_gpa, tdr_ptr->key_management_fields.hkid,
                                    level, &cached_sept_entry, false);

    if (requested_level != *level)
    {
        return TDX_L2_SEPT_WALK_FAILED;
    }

    return TDX_SUCCESS;
}

api_error_type l2_sept_walk_guest_side(
    tdr_t* tdr_ptr,
    tdcs_t* tdcs_ptr,
    uint16_t vm_id,
    pa_t page_gpa,
    ept_level_t* level,
    ia32e_sept_t* cached_l2_sept_entry,
    ia32e_sept_t** l2_septe_ptr)
{
    ia32e_eptp_t septp = get_l2_septp(tdr_ptr, tdcs_ptr, vm_id);

    ept_level_t requested_level = *level;
    *l2_septe_ptr = secure_ept_walk(septp, page_gpa, tdr_ptr->key_management_fields.hkid,
                                    level, cached_l2_sept_entry, true);

    if (requested_level != *level)
    {
        free_la(*l2_septe_ptr);
        *l2_septe_ptr = NULL;
        return TDX_EPT_WALK_FAILED;
    }

    return TDX_SUCCESS;
}

uint32_t prepare_servtd_hash_buff(tdcs_t* tdcs_ptr, servtd_hash_buff_t* servtd_has_buf)
{
    uint32_t num_tds = 0;

    tdx_debug_assert(MAX_SERVTDS <= 1);
    // TODO: add sorting for the array when the MAX_SERVTDS is greater than 1

    for (uint32_t i = 0; i < MAX_SERVTDS; i++)
    {
        if (tdcs_ptr->service_td_fields.servtd_bindings_table[i].state != SERVTD_NOT_BOUND)
        {
            tdx_memcpy(servtd_has_buf[num_tds].info_hash.qwords, sizeof(measurement_t),
                tdcs_ptr->service_td_fields.servtd_bindings_table[i].info_hash.qwords, sizeof(measurement_t));

            servtd_has_buf[num_tds].type = tdcs_ptr->service_td_fields.servtd_bindings_table[i].type;
            servtd_has_buf[num_tds].attrib.raw = tdcs_ptr->service_td_fields.servtd_bindings_table[i].attributes.raw;
            num_tds++;
        }
    }

    return num_tds;
}

void calculate_servtd_hash(tdcs_t* tdcs_ptr, bool_t handle_avx_state)
{
    servtd_hash_buff_t servtd_hash_buff[MAX_SERVTDS];
    basic_memset_to_zero((void*)servtd_hash_buff, (sizeof(servtd_hash_buff_t) * MAX_SERVTDS));
    uint32_t num_servtds = prepare_servtd_hash_buff(tdcs_ptr, servtd_hash_buff);

    if (num_servtds == 0)
    {
        basic_memset_to_zero((void*)&tdcs_ptr->service_td_fields.servtd_hash, sizeof(tdcs_ptr->service_td_fields.servtd_hash));
    }
    else
    {
        ALIGN(32) uint256_t ymms[16];

        if (handle_avx_state)
        {
            store_ymms_in_buffer(ymms);
        }

        crypto_api_error sha_error_code = sha384_generate_hash((const uint8_t*)servtd_hash_buff,
            num_servtds * sizeof(servtd_hash_buff_t),
            (uint64_t*)&tdcs_ptr->service_td_fields.servtd_hash);

        if (handle_avx_state)
        {
            load_ymms_from_buffer(ymms);
            basic_memset_to_zero(ymms, sizeof(ymms));
        }

        if (sha_error_code != 0)
        {
            // Unexpected error - Fatal Error
            TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
            FATAL_ERROR();
        }
    }
}

api_error_type check_cpuid_1f_and_compute_cpuid_0b(tdcs_t* tdcs_p, bool_t allow_null)
{
    uint32_t cpuid_0b_idx;
    cpuid_topology_level_type_e prev_level_type;
    cpuid_topology_level_type_e level_type = LEVEL_TYPE_INVALID;

    cpuid_config_return_values_t last_cpuid_values;
    uint32_t cpuid_0b_level = 0;

    cpuid_topology_shift_t cpuid_1f_eax;
    cpuid_topology_level_t cpuid_1f_ecx;

    bool_t null_config = false;
    bool_t core_level_scanned = false;

    // Scan the virtual CPUID(0x1F) sub-leaves

    for (uint32_t subleaf = 0; subleaf < LEVEL_TYPE_MAX; subleaf++)
    {
        uint32_t cpuid_1f_idx = get_cpuid_lookup_entry(CPUID_GET_TOPOLOGY_LEAF, subleaf);

        cpuid_config_return_values_t cpuid_values = tdcs_p->cpuid_config_vals[cpuid_1f_idx];

        // Null configuration case:  if all CPUID(0x1F) sub-leaves are configured as all-0, use the h/w values.
        // If the first subleaf is configured as 0, all the rest must be 0.
        if (subleaf == 0)
        {
            if ((cpuid_values.high == 0) && (cpuid_values.low == 0))
            {
                if (allow_null)
                {
                    null_config = true;
                }
                else
                {
                    return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
                }
            }
        }
        else if ((null_config) && (cpuid_values.high || cpuid_values.low))
        {
            return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
        }

        if (null_config)
        {
            cpuid_values = get_global_data()->cpuid_values[cpuid_1f_idx].values;

            tdcs_p->cpuid_config_vals[cpuid_1f_idx].low = cpuid_values.low;
            tdcs_p->cpuid_config_vals[cpuid_1f_idx].high = cpuid_values.high;
        }

        // We continue even if we use the h/w values, in order to set CPUID(0xB)
        cpuid_1f_eax.raw = cpuid_values.eax;
        cpuid_1f_ecx.raw = cpuid_values.ecx;

        prev_level_type = level_type;
        level_type = cpuid_1f_ecx.level_type;

        if (level_type != LEVEL_TYPE_INVALID)
        {
            // This is a valid sub-leaf.  Check that level type higher than the previous one
            // (initialized to INVALID, which is 0) but does not reach the max. Also check
            // that ECX provides the correct subleaf number.
            if ((level_type <= prev_level_type) || (level_type >= LEVEL_TYPE_MAX) || cpuid_1f_ecx.level_number != subleaf)
            {
                return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
            }

            if (level_type == LEVEL_TYPE_SMT)
            {
                // SMT level, if provided, must be at sub leaf 0
                if (subleaf != 0)
                {
                    return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
                }

                // CPUID(0x0B, 0) is the SMT level. It is identical to CPUID(0x1F) at the SMT level.
                cpuid_0b_idx = get_cpuid_lookup_entry(0xB, 0);
                tdcs_p->cpuid_config_vals[cpuid_0b_idx] = cpuid_values;

                cpuid_0b_level = 1;
            }
            else if (level_type == LEVEL_TYPE_CORE)
            {
                core_level_scanned = true;   // Prepare a flag for a sanity check later
            }

            last_cpuid_values = cpuid_values;
        }
        else  // level_type == CPUID_1F_ECX_t::INVALID
        {
            // The current sub-leaf is invalid, it marks the end of topology info.
            // Make sure we had at least one valid sub-leaf, otherwise CPUID leaf 1F is not configured properly.
            if (subleaf == 0)
            {
                return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
            }

            // Sanity check: core level must have been scanned
            if (!core_level_scanned)
            {
                return TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED;
            }
        }
    }

    // Generate virtual CPUID(0xB) values

    // Compute the CPUID(0x0B) core level.  EAX and EBX values are of the last valid level of CPUID(0x1F)
    cpuid_0b_idx = get_cpuid_lookup_entry(0xB, cpuid_0b_level);

    // ECX values:  sub-leaf and level type CORE
    cpuid_1f_ecx.raw = 0;
    cpuid_1f_ecx.level_number = cpuid_0b_level;
    cpuid_1f_ecx.level_type = LEVEL_TYPE_CORE;
    last_cpuid_values.ecx = cpuid_1f_ecx.raw;
    tdcs_p->cpuid_config_vals[cpuid_0b_idx] = last_cpuid_values;

    // Fill the next CPUID(0x0B) levels up to 2 as null, indicating last sub-leaf
    while (cpuid_0b_level < 2)
    {
        cpuid_0b_level++;
        cpuid_0b_idx = get_cpuid_lookup_entry(0xB, cpuid_0b_level);

        last_cpuid_values.eax = 0;
        last_cpuid_values.ebx = 0;

        // ECX values:  sub-leaf and level type INVALID
        cpuid_1f_ecx.raw = 0;
        cpuid_1f_ecx.level_number = cpuid_0b_level;
        cpuid_1f_ecx.level_type = LEVEL_TYPE_INVALID;
        last_cpuid_values.ecx = cpuid_1f_ecx.raw;

        basic_memset_to_zero((void*)&tdcs_p->cpuid_config_vals[cpuid_0b_idx], sizeof(cpuid_config_return_values_t));
    }

    return TDX_SUCCESS;
}
