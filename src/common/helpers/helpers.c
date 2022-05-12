// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file helpers.c
 * @brief Common TDX API flow helper functions
 */

#include "helpers.h"
#include "x86_defs/mktme.h"
#include "x86_defs/vmcs_defs.h"
#include "tdx_api_defs.h"
#include "auto_gen/cpuid_configurations.h"

#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/sept_manager.h"
#include "data_structures/td_vmcs_init.h"
#include "td_transitions/td_exit.h"
#include "td_dispatcher/tdx_td_dispatcher.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"

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
        if (get_global_data()->plt_common_config.ia32_tme_activate.mk_tme_crypto_algs_aes_xts_256)
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
        mktme_key_program.keyid_ctrl.enc_algo = AES_XTS_128_WITH_INTEGRITY;
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

    _ASM_VOLATILE_ ("cld\n"
                    "rep; stosb;"
                    :
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
        bool_t walk_to_leaf_size
        )
{
    // 1) Check that the operand’s HPA is within a TDMR (Trust Domain Memory Range) which is covered by a PAMT.
    if (!pamt_get_block(hpa, pamt_block))
    {
        TDX_ERROR("pamt_get_block error hpa = 0x%llx\n", hpa.raw);
        return TDX_OPERAND_ADDR_RANGE_ERROR;
    }

    page_size_t requested_leaf_size = *leaf_size;

    // 2) Find the PAMT entry for the page and verify that its metadata is as expected.
    pamt_entry_t* pamt_entry_lp = pamt_walk(hpa, *pamt_block, lock_type, leaf_size, walk_to_leaf_size);

    if (pamt_entry_lp == NULL)
    {
        TDX_ERROR("pamt_walk error\n");
        return TDX_OPERAND_BUSY;
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

api_error_code_e check_and_assign_hkid_to_hpa(tdr_t* tdr_p, pa_t hpa, pa_t* hpa_with_hkid)
{
    // Check that the HKID bits specified in the HPA (uppermost MK_TME_KEYID_BITS (N) bits) are all 0.

    if (get_hkid_from_pa(hpa) != 0)
    {
        return TDX_OPERAND_INVALID;
    }

    *hpa_with_hkid = assign_hkid_to_hpa(tdr_p, hpa);

    return TDX_SUCCESS;
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

    if (!is_valid_integer_range(seamrr_base, seamrr_size) ||
        !is_valid_integer_range(get_addr_from_pa(hpa), TDX_PAGE_SIZE_IN_BYTES) ||
        is_overlap(get_addr_from_pa(hpa), size, seamrr_base, seamrr_size))
    {
        return TDX_OPERAND_INVALID;
    }

    // 3) Check that HKID bits in the HPA are in the range configured for shared HKIDs (0 to MAX_MKTME_HKIDS – 1).

    if ((uint64_t)get_hkid_from_pa(hpa) > get_global_data()->max_mktme_hkids)
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
    page_size_t leaf_size;

    errc = check_and_lock_explicit_4k_private_hpa( hpa, operand_id,
             lock_type, expected_pt, pamt_block, pamt_entry, &leaf_size, is_locked);
    if (errc != TDX_SUCCESS)
    {
        return errc;
    }

    pa_t hpa_with_hkid;

    errc = check_and_assign_hkid_to_hpa(tdr_p, hpa, &hpa_with_hkid);

    if (errc != TDX_SUCCESS)
    {
        TDX_ERROR("check_and_assign_hkid_to_hpa failure\n");
        *is_locked = false;
        pamt_unwalk(hpa, *pamt_block, *pamt_entry, lock_type, leaf_size);
        return api_error_with_operand_id(errc, operand_id);
    }


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
            expected_pt, pamt_block, pamt_entry, leaf_size, walk_to_leaf_size);

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
        page_size_t* leaf_size,
        bool_t* is_locked
        )
{
    api_error_type errc;

    *leaf_size = PT_4KB;

    errc = check_and_lock_explicit_private_hpa(hpa, operand_id, _4KB, lock_type,
              expected_pt, pamt_block, pamt_entry, leaf_size, true, is_locked);

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
    pamt_entry_t* pamt_entry_lp = pamt_implicit_get_and_lock(tdr_pa, PT_4KB, lock_type);

    *pamt_entry = pamt_entry_lp;

    if (pamt_entry_lp == NULL)
    {
        TDX_ERROR("get_implicit_page_pamt_and_lock error\n");
        return api_error_with_operand_id(TDX_OPERAND_BUSY, operand_id);
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
        mapping_type_t mapping_type
        )
{
    uint16_t hkid = tdr_p->key_management_fields.hkid;

    // We don't map the last page (it's zero page for PASID usage), hence the MAX_NUM_TDCS_PAGES-1
    uint64_t tdcx_pa[MAX_NUM_TDCS_PAGES-1];

    for (uint32_t i = 0; i < MAX_NUM_TDCS_PAGES-1; i++)
    {
        tdcx_pa[i] = set_hkid_to_pa((pa_t)tdr_p->management_fields.tdcx_pa[i], hkid).raw;
    }

    return map_continuous_pages(tdcx_pa, MAX_NUM_TDCS_PAGES-1, mapping_type, STATIC_KEYHOLE_IDX_TDCS);
}

tdvps_t* map_tdvps(
        pa_t tdvpr_pa,
        uint16_t hkid,
        mapping_type_t mapping_type
        )
{
    tdvpr_pa.raw = set_hkid_to_pa(tdvpr_pa, hkid).raw;
    tdvps_t* tdvpr_lp = map_continuous_pages(&tdvpr_pa.raw, 1, mapping_type, STATIC_KEYHOLE_IDX_TDVPS);

    if (tdvpr_lp->management.num_tdvpx != (MAX_TDVPS_PAGES - 1))
    {
        TDX_ERROR("Num of TDVPX pages (%d) is incorrect\n", tdvpr_lp->management.num_tdvpx);
        free_la(tdvpr_lp);
        return NULL;
    }

    uint64_t tdvpx_pa[MAX_TDVPS_PAGES];

    // First TDVX PA is actually the PA of the TDVPR itself, since we already mapped it, it can be skipped
    for (uint32_t i = 1; i < MAX_TDVPS_PAGES; i++)
    {
        tdvpx_pa[i] = set_hkid_to_pa((pa_t)tdvpr_lp->management.tdvps_pa[i], hkid).raw;
    }

    map_continuous_pages(&tdvpx_pa[1], tdvpr_lp->management.num_tdvpx, mapping_type, STATIC_KEYHOLE_IDX_TDVPS + 1);

    return tdvpr_lp;
}

bool_t check_gpa_validity(
        pa_t gpa,
        bool_t gpaw,
        bool_t check_is_private
        )
{
    uint16_t gpa_width = gpaw ? 52 : 48;
    bool_t gpa_shared_bit = get_gpa_shared_bit(gpa.raw, gpaw);

    if (check_is_private && (gpa_shared_bit == true))
    {
        return false;
    }

    // Bits higher then MAX_PA except shared bit must be zero (bits above SHARED bit must be zero)
    if ((gpa.raw & ~BITS(MAX_PA-1,0)) != 0)
    {
        return false;
    }

    // When a TD is operating with GPAW 48, the CPU will treat bits 51:48 of every paging-structure
    // entry as reserved and will generate reserved-bit page fault upon encountering such an entry.
    if (!gpaw && (gpa.raw & BITS(MAX_PA-1, gpa_width)))
    {
        return false;
    }

    return true;
}

api_error_type lock_sept_check_and_walk_any_gpa(
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
    ia32e_eptp_t septp = tdcs_p->executions_ctl_fields.eptp;

    *is_sept_locked = false;

    if (acquire_sharex_lock(&tdcs_p->executions_ctl_fields.secure_ept_lock, lock_type) != LOCK_RET_SUCCESS)
    {
        return api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT);
    }

    ept_level_t requested_level = *level;

    *sept_entry_ptr = secure_ept_walk(septp, gpa, hkid, level, cached_sept_entry);

    if (*level != requested_level)
    {
        release_sharex_lock(&tdcs_p->executions_ctl_fields.secure_ept_lock, lock_type);
        free_la(*sept_entry_ptr);
        *sept_entry_ptr = NULL;
        return api_error_with_operand_id(TDX_EPT_WALK_FAILED, operand_id);
    }

    *is_sept_locked = true;
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
    bool_t gpaw = tdcs_p->executions_ctl_fields.gpaw;

    *is_sept_locked = false;

    if (!check_gpa_validity(gpa, gpaw, PRIVATE_ONLY))
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
    }

    return lock_sept_check_and_walk_any_gpa(tdcs_p, operand_id, gpa, hkid, lock_type,
            sept_entry_ptr, level, cached_sept_entry, is_sept_locked);
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
    ia32e_eptp_t septp = tdcs_p->executions_ctl_fields.eptp;

    ept_level_t requested_level = *level;

    *sept_entry_ptr = secure_ept_walk(septp, gpa, hkid, level, cached_sept_entry);

    if (*level != requested_level)
    {
        free_la(*sept_entry_ptr);
        *sept_entry_ptr = NULL;
        return TDX_EPT_WALK_FAILED;
    }

    return TDX_SUCCESS;
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

    if (!check_gpa_validity(gpa, gpaw, check_gpa_is_private))
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

    IF_RARE (walk_result == EPT_WALK_MISCONFIGURATION)
    {
        tdx_ept_misconfig_exit_to_vmm(gpa);
    }
    else IF_RARE (walk_result == EPT_WALK_VIOLATION)
    {
        vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };
        vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;

        tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qual.raw, 0);
    }
    else IF_RARE (walk_result == EPT_WALK_CONVERTIBLE_VIOLATION)
    {
        tdx_inject_ve(VMEXIT_REASON_EPT_VIOLATION, exit_qual.raw, tdvps_p, gpa.raw, 0);
        check_hw_exception();
        bus_lock_exit();
        tdx_return_to_td(true);
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

sept_entry_state get_sept_entry_state(ia32e_sept_t* sept_entry, ept_level_t level)
{
    if (sept_entry->present.rwx == 0x7)
    {
        return SEPTE_PRESENT;
    }

    sept_entry_state ret = SEPTE_FREE;

    if (sept_entry->fields_ps.tdb == 1)
    {
        ret |= SEPTE_BLOCKED;
    }

    if ((is_ept_leaf_entry(sept_entry, level)) &&
            ((level == LVL_PT) || (level == LVL_PD)) && (sept_entry->fields_4k.tdp == 1))
    {
        ret |= SEPTE_PENDING;
    }

    return ret;
}

api_error_code_e check_td_in_correct_build_state(tdr_t *tdr_p)
{
    if (tdr_p->management_fields.fatal)
    {
        return TDX_TD_FATAL;
    }
    if (tdr_p->management_fields.lifecycle_state != TD_KEYS_CONFIGURED)
    {
        return TDX_TD_KEYS_NOT_CONFIGURED;
    }
    if (!tdr_p->management_fields.init)
    {
        return TDX_TD_NOT_INITIALIZED;
    }
    return TDX_SUCCESS;
}

api_error_code_e associate_vcpu(tdvps_t * tdvps_ptr,
                                tdcs_t * tdcs_ptr,
                                tdr_t * tdr_ptr,
                                bool_t allow_disabled,
                                bool_t* new_association)
{
    uint32_t         prev_assoc_lpid;  // Previous associated LPID
    uint32_t         curr_lp_id = get_local_data()->lp_info.lp_id;
    uint16_t         curr_hkid;
    uint8_t          curr_vcpu_state = tdvps_ptr->management.state;
    pa_t             vmcs_addr;
    uint64_t         host_rsp;
    uint64_t         host_ssp;
    uint64_t         host_gs_base;
    api_error_code_e return_val = UNINITIALIZE_ERROR;

    /**
     *  Check the VCPU state to make sure it has been initialized and is not
     *  being torn down.  This may race with state changes if the VCPU is
     *  associated with another LP.  In this case the subsequent association
     *  below will fail
     */
    if (!(
          ((curr_vcpu_state & VCPU_READY) == VCPU_READY) ||
          ((curr_vcpu_state == VCPU_DISABLED) && allow_disabled)
         )
       )
    {
        return_val = TDX_VCPU_STATE_INCORRECT;
        goto EXIT;
    }

    /**
     *  Atomically check that this VCPU is not associated with any LP, and
     *  associate it with the current LP.  The VCPU may already be associated
     *  with the current LP, but if it's associated with another LP this is
     *  an error.
     */

    prev_assoc_lpid = _lock_cmpxchg_32b(VCPU_NO_LP, // Expected value: no lp
                                         curr_lp_id,  // New Value
                                         &tdvps_ptr->management.assoc_lpid); // Target
    if ((prev_assoc_lpid != (uint32_t)(~0)) && (prev_assoc_lpid != curr_lp_id))
    {
        return_val = TDX_VCPU_ASSOCIATED;
        goto EXIT;
    }

    // Association succeeded.  VCPU state must be VCPU_READY_*

    curr_hkid = tdr_ptr->key_management_fields.hkid;

    // Before loading the TD VMCS read/save SEAM VMCS LP-dependent host state fields
    if (prev_assoc_lpid == (uint32_t)(~0))
    {
        ia32_vmread(VMX_HOST_RSP_ENCODE, &host_rsp);
        ia32_vmread(VMX_HOST_SSP_ENCODE, &host_ssp);
        ia32_vmread(VMX_HOST_GS_BASE_ENCODE, &host_gs_base);
    }

    // Set the TD VMCS as the current VMCS
    vmcs_addr = set_hkid_to_pa((pa_t)tdvps_ptr->management.tdvps_pa[TDVPS_VMCS_PAGE_INDEX], curr_hkid);

    ia32_vmptrld((void*)vmcs_addr.raw);

    // If this is a new association, update TD VMCS
    if (prev_assoc_lpid == (uint32_t)(~0))
    {
        /**
         *  Check if the VCPU is associated with the current HKID.
         *  If not, update multiple TD VMCS physical address fields with the new HKID.
         */
        if (tdvps_ptr->management.assoc_hkid != (uint32_t)curr_hkid)
        {
            init_guest_td_address_fields(tdr_ptr, tdvps_ptr, curr_hkid);
        }
        /**
         *  Update the TD VMCS LP-dependent host state fields.
         *  Applicable fields are HOST_RSP, HOST_SSP and HOST_GS_BASE
         */
        ia32_vmwrite(VMX_HOST_RSP_ENCODE, host_rsp);
        ia32_vmwrite(VMX_HOST_SSP_ENCODE, host_ssp);
        ia32_vmwrite(VMX_HOST_GS_BASE_ENCODE, host_gs_base);

        // Atomically increment the number of associated VCPUs
        _lock_xadd_32b(&(tdcs_ptr->management_fields.num_assoc_vcpus), 1);

        *new_association = true;
    }
    else
    {
        *new_association = false;
    }

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}

void associate_vcpu_initial(tdvps_t * tdvps_ptr,
                            tdcs_t * tdcs_ptr,
                            tdr_t * tdr_ptr,
                            vmcs_host_values_t * host_values)
{
    uint32_t         curr_lp_id = get_local_data()->lp_info.lp_id;
    uint16_t         curr_hkid;
    pa_t             vmcs_addr;

    tdvps_ptr->management.assoc_lpid = curr_lp_id;


    curr_hkid = tdr_ptr->key_management_fields.hkid;

    // Set the TD VMCS as the current VMCS
    vmcs_addr = set_hkid_to_pa((pa_t)tdvps_ptr->management.tdvps_pa[TDVPS_VMCS_PAGE_INDEX], curr_hkid);

    ia32_vmptrld((void*)vmcs_addr.raw);

    /**
     *  Update multiple TD VMCS physical address fields with the new HKID.
     */
    init_guest_td_address_fields(tdr_ptr, tdvps_ptr, curr_hkid);

    /**
     *  Update the TD VMCS LP-dependent host state fields.
     *  Applicable fields are HOST_RSP, HOST_SSP and HOST_GS_BASE
     */
    ia32_vmwrite(host_values->RSP.encoding, host_values->RSP.value);
    ia32_vmwrite(host_values->SSP.encoding, host_values->SSP.value);
    ia32_vmwrite(host_values->GS_BASE.encoding, host_values->GS_BASE.value);

    // Atomically increment the number of associated VCPUs
    _lock_xadd_32b(&(tdcs_ptr->management_fields.num_assoc_vcpus), 1);
}

uint32_t get_cpuid_lookup_entry(uint32_t leaf, uint32_t subleaf)
{
    for (uint32_t i = 0; i < MAX_NUM_CPUID_LOOKUP; i++)
    {
        if (cpuid_lookup[i].leaf_subleaf.leaf == leaf &&
            (cpuid_lookup[i].leaf_subleaf.subleaf == (uint32_t)-1 ||
             cpuid_lookup[i].leaf_subleaf.subleaf == subleaf))
        {
            return i;
        }
    }
    return (uint32_t)-1;
}

uint32_t get_guest_td_cpl(void)
{
    uint64_t ss_arbyte;

    ia32_vmread(VMX_GUEST_SS_ARBYTE_ENCODE, &ss_arbyte);

    seg_arbyte_t arbyte = { .raw = (uint32_t)ss_arbyte };

    return arbyte.dpl;
}

void sept_split_entry(tdr_t* tdr_ptr, pa_t sept_page_pa, pa_t split_page_pa,
                      ia32e_sept_t* split_page_sept_entry, ept_level_t split_page_level_entry,
                      bool_t pending, bool_t suppress_ve)
{
    ALIGN(64) ia32e_sept_t sept_8_entries_chunk[8];
    ia32e_sept_t* sept_page_ptr;

    uint64_t page_size = ((split_page_level_entry == LVL_PDPT) ? _2MB : _4KB);
    sept_page_ptr = map_pa_with_hkid(sept_page_pa.raw_void,
                                     tdr_ptr->key_management_fields.hkid, TDX_RANGE_RW);

    for (uint32_t i = 0; i < NUM_CACHELINES_IN_PAGE; i++)
    {
        for (uint32_t j = 0; j < NUM_SEPT_ENTRIES_IN_CACHELINE; j++)
        {
            pa_t page_pa;

            page_pa.raw = split_page_pa.raw + (((i * 8) + j) * page_size);
            map_sept_leaf(&sept_8_entries_chunk[j], page_pa, pending, suppress_ve);
        }

        // Using MOVDIR64
        movdir64b((void*)sept_8_entries_chunk, (uint64_t)&sept_page_ptr[i*8]);

    }
    mfence();

    map_sept_non_leaf(split_page_sept_entry, sept_page_pa);

    free_la(sept_page_ptr);
}

bool_t is_sept_page_valid_for_merge(ia32e_paging_table_t* merged_sept_page_ptr,
                                    ept_level_t merged_sept_parent_level_entry)
{
    tdx_debug_assert(merged_sept_parent_level_entry != LVL_PT);
    ept_level_t leaf_entry_level = merged_sept_parent_level_entry - 1;

    uint64_t start_addr = leaf_ept_entry_to_hpa(merged_sept_page_ptr->sept[0], 0, leaf_entry_level);
    uint64_t merged_page_size = ((merged_sept_parent_level_entry == LVL_PDPT) ? _1GB : _2MB);
    uint64_t leaf_page_size = ((merged_sept_parent_level_entry == LVL_PDPT) ? _2MB : _4KB);

    if (!is_addr_aligned_pwr_of_2(start_addr, merged_page_size))
    {
        return false;
    }

    uint64_t prev_addr = start_addr;

    for (uint32_t i = 0; i < 512; i++)
    {
        ia32e_sept_t* current_sept = &merged_sept_page_ptr->sept[i];

        if (current_sept->present.rwx == 0 || !is_ept_leaf_entry(current_sept, leaf_entry_level))
        {
            return false;
        }

        uint64_t curr_addr = leaf_ept_entry_to_hpa(*current_sept, 0, leaf_entry_level);
        if ((i > 0) && (curr_addr != (prev_addr + leaf_page_size)))
        {
            return false;
        }

        prev_addr = curr_addr;
    }

    return true;
}

void inject_pf(uint64_t gla, pfec_t pfec)
{
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
        async_tdexit_to_vmm(TDX_NON_RECOVERABLE_VCPU, vm_exit_reason, 0, 0, 0, 0);
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

void set_arch_septe_details_in_vmm_regs(ia32e_sept_t ept_entry, ept_level_t level, tdx_module_local_t* local_data_ptr)
{
    ia32e_sept_t ept_entry_copy = {.raw = 0};
    sept_entry_state sept_state;
    sept_entry_arch_info_t info = {.raw = 0};
    bool_t is_leaf;

    sept_state = get_sept_entry_state(&ept_entry, level);
    is_leaf = is_ept_leaf_entry(&ept_entry, level);

    // Build the architectural representation of the Secure EPT entry
    ept_entry_copy.present.rwx = 0x7;
    ept_entry_copy.fields_4k.supp_ve = is_leaf ? ept_entry.fields_4k.supp_ve : (sept_state == SEPTE_FREE);

    if (sept_state != SEPTE_FREE)
    {
        ept_entry_copy.fields_ps.base = ept_entry.fields_ps.base;
        if (is_leaf)
        {
            ept_entry_copy.fields_4k.mt = MT_WB;
            ept_entry_copy.fields_4k.ipat = 1;
            ept_entry_copy.fields_4k.leaf = 1;
            if (sept_state == SEPTE_PENDING)
            {
                if (level == LVL_PD)
                {
                    // Cleanup leftover init counter
                    ept_entry_copy.accept.init_counter = 0;
                }
            }
        }
    }

    // Build the architectural information of the Secure EPT entry
    info.state = sept_state;
    info.level = level;

    // Return the values as simple 64b
    local_data_ptr->vmm_regs.rcx = ept_entry_copy.raw; // Secure EPT entry architectural content
    local_data_ptr->vmm_regs.rdx = info.raw; // Secure EPT entry information
}

cr_write_status_e write_guest_cr0(uint64_t value)
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
        return CR_WR_GP;
    }

    // The combination CR0.PE == 0 and CR0.PG == 1 is architecturally illegal
    if ((cr0.pe == 0) && (cr0.pg == 1))
    {
        TDX_LOG("MOV to CR0 - use illegal combination (0x%lx) - #GP", value);
        return CR_WR_GP;
    }

    // If the guest attempted to clear CR0.WP while CR4.CET is 1, throw a #GP(0)
    ia32_vmread(VMX_GUEST_CR4_ENCODE, &(cr4.raw));
    if ((cr4.cet == 1) && (cr0.wp == 0))
    {
        TDX_LOG("MOV to CR0 - illegal attempt to clear bit (0x%lx) - #GP", value);
        return CR_WR_GP;
    }

    //  If the guest attempted to change any CR0 bit that is owned by TDX-SEAM
    if ((cr0.pe == 0) ||
        (cr0.ne == 0) ||
        (cr0.nw == 1) ||
        (cr0.cd == 1) ||
        (cr0.reserved_3 != 0))
    {
        TDX_LOG("MOV to CR0 - other case (0x%lx) - #VE", value);
        return CR_WR_VE;
    }

    /* Update the value of guest CR0.
     * Values of bits 28-19, 17 and 15-6 left as they were before.
     */
    cr0.raw &= ~(uint64_t)CR0_IGNORED_MASK;
    uint64_t guest_cr0;
    ia32_vmread(VMX_GUEST_CR0_ENCODE, &guest_cr0);
    cr0.raw |= guest_cr0 & (uint64_t)CR0_IGNORED_MASK;
    ia32_vmwrite(VMX_GUEST_CR0_ENCODE, cr0.raw);

    return CR_WR_SUCCESS;
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
        return CR_WR_GP;
    }

    // If the guest attempted to set bits for features that are not enabled by XFAM,
    //   inject a #GP(0)
    ia32_xcr0_t cur_xfam;
    cur_xfam.raw = tdvps_p->management.xfam;
    if (((cur_xfam.pk == 0) && (cr4.pke == 1)) ||
        (((cur_xfam.cet_s == 0) || (cur_xfam.cet_u == 0)) && (cr4.cet == 1)) ||
        ((cur_xfam.uli == 0) && (cr4.uie == 1)))
    {
        TDX_LOG("MOV to CR4 - attempt to write features not enabled by XFAM (0x%lx) - #GP", value);
        return CR_WR_GP;
    }

    // If the guest attempted to set bits for features that are not enabled by ATTRIBUTES,
    // inject a #GP(0)
#if HSD1306130656_KL_SUPPORT
    if ((tdcs_p->executions_ctl_fields.attributes.kl == 0) && (cr4.keylocker == 1))
    {
        TDX_LOG("MOV to CR4 - keylocker not supported (0x%lx) - #GP", value);
        return CR_WR_GP;
    }
#else
    if (cr4.keylocker == 1)
    {
        TDX_LOG("MOV to CR4 - keylocker not supported (0x%lx) - #GP", value);
        return CR_WR_GP;
    }
#endif
    if ((tdcs_p->executions_ctl_fields.attributes.pks == 0) && (cr4.pks == 1))
    {
        TDX_LOG("MOV to CR4 - PKS not supported (0x%lx) - #GP", value);
        return CR_WR_GP;
    }

    // If the guest attempted to set CR4.CET while CR0.WP is 0, throw a #GP(0)
    ia32_vmread(VMX_GUEST_CR0_ENCODE, &(cr0.raw));
    if ((cr4.cet == 1) && (cr0.wp == 0))
    {
        TDX_LOG("MOV to CR4 - illegal attempt to clear bit (0x%lx) - #GP", value);
        return CR_WR_GP;
    }

    // In all other cases, inject a #VE
    TDX_LOG("MOV to CR4 - other case (0x%lx) - #VE", value);
    return CR_WR_VE;
}

cr_write_status_e write_guest_cr0_from_host(uint64_t value)
{
    uint64_t guest_host_mask;
    uint64_t read_shadow;

    ia32_vmread(VMX_CR0_GUEST_HOST_MASK_ENCODE, &guest_host_mask);
    ia32_vmread(VMX_CR0_READ_SHADOW_ENCODE, &read_shadow);

    if ((value & guest_host_mask) != (read_shadow & guest_host_mask))
    {
        // Attempt to modify host-owned bits
        return write_guest_cr0(value);
    }
    else
    {
        // Modify only guest-owned bits
        ia32_vmwrite(VMX_GUEST_CR0_ENCODE, value);
        return CR_WR_SUCCESS;
    }
}

cr_write_status_e write_guest_cr4_from_host(uint64_t value, tdcs_t* tdcs_p, tdvps_t* tdvps_t)
{
    uint64_t guest_host_mask;
    uint64_t read_shadow;

    ia32_vmread(VMX_CR4_GUEST_HOST_MASK_ENCODE, &guest_host_mask);
    ia32_vmread(VMX_CR4_READ_SHADOW_ENCODE, &read_shadow);

    if ((value & guest_host_mask) != (read_shadow & guest_host_mask))
    {
        // Attempt to modify host-owned bits
        return write_guest_cr4(value, tdcs_p,tdvps_t);
    }
    else
    {
        // Modify only guest-owned bits
        ia32_vmwrite(VMX_GUEST_CR4_ENCODE, value);
        return CR_WR_SUCCESS;
    }
}

bool_t check_xfam(uint64_t xfam_data)
{
    ia32_xcr0_t xfam = {.raw = xfam_data};
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    // Check that all bits set to 1 are allowed
    if ((xfam.raw &
         ~(TDX_XFAM_FIXED0 & (uint64_t)(tdx_global_data_ptr->xcr0_supported_mask |
                             tdx_global_data_ptr->ia32_xss_supported_mask))) != 0)
    {
        return false;
    }

    // Check that all bits set to 0 are allowed and check that all bit combinations are allowed
    if (((xfam.raw & TDX_XFAM_FIXED1) != TDX_XFAM_FIXED1) ||
        (xfam.avx3_kmask && !xfam.avx) ||         // AVX3 requires AVX
        (xfam.avx3_kmask != xfam.avx3_zmm_hi) ||  // All AVX3 bits must be the same
        (xfam.avx3_kmask != xfam.avx3_zmm) ||     // All AVX3 bits must be the same
        (xfam.cet_s != xfam.cet_u) ||             // All CET bits must be the same
        (xfam.amx_xtilecfg != xfam.amx_xtiledata))// All AMX bits must be the same
    {
        return false;
    }
    return true;
}

void send_self_ipi(ia32_apic_base_t apic_base, apic_delivery_mode_t delivery_mode, uint32_t vector)
{
    ia32_apic_icr_t icr;

    icr.raw = 0;
    icr.delivery_mode = delivery_mode;
    icr.dest_shorthand = DEST_SHORTHAND_NONE;
    icr.vector = vector;

    if (apic_base.extd != 0) // Bit 10 is extend bit
    {
        // APIC works in x2APIC mode (MSR access). APIC ID is 32 bits.
        if (delivery_mode == APIC_DELIVERY_FIXED)
        {
            ia32_wrmsr(IA32_X2APIC_EOI, 0);
        }

        icr.x2apic_dest_field = ia32_rdmsr(IA32_X2APIC_APICID) & BIT_MASK_32BITS;

        ia32_wrmsr(IA32_X2APIC_ICR, icr.raw);
    }
    else
    {
        // APIC works in xAPIC mode (MMIO access)
        // APIC ID is 8 bits; the caller has verified that maximum APIC ID on the platform fits in 8 bits.

        volatile tdvps_vapic_t* apic_p;
        apic_p = (tdvps_vapic_t*)map_pa_non_wb((void*)(apic_base.apic_base << 12), TDX_RANGE_RW);

        if (delivery_mode == APIC_DELIVERY_FIXED)
        {
            *((uint32_t*)(&apic_p->apic[APIC_MMIO_EOI_OFFSET])) = (uint32_t)0;
        }

        ia32_xapic_id_t xapic_id;
        xapic_id.raw = *((uint32_t*)(&apic_p->apic[APIC_MMIO_APICID_OFFSET]));

        icr.xapic_dest_field = xapic_id.apic_id;

        // The high part should be written first
        *((volatile uint32_t*)(&apic_p->apic[APIC_MMIO_ICR_HIGH_OFFSET])) = icr.raw_high;
        *((volatile uint32_t*)(&apic_p->apic[APIC_MMIO_ICR_LOW_OFFSET]))  = icr.raw_low;

        free_la((void*)apic_p);
    }
}

bool_t lfsr_init_seed (uint32_t* lfsr_value)
{
    uint64_t rand;
    ia32_rflags_t rflags = {.raw = 0};

    if (!ia32_rdrand(&rflags, &rand))
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

        if ((tme_activate.mk_tme_crypto_algs_aes_xts_256 == 0) &&
            (tme_activate.mk_tme_crypto_algs_aes_xts_128 == 0))
        {
            return IA32_TME_ACTIVATE_MSR_ADDR;
        }
    }
    else
    {
        if (tme_capability.aes_xts_128_with_integrity == 0)
        {
            return IA32_TME_CAPABILITY_MSR_ADDR;
        }
        if (tme_activate.mk_tme_crypto_algs_aes_xts_128_with_integrity == 0)
        {
            return IA32_TME_ACTIVATE_MSR_ADDR;
        }
    }

    return 0;
}

