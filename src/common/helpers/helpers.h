// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file helpers.h
 * @brief Common TDX API flow helper functions
 */

#ifndef SRC_COMMON_HELPERS_HELPERS_H_
#define SRC_COMMON_HELPERS_HELPERS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "tdx_api_defs.h"
#include "x86_defs/x86_defs.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "data_structures/td_vmcs_init.h"
#include "error_reporting.h"

#define PRIVATE_ONLY true
#define PRIVATE_OR_SHARED false
#define NUM_OF_BHB_CLEARING_ITERATIONS 32 // 194 branch stews in BHB, NUM_ITERS = round-up(194 / 6) = 32

/**
 * @brief Program MKTME keys using PCONFIG
 *
 * @param command - MKTME program command to pass to PCONFIG
 * @param key_info_ptr - Points to a key info struct that holds the rest
 *                       of the required MKTME program info
 *                       - i.e. hkid, encryption algo and keys
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e program_mktme_keys(uint16_t hkid);

_STATIC_INLINE_ uint64_t construct_wrmsr_value(uint64_t rdx, uint64_t rax)
{
    return ((rdx << 32) | (rax & BIT_MASK_32BITS));
}

_STATIC_INLINE_ bool_t are_gpa_bits_above_shared_set(uint64_t gpa, bool_t gpaw, uint64_t max_pa)
{
    uint16_t gpa_width = gpaw ? 52 : 48;

    if (max_pa > (uint64_t)gpa_width)
    {
        return ((gpa & BITS(max_pa-1, gpa_width)) != 0);
    }

    return false;
}

_STATIC_INLINE_ bool_t get_gpa_shared_bit(uint64_t gpa, bool_t gpaw)
{
    uint16_t gpa_width_minus_1 = gpaw ? 51 : 47;

    // When TD is configured with a 4 level EPT then the S bit is always bit 47 of the GPA.
    // When a TD is configured with 5 level EPT then the S bit is in bit 47 if GPAW
    // is configured to be 48, else it is bit 51.

    return (gpa & BIT(gpa_width_minus_1)) != 0;
}


_STATIC_INLINE_ uint64_t get_addr_from_pa(pa_t pa)
{
    return pa.full_pa & ~(get_global_data()->hkid_mask);
}

_STATIC_INLINE_ uint16_t get_hkid_from_pa(pa_t pa)
{
    tdx_module_global_t* global_data = get_global_data();

    return (uint16_t)((pa.full_pa & global_data->hkid_mask) >> global_data->hkid_start_bit);
}

_STATIC_INLINE_ pa_t set_hkid_to_pa(pa_t pa, uint16_t hkid)
{
    tdx_module_global_t* global_data = get_global_data();

    pa.full_pa &= ~(global_data->hkid_mask);
    pa.full_pa |= ((uint64_t)hkid << global_data->hkid_start_bit);

    return pa;
}

_STATIC_INLINE_ bool_t is_addr_aligned_pwr_of_2(uint64_t addr, uint64_t size)
{
    tdx_debug_assert((size > 1) && ((size & (size - 1)) == 0));
    return ((addr & (size - 1)) == 0);
}

_STATIC_INLINE_ bool_t is_addr_aligned_any(uint64_t addr, uint64_t size)
{
    tdx_debug_assert(size > 0);
    return ((addr % size) == 0);
}

_STATIC_INLINE_ bool_t is_gpa_aligned(page_info_api_input_t gpa_mappings)
{
    uint64_t page_gpa = gpa_mappings.gpa << 12;
    uint64_t alignment = (1ULL) << (12 + (gpa_mappings.level * 9));

    return is_addr_aligned_pwr_of_2(page_gpa, alignment);
}

_STATIC_INLINE_ bool_t is_private_hkid(uint16_t hkid)
{
    return ((uint32_t)hkid >= get_global_data()->private_hkid_min &&
            (uint32_t)hkid <= get_global_data()->private_hkid_max);
}

_STATIC_INLINE_ bool_t is_pa_smaller_than_max_pa(uint64_t pa)
{
    return (pa < BIT(MAX_PA));
}

_STATIC_INLINE_ bool_t is_valid_integer_range(uint64_t base, uint64_t size)
{
    return (base <= (MAX_UINT64 - size));
}

_STATIC_INLINE_ bool_t is_overlap(uint64_t base, uint64_t size, uint64_t base2, uint64_t size2)
{
    // Check for integer overflow - in all calls to is_overlap, the ranges should be checked
    // before, and create an appropriate error, if the FATAL ERROR is not desired
    // The check here is for DiD only, not functionality
    IF_RARE (!is_valid_integer_range(base, size) || !is_valid_integer_range(base2, size2))
    {
        FATAL_ERROR();
    }

    if ((base >= (base2 + size2)) || (base2 >= (base + size)))
    {
        return false;
    }
    return true;
}

_STATIC_INLINE_ uint64_t mask_to_size(uint64_t mask)
{
    return BIT(bit_scan_forward64(mask));
}

_STATIC_INLINE_ bool_t is_reserved_zero_in_mappings(page_info_api_input_t mappings)
{
    return !(mappings.reserved_0 || mappings.reserved_1);
}

_STATIC_INLINE_ void* map_pa_with_hkid(void* pa, uint16_t hkid, mapping_type_t mapping_type)
{
    pa_t temp_pa = {.raw_void = pa};
    pa_t pa_with_hkid = set_hkid_to_pa(temp_pa, hkid);
    return map_pa((void*) pa_with_hkid.raw, mapping_type);
}

_STATIC_INLINE_ void* map_pa_with_global_hkid(void* pa, mapping_type_t mapping_type)
{
    uint16_t tdx_global_hkid = get_global_data()->hkid;
    return map_pa_with_hkid(pa, tdx_global_hkid, mapping_type);
}

/**
 * @brief Get HPA from EPT entry and GPA
 *
 * @param entry - EPT entry for this GPA
 * @param gpa - GPA
 * @param level - EPT entry level
 *
 * @return Address of HPA
 */
_STATIC_INLINE_ uint64_t leaf_ept_entry_to_hpa(ia32e_sept_t entry, uint64_t gpa, ept_level_t level)
{
    switch(level)
    {
        case LVL_PT:
        {
            return ((entry.fields_4k.base << IA32E_4K_PAGE_OFFSET) | (gpa & IA32E_4K_OFFSET));
        }
        case LVL_PD:
        {
            return (((uint64_t)(entry.fields_2m.base) << IA32E_2M_PAGE_OFFSET) | (gpa & IA32E_2M_OFFSET));
        }
        case LVL_PDPT:
        {
            return (((uint64_t)(entry.fields_1g.base) << IA32E_1G_PAGE_OFFSET) | (gpa & IA32E_1G_OFFSET));
        }
        default:
        {
            // Not supported
            tdx_sanity_check(0, SCEC_HELPERS_SOURCE, 0);
            return 0;
        }
    }
}

/**
 * @brief Calculate the offset and the mask
 *
 * @param offset - the calculated offset
 * @param rd_mask - the calculated mask
 * @param addr - address of the relevant field
 * @param size - size of the relevant field
 */
_STATIC_INLINE_ void calc_offset_and_mask(uint64_t* offset, uint64_t* rd_mask, uint64_t addr, uint64_t size)
{
    *offset = addr;
    *rd_mask = BITS((8*size - 1), 0);
}

/**
 * @brief Memset functions that use basic memory access (not direct access with MOVDIR64)
 *
 */
void basic_memset(uint64_t dst, uint64_t dst_bytes, uint8_t val, uint64_t nbytes);
void basic_memset_to_zero(void * dst, uint64_t nbytes);

/**
 * @brief Copies source to destination using movdir64b
 *
 * Source, destination and size need to be cache aligned (64 byte)
 * Uses lfence between movdir64b calls
 *
 * @param src - Source address
 * @param dst - Destination address
 * @param size - Size in bytes to copy
 *
 * @return Address of HPA
 */
void cache_aligned_copy_direct(uint64_t src, uint64_t dst, uint64_t size);

_STATIC_INLINE_ bool_t is_cacheline_aligned(void* dst)
{
    return (((uint64_t)dst % MOVDIR64_CHUNK_SIZE) == 0);
}

/**
 * @brief Fill cache lines with movdir64 using cache aligned & sized chunks
 *
 * @note dst address must be aligned to cache line
 * @note cacheline_with_value must be aligned to cache line
 *
 * @param dst destination address
 * @param cacheline_with_value a cache line aligned and sized array with a value
 * @param num_of_cachelines number of cache lines to write to in dst
 */
_STATIC_INLINE_ void fill_cachelines_no_sfence(void* dst, uint8_t* cacheline_with_value, uint64_t num_of_cachelines)
{
    tdx_debug_assert(((uint64_t)dst % MOVDIR64_CHUNK_SIZE) == 0);
    tdx_debug_assert(((uint64_t)cacheline_with_value % MOVDIR64_CHUNK_SIZE) == 0);
    uint64_t tmp_dst = (uint64_t)dst;

    for (uint64_t i = 0; i < num_of_cachelines; i++, tmp_dst+=MOVDIR64_CHUNK_SIZE)
    {
        movdir64b(cacheline_with_value, tmp_dst);
    }
}

/**
 * @brief Fill cache lines with movdir64 using cache aligned & sized chunks
 *
 * @note dst address must be aligned to cache line
 * @note cacheline_with_value must be aligned to cache line
 *
 * @param dst destination address
 * @param cacheline_with_value a cache line aligned and sized array with a value
 * @param num_of_cachelines number of cache lines to write to in dst
 */
_STATIC_INLINE_ void fill_cachelines(void* dst, uint8_t* cacheline_with_value, uint64_t num_of_cachelines)
{
    fill_cachelines_no_sfence(dst, cacheline_with_value, num_of_cachelines);
    mfence();
}

/**
 * @brief Fill memory area using movdir64
 *
 * @note dst address must be aligned to cache line
 * @note nBytes size must be in complete cache lines
 * @note val64 value to be filled
 *
 * @param dst
 * @param nBytes
 */
_STATIC_INLINE_ void fill_area_cacheline(void* dst, uint64_t nBytes, uint64_t val64)
{
    tdx_debug_assert((nBytes % MOVDIR64_CHUNK_SIZE == 0));
    tdx_debug_assert((uint64_t)dst % MOVDIR64_CHUNK_SIZE == 0);

    // create a cache aligned, cache sized chunk and fill it with 'val'
    ALIGN(MOVDIR64_CHUNK_SIZE) uint64_t chunk[MOVDIR64_CHUNK_SIZE / sizeof(uint64_t)];

    for (uint32_t i = 0; i < MOVDIR64_CHUNK_SIZE / sizeof(uint64_t); i++)
    {
        chunk[i] = val64;
    }

    fill_cachelines(dst, (uint8_t*)chunk, nBytes/MOVDIR64_CHUNK_SIZE);
}

/**
 * @brief Zero memory area using movdir64
 *
 * @note nBytes size must be in complete cache lines
 * @note dst address must be aligned to cache line
 *
 * @param dst
 * @param nBytes
 */
_STATIC_INLINE_ void zero_area_cacheline(void* dst, uint64_t nBytes)
{
    fill_area_cacheline(dst, nBytes, 0);
}

_STATIC_INLINE_ void zero_cacheline(void* dst)
{
    fill_area_cacheline(dst, MOVDIR64_CHUNK_SIZE, 0);
}

_STATIC_INLINE_ void tdx_memcpy(void * dst, uint64_t dst_bytes, void * src, uint64_t nbytes)
{
    volatile uint64_t junk_a, junk_b;

    tdx_sanity_check (dst_bytes >= nbytes, SCEC_HELPERS_SOURCE, 1);

    _ASM_VOLATILE_ ("rep; movsb;"
                    :"=S"(junk_a), "=D"(junk_b)
                    :"c"(nbytes), "S"(src), "D"(dst)
                    :"memory");
}

_STATIC_INLINE_ bool_t tdx_memcmp(void * a, void * b, uint64_t nbytes)
{
    ia32_rflags_t rflags;
    uint64_t junk_a, junk_b;
    _ASM_VOLATILE_ ("repe; cmpsb;"
                    "pushfq\n"
                    "popq %0"
                    : "=r"(rflags.raw), "=S"(junk_a), "=D"(junk_b)
                    :"c"(nbytes), "S"(b), "D"(a)
                    :"memory");
    if (rflags.zf == 0)
    {
        return false;
    }
    return true;
}

_STATIC_INLINE_ bool_t tdx_memcmp_to_zero(void *a, uint64_t nBytes)
{
    uint64_t i = 0;
    uint8_t* a_8 = (uint8_t*)a;

    for ( ; (i + (uint64_t)sizeof(uint64_t)) <= nBytes; i += (uint64_t)sizeof(uint64_t))
    {
        uint64_t* a_64 = (uint64_t*)(&a_8[i]);

        if (*a_64 != 0)
        {
            return false;
        }
    }

    for ( ; i < nBytes; i++)
    {
        if (a_8[i] != 0)
        {
            return false;
        }

    }

    return true;
}

/**
 * @brief Invalidate cache lines using CLFLUSHOPT
 *
 * @note Assuming addr is cache aligned and size is cache line size divisible
 *
 * @param start_addr - Start address (cache aligned) of memory we want to invalidate (linear address)
 * @param size - Size of memory to invalidate
 *
 * @return None
 */
_STATIC_INLINE_ void invalidate_cache_lines(uint64_t start_addr, uint64_t size)
{
    // CLFLUSHOPT works on cache lines
    uint64_t num_of_cache_lines = (size/CACHELINE_SIZE);

    for (uint64_t i = 0; i < num_of_cache_lines; i++)
    {
        ia32_clflushopt((void *)start_addr);
        start_addr += (uint64_t)CACHELINE_SIZE;
    }
    mfence();
}

/*
 * Access semantics internal helpers:
 */

/**
 * @brief PAMT walk and check for non-shared HPA semantics
 *
 *  1) Check that the operand’s HPA is within a TDMR (Trust Domain Memory Range) which is covered by a PAMT.
 *  2) Find the PAMT entry for the page and verify that its metadata is as expected.
 *  3) If asked by walk_to_leaf_size, will also check if a correct leaf was reached
 *
 * @param hpa - HPA that needs to be checked
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param pamt_block - Returns the the pamt_block virtual structure that covers the HPA
 * @param pamt_entry - Returns the linear pointer to the pamt_entry that belongs to the HPA
 * @param leaf_size  - Returns the PAMT leaf size of the HPA entry
 * @param walk_to_leaf_size - If it is true, leaf_size is used as an input too, and PAMT walk stops at that level
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e non_shared_hpa_metadata_check_and_lock(
        pa_t hpa,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        page_size_t*   leaf_size,
        bool_t walk_to_leaf_size
        );

/**
 * @brief Assigns the HKID from given TDR to the given HPA
 *
 *  1) If the target page is TDR (given TDR pointer is NULL), then use the TDX-SEAM global private HKID.
 *  2) Else, read the HKID value associated with the TD from the TDR page.
 *
 * @note If the TDR is not NULL - function assumes that it is already assigned with the HKID
 *
 * @param tdr_p Linear pointer to TDR where HKID will be taken from. If it's NULL then TDX-SEAM global
 *              private HKID will be used
 * @param hpa HPA to which the HKID will be assigned to
 * @return HPA with the assigned HKID
 */
pa_t assign_hkid_to_hpa(tdr_t* tdr_p, pa_t hpa);


/**
 * @brief Checks the HPA to have zeroed HKID, and assigns the HKID from given TDR to the given HPA
 *
 *  1) Check that the HKID bits specified in the HPA (uppermost MK_TME_KEYID_BITS (N) bits) are all 0.
 *  2) If the target page is TDR (given TDR pointer is NULL), then use the TDX-SEAM global private HKID.
 *  3) Else, read the HKID value associated with the TD from the TDR page.
 *
 * @param tdr_p Linear pointer to TDR where HKID will be taken from. If it's NULL then TDX-SEAM global
 *              private HKID will be used
 * @param hpa HPA which will be checked, and to which the HKID will be assigned to
 * @param hpa_with_hkid
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e check_and_assign_hkid_to_hpa(tdr_t* tdr_p, pa_t hpa, pa_t* hpa_with_hkid);

/**
 * @brief Check the HPA for shared access semantics
 *
 *  1) Check that the provided HPA is outside SEAMRR.
 *  2) Check that HKID bits in the HPA are in the range configured for shared HKIDs (0 to MAX_MKTME_HKIDS – 1).
 *
 * @param hpa HPA to be checked
 * @param size of the HPA
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e shared_hpa_check(pa_t hpa, uint64_t size);

/**
 * @brief Adds alignment check with power of 2 size to shared_hpa_check
 *
 * @param hpa HPA to be checked
 * @param size Size to be aligned with (MUST be power of 2)
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e shared_hpa_check_with_pwr_2_alignment(pa_t hpa, uint64_t size);

/**
 * @brief Adds alignment check with power of 2 size to hpa_check
 *
 * @param hpa HPA to be checked
 * @param size Size to be aligned with (MUST be power of 2)
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e hpa_check_with_pwr_2_alignment(pa_t hpa, uint64_t size);

/*
 * Explicit access semantics helpers:
 */

/**
 * @brief Check the HPA for shared access semantics, and maps it to LA in TDX-SEAM module address space.
 *
 * @param hpa HPA to be checked
 * @param mapping_type - If write access is required
 * @param la Returns mapped linear address of the HPA. Should be freed after use.
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e check_and_map_explicit_shared_hpa(pa_t hpa, mapping_type_t mapping_type, void** la);

/**
 * @brief Check an explicit TDR operand for opaque access semantics, given its HPA, get and
 *        lock its PAMT block & entry and map to LA in the TDX-SEAM module address space.
 *
 * @note  Expected page size is 4KB.
 *
 * @param tdr_hpa - Physical address of the TDR page
 * @param operand_id - Operand ID number
 * @param mapping_type - If write access is required
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type - should be either PT_NDA during
 *                      TDR creation, or PT_TDR for everything else.
 * @param pamt_block - Returns the virtual pamt_block structure that covers the HPA
 * @param pamt_entry - Returns the pointer to the pamt_entry that belongs to the HPA
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 * @param tdr_p      - Returns the linear pointer to the TDR page. Should be freed after use.
 *
 * @return Error code that states the reason of failure
 */
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
        );

/**
 * @brief Check an explicit 4KB page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry, and map to LA in the TDX-SEAM module address space.
 *
 * @note  Expected page size is 4KB.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param tdr_p - Linear pointer to the TDR page
 * @param mapping_type - If write access is required
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param pamt_block - Returns the virtual pamt_block structure that covers the HPA
 * @param pamt_entry - Returns the linear pointer to the pamt_entry that belongs to the HPA
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 * @param la         - Returns mapped linear address of the HPA. Should be freed after use.
 *
 * @return Error code that states the reason of failure
 */
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
        );

/**
 * @brief Check an explicit page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param alignment - the hpa alignment
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param pamt_block - Returns the virtual pamt_block structure that covers the HPA
 * @param pamt_entry - Returns the linear pointer to the pamt_entry that belongs to the HPA
 * @param leaf_size  - Returns the PAMT leaf size of the HPA entry
 * @param walk_to_leaf_size - If it is true, leaf_size is used as an input too, and PAMT walk stops at that level
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 *
 * @return Error code that states the reason of failure
 */
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
        );

/**
 * @brief Check an explicit page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param expected_pt - Check the found PAMT entry against that type
 * @param pamt_block - Returns the virtual pamt_block structure that covers the HPA
 * @param pamt_entry - Returns the linear pointer to the pamt_entry that belongs to the HPA
 * @param leaf_size  - Returns the PAMT leaf size of the HPA entry
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_and_lock_explicit_4k_private_hpa(
        pa_t hpa,
        uint64_t operand_id,
        lock_type_t lock_type,
        page_type_t expected_pt,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        page_size_t* leaf_size,
        bool_t* is_locked
        );

/**
 * @brief Check an explicit page operand for non-shared access semantics, given it HPA, get and
 *        lock its PAMT block & entry.
 *
 * @param hpa - HPA that needs to be checked
 * @param operand_id - Operand ID number
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param range_size - Desired range size to check and lock. Should be only 4KB or 2MB.
 * @param pamt_block - Returns the virtual pamt_block structure that covers the HPA
 * @param pamt_entry - Returns the linear pointer to the pamt_entry that belongs to the HPA
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 *
 * @return Error code that states the reason of failure
 */
api_error_type check_and_lock_free_range_hpa(
        pa_t hpa,
        uint64_t operand_id,
        lock_type_t lock_type,
        page_size_t range_size,
        pamt_block_t* pamt_block,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked
        );

/**
 * @brief Checks a GPA validity, including the shared bit
 * @param gpa - GPA that will ne checked
 * @param gpaw - Value of the GPAW of the current TDCS
 * @param check_is_private - Flag to determine whether the GPA will be checked as private GPA
 *                           Use with PRIVATE_ONLY or PRIVATE_OR_SHARED defines.
 * @return true if the GPA is valid, otherwise false
 */
bool_t check_gpa_validity(
        pa_t gpa,
        bool_t gpaw,
        bool_t check_is_private
        );

/**
 * @brief Checks a GPA to be valid, and GPA.SHARED bit == 0, translates it and returns requested
 *        EPT entry, and the reached walking level.
 *
 * @note Function takes an exclusive lock over SEPT (TDCS.SEPT_LOCK). Lock should be freed after
 *       the returned EPT entry is no longer used.
 *
 * @param tdcs_p - Linear pointer to the TDCS - used to get GPAW, SEPTP and acquire SEPT lock.
 * @param operand_id - Operand ID number
 * @param gpa - GPA - Guest Physical Address that needs to be checked and translated.
 * @param hkid - HKID to be used during the SEPT page walk (accesses to SEPT entries)
 * @param lock_type - Type of lock to take on the SEPT lock
 * @param sept_entry - Returns a linear pointer to the SEPT entry at the requested level.
 *                     Returns NULL if walk failed and didn't reach the requested level.
 *                     Should be freed after finishing using it (only on success).
 * @param level - Request walk level, at which the walking should stop. Returns a higher level if
 *                the walk failed from any reason and couldn't reach the requested level.
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 * @param is_sept_locked - A boolean flag indicating if the TDCS.SEPT_LOCK was exclusively taken.
 *
 * @return Error code that states the reason of failure
 */
api_error_type lock_sept_check_and_walk_private_gpa(
        tdcs_t* tdcs_p,
        uint64_t operand_id,
        pa_t gpa,
        uint16_t hkid,
        lock_type_t lock_type,
        ia32e_sept_t** sept_entry,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry,
        bool_t* is_sept_locked
        );

/**
 * @brief Same as lock_sept_check_and_walk_private_gpa, but doesn't check GPA validity
 *
 */
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
        );


/**
 * @brief Translates the GPA and returns requested EPT entry, and the reached walking level.
 *
 * @param tdcs_p - Linear pointer to the TDCS - used to get GPAW, SEPTP and acquire SEPT lock.
 * @param gpa - GPA - Guest Physical Address that needs to be checked and translated.
 * @param hkid - HKID to be used during the SEPT page walk (accesses to SEPT entries)
 * @param sept_entry - Returns a linear pointer to the SEPT entry at the requested level.
 *                     Returns NULL if walk failed and didn't reach the requested level.
 *                     Should be freed after finishing using it (only on success).
 * @param level - Request walk level, at which the walking should stop. Returns a higher level if
 *                the walk failed from any reason and couldn't reach the requested level.
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 *
 * @return Error code that states the reason of failure
 */
api_error_type walk_private_gpa(
        tdcs_t* tdcs_p,
        pa_t gpa,
        uint16_t hkid,
        ia32e_sept_t** sept_entry,
        ept_level_t* level,
        ia32e_sept_t* cached_sept_entry
        );

/**
 * @brief Checks a GPA to be valid, if shared bit is 1, walks the shared EPT (taken from the TD VMCS)
 *        Else walk the SEPT and finally maps the translated GPA
 *
 * @param tdcs_p Linear pointer to the TDCS - used to get GPAW and SEPTP
 * @param tdvps_p Linear pointer to the TDVPS - used for #VE if required
 * @param gpa GPA - Guest Physical Address that needs to be checked and translated.
 * @param hkid HKID to be used during the SEPT page walk (accesses to SEPT entries)
 * @param mapping_type RW access to mapped linear address
 * @param check_gpa_is_private - if true, check that gpa is private. otherwise, it can be private or shared (don't care).
 * @param la Pointer to linear address mapped from translated GPA
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e check_walk_and_map_guest_side_gpa(
        tdcs_t* tdcs_p,
        tdvps_t* tdvps_p,
        pa_t gpa,
        uint16_t hkid,
        mapping_type_t mapping_type,
        bool_t check_gpa_is_private,
        void ** la
        );

/**
 * @brief Returns the state of the SEPT entry.
 *
 * @param sept_entry - Linear pointer to the SEPT entry
 * @param level - Level of the SEPT entry
 *
 * @return SEPT entry state
 */
sept_entry_state get_sept_entry_state(ia32e_sept_t* sept_entry, ept_level_t level);


/*
 * Implicit access semantics helpers:
 */

/**
 * @brief Lock an implicit TDR and map as a linear address in the TDX-SEAM module address space.
 *
 * @param tdr_pa - Physical address of the TDR page
 * @param operand_id - Operand ID number
 * @param mapping_type - If write access is required
 * @param lock_type - What type of lock to take on the PAMT leaf entry
 * @param pamt_entry - Returns the linear pointer to the pamt_entry that belongs to the PA
 * @param is_locked  - Returns TRUE if the lock on PAMT was taken
 * @param tdr_p      - Returns the linear pointer to the TDR page
 *
 * @return Error code that states the reason of failure
 */
api_error_type lock_and_map_implicit_tdr(
        pa_t tdr_pa,
        uint64_t operand_id,
        mapping_type_t mapping_type,
        lock_type_t lock_type,
        pamt_entry_t** pamt_entry,
        bool_t* is_locked,
        tdr_t** tdr_p
        );

/**
 * @brief Map an implicit multi-page TDCS, as a single contiguous structure in the linear
 *        address space of the TDX-SEAM module.
 *        The function retrieves the physical addresses of the TDCS pages from the TDCS_PA
 *        array in the TDR page.
 *
 * @param tdr_p - Linear pointer to the TDR page
 * @param mapping_type - If write access is required
 *
 * @return Returns the linear pointer to the TDCS structure
 */
tdcs_t* map_implicit_tdcs(
        tdr_t* tdr_p,
        mapping_type_t mapping_type
        );

/**
 * @brief Map a multi-page TDVPS, composed of a TDVPR page and multiple TDVPX pages, as a single
 *        contiguous structure in the linear address space of the TDX-SEAM module.
 *        The function works as follows:
 *        - Map the root TDVPR page
 *        - Check that the required number of TDVPX pages have been allocated (NUM_TDVPX != TDVPS_PAGES - 1)
 *          If not, return NULL.
 *        - Retrieve the physical addresses of the TDVPX pages from the TDVPS_PAGE_PA
 *          array in the root page of TDVPS.
 *
 * @param tdvpr_pa - Physical address of the TDVPR page
 * @param hkid - TD ephemeral HKID
 * @param mapping_type - If write access is required
 *
 * @return Returns the linear pointer to the TDVPS structure
 */
tdvps_t* map_tdvps(
        pa_t tdvpr_pa,
        uint16_t hkid,
        mapping_type_t mapping_type
        );


/**
 * @brief Check that TD is in build phase
 *
 * Check for TDR fatal, init and keys state
 *
 * @param tdr_p - Pointer the checked, locked and mapped TDR
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e check_td_in_correct_build_state(tdr_t *tdr_p);


uint8_t get_max_physical_address_space_bits(void);


/**
 * @brief Associate a VCPU with the current LP
 *
 * Check that the VCPU has been initialized and is not being torn down
 * - Atomically check that the VCPU is not associated with another LP and
 *   associate it with the current LP
 * - Do VMPTRLD of TD VMCS.
 * - If newly associated, update all LP-dependent host state fields
 * - If HKID changed, update all physical address fields
 * Exit with an ERROR if the VCPU is already associated with another LP.
 *
 * @param tvps_ptr - Pointer to a checked, locked and mapped TDVPS
 * @param tdcs_ptr - Pointer to a mapped TDCS
 * @param tdr_ptr - Pointer to a locked and mapped TDR
 * @param allow_disabled - Flag that indicates if disabled VCPU needs to be associated
 * @param association_flag - Pointer to a flag to indicate if it is a new association
 *
 * @return Error code that states the reason of failure
 */
api_error_code_e associate_vcpu(tdvps_t * tdvps_ptr,
                                tdcs_t * tdcs_ptr,
                                tdr_t * tdr_ptr,
                                bool_t allow_disabled,
                                bool_t* new_association);

/**
 * @brief Associate a VCPU with the current LP without checks
 *
 * Does exactly what associate_vcpu does, but without checks
 *
 * @param tvps_ptr - Pointer to a checked, locked and mapped TDVPS
 * @param tdcs_ptr - Pointer to a mapped TDCS
 * @param tdr_ptr - Pointer to a locked and mapped TDR
 * @param host_values - Pointer to saved host VMCS values
 *
 */
void associate_vcpu_initial(tdvps_t * tdvps_ptr,
                            tdcs_t * tdcs_ptr,
                            tdr_t * tdr_ptr,
                            vmcs_host_values_t * host_values);

/**
 * @brief Set the SEAM VMCS as the active VMCS
 */
_STATIC_INLINE_ void set_seam_vmcs_as_active(void)
{
    // Set the SEAM VMCS as the current VMCS
    // SEAM VMCS addr: seamrr_base + page_size + (lp_id * page_size)
    uint64_t seam_vmcs_pa = get_global_data()->seamrr_base +
                            (TDX_PAGE_SIZE_IN_BYTES * (get_local_data()->lp_info.lp_id + 1));

    ia32_vmptrld((vmcs_ptr_t*)seam_vmcs_pa);
}

/**
 * @brief Injects #UD exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_ud(void)
{
    ia32_rflags_t rflags;

    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);
    rflags.rf = 1;
    ia32_vmwrite(VMX_GUEST_RFLAGS_ENCODE, rflags.raw);

    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, UD_INTERRUPTION_INFO);
}

/**
 * @brief Injects #GP exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_gp(uint32_t error_code)
{
    ia32_rflags_t rflags;

    ia32_vmread(VMX_GUEST_RFLAGS_ENCODE, &rflags.raw);
    rflags.rf = 1;
    ia32_vmwrite(VMX_GUEST_RFLAGS_ENCODE, rflags.raw);

    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, GP_INTERRUPTION_INFO);
    ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, (uint64_t)error_code);
}

/**
 * @brief Injects #VE exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_ve(void)
{
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, VE_INTERRUPTION_INFO);
}

/**
 * @brief Injects #DF exception in the current active VMCS
 */
_STATIC_INLINE_ void inject_df(void)
{
    ia32_vmwrite(VMX_VM_ENTRY_INTR_INFO_ENCODE, DF_INTERRUPTION_INFO);
    ia32_vmwrite(VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE, 0);
}

/**
 * @brief Injects #PF exception in the current active VMCS
 */
void inject_pf(uint64_t gla, pfec_t pfec);

/**
 * @brief Adds an instruction_len offset to Guest RIP of current active VMCS
 *
 * @param instruction_len - If 0 - instruction length will be take from VM-Exit Instruction Length VMCS field
 */
_STATIC_INLINE_ void current_vmcs_guest_rip_advance(uint64_t instruction_len)
{
    uint64_t current_vmm_rip;
    ia32_vmread(VMX_GUEST_RIP_ENCODE, &current_vmm_rip);

    if (instruction_len == 0)
    {
        ia32_vmread(VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &instruction_len);
        tdx_sanity_check(instruction_len != 0, SCEC_HELPERS_SOURCE, 1);
    }

    ia32_vmwrite(VMX_GUEST_RIP_ENCODE, current_vmm_rip + instruction_len);
}

_STATIC_INLINE_ void restore_guest_td_extended_state(tdvps_t* tdvps_ptr)
{
    // Set Guest XCR0 and XSS context for restoring the state
    ia32_xsetbv(0, tdvps_ptr->management.xfam & XCR0_USER_BIT_MASK);
    ia32_wrmsr(IA32_XSS_MSR_ADDR, tdvps_ptr->management.xfam & XCR0_SUPERVISOR_BIT_MASK);

    ia32_xrstors(&tdvps_ptr->guest_extension_state.xbuf, tdvps_ptr->management.xfam);
}

_STATIC_INLINE_ void save_guest_td_extended_state(tdvps_t* tdvps_ptr, uint64_t xfam)
{
    // Set Guest XCR0 and XSS context for saving the state
    ia32_xsetbv(0, xfam & XCR0_USER_BIT_MASK);
    ia32_wrmsr(IA32_XSS_MSR_ADDR, xfam & XCR0_SUPERVISOR_BIT_MASK);

    ia32_xsaves(&tdvps_ptr->guest_extension_state.xbuf, xfam);
}

_STATIC_INLINE_ bool_t adjust_tlb_tracking_state(tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr, bool_t new_association)
{
    tdcs_epoch_tracking_fields_t* epoch_tracking = &tdcs_ptr->epoch_tracking;

    // Lock the TD epoch
    if (acquire_sharex_lock_sh(&epoch_tracking->epoch_lock) != LOCK_RET_SUCCESS)
    {
        return false;
    }

    // Sample the TD epoch and atomically increment the REFCOUNT
    uint64_t vcpu_epoch = epoch_tracking->epoch_and_refcount.td_epoch;
    _lock_xadd_16b(&epoch_tracking->epoch_and_refcount.refcount[vcpu_epoch & 1], 1);

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
            ept_descriptor_t ept_desc = {.ept = tdcs_ptr->executions_ctl_fields.eptp.raw, .reserved = 0};
            ia32_invept(&ept_desc, INVEPT_TYPE_1);
        }

        // Store the sampled value of TD_EPOCH as the new value of VCPU_EPOCH
        tdvps_ptr->management.vcpu_epoch = vcpu_epoch;
    }

    return true;
}

/**
 * @brief Checks TLB tracking conditions
 *
 * @param tdcs_t Pointer to TDCS for reading TD's epoch value and refcount
 * @param bepoch The EPOCH value that needs to be checked if tracked
 */
_STATIC_INLINE_ bool_t is_tlb_tracked(tdcs_t * tdcs_ptr, uint64_t bepoch)
{
    epoch_and_refcount_t epoch_and_refcount = {
            .raw = _lock_read_128b(&tdcs_ptr->epoch_tracking.epoch_and_refcount.raw)
                                              };

    if ((bepoch + 1 > epoch_and_refcount.td_epoch) ||
        (((bepoch + 1) == epoch_and_refcount.td_epoch) &&
         (epoch_and_refcount.refcount[((epoch_and_refcount.td_epoch) - 1) %2] > 0)) )
    {
        TDX_ERROR("Page is not TLB tracked: Page BEPOCH = %llx, TD_EPOCH = %llx, REFCOUNT[%llx] = %x\n",
                   bepoch,
                   epoch_and_refcount.td_epoch,
                   (((epoch_and_refcount.td_epoch) - 1)%2),
                   epoch_and_refcount.refcount[((epoch_and_refcount.td_epoch) - 1) %2]);
        return false;
    }
    return true;
}

/**
 * @brief Decrement the TLB tracking state if was incremented earlier and need to be reverted
 * @param tdcs_ptr Pointer to TDCS for reading TD's epoch value and refcount
 */
_STATIC_INLINE_ void revert_tlb_tracking_state(tdcs_t* tdcs_ptr, tdvps_t* tdvps_ptr)
{
    tdcs_epoch_tracking_fields_t* epoch_tracking = &tdcs_ptr->epoch_tracking;

    // Sample the TD epoch and atomically decrement the REFCOUNT
    _lock_xadd_16b(&epoch_tracking->epoch_and_refcount.refcount[tdvps_ptr->management.vcpu_epoch & 1], (uint16_t)-1);
}

/**
 * @brief retrieve index in CPUID_LOOKUP matching input leaf_subleaf
 *
 * @param leaf
 * @param subleaf
 *
 * @return the index if exist, otherwise -1
 */
uint32_t get_cpuid_lookup_entry(uint32_t leaf, uint32_t subleaf);


/**
 * @brief Return the current CPL of the guest TD
 *
 * @return the current CPL of the guest TD
 */
uint32_t get_guest_td_cpl(void);


_STATIC_INLINE_ bool_t is_perfmon_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (bool_t)tdcs_ptr->executions_ctl_fields.attributes.perfmon;
}

_STATIC_INLINE_ bool_t is_cet_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return ((tdcs_ptr->executions_ctl_fields.xfam & (BIT(11))) |
            (tdcs_ptr->executions_ctl_fields.xfam & (BIT(12)))) ? true : false;
}

_STATIC_INLINE_ bool_t is_cet_supported_in_tdvps(tdvps_t * tdvps_ptr)
{
    return ((tdvps_ptr->management.xfam & (BIT(11))) |
            (tdvps_ptr->management.xfam & (BIT(12)))) ? true : false;
}

_STATIC_INLINE_ bool_t is_pt_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (tdcs_ptr->executions_ctl_fields.xfam & (BIT(8))) ? true : false;
}

_STATIC_INLINE_ bool_t is_pt_supported_in_tdvps(tdvps_t * tdvps_ptr)
{
    return (tdvps_ptr->management.xfam & (BIT(8))) ? true : false;
}

_STATIC_INLINE_ bool_t is_uli_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (tdcs_ptr->executions_ctl_fields.xfam & (BIT(14))) ? true : false;
}

_STATIC_INLINE_ bool_t is_uli_supported_in_tdvps(tdvps_t * tdvps_ptr)
{
    return (tdvps_ptr->management.xfam & (BIT(14))) ? true : false;
}

_STATIC_INLINE_ bool_t is_lbr_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return (tdcs_ptr->executions_ctl_fields.xfam & (BIT(15))) ? true : false;
}

_STATIC_INLINE_ bool_t is_lbr_supported_in_tdvps(tdvps_t * tdvps_ptr)
{
    return (tdvps_ptr->management.xfam & (BIT(15))) ? true : false;
}

_STATIC_INLINE_ bool_t is_dca_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.dca_supported;
}
_STATIC_INLINE_ bool_t is_waitpkg_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported;
}
_STATIC_INLINE_ bool_t is_tme_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.tme_supported;
}
_STATIC_INLINE_ bool_t is_mktme_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.mktme_supported;
}
_STATIC_INLINE_ bool_t is_pks_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.attributes.pks;
}
_STATIC_INLINE_ bool_t is_xfd_supported_in_tdcs(tdcs_t * tdcs_ptr)
{
    return tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported;
}

_STATIC_INLINE_ api_error_type check_perf_msrs(void)
{
    // Check Support of IA32_A_PMC MSRs
    ia32_perf_capabilities_t perf_cap = {.raw = ia32_rdmsr(IA32_PERF_CAPABILITIES_MSR_ADDR)};
    if ((perf_cap.full_write != 1) || (perf_cap.perf_metrics_available != 1))
    {
        return api_error_with_operand_id(TDX_INCORRECT_MSR_VALUE, IA32_PERF_CAPABILITIES_MSR_ADDR);
    }
    return TDX_SUCCESS;
}

_STATIC_INLINE_ void ia32_perf_global_status_write(uint64_t reset_command, uint64_t set_command)
{
    // IA32_PERF_GLOBAL_STATUS is written in a special way, using the RESET and SET command MSRs
    ia32_wrmsr(IA32_PERF_GLOBAL_STATUS_RESET_MSR_ADDR, reset_command);
    ia32_wrmsr(IA32_PERF_GLOBAL_STATUS_SET_MSR_ADDR, set_command);
}


/**
 * @brief Helper function that split a 2MB or 1GB SEPT entry into pointing to 512 leaf pages
 *
 * @param tdr_ptr - TDR linear pointer
 * @param sept_page_pa - Physical address of the new SEPT page that will contain pointers to 512 leaf pages
 * @param split_page_pa - Physical address of the 2MB or 1GB page that needs to be split
 * @param split_page_sept_entry - SEPT entry that points to the 2MB/1GB page that needs to be split
 * @param split_page_level_entry - Level of the SEPT entry pointing to the 2MB/1GB page
 * @param pending
 * @param suppress_ve
 */
void sept_split_entry(tdr_t* tdr_ptr, pa_t sept_page_pa, pa_t split_page_pa,
                      ia32e_sept_t* split_page_sept_entry, ept_level_t split_page_level_entry,
                      bool_t pending, bool_t suppress_ve);

/**
 * @brief Helper function that determines that check the following conditions on all entries
 *        in a given extended page table:
 *        1. All entries are in SEPT_PRESENT state
 *        2. All entries are of leaf EPT type
 *        3. First entry PA is aligned to the merged page size
 *        4. Each EPT entry PA equals the previous one PA + page
 * @param merged_sept_page_ptr - Linear pointer to the page table
 * @param merged_sept_parent_level_entry - Level of the parent entry pointing to the page table
 *
 * @return True or false
 */
bool_t is_sept_page_valid_for_merge(ia32e_paging_table_t* merged_sept_page_ptr,
                                    ept_level_t merged_sept_parent_level_entry);

/**
 * @brief Helper function that updates the definition of SEPT-related return values (vmm registers - RCX and RDX)
 *          in the TDH.MEM.* functions' to abstract the actual SEPT format
 * @param ept_entry
 * @param level - Level of the returned Secure EPT entry
 * @param local_data_ptr - Pointer to the local date
 */
void set_arch_septe_details_in_vmm_regs(ia32e_sept_t ept_entry, ept_level_t level, tdx_module_local_t  * local_data_ptr);

/**
 * @brief CR write status enumeration for return value of the CR-writing helper function below
 */
typedef enum
{
    CR_WR_SUCCESS,   // Write is successful
    CR_WR_GP,        // #GP(0) should be injected if called from guest context
    CR_WR_VE         // #VE should be injected if called from guest context
} cr_write_status_e;

/**
 * @brief Checks the validity of input CR0 and writes it to the GUEST_CR0 TD-VMCS field
 *        This function is used when handling CR0 writes from the Guest-TD side
 *        TD-VMCS field should be the active VMCS before invoking this function
 * @param value - input CR0
 *
 * @return Success status or a #GP/#VE indicator
 */
cr_write_status_e write_guest_cr0(uint64_t value);

/**
 * @brief Checks the validity of input CR4 and writes it to the GUEST_CR4 TD-VMCS field
 *        This function is used when handling CR4 writes from the Guest-TD side
 *        TD-VMCS field should be the active VMCS before invoking this function
 * @param value - input CR4
 * @param tdcs_p - current TDCS
 *
 * @return Success status or a #GP/#VE indicator
 */
cr_write_status_e write_guest_cr4(uint64_t value, tdcs_t* tdcs_p, tdvps_t* tdvsp_p);

/**
 * @brief Checks the validity of input CR0 and writes it to the GUEST_CR0 TD-VMCS field
 *        This function is used when writing is done from the host side (e.g., TDH.VP.WR).
 *        TD-VMCS field should be the active VMCS before invoking this function
 * @param value - input CR0
 *
 * @return Success status or a #GP/#VE indicator
 */
cr_write_status_e write_guest_cr0_from_host(uint64_t value);

/**
 * @brief Checks the validity of input CR4 and writes it to the GUEST_CR4 TD-VMCS field
 *        This function is used when writing is done from the host side (e.g., TDH.VP.WR).
 *        TD-VMCS field should be the active VMCS before invoking this function
 * @param value - input CR4
 * @param tdcs_p - current TDCS
 *
 * @return Success status or a #GP/#VE indicator
 */
cr_write_status_e write_guest_cr4_from_host(uint64_t value, tdcs_t* tdcs_p, tdvps_t* tdvsp_p);

/**
 * @brief Checks that a given XFAM value is valid and compatible with the platform
 * @param xfam
 *
 * @return True if the value valid and compatible with the platform, otherwise false
 */
bool_t check_xfam(uint64_t xfam);

/**
 * @brief The function supports sending INIT and NMI. Thus it can't use the self-IPI shorthand
 * and must use the actual APIC ID as the destination.
 * The function supports x2APIC and xAPIC modes. The caller must have checked that if
 * the maximum value of local APIC ID on the platform is higher than 255, the local APIC
 * mode is x2APIC.
 *
 * @param apic_base
 * @param delivery_mode
 * @param vector
 */
void send_self_ipi(ia32_apic_base_t apic_base, apic_delivery_mode_t delivery_mode, uint32_t vector);

/**
 * @brief Initialize the LFSR
 *
 * @return False if there's no sufficient entropy, otherwise True
 */
bool_t lfsr_init_seed (uint32_t* lfsr_value);

/**
 * @brief
 *
 * @return True
 */
uint32_t lfsr_get_random (void);

/*------------------------------------------------------------------------------
                 Optimized DR and MSR Write and Init Helpers
-------------------------------------------------------------------------------*/
/**
 * @brief Write 'value' to MSR 'index' if value != cur_value
 *
 * @param addr - MSR address
 * @param new_value - The new value that should be written to the MSR
 * @param cur_value - MSR current value
 */
_STATIC_INLINE_ void wrmsr_opt(uint64_t addr, uint64_t new_value, uint64_t cur_value)
{
    if (new_value != cur_value)
    {
        ia32_wrmsr(addr, new_value);
    }
}

/**
 * @brief Initialized extended states defined in XFAM to their reset values
 *        by invoking XRSTORS
 *
 * @param xfam - XFAM mask that indicate which states will be initialized
 */
void initialize_extended_state(uint64_t xfam);

/**
 * @brief Sets guest PDE.BS bit according to the current state of single-step
 *        trap in RFLAGS and IA32_DEBUGCTL
 */
void set_guest_pde_bs(void);

/**
 * @brief Only this function should be used when guest RIP is advanced to the next instruction,
 *        and clear STI blocking and MOVSS blocking interruptibility state.
 */
void advance_guest_rip(void);

/**
 * @brief Terminate MOVSS-blocking and STI blocking.
 */
void clear_movss_sti_blocking(void);

/**
 * @brief Check the memory encryption algorithm configuration based on MCHECK input.
 *
 * @param tme_capability - IA32_TME_CAPABILITY MSR value
 * @param tme_activate - IA32_TME_ACTIVATE MSR value
 *
 * @return O if no error, offending MSR address if error
 */
uint32_t check_mem_enc_alg(ia32_tme_capability_t tme_capability, ia32_tme_activate_t tme_activate);

/**
 * @brief  TSX-Abort sequence.
 *
 */
_STATIC_INLINE_ void tsx_abort_sequence()
{
    _ASM_VOLATILE_ (
        "xbegin AbortTarget\n"
        "xabort $0\n"
        "lfence\n" 
        "AbortTarget: nop\n"
        : : : ); 
}

#endif /* SRC_COMMON_HELPERS_HELPERS_H_ */
