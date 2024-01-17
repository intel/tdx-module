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
 * @file pamt_manager.h
 * @brief PAMT manager headers
 */

#ifndef SRC_COMMON_MEMORY_HANDLERS_PAMT_MANAGER_H_
#define SRC_COMMON_MEMORY_HANDLERS_PAMT_MANAGER_H_

#include "tdx_basic_types.h"
#include "helpers/tdx_locks.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_global_data.h"

#include "auto_gen/tdx_error_codes_defs.h"

/**
 * @brief Enum for page type in PAMT
 */
typedef enum {
    PT_NDA   = 0,
    PT_RSVD  = 1,
    PT_REG   = 3,
    PT_TDR   = 4,
    PT_TDCX  = 5,
    PT_TDVPR = 6,
    //reserved = 7,
    PT_EPT   = 8
} page_type_t;

/**
 * @brief Enum of page size in PAMT
 */
typedef enum {
    PT_4KB  = 0,
    PT_2MB  = 1,
    PT_1GB  = 2
} page_size_t;

#define PAMT_ENTRY_SIZE_IN_BYTES        16


/**
 * @struct bepoch_t
 *
 * @brief BEPOCH is part of the PAMT entry.  It is used for either holding BEPOCH for TLB tracking
   or migration epoch for migration tracking.
 */
typedef union bepoch_u
{
    struct
    {
        uint64_t mig_epoch    : 32; // Bits 31:0  : Migration epoch
        uint64_t export_count : 31; // Bits 62:32 : Export counter
        uint64_t mig_flag     : 1;  // Bit 63     : If set, indicates that BEPOCH is used for migration epoch
    };

    uint64_t raw;
} bepoch_t;
tdx_static_assert(sizeof(bepoch_t) == 8, bepoch_t);

/**
 * @struct pamt_entry_t
 *
 * @brief PAMT entry structure
 */
typedef struct pamt_entry_s
{
    struct
    {
        sharex_hp_lock_t entry_lock; // 2 byte (16 bit)
        page_type_t pt : 8;
        uint64_t owner : 40; // don't access this field directly, use accessors below
    }; // primary

    union
    {
        bepoch_t bepoch;
    }; // additional
} pamt_entry_t;
tdx_static_assert(sizeof(pamt_entry_t) == PAMT_ENTRY_SIZE_IN_BYTES, pamt_entry_t);
tdx_static_assert((MOVDIR64_CHUNK_SIZE % sizeof(pamt_entry_t)) == 0, pamt_entry_t_2);

_STATIC_INLINE_ pa_t get_pamt_entry_owner(pamt_entry_t* pamt_entry)
{
    pa_t owner_pa;
    owner_pa.raw = ((uint64_t)pamt_entry->owner) << 12;
    return owner_pa;
}

_STATIC_INLINE_ void set_pamt_entry_owner(pamt_entry_t* pamt_entry, pa_t owner)
{
    pamt_entry->owner = owner.page_4k_num;
}

#define PAMT_CHILD_ENTRIES              ( 512 )

#define PAMT_2MB_ENTRIES_IN_1GB         ( PAMT_CHILD_ENTRIES )
#define PAMT_4KB_ENTRIES_IN_1GB         ( PAMT_CHILD_ENTRIES * PAMT_2MB_ENTRIES_IN_1GB )

/**
 * @struct pamt_block_t
 *
 * @brief 1GB PAMT block virtual structure. Contains 3 physical pointers, 1 to PAMT_1GB entry
 *        from the TDMR.PAMT_1GB array, and to the corresponding (to that 1GB area) PAMT_2MB entries (512)
 *        and PAMT_4KB entries (512*512).
 */
typedef struct pamt_block_s
{
    pamt_entry_t* pamt_1gb_p;
    pamt_entry_t* pamt_2mb_p;
    pamt_entry_t* pamt_4kb_p;
} pamt_block_t;

/**
 * @brief This function gets a 4KB page aligned physical address and valid flag and returns a
 * physical pointer to PAMT entries corresponding 1GB PAMT range and its valid state.
 *
 * If [pa] is not covered by any TDMR or the PAMT return NULL.
 *
 * If the PAMT block is not initialized, return NULL;
 *
 * @param pa Physical address corresponding to the PAMT block
 * @param pamt_block PAMT block structure to be filled with relevant physical pointers
 *
 * @return Returns TRUE if found PAMT block. FALSE if not found, or if @a pa not initilizaed.
 *
 */
bool_t pamt_get_block(pa_t pa, pamt_block_t* pamt_block);

/**
 * @brief PAMT initialize function that gets a PAMT block.
 *
 * This function implicitly initializes node PAMT entries of 2MB and 1GB pages.
 *
 * @param pamt_block Physical address of the pamt_block that needs to be initialized.
 */
void pamt_init(pamt_block_t* pamt_block, uint64_t num_4k_entries, tdmr_entry_t *tdmr_entry);

/**
 * @brief Performs PAMT hierarchical walk from top PAMT entry(1GB) to leaf level (1GB...4KB)
 *
 * PAMT walk acquires shared locks on non-leaf entries and shared/exclusive lock on the
 * leaf entry according to exclusive_leaf_lock flag.
 *
 * PAMT walk may fail to acquire PAMT entry lock, in this case, it unlocks all the PAMT
 * entry locks it already acquired and return NULL.
 *
 * @note Returned physical pointer to the PAMT entry should be always mapped to linear.
 *
 * @param pa Physical address corresponding to the PAMT entry
 * @param pamt_block PAMT block virtual structure covering the @a pa
 * @param leaf_lock_type Determines whether on the found PAMT leaf entry, the taken lock should
 *                            be shared or exclusive.
 * @param leaf_size Returns the leaf size of the found PAMT entry
 * @param walk_to_leaf_size - If it is true, leaf_size is used as an input too, and PAMT walk stops at that level
 * @param is_guest - Indicates whether the walk+lock request came from the TD guest
 * @param pamt_entry returns the linear address of the PAMT entry if the lock acquisition succeeded.
 *                   Should be freed after use. Returns NULL if lock failed (doesn't need to be freed in that case).
 *
 * @return Error code status
 */
api_error_code_e pamt_walk(pa_t pa, pamt_block_t pamt_block, lock_type_t leaf_lock_type,
                           page_size_t* leaf_size, bool_t walk_to_leaf_size, bool_t is_guest,
                           pamt_entry_t** pamt_entry);

/**
 * @brief Performs PAMT lock release in a reverse order to PAMT walk (i.e. from leaf PAMT entry
 *        to top 1GB PAMT entry.
 *
 * @note The function does not perform and check on PAMT entries and assumes the user
 *       is responsible to call it with the same parameters used for the previous PAMT walk.
 *       The leaf entry linear pointer that was received from the corresponding PAMT walk will
 *       also be freed by the unwalk function.
 *
 * @param pa Physical address corresponding to the PAMT entry
 * @param pamt_block PAMT block virtual structure covering the @a pa
 * @param pamt_entry_p Linear pointer to the leaf PAMT entry that will be freed by the function
 * @param leaf_lock_type Determines whether the lock taken on the leaf entry by the PAMT walk was
 *                            shared or exclusive.
 * @param leaf_size Leaf size of the leaf PAMT entry
 */
void pamt_unwalk(pa_t pa, pamt_block_t pamt_block, pamt_entry_t* pamt_entry_p,
                 lock_type_t leaf_lock_type, page_size_t leaf_size);


/**
 * @brief Given a page physical address, promote 512 leaf PAMT entries corresponding to
 *        the physical address by setting their parent PAMT entry LEAF bit and initializing
 *        the 512 leaf entries state to FREE.
 *
 * During the promotion this function acquires PAMT entry exclusive lock on new leaf entry
 * and shared locks on its parent PAMT entry when promoting to 2MB page.
 *
 * @param pa Physical address corresponding to the PAMT entry
 * @param new_leaf_size Size of the new promoted page
 *
 * @return Error code status
 */
api_error_code_e pamt_promote(pa_t pa, page_size_t new_leaf_size);


/**
 * @brief Given a page physical address [pa], locate its leaf PAMT entry and demote it to 512
 *        child leaf PAMT entries.
 *
 *  During the demotion, this function acquires PAMT entry exclusive lock on the demoted
 *  entry and shared locks on its parent PAMT entry when demoting a 2MB page.
 *
 * @param pa Physical address corresponding to the PAMT entry
 * @param leaf_size Size of the page to demote
 *
 * @return Error code status
 */
api_error_code_e pamt_demote(pa_t pa, page_size_t leaf_size);


/**
 * @brief Returns a linear address of pamt_entry describing the given pa. Does not acquires any locks.
 *        Function cannot fail, and failure will result in module halt.
 * @param pa Physical address corresponding to the PAMT entry
 * @param leaf_size Leaf size of the relevant page
 * @return Linear address of the pamt_entry. Should be freed after use.
 */
pamt_entry_t* pamt_implicit_get(pa_t pa, page_size_t leaf_size);

/**
 * @brief Returns a linear address of pamt_entry describing the given pa. Acquires a lock as stated in
 *        the input parameter
 * @param pa Physical address corresponding to the PAMT entry
 * @param leaf_size Leaf size of the relevant page
 * @param leaf_lock_type Determines whether on the found PAMT leaf entry, the taken lock should
 *                            be shared or exclusive.
 * @param pamt_entry returns the linear address of the PAMT entry if the lock acquisition succeeded.
 *                   Should be freed after use. Returns NULL if lock failed (doesn't need to be freed in that case).
 *
 * @return Error code status
 */
api_error_code_e pamt_implicit_get_and_lock(pa_t pa, page_size_t leaf_size, lock_type_t leaf_lock_type,
                                            pamt_entry_t** pamt_entry);

/**
 * @brief Frees the lock of an implicit pamt entry, and also frees the pamt_entry linear address
 * @param pamt_entry Linear pointer to the leaf PAMT entry that will be freed by the function
 * @param leaf_lock_type Determines whether the lock taken on the leaf entry was shared or exclusive.
 */
void pamt_implicit_release_lock(pamt_entry_t* pamt_entry, lock_type_t leaf_lock_type);

/**
 * @brief Frees the lock of an implicit pamt entry, and also frees the pamt_entry linear address
 * @param pamt_entry Linear pointer to the leaf PAMT entry that will be freed by the function
 * @param leaf_lock_type Determines whether the lock taken on the leaf entry was shared or exclusive.
 */
void pamt_implicit_release_lock(pamt_entry_t* pamt_entry, lock_type_t leaf_lock_type);

/**
 * @brief Goes over 2MB PAMT range and checks that all 4KB child entries has NDA type
 * @param pa Physical address corresponding to the 2MB PAMT range
 * @param pamt_block PAMT block virtual structure covering the @a pa
 *
 * @return if the 2MB range free or not
 */
bool_t pamt_is_2mb_range_free(pa_t pa, pamt_block_t* pamt_block);

#endif /* SRC_COMMON_MEMORY_HANDLERS_PAMT_MANAGER_H_ */
