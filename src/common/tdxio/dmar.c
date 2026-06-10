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
 * @file dmar.c
 */

#include "dmar.h"
#include "tdxio/devifmt.h"
#include "devif.h"

/**
 * @brief Helper function for dmar_walk.
 *        Locks PAMT as shared and maps linear address after calculating the correct index and offset
 *
 * @param tbl_pa_ptr
 * @param entry_idx
 * @param entry_size
 * @param mapping_type
 * @param entry_pamt
 * @param entry_la
 * @param is_guest
 *
 * @return Success or Error code
 */
_STATIC_INLINE_ api_error_code_e dmar_lock_pamt_and_map_la(
    pa_t *const tbl_pa_ptr,
    const uint64_t entry_idx,
    const uint64_t entry_size,
    const mapping_type_t mapping_type,
    pamt_entry_t **entry_pamt,
    void **entry_la,
    const bool_t is_guest)
{
    api_error_code_e return_val = UNINITIALIZE_ERROR;

    // Compute offset in the table structure where the next link is present
    tbl_pa_ptr->raw += entry_idx * entry_size;

    return_val = pamt_implicit_get_and_lock(
        *tbl_pa_ptr,
        PT_4KB,
        TDX_LOCK_SHARED,
        entry_pamt,
        is_guest);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock dmar pamt entry (pa = 0x%llx)\n", tbl_pa_ptr->raw);
        goto EXIT;
    }

    *entry_la = map_pa_with_global_hkid(
        tbl_pa_ptr->raw_void,
        mapping_type);

    return_val = TDX_SUCCESS;
EXIT:
    return return_val;
}

api_error_code_e dmar_walk(
    const dmar_idx_t dmar_idx,
    const bool_t check_pasid,
    const bool_t lock_entry,
    const mapping_type_t leaf_mapping_type,
    const bool_t is_guest,
    bool_t *const is_dmar_walked_ptr,
    dmar_walk_res_t *const dmar_walk_res)
{
    api_error_code_e return_val = UNINITIALIZE_ERROR;

    pa_t cur_tbl_pa;
    mapping_type_t mapping_type;

    dmar_walk_res->dmar_level = DMAR_INV_LVL;

    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    iommu_config_t *iommu_config_ptr = &tdx_global_data_ptr->iommu_configs[dmar_idx.iommu_id.raw];

    // Start walking from the root page - first link the address stored in IOMMU_config
    cur_tbl_pa.raw = iommu_config_ptr->t_rtaddr.raw;

    mapping_type = DMAR_RTE_LVL == dmar_idx.level ? leaf_mapping_type : TDX_RANGE_RO;
    // Lock PAMT and MAP RT entry
    return_val = dmar_lock_pamt_and_map_la(
        &cur_tbl_pa,
        dmar_idx.rt_idx,
        sizeof(dmar_rte_t),
        mapping_type,
        &dmar_walk_res->rt_pamt_ptr,
        (void **)&dmar_walk_res->rte_ptr,
        is_guest);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map RT entry - error = %llx\n", return_val);
        goto EXIT;
    }

    // Set level as RT
    dmar_walk_res->dmar_level = DMAR_RTE_LVL;
    dmar_walk_res->rte_pa = cur_tbl_pa;

    // If desired level reached exit
    if (dmar_walk_res->dmar_level == dmar_idx.level)
    {
        goto EXIT_LOCK;
    }

    // Check RTE present bit
    if (!dmar_walk_res->rte_ptr->p)
    {
        TDX_ERROR("RT entry not present\n");
        return_val = TDX_DMAR_ENTRY_NOT_PRESENT;
        goto EXIT;
    }

    // Set next base as context table
    cur_tbl_pa.raw = 0;
    cur_tbl_pa.page_4k_num = dmar_walk_res->rte_ptr->ctp;
    mapping_type = (DMAR_CTE_LVL == dmar_idx.level && leaf_mapping_type) ? TDX_RANGE_RW : TDX_RANGE_RO;

    // Lock PAMT and MAP CT entry
    return_val = dmar_lock_pamt_and_map_la(
        &cur_tbl_pa,
        dmar_idx.ct_idx,
        sizeof(dmar_cte_t),
        mapping_type,
        &dmar_walk_res->ct_pamt_ptr,
        (void **)&dmar_walk_res->cte_ptr,
        is_guest);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map CT entry - error = %llx\n", return_val);
        goto EXIT;
    }

    // Set level as CT
    dmar_walk_res->dmar_level = DMAR_CTE_LVL;
    dmar_walk_res->cte_pa = cur_tbl_pa;

    // If desired level reached exit
    if (dmar_walk_res->dmar_level == dmar_idx.level)
    {
        goto EXIT_LOCK;
    }

    // Check CTE present bit
    if (!dmar_walk_res->cte_ptr->p)
    {
        TDX_ERROR("CT entry not present\n");
        return_val = TDX_DMAR_ENTRY_NOT_PRESENT;
        goto EXIT;
    }

    // Added following the removal of SIOV
    if (check_pasid &&
        dmar_walk_res->cte_ptr->rid_pasid != dmar_idx.pasid)
    {
        TDX_ERROR("Invalid check_pasid (check_pasid = %u, expected check_pasid = %u),\n\
                    or invalid rid_pasid (dmar_walk_res->cte_ptr->rid_pasid = 0x%llx, dmar_idx.pasid = 0x%llx)\n",
                  check_pasid, true,
                  dmar_walk_res->cte_ptr->rid_pasid, dmar_idx.pasid);
        return_val = TDX_OPERAND_INVALID;
        goto EXIT;
    }

    uint64_t max_pde = GET_PD_NUM_OF_ENTRIES(dmar_walk_res->cte_ptr);
    if (dmar_walk_res->cte_ptr->pd_idx >= max_pde)
    {
        TDX_ERROR("PD index (%u) is greater than max pd entries (%u)\n", dmar_walk_res->cte_ptr->pd_idx, max_pde);
        return_val = TDX_DMAR_INDEX_OUT_OF_BOUNDS;
        goto EXIT;
    }

    // Set next base as PASID dir
    cur_tbl_pa.raw = 0;
    cur_tbl_pa.page_4k_num = dmar_walk_res->cte_ptr->pasiddirptr;
    mapping_type = (DMAR_PDE_LVL == dmar_idx.level && leaf_mapping_type) ? TDX_RANGE_RW : TDX_RANGE_RO;

    // Lock PAMT and MAP PD entry
    return_val = dmar_lock_pamt_and_map_la(
        &cur_tbl_pa,
        dmar_walk_res->cte_ptr->pd_idx,
        sizeof(dmar_pde_t),
        mapping_type,
        &dmar_walk_res->pd_pamt_ptr,
        (void **)&dmar_walk_res->pde_ptr,
        is_guest);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map PD entry - error = %llx\n", return_val);
        goto EXIT;
    }

    // Set level as PD
    dmar_walk_res->dmar_level = DMAR_PDE_LVL;
    dmar_walk_res->pde_pa = cur_tbl_pa;

    // If desired level reached exit
    if (dmar_walk_res->dmar_level == dmar_idx.level)
    {
        goto EXIT_LOCK;
    }

    // Check PDE present bit
    if (!dmar_walk_res->pde_ptr->p)
    {
        TDX_ERROR("PD entry not present\n");
        return_val = TDX_DMAR_ENTRY_NOT_PRESENT;
        goto EXIT;
    }

    // Set next base as PASID table
    cur_tbl_pa.raw = 0;
    cur_tbl_pa.page_4k_num = dmar_walk_res->pde_ptr->smptblptr;
    mapping_type = (DMAR_PASIDTE_LVL == dmar_idx.level && leaf_mapping_type) ? TDX_RANGE_RW : TDX_RANGE_RO;

    // Lock PAMT and MAP PASIDT entry
    return_val = dmar_lock_pamt_and_map_la(
        &cur_tbl_pa,
        dmar_walk_res->cte_ptr->pasidt_idx,
        sizeof(dmar_pasidte_t),
        mapping_type,
        &dmar_walk_res->pasidt_pamt_ptr,
        (void **)&dmar_walk_res->pasidte_ptr,
        is_guest);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map PASIDT entry - error = %llx\n", return_val);
        goto EXIT;
    }

    // Set level as PASIDT
    dmar_walk_res->dmar_level = DMAR_PASIDTE_LVL;
    dmar_walk_res->pasidte_pa = cur_tbl_pa;

EXIT_LOCK:
    if (lock_entry &&
        (!dmar_lock(dmar_walk_res)))
    {
        TDX_ERROR("Failed to acquire lock on dmar walk result\n");
        return_val = TDX_OPERAND_BUSY;
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:
    if (return_val != TDX_SUCCESS)
    {
        dmar_unwalk(dmar_walk_res);
    }

    *is_dmar_walked_ptr = return_val == TDX_SUCCESS;

    return return_val;
}

void dmar_unwalk(dmar_walk_res_t *const dmar_walk_res)
{
    tdx_sanity_check(dmar_walk_res != NULL, SCEC_DMAR_SOURCE, 1);

    if (dmar_walk_res->entry_locked)
    {
        dmar_unlock(dmar_walk_res);
    }

    switch (dmar_walk_res->dmar_level)
    {
    case DMAR_PASIDTE_LVL:
        free_la(dmar_walk_res->pasidte_ptr);
        pamt_implicit_release_lock(dmar_walk_res->pasidt_pamt_ptr, TDX_LOCK_SHARED);
        /* no break */
    case DMAR_PDE_LVL:
        free_la(dmar_walk_res->pde_ptr);
        pamt_implicit_release_lock(dmar_walk_res->pd_pamt_ptr, TDX_LOCK_SHARED);
        /* no break */
    case DMAR_CTE_LVL:
        free_la(dmar_walk_res->cte_ptr);
        pamt_implicit_release_lock(dmar_walk_res->ct_pamt_ptr, TDX_LOCK_SHARED);
        /* no break */
    case DMAR_RTE_LVL:
        free_la(dmar_walk_res->rte_ptr);
        pamt_implicit_release_lock(dmar_walk_res->rt_pamt_ptr, TDX_LOCK_SHARED);
        break;
    case DMAR_INV_LVL:
        // Nothing to do
        break;
    default:
        TDX_ERROR("Invalid dmar level (%u)\n", dmar_walk_res->dmar_level);
        FATAL_ERROR();
    }
}

/**
 * @brief DMAR helper, update PAMT pages and map DMAR page using @param pamt_val
 *
 * @note PAMT values are only changed, once all pages are mapped.
 *       If one page fails to map/lock, then no change will take effect and the function will auto unwalk the PAMT pages
 *
 * @param start_pa
 * @param num_pages
 * @param pamt_val
 *
 * @return SUCCESS or Error type
 */
_STATIC_INLINE_ api_error_type dmar_table_alloc(
    const pa_t start_pa,
    const uint8_t num_pages,
    const pamt_entry_t *const pamt_val_ptr)
{
    uint8_t alloc_page_cnt = 0; // Indicates how many pages were allocated successfully

    pamt_block_t next_page_pamt_block;
    pamt_entry_t *next_page_pamt_entry_ptr = NULL;
    bool_t pamt_locked_flag = false; // Flag indicating PAMT entry is locked

    pamt_entry_t *pamt_entry_arr[num_pages]; // store walked PAMT entries
    pamt_block_t pamt_block_arr[num_pages];  // store walked PAMT blocks

    api_error_type return_val = UNINITIALIZE_ERROR;

    // TODO perfomance once aligned to development 0.8 change to new pamt walk
    // i.e. map first and last 1GB & 2MB pages then map every 32 4K page

    /*
     * iterate and lock all PAMT pages and store them within the array
     * If they all succeed change their values
     * Else unwalk without changing
     */
    for (alloc_page_cnt = 0; alloc_page_cnt < num_pages; alloc_page_cnt++)
    {
        // Check and lock the new page in PAMT and initialize it to zero
        pa_t next_page_pa = {.raw = start_pa.raw + alloc_page_cnt * TDX_PAGE_SIZE_IN_BYTES};
        return_val = check_and_lock_explicit_4k_private_hpa(
            next_page_pa,
            OPERAND_ID_RDX,
            TDX_LOCK_EXCLUSIVE,
            PT_NDA,
            &next_page_pamt_block,
            &next_page_pamt_entry_ptr,
            &pamt_locked_flag);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to check/lock/map a DMAR page - error = %llx\n", return_val);
            goto EXIT;
        }
        pamt_entry_arr[alloc_page_cnt] = next_page_pamt_entry_ptr;
        pamt_block_arr[alloc_page_cnt] = next_page_pamt_block;
    }

    // Successfully locked all PAMT pages.
    // Update their value
    for (uint8_t i = 0; i < num_pages; i++)
    {
        // Initialize page
        pamt_entry_arr[i]->owner = pamt_val_ptr->owner;
        pamt_entry_arr[i]->bepoch = pamt_val_ptr->bepoch;
        pamt_entry_arr[i]->pt = pamt_val_ptr->pt;
    }

    return_val = TDX_SUCCESS;

EXIT:
    tdx_sanity_check(alloc_page_cnt <= 127, SCEC_DMAR_SOURCE, 2);
    for (int8_t i = (int8_t)alloc_page_cnt - 1; i >= 0; i--)
    {
        pa_t next_page_pa = {.raw = start_pa.raw + (uint64_t)i * TDX_PAGE_SIZE_IN_BYTES};
        next_page_pamt_entry_ptr = pamt_entry_arr[i];
        next_page_pamt_block = pamt_block_arr[i];
        pamt_unwalk(next_page_pa, next_page_pamt_block, next_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }

    return return_val;
}

/**
 * @brief
 *
 *
 * @param start_pa
 * @param num_pages
 *
 * @return SUCCESS or Error type
 */
_STATIC_INLINE_ api_error_type dmar_table_free(
    pa_t start_pa,
    const uint8_t num_pages)
{
    uint8_t reached_page = 0; // Indicates how many PAMT pages were mapped successfully

    pamt_block_t next_page_pamt_block;
    pamt_entry_t *next_page_pamt_entry_ptr = NULL;
    bool_t pamt_locked_flag = false; // Flag indicating PAMT entry is locked

    pamt_entry_t *pamt_entry_arr[num_pages]; // store walked PAMT entries
    pamt_block_t pamt_block_arr[num_pages];  // store walked PAMT blocks

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Reset HKID, since the function check_and_lock_explicit_4k_private_hpa expects HKID == 0
    start_pa = remove_hkid_from_pa(start_pa);
    /*
     * Iterate and lock all PAMT pages and store them within the array
     * If they all succeed change their values
     * Else unwalk without changing
     */
    for (reached_page = 0; reached_page < num_pages; reached_page++)
    {
        // Check and lock the new page in PAMT and initialize it to zero
        pa_t next_page_pa = {.raw = start_pa.raw + reached_page * TDX_PAGE_SIZE_IN_BYTES};
        return_val = check_and_lock_explicit_4k_private_hpa(
            next_page_pa,
            OPERAND_ID_RCX,
            TDX_LOCK_EXCLUSIVE,
            PT_IOMMU_MT,
            &next_page_pamt_block,
            &next_page_pamt_entry_ptr,
            &pamt_locked_flag);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to check/lock/remove a DMAR page - error = %llx\n", return_val);
            goto EXIT;
        }
        pamt_entry_arr[reached_page] = next_page_pamt_entry_ptr;
        pamt_block_arr[reached_page] = next_page_pamt_block;
    }
    // Successfully locked all PAMT pages.
    // Update their value
    for (uint8_t i = 0; i < reached_page; i++)
    {
        pamt_entry_arr[i]->pt = PT_NDA;
    }

    return_val = TDX_SUCCESS;
EXIT:
    for (int8_t i = (int8_t)reached_page - 1; i >= 0; i--)
    {
        pa_t next_page_pa = {.raw = start_pa.raw + (uint64_t)i * TDX_PAGE_SIZE_IN_BYTES};
        next_page_pamt_entry_ptr = pamt_entry_arr[i];
        next_page_pamt_block = pamt_block_arr[i];
        pamt_unwalk(next_page_pa, next_page_pamt_block, next_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }
    return return_val;
}

void dmar_map_entry(
    dmar_walk_res_t *const dmar_walk_res,
    const dmar_state_info_t dmar_state_info,
    const dmar_entry_t *const dmar_entry_ptr)
{
    switch (dmar_walk_res->dmar_level)
    {
    case DMAR_RTE_LVL:
        dmar_set_rte(dmar_walk_res->rte_ptr, dmar_entry_ptr->raw.qwords[0]);
        break;
    case DMAR_CTE_LVL:
        dmar_set_cte(
            dmar_walk_res->cte_ptr,
            dmar_entry_ptr->raw.qwords[0],
            dmar_entry_ptr->raw.qwords[1],
            dmar_entry_ptr->raw.qwords[2],
            dmar_entry_ptr->raw.qwords[3]);
        break;
    case DMAR_PDE_LVL:
        dmar_set_pde(dmar_walk_res->pde_ptr, dmar_entry_ptr->raw.qwords[0]);
        break;
    case DMAR_PASIDTE_LVL:
        dmar_set_pasidte(
            dmar_walk_res->pasidte_ptr,
            dmar_entry_ptr->raw.qwords[0],
            dmar_entry_ptr->raw.qwords[1],
            dmar_entry_ptr->raw.qwords[2],
            dmar_entry_ptr->raw.qwords[3],
            dmar_entry_ptr->raw.qwords[4],
            dmar_entry_ptr->raw.qwords[5],
            dmar_entry_ptr->raw.qwords[6],
            dmar_entry_ptr->raw.qwords[7]);
        break;
    default:
        FATAL_ERROR();
        break;
    }
    dmar_set_state_info(dmar_walk_res, dmar_state_info);
}

api_error_type dmar_rte_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const pamt_entry_t *const pamt_val)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    pa_t start_page_pa = {.raw = 0}; // start page to map
    dmar_rte_t *rte_ptr = &dmar_entry_ptr->rte;

    if (!is_valid_dmar_rte(rte_ptr))
    {
        TDX_ERROR("Invalid RTE entry = 0x%llx\n", rte_ptr->raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // set start_page as the CTP without any offset
    start_page_pa.page_4k_num = rte_ptr->ctp;

    // Allocate the page for CT in PAMT
    if ((return_val = dmar_table_alloc(start_page_pa, NUM_CT_PAGES_TO_MAP, pamt_val)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to allocate DMAR page for CTP in PAMT\n");
        goto EXIT;
    }

    // Initialize DMAR table
    void *new_page_ptr = map_pa_with_global_hkid(start_page_pa.raw_void, TDX_RANGE_RW);
    zero_area_cacheline(new_page_ptr, TDX_PAGE_SIZE_IN_BYTES);
    free_la(new_page_ptr);

    // Set context table pointer in root table entry with TDX HKID inserted
    rte_ptr->ctp = set_hkid_to_pa(start_page_pa, get_global_data()->hkid).page_4k_num;

    // Update state to present
    dmar_state_info.map_sts = DMAR_PRESENT;
    dmar_state_info.inv_sts = DMAR_INV_PENDING;

    if (dmar_walk_res->entry_locked)
    {
        rte_ptr->locked = 1;
    }

    dmar_map_entry(dmar_walk_res, dmar_state_info, dmar_entry_ptr);
    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}

api_error_type dmar_cte_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const pamt_entry_t *const pamt_val)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    pa_t start_page_pa = {.raw = 0}; // start page to map
    dmar_cte_t *cte_ptr = &dmar_entry_ptr->cte;
    uint8_t num_pd_pages = dmar_get_cte_pd_page_cnt(cte_ptr);

    // Set start_page as the PASIDDIRPTR without any offset
    start_page_pa.page_4k_num = cte_ptr->pasiddirptr;

    if (dmar_state_info.pd_cnt == 0)
    {
        if ((return_val = is_valid_dmar_cte(cte_ptr)) != TDX_SUCCESS)
        {
            TDX_ERROR("Invalid CTE entry\n");
            TDX_ERROR("CTE entry qword[0]: 0x%llx\n\
                       CTE entry qword[1]: 0x%llx\n\
                       CTE entry qword[2]: 0x%llx\n\
                       CTE entry qword[3]: 0x%llx\n",
                      cte_ptr->raw.qwords[0],
                      cte_ptr->raw.qwords[1],
                      cte_ptr->raw.qwords[2],
                      cte_ptr->raw.qwords[3]);
            goto EXIT;
        }

        // Allocate the page for PASID DIR in PAMT
        if ((return_val = dmar_table_alloc(start_page_pa, num_pd_pages, pamt_val)) != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to allocate DMAR page for PASID DIR in PAMT\n");
            goto EXIT;
        }
    }
    else
    {
        // Verify CTE_VAL matches mapped value
        dmar_cte_t expected_cte_value = *dmar_walk_res->cte_ptr;
        expected_cte_value.p = 1;     // Match with VMM expected
        expected_cte_value.rsvd1 = 0; // Match with VMM expected
        expected_cte_value.rsvd2 = 0; // Match with VMM expected
        expected_cte_value.rsvd3 = 0; // Match with VMM expected
        expected_cte_value.rsvd4 = 0; // Match with VMM expected

        for (uint8_t curr_q = 0; curr_q < sizeof(dmar_cte_t) / sizeof(uint64_t); curr_q++)
        {
            if (expected_cte_value.raw.qwords[curr_q ] != cte_ptr->raw.qwords[curr_q ])
            {
                TDX_ERROR("dmar_val_%u  != 0\n", curr_q);
                uint16_t operand_id = curr_q == 0? OPERAND_ID_RDX: curr_q + OPERAND_ID_R8 - 1;
                return api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
            }
        }
    }


    // Initialize DMAR table
    // Each time at least one page can be added before an interrupt occurs!
    uint8_t pd_cnt = dmar_state_info.pd_cnt;
    while (true)
    {
        pa_t new_page_pa = {.raw = start_page_pa.raw + pd_cnt * TDX_PAGE_SIZE_IN_BYTES};
        void *new_page_ptr = map_pa_with_global_hkid(new_page_pa.raw_void, TDX_RANGE_RW);
        zero_area_cacheline(new_page_ptr, TDX_PAGE_SIZE_IN_BYTES);
        free_la(new_page_ptr);
        pd_cnt++;
        if (pd_cnt == num_pd_pages)
        {
            break;
        }


        if (is_interrupt_pending_host_side())
        {
            dmar_state_info.pd_cnt = pd_cnt;
            if (dmar_walk_res->entry_locked)
            {
                cte_ptr->locked = 1;
            }
            dmar_map_entry(dmar_walk_res, dmar_state_info, dmar_entry_ptr);
            return_val = TDX_INTERRUPTED_RESUMABLE;
            goto EXIT;
        }
    }

    // Set pasid dir pointer in context table entry with TDX HKID inserted
    cte_ptr->pasiddirptr = set_hkid_to_pa(start_page_pa, get_global_data()->hkid).page_4k_num;
    dmar_state_info.pd_cnt = 0;

    // Update state to present
    dmar_state_info.map_sts = DMAR_PRESENT;
    dmar_state_info.inv_sts = DMAR_INV_PENDING;

    if (dmar_walk_res->entry_locked)
    {
        cte_ptr->locked = 1;
    }

    dmar_map_entry(dmar_walk_res, dmar_state_info, dmar_entry_ptr);
    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}

api_error_type dmar_pde_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const pamt_entry_t *const pamt_val)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    pa_t start_page_pa = {.raw = 0}; // start page to map
    dmar_pde_t *pde_ptr = &dmar_entry_ptr->pde;

    if (!is_valid_dmar_pde(pde_ptr))
    {
        TDX_ERROR("Invalid PASID DIR entry = 0x%llx\n", pde_ptr->raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Set start_page as the SMPTBLPTR without any offset
    start_page_pa.page_4k_num = pde_ptr->smptblptr;

    // Allocate the page for CT in PAMT
    if ((return_val = dmar_table_alloc(start_page_pa, NUM_PASIDT_PAGES_TO_MAP, pamt_val)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to allocate DMAR page for CT in PAMT\n");
        goto EXIT;
    }

    // Initialize DMAR table
    void *next_page_ptr = map_pa_with_global_hkid(start_page_pa.raw_void, TDX_RANGE_RW);
    zero_area_cacheline(next_page_ptr, TDX_PAGE_SIZE_IN_BYTES);
    free_la(next_page_ptr);

    // Set PASID table pointer in PASID DIR entry with TDX HKID inserted
    pde_ptr->smptblptr = set_hkid_to_pa(start_page_pa, get_global_data()->hkid).page_4k_num;

    // Update state to present
    dmar_state_info.map_sts = DMAR_PRESENT;
    dmar_state_info.inv_sts = DMAR_INV_PENDING;

    if (dmar_walk_res->entry_locked)
    {
        pde_ptr->locked = 1;
    }

    dmar_map_entry(dmar_walk_res, dmar_state_info, dmar_entry_ptr);
    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}

api_error_type dmar_pasidte_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const iommu_id_t iommu_id)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    dmar_pasidte_t *pasidte_ptr = &dmar_entry_ptr->pasidte;

    if ((return_val = is_valid_dmar_pasidte(pasidte_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("Invalid PASIDTE entry\n");
        goto EXIT;
    }

    /*
     * Program DID to TD KeyID value with the most significant bit of DID set to 1
     * Domain-ID is the TD-HKID with the MSB bit of the maximum supported domain ID set
     */
    tdx_module_global_t *tdx_global_data_ptr = get_global_data();
    iommu_config_t *iommu_config_ptr = &tdx_global_data_ptr->iommu_configs[iommu_id.raw];
    pasidte_ptr->did = BIT(iommu_config_ptr->iommu_cap.did_msb);

    // Update state to pending
    dmar_state_info.map_sts = DMAR_PENDING;

    if (dmar_walk_res->entry_locked)
    {
        pasidte_ptr->locked = 1;
    }

    dmar_map_entry(dmar_walk_res, dmar_state_info, dmar_entry_ptr);

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}

void dmar_arc_read(const dmar_walk_res_t *const dmar_walk_res)
{
    tdx_module_local_t *local_data_ptr = get_local_data();
    switch (dmar_walk_res->dmar_level)
    {
    case DMAR_RTE_LVL:
        local_data_ptr->vmm_regs.r8 = dmar_walk_res->rte_ptr->raw;
        break;
    case DMAR_CTE_LVL:
        local_data_ptr->vmm_regs.r8 = dmar_walk_res->cte_ptr->raw.qwords[0];
        local_data_ptr->vmm_regs.r9 = dmar_walk_res->cte_ptr->raw.qwords[1];
        local_data_ptr->vmm_regs.r10 = dmar_walk_res->cte_ptr->raw.qwords[2];
        local_data_ptr->vmm_regs.r11 = dmar_walk_res->cte_ptr->raw.qwords[3];
        break;
    case DMAR_PDE_LVL:
        local_data_ptr->vmm_regs.r8 = dmar_walk_res->pde_ptr->raw;
        break;
    case DMAR_PASIDTE_LVL:
        local_data_ptr->vmm_regs.r8 = dmar_walk_res->pasidte_ptr->raw.qwords[0];
        local_data_ptr->vmm_regs.r9 = dmar_walk_res->pasidte_ptr->raw.qwords[1];
        local_data_ptr->vmm_regs.r10 = dmar_walk_res->pasidte_ptr->raw.qwords[2];
        local_data_ptr->vmm_regs.r11 = dmar_walk_res->pasidte_ptr->raw.qwords[3];
        local_data_ptr->vmm_regs.r12 = dmar_walk_res->pasidte_ptr->raw.qwords[4];
        local_data_ptr->vmm_regs.r13 = dmar_walk_res->pasidte_ptr->raw.qwords[5];
        local_data_ptr->vmm_regs.r14 = dmar_walk_res->pasidte_ptr->raw.qwords[6];
        local_data_ptr->vmm_regs.r15 = dmar_walk_res->pasidte_ptr->raw.qwords[7];
        break;
    default:
        FATAL_ERROR();
    }
    local_data_ptr->vmm_regs.rdx = dmar_get_state_info(dmar_walk_res).raw;
}

api_error_type dmar_rte_remove(dmar_walk_res_t *const dmar_walk_res)
{
    pa_t cte_pa = {.raw = 0};
    cte_pa.page_4k_num = dmar_walk_res->rte_ptr->ctp;

    pamt_entry_t *cte_pamt_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;

    if (!is_dmar_child_entires_free(dmar_walk_res))
    {
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Locate & lock PAMT
    return_val = pamt_implicit_get_and_lock(
        cte_pa,
        PT_4KB,
        TDX_LOCK_EXCLUSIVE,
        &cte_pamt_ptr,
        false);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to get or lock ct entries PAMT\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Update pamt
    cte_pamt_ptr->pt = PT_NDA;

    // Return removed CT page
    tdx_module_local_t *local_data_ptr = get_local_data();
    local_data_ptr->vmm_regs.rcx = remove_hkid_from_pa(cte_pa).raw;

    return_val = TDX_SUCCESS;

EXIT:
    if (cte_pamt_ptr != NULL)
    {
        pamt_implicit_release_lock(cte_pamt_ptr, TDX_LOCK_EXCLUSIVE);
    }

    return return_val;
}

api_error_type dmar_cte_remove(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t *const dmar_state_info)
{
    pa_t pde_pa = {.raw = 0};
    dmar_pde_t *pde_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;

    uint8_t num_pd_pages = dmar_get_cte_pd_page_cnt(dmar_walk_res->cte_ptr);
    uint8_t pd_cnt = dmar_state_info->pd_cnt;


    // Each time at least one page can be removed before an interrupt occurs!
    while (true)
    {
        pde_pa.page_4k_num = dmar_walk_res->cte_ptr->pasiddirptr + pd_cnt;
        dmar_pde_t *pd_tbl_ptr = (dmar_pde_t *)map_pa_with_global_hkid(
            pde_pa.raw_void,
            TDX_RANGE_RO);
        for (uint16_t i = 0; i < MAX_PD_ENTRIES_PER_PAGE; i++)
        {
            pde_ptr = pd_tbl_ptr + i;
            if (dmar_get_pde_state(pde_ptr) != DMAR_PDE_FREE)
            {
                TDX_ERROR("PASID DIR entry not in PDE_FREE state\n");
                return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_RCX);
                free_la(pd_tbl_ptr);
                goto EXIT;
            }
        }
        pd_cnt++;
        free_la(pd_tbl_ptr);
        if (pd_cnt == num_pd_pages)
        {
            break;
        }


        if (is_interrupt_pending_host_side())
        {
            dmar_state_info->pd_cnt = pd_cnt;
            dmar_set_state_info(dmar_walk_res, *dmar_state_info);
            return_val = TDX_INTERRUPTED_RESUMABLE;
            goto EXIT;
        }
    }

    // Update removed PASID directory pages in PAMT
    pde_pa.raw = 0;
    pde_pa.page_4k_num = dmar_walk_res->cte_ptr->pasiddirptr;
    return_val = dmar_table_free(pde_pa, num_pd_pages);
    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Update DMAR entry
    dmar_state_info->pd_cnt = 0;

    // Return removed PD page
    tdx_module_local_t *local_data_ptr = get_local_data();
    local_data_ptr->vmm_regs.rcx = remove_hkid_from_pa(pde_pa).raw;

EXIT:

    return return_val;
}

api_error_type dmar_pde_remove(dmar_walk_res_t *const dmar_walk_res)
{
    pa_t pasidte_pa = {.raw = 0};
    pasidte_pa.page_4k_num = dmar_walk_res->pde_ptr->smptblptr;
    pamt_entry_t *pasidte_pamt_ptr = NULL;

    api_error_type return_val = UNINITIALIZE_ERROR;

    if (!is_dmar_child_entires_free(dmar_walk_res))
    {
        return_val = api_error_with_operand_id(TDX_DMAR_INVALID_MAPPING_STATE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Locate & lock PAMT
    return_val = pamt_implicit_get_and_lock(
        pasidte_pa,
        PT_4KB,
        TDX_LOCK_EXCLUSIVE,
        &pasidte_pamt_ptr,
        false);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to get and lock pasidte PAMT\n");
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Update pamt
    pasidte_pamt_ptr->pt = PT_NDA;

    // Return removed PASIDT page
    tdx_module_local_t *local_data_ptr = get_local_data();
    local_data_ptr->vmm_regs.rcx = remove_hkid_from_pa(pasidte_pa).raw;

    return_val = TDX_SUCCESS;

EXIT:
    if (pasidte_pamt_ptr != NULL)
    {
        pamt_implicit_release_lock(pasidte_pamt_ptr, TDX_LOCK_EXCLUSIVE);
    }

    return return_val;
}

api_error_type dmar_pasidte_remove(
    const dmar_idx_t dmar_idx,
    tdcs_t *const tdcs_ptr)
{
    api_error_type return_val = UNINITIALIZE_ERROR;
    bool_t is_epoch_locked = false;

    // DEVIFCS parameters
    function_id_reg_t function_id_reg = {.raw = 0};
    function_id_reg.function_id.rid = dmar_idx.rid;
    devif_verify_param_t devif_verify_param = {0};

    // Acquire TDCS epoch lock or fail with TDX_OPERAND_BUSY
    if (acquire_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to get epoch lock on TDCS\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);
        goto EXIT;
    }
    is_epoch_locked = true;

    if (tdcs_ptr->tdxio_fields.prev_iotlb_cnt != 0 &&
        tdcs_ptr->tdxio_fields.iotlb_track_array[dmar_idx.iommu_id.raw].pasidte_ref_cnt != 0)
    {
        TDX_ERROR("Failed to remove PASIDTE while IOTLB INV still remaining\n");
        return_val = api_error_with_operand_id(TDX_IOMMU_IOTLB_TRACKING_NOT_DONE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Lock and map devifcs
    return_val = tdh_devifmt_get_devifcs(
        function_id_reg,
        TDX_RANGE_RW,
        OPERAND_ID_RCX, // RCX is the operand for dmar_idx
        &devif_verify_param);

    if (return_val != TDX_SUCCESS)
    {
        goto EXIT;
    }

    // Update IOTLB tracking
    if (increment_iotlb_tracker_pasidte_ref_cnt(&tdcs_ptr->tdxio_fields.iotlb_track_array[dmar_idx.iommu_id.raw], (uint64_t)-1) == 1)
    {
        _lock_xadd_64b(&tdcs_ptr->tdxio_fields.curr_iotlb_cnt, (uint64_t)-1);
    }

    // Set DMAR mapping state in DEVIFCS to FALSE
    devif_verify_param.devifcs_ptr->dmar_mapped_flag = false;

    return_val = TDX_SUCCESS;
EXIT:
    devif_unmap_devifcs(&devif_verify_param);

    if (is_epoch_locked)
    {
        release_sharex_lock_sh(&tdcs_ptr->epoch_tracking.epoch_lock);
    }

    return return_val;
}

bool_t is_dmar_child_entires_free(const dmar_walk_res_t *const dmar_walk_res)
{
    bool_t ret_val = false;
    pa_t entry_pa = {.raw = 0};
    void *entry_ptr = NULL;

    switch (dmar_walk_res->dmar_level)
    {
    case DMAR_RTE_LVL:
    {
        entry_pa.page_4k_num = dmar_walk_res->rte_ptr->ctp;
        dmar_cte_t *cte_ptr = (dmar_cte_t *)map_pa_with_global_hkid(
            entry_pa.raw_void,
            TDX_RANGE_RO);
        entry_ptr = cte_ptr;

        for (uint8_t i = 0; i < MAX_CT_ENTRIES_PER_PAGE; i++)
        {
            if (dmar_get_cte_state(cte_ptr + i) != DMAR_CTE_FREE)
            {
                TDX_ERROR("CT entry %u not in DMAR_CTE_FREE state\n", i);
                ret_val = false;
                goto EXIT;
            }
        }
        break;
    }
    case DMAR_CTE_LVL:
    {
        entry_pa.page_4k_num = dmar_walk_res->cte_ptr->pasiddirptr;
        dmar_pde_t *pde_base_ptr = (dmar_pde_t *)map_pa_with_global_hkid(
            entry_pa.raw_void,
            TDX_RANGE_RO);
        entry_ptr = pde_base_ptr;

        uint64_t total_num_of_pde_entries = GET_PD_NUM_OF_ENTRIES(dmar_walk_res->cte_ptr);
        uint64_t tatal_number_of_pages = (total_num_of_pde_entries % MAX_PD_ENTRIES_PER_PAGE) == 0? (total_num_of_pde_entries / MAX_PD_ENTRIES_PER_PAGE): (total_num_of_pde_entries / MAX_PD_ENTRIES_PER_PAGE + 1);

        for (uint8_t pde_page_idx = 0; pde_page_idx < tatal_number_of_pages; pde_page_idx++)
        {
            pa_t new_page_pa = {.raw = entry_pa.raw + pde_page_idx * TDX_PAGE_SIZE_IN_BYTES};
            dmar_pde_t *pde_ptr = map_pa_with_global_hkid(new_page_pa.raw_void, TDX_RANGE_RO);

            uint64_t pd_entries_in_curr_page = MIN(MAX_PD_ENTRIES_PER_PAGE, total_num_of_pde_entries);
            total_num_of_pde_entries -= pd_entries_in_curr_page;

            for (uint64_t i = 0; i < pd_entries_in_curr_page; i++)
            {
                if (dmar_get_pde_state(pde_ptr + i) != DMAR_PDE_FREE)
                {
                    TDX_ERROR("PD entry %u not in DMAR_PDE_FREE state\n", i);
                    ret_val = false;
                    free_la(pde_ptr);
                    goto EXIT;
                }
            }
            free_la(pde_ptr);
        }
        break;
    }
    case DMAR_PDE_LVL:
    {
        entry_pa.page_4k_num = dmar_walk_res->pde_ptr->smptblptr;
        dmar_pasidte_t *pasidte_ptr = (dmar_pasidte_t *)map_pa_with_global_hkid(
            entry_pa.raw_void,
            TDX_RANGE_RO);
        entry_ptr = pasidte_ptr;

        for (uint8_t i = 0; i < MAX_PASIDT_ENTRIES_PER_PAGE; i++)
        {
            if (dmar_get_pasidte_state(pasidte_ptr + i) != DMAR_PASIDTE_FREE)
            {
                TDX_ERROR("PASIDT entry %u not in DMAR_PASIDTE_FREE\n", i);
                ret_val = false;
                goto EXIT;
            }
        }
        break;
    }
    case DMAR_PASIDTE_LVL:
    {
        // No children for PASIDTEs
        break;
    }
    default:
    {
        FATAL_ERROR();
    }
    }
    ret_val = true;
EXIT:
    if (entry_ptr != NULL)
    {
        free_la(entry_ptr);
    }
    return ret_val;
}
