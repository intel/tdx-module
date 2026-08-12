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
 * @file dmar.h
 */

#ifndef SRC_COMMON_TDXIO_DMAR_H_
#define SRC_COMMON_TDXIO_DMAR_H_

#include "data_structures/tdxio/dmar_defs.h"
#include "helpers/helpers.h"
#include "iommu.h"

_STATIC_INLINE_ void dmar_set_rte(
    dmar_rte_t *const rte_ptr,
    const uint64_t val)
{
    rte_ptr->raw = val;
}

_STATIC_INLINE_ dmar_rte_state_e dmar_get_rte_state(const dmar_rte_t *const rte_ptr)
{
    return (dmar_rte_state_e)(rte_ptr->raw & (uint64_t)DMAR_RTE_STATE_BIT_MASK);
}

_STATIC_INLINE_ void dmar_set_rte_state(
    dmar_rte_t *const rte_ptr,
    const dmar_rte_state_e new_state)
{
    dmar_rte_t rte_tmp = *rte_ptr;
    rte_tmp.raw &= (~(uint64_t)DMAR_RTE_RESET_STATE_BIT_MASK);
    rte_tmp.raw |= (uint64_t)new_state;
    rte_ptr->raw = rte_tmp.raw;
}

_STATIC_INLINE_ void dmar_set_rte_inv_state(
    dmar_rte_t *const rte_ptr,
    const dmar_inv_sts_t new_inv_state)
{
    dmar_rte_t rte_tmp = *rte_ptr;
    rte_tmp.inv_state = new_inv_state;
    rte_ptr->raw = rte_tmp.raw;
}

_STATIC_INLINE_ void dmar_set_cte(
    dmar_cte_t *const cte_ptr,
    const uint64_t val1,
    const uint64_t val2,
    const uint64_t val3,
    const uint64_t val4)
{
    cte_ptr->raw.qwords[0] = val1;
    cte_ptr->raw.qwords[1] = val2;
    cte_ptr->raw.qwords[2] = val3;
    cte_ptr->raw.qwords[3] = val4;
}

_STATIC_INLINE_ dmar_cte_state_e dmar_get_cte_state(const dmar_cte_t *const cte_ptr)
{
    return (dmar_cte_state_e)(cte_ptr->raw.qwords[0] & (uint64_t)DMAR_CTE_STATE_BIT_MASK);
}

_STATIC_INLINE_ void dmar_set_cte_state(
    dmar_cte_t *const cte_ptr,
    const dmar_cte_state_e new_state)
{
    uint64_t tmp_q1 = cte_ptr->raw.qwords[0];
    tmp_q1 &= (~(uint64_t)DMAR_CTE_STATE_BIT_MASK);
    tmp_q1 |= (uint64_t)new_state;
    cte_ptr->raw.qwords[0] = tmp_q1;
}

_STATIC_INLINE_ void dmar_set_cte_inv_state(
    dmar_cte_t *const cte_ptr,
    const dmar_inv_sts_t new_inv_state)
{
    // inv_state is located in Q1
    dmar_cte_t cte_tmp = {.raw.qwords[1] = cte_ptr->raw.qwords[1]};
    cte_tmp.inv_state = new_inv_state;
    cte_ptr->raw.qwords[1] = cte_tmp.raw.qwords[1];
}

_STATIC_INLINE_ void dmar_set_cte_pde_cnt(
    dmar_cte_t *const cte_ptr,
    const uint8_t new_pde_cnt)
{
    // pde_cnt is located in Q1
    dmar_cte_t cte_tmp = {.raw.qwords[1] = cte_ptr->raw.qwords[1]};
    cte_tmp.pde_cnt = new_pde_cnt;
    cte_ptr->raw.qwords[1] = cte_tmp.raw.qwords[1];
}

/**
 * max # pages = 32
 * min # pages = 1
 */
_STATIC_INLINE_ uint8_t dmar_get_cte_pd_page_cnt(const dmar_cte_t *const cte_ptr)
{
    uint8_t num_pd_pages = (uint8_t)CALCULATE_NUMBER_OF_UNITS_WITH_PADDING(BIT(cte_ptr->pdts + PDTS_IDX_CONST) * sizeof(dmar_pde_t), _4KB);
    tdx_sanity_check((num_pd_pages >= MIN_NUM_PD_PAGES && num_pd_pages <= MAX_NUM_PD_PAGES), FATAL_ERROR_ID_245, 3);

    return num_pd_pages;
}

_STATIC_INLINE_ void dmar_set_pde(
    dmar_pde_t *const pde_ptr,
    const uint64_t val)
{
    pde_ptr->raw = val;
}

_STATIC_INLINE_ dmar_pde_state_e dmar_get_pde_state(const dmar_pde_t *const pde_ptr)
{
    return (dmar_pde_state_e)(pde_ptr->raw & (uint64_t)DMAR_PDE_STATE_BIT_MASK);
}

_STATIC_INLINE_ void dmar_set_pde_state(
    dmar_pde_t *const pde_ptr,
    const dmar_pde_state_e new_state)
{
    dmar_pde_t pde_tmp = *pde_ptr;
    pde_tmp.raw &= (~(uint64_t)DMAR_PDE_RESET_STATE_BIT_MASK);
    pde_tmp.raw |= (uint64_t)new_state;
    pde_ptr->raw = pde_tmp.raw;
}

_STATIC_INLINE_ void dmar_set_pde_inv_state(
    dmar_pde_t *const pde_ptr,
    const dmar_inv_sts_t new_inv_state)
{
    dmar_pde_t pde_tmp = *pde_ptr;
    pde_tmp.inv_state = new_inv_state;
    pde_ptr->raw = pde_tmp.raw;
}

_STATIC_INLINE_ void dmar_set_pasidte(
    dmar_pasidte_t *const pasidte_ptr,
    const uint64_t val1,
    const uint64_t val2,
    const uint64_t val3,
    const uint64_t val4,
    const uint64_t val5,
    const uint64_t val6,
    const uint64_t val7,
    const uint64_t val8)
{
    pasidte_ptr->raw.qwords[0] = val1;
    pasidte_ptr->raw.qwords[1] = val2;
    pasidte_ptr->raw.qwords[2] = val3;
    pasidte_ptr->raw.qwords[3] = val4;
    pasidte_ptr->raw.qwords[4] = val5;
    pasidte_ptr->raw.qwords[5] = val6;
    pasidte_ptr->raw.qwords[6] = val7;
    pasidte_ptr->raw.qwords[7] = val8;
}

_STATIC_INLINE_ dmar_pasidte_state_e dmar_get_pasidte_state(const dmar_pasidte_t *const pasidte_ptr)
{
    return (dmar_pasidte_state_e)(pasidte_ptr->raw.qwords[0] & (uint64_t)DMAR_PASIDTE_STATE_BIT_MASK);
}

_STATIC_INLINE_ void dmar_set_pasidte_state(
    dmar_pasidte_t *const pasidte_ptr,
    const dmar_pasidte_state_e new_state)
{
    uint64_t tmp_q1 = pasidte_ptr->raw.qwords[0];
    tmp_q1 &= (~(uint64_t)DMAR_PASIDTE_STATE_BIT_MASK);
    tmp_q1 |= (uint64_t)new_state;
    pasidte_ptr->raw.qwords[0] = tmp_q1;
}

_STATIC_INLINE_ void dmar_set_pasidte_inv_state(
    dmar_pasidte_t *const pasidte_ptr,
    const dmar_inv_sts_t new_inv_state)
{
    // inv_state is located in Q1
    dmar_pasidte_t pasidte_tmp = {.raw.qwords[1] = pasidte_ptr->raw.qwords[1]};
    pasidte_tmp.inv_state = new_inv_state;
    pasidte_ptr->raw.qwords[1] = pasidte_tmp.raw.qwords[1];
}

/**
 * @brief Given DMAR index, verify the following:
 *        1. Reserved field is equal to zero
 *        2. Level <= DMAR MAX LEVL
 *
 * @param idx
 *
 * @return
 */
_STATIC_INLINE_ bool_t is_valid_dmar_idx(const dmar_idx_t idx)
{
    return (!idx.rsvd) &&
           (idx.level < DMAR_INV_LVL);
}

/**
 * @brief Given root table entry verify the following:
 *    1. Reserved bits not set
 *    2. Present bit set
 *    3. Context table pointer does not have private Key ID
 *
 * @param rte
 *
 * @return
 */
_STATIC_INLINE_ bool_t is_valid_dmar_rte(const dmar_rte_t *const rte)
{
    pa_t ctp_pa = {.raw = 0};
    ctp_pa.page_4k_num = rte->ctp;
    return (!rte->rsvd) &&
           rte->p &&
           (get_hkid_from_pa(ctp_pa) == 0);
}

/**
 * @brief Given context table entry, verify the following:
 *        1. Reserved bits not set
 *        2. KeyID bits in PASID directory pointer doesn't have a private KeyID
 *        3. RID_PASID index in PASID directory table entry is within bounds of
 *           the table size as specified by PDTS (2^(PDTS + 7))field of CT entry
 *        4. Present bit is set
 *        5. (GNR only) DTE and PRE are not set
 *        6. rid_priv not set
 *
 * @param cte
 *
 * @return  Success or Error type
 */
_STATIC_INLINE_ api_error_type is_valid_dmar_cte(const dmar_cte_t *const cte)
{
    api_error_type res = UNINITIALIZE_ERROR;
    pa_t pdp_pa = {.raw = 0};
    pdp_pa.page_4k_num = cte->pasiddirptr;
    pa_t max_pdp_pa = {.raw = pdp_pa.raw + dmar_get_cte_pd_page_cnt(cte) * _4KB};

    if ((!cte->p) ||
        cte->dte || // no secure ATS on GNR
        cte->pre || // no secure ATS on GNR
        cte->rsvd1 ||
        cte->paside ||
        (get_hkid_from_pa(pdp_pa) != 0) ||
        (get_hkid_from_pa(max_pdp_pa) != 0))
    {
        res = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
    }
    else if ((cte->pd_idx >= (BIT(cte->pdts + PDTS_IDX_CONST))) || // RID_PASID does not overflow the PDTS
             cte->rid_pasid ||
             cte->rid_priv ||
             cte->rsvd2)
    {
        res = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
    }
    else if (cte->rsvd3)
    {
        res = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R9);
    }
    else if (cte->rsvd4)
    {
        res = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
    }
    else
    {
        res = TDX_SUCCESS;
    }
    return res;
}

/**
 * @brief Given PASID directory entry, verify the following:
 *        1. Reserved bits not set
 *        2. KeyID bits in PASID table pointer don’t have a private KeyID
 *        3. Present bit is set
 *
 * @param pde
 *
 * @return
 */
_STATIC_INLINE_ bool_t is_valid_dmar_pde(const dmar_pde_t *const pde)
{
    pa_t ptp_pa = {.raw = 0};
    ptp_pa.page_4k_num = pde->smptblptr;

    return (!pde->rsvd) &&
           (get_hkid_from_pa(ptp_pa) == 0) &&
           pde->p;
}

/**
 * @brief Given PASID table entry, verify the following:
 *        1. AW value is matching with the value in TDCS of the EPT level
 *        2.1. PGTT is 10b – second level only
 *          2.2. ORPGTT is 011b – nested if TD requests
 *        3. Ensure VMM provides 0 for all second level parameters
 *           3.1. SLEE, PWT, PCD, PAT,
 *           3.2. Fields [SRE, ERE, FLPM, WPE, SMEP, EAFE, FLPTR, NXE] are all in Qword[2]
 *        4. PWSNP, PGSNP, and EMTE are 0x1
 *        5. CD is 0x0
 *        6. EMT is 0x6 (MT_WB)
 *        7. DID is 0x0
 *        8. Present bit must be 1
 *        9. SLPTR specified by VMM is 0
 *       10. SLADE must match the EPT A/D enable in secure EPTP
 *
 * @param pasidte
 * @param tdcs_ptr
 *
 * @return  Success or Error type
 */
_STATIC_INLINE_ api_error_type is_valid_dmar_pasidte(
    const dmar_pasidte_t *const pasidte)
{
    // Check Qword[0]
    if (pasidte->p ||
        (!pasidte->slee) ||
        (pasidte->pgtt != AW_48_BIT) ||
        (pasidte->rsvd1) ||
        (pasidte->slptptr))
    {
        TDX_ERROR("Invalid pasidte entry qword[0] = 0x%llx\n", pasidte->raw.qwords[0]);
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
    }
    // Check Qword[1]
    else if (pasidte->did ||
             pasidte->rsvd2 ||
             (!pasidte->pwsnp) ||
             (!pasidte->pgsnp) ||
             pasidte->cd ||
             (!pasidte->emte) ||
             (pasidte->emt != MT_WB) ||
             pasidte->pwt ||
             pasidte->pcd ||
             pasidte->pat)
    {
        TDX_ERROR("Invalid pasidte entry qword[1] = 0x%llx\n", pasidte->raw.qwords[1]);
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
    }

    for (uint8_t curr_q = 2; curr_q < sizeof(dmar_entry_t) / sizeof(uint64_t); curr_q++)
    {
        if (pasidte->raw.qwords[curr_q] != 0)
        {
            uint16_t operand_id = curr_q == 0? OPERAND_ID_RDX: curr_q + OPERAND_ID_R8 - 1;
            TDX_ERROR("dmar_val_%u  != 0\n", curr_q);
            return api_error_with_operand_id(TDX_OPERAND_INVALID, operand_id);
        }
    }

    return TDX_SUCCESS;
}

/**
 * @brief Extract relevant info from the dmar_walk_res
 *
 * @param dmar_walk_res
 *
 * @return dmar_state_info_t
 */
_STATIC_INLINE_ dmar_state_info_t dmar_get_state_info(const dmar_walk_res_t *const dmar_walk_res)
{
    dmar_state_info_t dmar_state_info = {.raw = 0};
    dmar_state_info.level = dmar_walk_res->dmar_level;
    switch (dmar_walk_res->dmar_level)
    {
    case DMAR_RTE_LVL:
        dmar_state_info.inv_sts = dmar_walk_res->rte_ptr->inv_state;
        switch (dmar_get_rte_state(dmar_walk_res->rte_ptr))
        {
        case DMAR_RTE_FREE:
            dmar_state_info.map_sts = DMAR_FREE;
            break;
        case DMAR_RTE_PRESENT:
            dmar_state_info.map_sts = DMAR_PRESENT;
            break;
        case DMAR_RTE_BLOCKED:
            dmar_state_info.map_sts = DMAR_BLOCKED;
            break;
        default:
            break;
        }
        break;
    case DMAR_CTE_LVL:
        dmar_state_info.inv_sts = dmar_walk_res->cte_ptr->inv_state;
        dmar_state_info.pd_cnt = dmar_walk_res->cte_ptr->pde_cnt;
        switch (dmar_get_cte_state(dmar_walk_res->cte_ptr))
        {
        case DMAR_CTE_FREE:
            dmar_state_info.map_sts = DMAR_FREE;
            break;
        case DMAR_CTE_PRESENT:
            dmar_state_info.map_sts = DMAR_PRESENT;
            break;
        case DMAR_CTE_BLOCKED:
            dmar_state_info.map_sts = DMAR_BLOCKED;
            break;
        default:
            break;
        }
        break;
    case DMAR_PDE_LVL:
        dmar_state_info.inv_sts = dmar_walk_res->pde_ptr->inv_state;
        switch (dmar_get_pde_state(dmar_walk_res->pde_ptr))
        {
        case DMAR_PDE_FREE:
            dmar_state_info.map_sts = DMAR_FREE;
            break;
        case DMAR_PDE_PRESENT:
            dmar_state_info.map_sts = DMAR_PRESENT;
            break;
        case DMAR_PDE_BLOCKED:
            dmar_state_info.map_sts = DMAR_BLOCKED;
            break;
        default:
            break;
        }
        break;
    case DMAR_PASIDTE_LVL:
        dmar_state_info.inv_sts = dmar_walk_res->pasidte_ptr->inv_state;
        switch (dmar_get_pasidte_state(dmar_walk_res->pasidte_ptr))
        {
        case DMAR_PASIDTE_FREE:
            dmar_state_info.map_sts = DMAR_FREE;
            break;
        case DMAR_PASIDTE_PRESENT:
            dmar_state_info.map_sts = DMAR_PRESENT;
            break;
        case DMAR_PASIDTE_BLOCKED:
            dmar_state_info.map_sts = DMAR_BLOCKED;
            break;
        case DMAR_PASIDTE_PENDING:
            dmar_state_info.map_sts = DMAR_PENDING;
            break;
        default:
            break;
        }
        break;
    }
    return dmar_state_info;
}

_STATIC_INLINE_ bool_t dmar_lock(dmar_walk_res_t *const dmar_walk_res_ptr)
{
    uint32_t *entry_ptr = NULL;

    switch (dmar_walk_res_ptr->dmar_level)
    {
    case DMAR_RTE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->rte_ptr;
        break;
    case DMAR_CTE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->cte_ptr;
        break;
    case DMAR_PDE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->pde_ptr;
        break;
    case DMAR_PASIDTE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->pasidte_ptr;
        break;
    default:
        return false;
    }

    uint32_t bit_position = dmar_walk_res_ptr->dmar_level == DMAR_CTE_LVL ? CTE_LOCK_BIT : RTE_PDE_PASIDTE_LOCK_BIT;
    dmar_walk_res_ptr->entry_locked = acquire_bit_lock(entry_ptr, bit_position) == TDX_SUCCESS;
    return dmar_walk_res_ptr->entry_locked;
}

_STATIC_INLINE_ void dmar_unlock(dmar_walk_res_t *const dmar_walk_res_ptr)
{
    uint32_t *entry_ptr = NULL;

    switch (dmar_walk_res_ptr->dmar_level)
    {
    case DMAR_RTE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->rte_ptr;
        break;
    case DMAR_CTE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->cte_ptr;
        break;
    case DMAR_PDE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->pde_ptr;
        break;
    case DMAR_PASIDTE_LVL:
        entry_ptr = (uint32_t *)dmar_walk_res_ptr->pasidte_ptr;
        break;
    default:
        return;
    }

    uint32_t bit_position = dmar_walk_res_ptr->dmar_level == DMAR_CTE_LVL ? CTE_LOCK_BIT : RTE_PDE_PASIDTE_LOCK_BIT;
    release_bit_lock(entry_ptr, bit_position);
    dmar_walk_res_ptr->entry_locked = false;
}

/**
 * @brief Set relevant info from the dmar_state_info into dmar_walk_res
 *
 * @param dmar_walk_res
 * @param dmar_state_info
 */
_STATIC_INLINE_ void dmar_set_state_info(
    dmar_walk_res_t *const dmar_walk_res,
    const dmar_state_info_t dmar_state_info)
{
    switch (dmar_walk_res->dmar_level)
    {
    case DMAR_RTE_LVL:
        switch (dmar_state_info.map_sts)
        {
        case DMAR_FREE:
            dmar_set_rte_state(dmar_walk_res->rte_ptr, DMAR_RTE_FREE);
            break;
        case DMAR_PRESENT:
            dmar_set_rte_state(dmar_walk_res->rte_ptr, DMAR_RTE_PRESENT);
            break;
        case DMAR_BLOCKED:
            dmar_set_rte_state(dmar_walk_res->rte_ptr, DMAR_RTE_BLOCKED);
            break;
        default:
            break;
        }
        if (dmar_state_info.map_sts != DMAR_FREE)
        {
            dmar_set_rte_inv_state(dmar_walk_res->rte_ptr, dmar_state_info.inv_sts);
        }
        break;
    case DMAR_CTE_LVL:
        switch (dmar_state_info.map_sts)
        {
        case DMAR_FREE:
            dmar_set_cte_state(dmar_walk_res->cte_ptr, DMAR_CTE_FREE);
            break;
        case DMAR_PRESENT:
            dmar_set_cte_state(dmar_walk_res->cte_ptr, DMAR_CTE_PRESENT);
            break;
        case DMAR_BLOCKED:
            dmar_set_cte_state(dmar_walk_res->cte_ptr, DMAR_CTE_BLOCKED);
            break;
        default:
            break;
        }
        dmar_set_cte_inv_state(dmar_walk_res->cte_ptr, dmar_state_info.inv_sts);
        dmar_set_cte_pde_cnt(dmar_walk_res->cte_ptr, dmar_state_info.pd_cnt);
        break;
    case DMAR_PDE_LVL:
        switch (dmar_state_info.map_sts)
        {
        case DMAR_FREE:
            dmar_set_pde_state(dmar_walk_res->pde_ptr, DMAR_PDE_FREE);
            break;
        case DMAR_PRESENT:
            dmar_set_pde_state(dmar_walk_res->pde_ptr, DMAR_PDE_PRESENT);
            break;
        case DMAR_BLOCKED:
            dmar_set_pde_state(dmar_walk_res->pde_ptr, DMAR_PDE_BLOCKED);
            break;
        default:
            break;
        }
        if (dmar_state_info.map_sts != DMAR_FREE)
        {
            dmar_set_pde_inv_state(dmar_walk_res->pde_ptr, dmar_state_info.inv_sts);
        }
        break;
    case DMAR_PASIDTE_LVL:
        dmar_set_pasidte_inv_state(dmar_walk_res->pasidte_ptr, dmar_state_info.inv_sts);
        switch (dmar_state_info.map_sts)
        {
        case DMAR_FREE:
            dmar_set_pasidte_state(dmar_walk_res->pasidte_ptr, DMAR_PASIDTE_FREE);
            break;
        case DMAR_PRESENT:
            dmar_set_pasidte_state(dmar_walk_res->pasidte_ptr, DMAR_PASIDTE_PRESENT);
            break;
        case DMAR_BLOCKED:
            dmar_set_pasidte_state(dmar_walk_res->pasidte_ptr, DMAR_PASIDTE_BLOCKED);
            break;
        case DMAR_PENDING:
            dmar_set_pasidte_state(dmar_walk_res->pasidte_ptr, DMAR_PASIDTE_PENDING);
            break;
        default:
            break;
        }
        break;
    }
}

/**
 * @brief Map the rta address as RO.
 *        Scan all entries and return true if all entries are not present.
 *
 * @param rta_addr_reg
 *
 * @return bool_t
 */
_STATIC_INLINE_ bool_t is_dmar_root_table_empty(const rta_addr_reg_t rta_addr_reg)
{
    bool_t ret_val = false;

    pa_t rta_pa = {.raw = 0};
    rta_pa.page_4k_num = rta_addr_reg.rta;

    dmar_rte_t *rte_base_ptr = (dmar_rte_t *)map_pa_with_global_hkid(
        rta_pa.raw_void,
        TDX_RANGE_RO);

    for (uint16_t i = 0; i < MAX_RT_ENTRIES_PER_PAGE; i++)
    {
        if (dmar_get_rte_state(rte_base_ptr + i) != DMAR_RTE_FREE)
        {
            goto EXIT;
        }
    }
    ret_val = true;
EXIT:
    free_la(rte_base_ptr);

    return ret_val;
}

/**
 * @brief Perform DMA walk from root to indicated level and retrieve a path of DMAR
 *        entry pointers and the lowest level of present DMAR page visited.
 *        The function walks the DMA from T_RTA_ADDR retrieved using the IOMMU_ID until the
 *        requested DMAR entry level.
 *        entry_pamt_lock aqcuires a shared lock on the pamt entries.
 *
 * @note Caller must call dmar_unwalk to un-map and unlock DMAR PAMT entries
 *       If walk fails, there is no need to call dmar_unwalk
 *
 * @param dmar_idx
 * @param leaf_mapping_type - when true, leaf level will be mapped as RW, else as RO
 * @param is_guest - Specifies if the lock is for guest or host
 * @param is_dmar_walked_ptr - Reminds the user to unwalk the DMAR tree
 * @param dmar_walk_res
 *
 * @return Success or Error code
 */
api_error_code_e dmar_walk(
    const dmar_idx_t dmar_idx,
    const bool_t check_pasid,
    const bool_t lock_entry,
    const mapping_type_t leaf_mapping_type,
    const bool_t is_guest,
    bool_t *const is_dmar_walked_ptr,
    dmar_walk_res_t *const dmar_walk_res);

/**
 * @brief Un-map and unlock DMAR entries and DMAR locked PAMT entries
 *        entry_pamt_lock releases the shared lock on the pamt entries
 *
 * @param dmar_res
 * @param entry_pamt_unlock
 */
void dmar_unwalk(dmar_walk_res_t *const dmar_walk_res);

/**
 * @brief Atomically map DMAR entry (per q-word) using DMAR value and state info
 *
 * @param dmar_walk_res
 * @param dmar_state_info
 * @param dmar_entry_ptr
 */
void dmar_map_entry(
    dmar_walk_res_t *const dmar_walk_res,
    const dmar_state_info_t dmar_state_info,
    const dmar_entry_t *const dmar_entry_ptr);

/**
 * @brief Add root table entry
 *
 * @param dmar_walk_res
 * @param dmar_state_info
 * @param dmar_entry_ptr
 * @param pamt_val
 * @return Success or Error type
 */
api_error_type dmar_rte_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const pamt_entry_t *const pamt_val);

/**
 *
 * @brief Add context table entry
 *
 * @param dmar_walk_res
 * @param dmar_state_info
 * @param dmar_entry_ptr
 * @param pamt_val
 * @return Success or Error type
 */
api_error_type dmar_cte_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const pamt_entry_t *const pamt_val);

/**
 * @brief Add PASID Directory entry
 *
 * @param dmar_walk_res
 * @param dmar_state_info
 * @param dmar_entry_ptr
 * @param pamt_val
 *
 * @return Success or Error type
 */
api_error_type dmar_pde_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const pamt_entry_t *const pamt_val);

/**
 * @brief Add PASID Table Entry
 *
 * @param dmar_walk_res
 * @param dmar_state_info
 * @param dmar_entry_ptr
 * @param iommu_id
 *
 * @return Success or Error type
 */
api_error_type dmar_pasidte_add(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t dmar_state_info,
    dmar_entry_t *const dmar_entry_ptr,
    const iommu_id_t iommu_id);

/**
 * @brief Infer current DMAR entry using the level and set R8-R15 with the DMAR entry value with TDX
 *        internal state bits set to zero and set RDX with the corresponding architectural DMAR_STATE_INFO_T value.
 *
 * @param dmar_walk_res
 */
void dmar_arc_read(const dmar_walk_res_t *const dmar_walk_res);

/**
 * @brief Remove root table entry
 *
 * @param dmar_walk_res
 *
 * @return Success or Error type
 */
api_error_type dmar_rte_remove(dmar_walk_res_t *const dmar_walk_res);

/**
 * @brief Remove context table entry
 *
 * @param dmar_walk_res
 * @param dmar_idx
 *
 * @return Success or Error type
 */
api_error_type dmar_cte_remove(
    dmar_walk_res_t *const dmar_walk_res,
    dmar_state_info_t *const dmar_state_info);

/**
 * @brief Remove PASID directory entry
 *
 * @param dmar_walk_res
 *
 * @return Success or Error type
 */
api_error_type dmar_pde_remove(dmar_walk_res_t *const dmar_walk_res);

/**
 * @brief Remove PASID table entry
 *
 * @param dmar_state_info
 * @param tdcs_ptr
 *
 * @return Success or Error type
 */
api_error_type dmar_pasidte_remove(
    const dmar_idx_t dmar_idx,
    tdcs_t *const tdcs_ptr);

/**
 * @brief Verify all child nodes of the relevant DMAR level are set as free
 *
 * @param dmar_walk_res
 *
 * @return bool_t
 */
bool_t is_dmar_child_entires_free(const dmar_walk_res_t *const dmar_walk_res);

#endif /* SRC_COMMON_TDXIO_DMAR_H_ */
