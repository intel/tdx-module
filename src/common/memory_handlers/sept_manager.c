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
 * @file sept_manager.c
 * @brief SEPT manager implementaiton
 */


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"

#include "sept_manager.h"
#include "keyhole_manager.h"
#include "x86_defs/x86_defs.h"
#include "accessors/data_accessors.h"
#include "data_structures/tdx_local_data.h"
#include "helpers/helpers.h"


_STATIC_INLINE_ uint64_t get_ept_entry_idx(pa_t gpa, ept_level_t lvl)
{
    uint64_t idx = 0;

    switch (lvl)
    {
        case LVL_PML5:
            idx = gpa.fields_4k.pml5_index;
            break;
        case LVL_PML4:
            idx = gpa.fields_4k.pml4_index;
            break;
        case LVL_PDPT:
            idx = gpa.fields_4k.pdpt_index;
            break;
        case LVL_PD:
            idx = gpa.fields_4k.pd_index;
            break;
        case LVL_PT:
            idx = gpa.fields_4k.pt_index;
            break;
        default:
            tdx_sanity_check(0, SCEC_SEPT_MANAGER_SOURCE, 0);
            break;
    }

    return idx;
}

_STATIC_INLINE_ bool_t is_secure_ept_entry_misconfigured(ia32e_sept_t* pte, ept_level_t level)
{
    pa_t hpa;
    hpa.raw = pte->raw & IA32E_PAGING_STRUCT_ADDR_MASK;

    if (!is_pa_smaller_than_max_pa(hpa.raw))
    {
        return true;
    }

    if ((pte->r == 0) && (pte->w == 1))
    {
        TDX_ERROR("Read bit is zero but write bit is 1 - 0x%llx\n", pte->raw);
        return true;
    }

    platform_common_config_t* msr_values = &get_global_data()->plt_common_config;

    if (!(msr_values->ia32_vmx_ept_vpid_cap & EPT_VPID_CAP_ALLOW_EXECUTE_ONLY))
    {
        if ((pte->r == 0) && (pte->x == 1))
        {
            TDX_ERROR("Read bit is zero but X bit is 1 - 0x%llx\n", pte->raw);
            return true;
        }
    }

    if (pte->rwx)
    {
        // A reserved bit is set. This includes the setting of a bit in the
        // range 51:12 that is beyond the logical processor’s physical-address width.

        // Bits beyond logical processor physical-address width will be checked
        // by the is_pa_smaller_than_max_pa() function call above

        // Paging structure case:
        if (((level > LVL_PDPT) || ((level > LVL_PT) && !pte->leaf))
                && pte->fields_ps.reserved_0)
        {
            TDX_ERROR("Reserved bits are set in PS entry - 0x%llx\n", pte->raw);
            return true;
        }
        // Leaf case
        if ( ((level == LVL_PDPT) && pte->leaf && pte->reserved_1) ||
             ((level == LVL_PD) && pte->leaf && pte->reserved_1)
           )
        {
            TDX_ERROR("Reserved bits are set in leaf entry - 0x%llx\n", pte->raw);
            return true;
        }

        // The entry is the last one used to translate a guest physical address
        // (either an EPT PDE with bit 7 set to 1 or an EPT PTE) and the
        // value of bits 5:3 (EPT memory type) is 2, 3, or 7 (these values are reserved).
        if ( ((level == LVL_PDPT) && pte->leaf) ||
             ((level == LVL_PD) && pte->leaf) ||
              (level == LVL_PT) )
        {
            // Looking here at 4K struct because the MT bits location is the same in 1G and 2M
            if ((pte->mt == MT_RSVD0) || (pte->mt == MT_RSVD1) ||
                (pte->mt == MT_UCM))
            {
                TDX_ERROR("Memory type is incorrect (%d) - 0x%llx\n", pte->mt, pte->raw);
                return true;
            }
        }
    }

    return false;
}

_STATIC_INLINE_ bool_t is_shared_ept_entry_misconfigured(ia32e_ept_t* pte, ept_level_t level)
{
    pa_t hpa;
    hpa.raw = pte->raw & IA32E_PAGING_STRUCT_ADDR_MASK;

    // 28.2.3.1 EPT Misconfigurations from Intel SDM:
    // Bit 0 of the entry is clear (indicating that data reads are not allowed)
    // and bit 1 is set (indicating that data writes are allowed).
    if ((pte->fields_ps.r == 0) && (pte->fields_ps.w == 1))
    {
        return true;
    }

    platform_common_config_t* msr_values = &get_global_data()->plt_common_config;

    // Either of the following if the processor does not support execute-only translations:
    if (!(msr_values->ia32_vmx_ept_vpid_cap & EPT_VPID_CAP_ALLOW_EXECUTE_ONLY))
    {
        // Bit 0 of the entry is clear (indicating that data reads are not allowed)
        // and bit 2 is set (indicating that instruction fetches are allowed)
        if ((pte->fields_ps.r == 0) && (pte->fields_ps.x == 1))
        {
            return true;
        }

        // The "mode-based execute control for EPT" VM-execution control is 1,
        // bit 0 of the entry is clear (indicating that data reads are not allowed),
        // and bit 10 is set (indicating that instruction fetches are allowed from
        // usermode linear addresses).

        // No need to check, because "mode-based execute control for EPT" bit
        // is defined to be a constant 0 in TD VMCS.
    }

    // The entry is present (see Section 28.2.2) and one of the following holds:
    if (pte->present.rwx)
    {
        // A reserved bit is set. This includes the setting of a bit in the
        // range 51:12 that is beyond the logical processor’s physical-address width.

        // Bits beyond logical processor physical-address width will be checked
        // by the shared_hpa_check() function call above

        // Paging structure case:
        if (((level > LVL_PDPT) || ((level > LVL_PT) && !pte->fields_1g.leaf))
                && pte->fields_ps.reserved_0)
        {
            return true;
        }
        // Leaf case
        if ( ((level == LVL_PDPT) && pte->fields_1g.leaf && pte->fields_1g.reserved_0) ||
             ((level == LVL_PD) && pte->fields_2m.leaf && pte->fields_2m.reserved_0)
           )
        {
            return true;
        }

        // The entry is the last one used to translate a guest physical address
        // (either an EPT PDE with bit 7 set to 1 or an EPT PTE) and the
        // value of bits 5:3 (EPT memory type) is 2, 3, or 7 (these values are reserved).
        if ( ((level == LVL_PDPT) && pte->fields_1g.leaf) ||
             ((level == LVL_PD) && pte->fields_2m.leaf) ||
              (level == LVL_PT) )
        {
            // Looking here at 4K struct because the MT bits location is the same in 1G and 2M
            if ((pte->fields_4k.mt == MT_RSVD0) || (pte->fields_4k.mt == MT_RSVD1) ||
                (pte->fields_4k.mt == MT_UCM))
            {
                return true;
            }
        }
        else
        {
            // Shared 4KB HPA check is relevant only for present and non-leaf entries
            // Leaf entry HPA should be checked at the end of the final translation
            if (shared_hpa_check(hpa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS)
            {
                return true;
            }
        }
    }

    return false;
}

_STATIC_INLINE_ bool_t is_ept_violation_convertible(ia32e_ept_t* pte, ept_level_t level)
{
    // #VE is enabled unconditionally for TDX non-root operation.
    // The TDX-SEAM module sets the TD VMCS EPT-violation #VE VM-execution control to 1.

    // Checks are according to SDM (25.5.6.1) - Convertible EPT Violations

    // The values of certain EPT paging-structure entries determine which EPT violations are convertible. Specifically,
    // bit 63 of certain EPT paging-structure entries may be defined to mean suppress #VE:
    // - If bits 2:0 of an EPT paging-structure entry are all 0, the entry is not present.
    //      (If the “mode-based execute control for EPT" VM-execution control is 1,
    //       an EPT paging-structure entry is present if any of bits 2:0 or bit 10 is 1)
    //      If the processor encounters such an entry while translating a guest-physical address,
    //      it causes an EPT violation. The EPT violation is convertible if and only if bit 63 of the entry is 0.

    // - If an EPT paging-structure entry is present, the following cases apply:
    //      * If bit 7 of the entry is 1, or if the entry is an EPT PTE, the entry maps a page.
    //        If the processor uses such an entry to translate a guest-physical address, and if
    //        an access to that address causes an EPT violation, the EPT violation is convertible
    //        if and only if bit 63 of the entry is 0.
    //      * If bit 7 of the entry is 0 and the entry is not an EPT PTE, the entry references another EPT paging
    //        structure. The processor does not use the value of bit 63 of the entry to determine whether any
    //        subsequent EPT violation is convertible.

    // Note that Bit(22) - Mode-based execute control for EPT in TD exec controls is always 0
    // So no need to check bit 10 in EPT entry to determine whether the entry is present

    if ((!pte->present.rwx || pte->fields_2m.leaf || (level == LVL_PT)) && !pte->fields_4k.supp_ve)
    {
        return true;
    }

    return false;
}

ept_walk_result_t gpa_translate(ia32e_eptp_t eptp, pa_t gpa, bool_t private_gpa,
                                uint16_t private_hkid, access_rights_t access_rights,
                                pa_t* hpa, ia32e_ept_t* cached_ept_entry, access_rights_t* accumulated_rwx)
{
    ia32e_paging_table_t *pt;
    ia32e_ept_t *pte;
    pa_t pt_pa;
    ept_level_t current_lvl;

    // Get root PML EPT page address
    pt_pa.raw = eptp.raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    current_lvl = eptp.fields.ept_pwl;
    // No need to check the HPA of PML5 in Shared EPTP, it is checked during TDHVPWR

    accumulated_rwx->raw = (uint8_t)7;

    for (;current_lvl >= LVL_PT; current_lvl--)
    {
        if (private_gpa)
        {
            pt_pa = set_hkid_to_pa(pt_pa, private_hkid);
        }
        pt = map_pa((void*)(pt_pa.full_pa), TDX_RANGE_RO);
        pte = &(pt->ept[get_ept_entry_idx(gpa, current_lvl)]);

        // Update the output data - note the we read only from the cached entry
        cached_ept_entry->raw = pte->raw; // Atomic copy
        accumulated_rwx->rwx &= cached_ept_entry->present.rwx;

        free_la(pt); // Not needed at that point

        // Check misconfiguration conditions
        IF_RARE (!private_gpa && is_shared_ept_entry_misconfigured(cached_ept_entry, current_lvl))
        {
            return EPT_WALK_MISCONFIGURATION;
        }

        // Misconfigurations on Secure EPT are not expected and considered to be fatal errors
        IF_RARE (private_gpa && is_secure_ept_entry_misconfigured((ia32e_sept_t*)cached_ept_entry, current_lvl))
        {
            FATAL_ERROR();
        }

        // Check violation conditions
        IF_RARE ((cached_ept_entry->present.rwx == 0) ||
                 ((uint8_t)(access_rights.rwx & cached_ept_entry->present.rwx) != access_rights.rwx))
        {
            if (is_ept_violation_convertible(cached_ept_entry, current_lvl))
            {
                return EPT_WALK_CONVERTIBLE_VIOLATION;
            }
            else
            {
                return EPT_WALK_VIOLATION;
            }
        }

        // Check if leaf is reached - page walk done
        if (is_ept_leaf_entry(cached_ept_entry, current_lvl))
        {
            // Calculate the final HPA
            hpa->raw = leaf_ept_entry_to_hpa((*(ia32e_sept_t*)cached_ept_entry), gpa.raw, current_lvl);
            break;
        }

        // Cannot continue to next level, this should be the last one
        IF_RARE (current_lvl == LVL_PT)
        {
            FATAL_ERROR();
        }

        pt_pa.raw = cached_ept_entry->raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    }

    // Shared HPA check on the final translated 4KB page.
    // Since TDX module works only with 4KB operands, this check is sufficient,
    // and we don't need to check SEAMRR overlaps of whole area in case when bigger (1GB or 2MB)
    // leaf page is mapped by the TD.
    if (!private_gpa && (shared_hpa_check(*hpa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS))
    {
        return EPT_WALK_MISCONFIGURATION;
    }

    return EPT_WALK_SUCCESS;
}

ia32e_sept_t* secure_ept_walk(ia32e_eptp_t septp, pa_t gpa, uint16_t private_hkid,
                              ept_level_t* level, ia32e_sept_t* cached_sept_entry,
                              bool_t l2_sept_guest_side_walk)
{
    ia32e_paging_table_t *pt;
    ia32e_sept_t *pte;
    pa_t pt_pa;

    ept_level_t requested_level = *level;
    ept_level_t current_lvl;

    tdx_sanity_check(requested_level <= LVL_PML5, SCEC_SEPT_MANAGER_SOURCE, 1);

    // Get root PML EPT page address
    pt_pa.raw = septp.raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    current_lvl = septp.fields.ept_pwl;
    // No need to check the HPA of PML5 in Shared EPTP, it is checked during TDHVPWR

    for (;current_lvl >= LVL_PT; current_lvl--)
    {
        pt_pa = set_hkid_to_pa(pt_pa, private_hkid);
        pt = map_pa((void*)(pt_pa.full_pa), TDX_RANGE_RW);
        pte = &(pt->sept[get_ept_entry_idx(gpa, current_lvl)]);

        // Update the output data - note the we read only from the cached entry
        cached_sept_entry->raw = pte->raw; // Atomic copy
        *level = current_lvl;

        // Check if it is the requested level - success
        if (current_lvl == requested_level)
        {
            break;
        }

        IF_RARE (is_secure_ept_entry_misconfigured(cached_sept_entry, current_lvl))
        {
            FATAL_ERROR();
        }

        // Check if entry not present, or a leaf - so can't walk any further.
        // In L2 SEPT guest-side walk mode, a L2_FREE state is checked
        // In any other walk mode, RWX bits are checked
        IF_RARE ((l2_sept_guest_side_walk && is_l2_sept_free(cached_sept_entry)) ||
                 (!l2_sept_guest_side_walk && (cached_sept_entry->rwx == 0))     ||
                  is_secure_ept_leaf_entry(cached_sept_entry))
        {
            break;
        }

        // Cannot continue to next level, this should be the last one
        IF_RARE (current_lvl == LVL_PT)
        {
            FATAL_ERROR();
        }

        // Continue to next level in the walk
        pt_pa.raw = cached_sept_entry->raw & IA32E_PAGING_STRUCT_ADDR_MASK;
        free_la(pt); // Not needed at that point
    }

    // Note that the caller should remember to free the
    // PTE pointer after he finishes to use it!

    return pte;
}

static void sept_set_leaf_no_lock_internal(ia32e_sept_t * ept_entry, uint64_t attributes, pa_t page_pa,
                                           uint64_t state_encoding, bool_t set_lock)
{
    ia32e_sept_t septe_value = {.raw = attributes};

    // Sanity check:  any attributes bit that is set to 1 must also be 1 in the MIGRATABLE_ATTRIBUTES_MASK
    tdx_debug_assert((attributes & (~SEPT_MIGRATABLE_ATTRIBUTES_MASK)) == 0);

    septe_value.raw |= state_encoding;
    septe_value.mt = MT_WB;
    septe_value.ipat = 1;
    septe_value.base = page_pa.page_4k_num;

    tdx_debug_assert(septe_value.leaf == 1);   // PS is part of the state encoding assigned above
    septe_value.base = page_pa.page_4k_num;

    septe_value.supp_ve = 1;
    septe_value.tdel = set_lock ? 1 : 0;

    atomic_mem_write_64b(&ept_entry->raw, septe_value.raw);
}

void sept_set_leaf_and_release_locks(ia32e_sept_t * ept_entry, uint64_t attributes,
                                     pa_t page_pa, uint64_t state_encoding)
{
    sept_set_leaf_no_lock_internal(ept_entry, attributes, page_pa, state_encoding, false);
}

void sept_set_leaf_and_keep_lock(ia32e_sept_t * ept_entry, uint64_t attributes,
                                 pa_t page_pa, uint64_t state_encoding)
{
    // Sanity check, entry should already be locked
    tdx_sanity_check(ept_entry->tdel, SCEC_SEPT_MANAGER_SOURCE, 3);

    sept_set_leaf_no_lock_internal(ept_entry, attributes, page_pa, state_encoding, true);
}

void sept_set_leaf_unlocked_entry(ia32e_sept_t * ept_entry, uint64_t attributes,
                                  pa_t page_pa, uint64_t state_encoding)
{
    // Sanity check: SEPT entry must be unlocked
    tdx_sanity_check(ept_entry->tdel == 0, SCEC_SEPT_MANAGER_SOURCE, 4);

    sept_set_leaf_no_lock_internal(ept_entry, attributes, page_pa, state_encoding, false);
}

void sept_set_mapped_non_leaf(ia32e_sept_t * ept_entry, pa_t page_pa, bool_t lock)
{
    ia32e_sept_t curr_entry = {.raw = SEPT_PERMISSIONS_RWX | SEPT_STATE_NL_MAPPED_MASK};

    tdx_debug_assert(curr_entry.leaf == 0);   // PS is part of the state encoding assigned above

    curr_entry.base = page_pa.page_4k_num;
    curr_entry.supp_ve = 1;
    curr_entry.tdel = lock;

    // One aligned assignment to make it atomic
    atomic_mem_write_64b(&ept_entry->raw, curr_entry.raw);
}

void sept_l2_set_leaf(ia32e_sept_t* l2_sept_entry_ptr, gpa_attr_single_vm_t gpa_attr_single_vm,
                      pa_t pa, bool_t is_l2_blocked)
{
    ia32e_sept_t tmp_sept = *l2_sept_entry_ptr;
    tmp_sept.l2_encoding.r = gpa_attr_single_vm.r;
    tmp_sept.l2_encoding.w = gpa_attr_single_vm.w;
    tmp_sept.l2_encoding.x = gpa_attr_single_vm.xs;
    tmp_sept.l2_encoding.xu = gpa_attr_single_vm.xu;
    tmp_sept.l2_encoding.vgp = gpa_attr_single_vm.vgp;
    tmp_sept.l2_encoding.pwa = gpa_attr_single_vm.pwa;
    tmp_sept.l2_encoding.sss = gpa_attr_single_vm.sss;
    tmp_sept.l2_encoding.sve = gpa_attr_single_vm.sve;
    tmp_sept.l2_encoding.hpa = pa.page_4k_num;

    tmp_sept.mt = MT_WB;
    tmp_sept.l2_encoding.tdwr = 0;
    tmp_sept.ipat = 1;

    sept_state_mask_t sept_state_mask = SEPT_STATE_L2_MAPPED_MASK;

    if (is_l2_blocked)
    {
        sept_state_mask = SEPT_STATE_L2_BLOCKED_MASK;
        tmp_sept.l2_encoding.mt0_tdrd = gpa_attr_single_vm.r;
        tmp_sept.l2_encoding.r = 0;
        tmp_sept.l2_encoding.tdwr = gpa_attr_single_vm.w;
        tmp_sept.l2_encoding.w = 0;
        tmp_sept.l2_encoding.mt1_tdxs = gpa_attr_single_vm.xs;
        tmp_sept.l2_encoding.x = 0;
        tmp_sept.l2_encoding.mt2_tdxu = gpa_attr_single_vm.xu;
        tmp_sept.l2_encoding.xu = 0;
    }

    sept_l2_update_state(&tmp_sept, sept_state_mask);

    atomic_mem_write_64b(&l2_sept_entry_ptr->raw, tmp_sept.raw);
}

void sept_l2_set_mapped_non_leaf(ia32e_sept_t * ept_entry, pa_t page_pa)
{
    ia32e_sept_t curr_entry = {.raw = SEPT_PERMISSIONS_RW_XS_XU | SEPT_STATE_L2_NL_MAPPED_MASK};

    tdx_debug_assert(curr_entry.leaf == 0);   // PS is part of the state encoding assigned above

    curr_entry.base = page_pa.page_4k_num;

    // One aligned assignment to make it atomic
    atomic_mem_write_64b(&ept_entry->raw, curr_entry.raw);
}

void set_arch_septe_details_in_vmm_regs(ia32e_sept_t sept_entry, ept_level_t level, tdx_module_local_t* local_data_ptr)
{
    ia32e_sept_t detailed_arch_sept_entry;
    sept_entry_arch_info_t detailed_arch_info;

    /* Build the architectural representation of the Secure EPT entry.
       See the table in the spec for details*/
    if (is_sept_free(&sept_entry))
    {
        detailed_arch_sept_entry.raw = 0;
        detailed_arch_sept_entry.supp_ve = 1;
    }
    else
    {
        detailed_arch_sept_entry.raw = sept_entry.raw;
        sept_cleanup_if_pending(&sept_entry, level);

        if (is_secure_ept_leaf_entry(&detailed_arch_sept_entry))
        {
            detailed_arch_sept_entry.raw &= SEPT_ARCH_ENTRY_LEAF_MASK;
        }
        else
        {
            detailed_arch_sept_entry.raw &= SEPT_ARCH_ENTRY_NON_LEAF_MASK;
        }
        // No need to restore the values of MT1 and MT2, they are not overwritten
    }

    // Build the architectural information of the Secure EPT entry
    detailed_arch_info.raw = 0;

    detailed_arch_info.state = sept_get_arch_state(sept_entry);
    detailed_arch_info.level = (uint8_t)level;   // Cast down is OK since level fits in 8 bits

    // Return the values as simple 64b
    local_data_ptr->vmm_regs.rcx = detailed_arch_sept_entry.raw;
    local_data_ptr->vmm_regs.rdx = detailed_arch_info.raw;
}

void set_arch_l2_septe_details_in_vmm_regs(ia32e_sept_t l2_sept_entry, uint16_t vm_id, bool_t is_debug,
                                           uint64_t level, tdx_module_local_t* local_data_ptr)
{
    ia32e_sept_t           detailed_arch_sept_entry;
    sept_entry_arch_info_t detailed_arch_info;

    // Build the architectural representation of the L2 Secure EPT entry.
    // See the table in the spec for details
    if (is_l2_sept_free(&l2_sept_entry))
    {
        detailed_arch_sept_entry.raw = 0;
        detailed_arch_sept_entry.supp_ve = 1;
    }
    else
    {
        // Create the architectural SEPT entry as reported to the user
        detailed_arch_sept_entry.raw = l2_sept_entry.raw;
        if (is_secure_ept_leaf_entry(&l2_sept_entry))
        {
            if (is_debug)
            {
                detailed_arch_sept_entry.raw &= L2_SEPT_ARCH_ENTRY_LEAF_DEBUG_MASK;   // Attribute bits are included
            }
            else if (is_l2_sept_mapped(&l2_sept_entry))
            {
                detailed_arch_sept_entry.raw &= L2_SEPT_ARCH_ENTRY_LEAF_MASK;   // Attribute bits are excluded
                detailed_arch_sept_entry.raw |= L2_SEPT_PERMISSIONS_MASK;       // Force RWXsXu to 1111
            }
            else   // L2_BLOCKED
            {
                detailed_arch_sept_entry.raw &= L2_SEPT_ARCH_ENTRY_LEAF_MASK;   // Attribute bits are excluded
            }
        }
        else
        {
            detailed_arch_sept_entry.raw &= L2_SEPT_ARCH_ENTRY_NON_LEAF_MASK;
        }
    }

    // Build the architectural information of the Secure EPT entry
    detailed_arch_info.raw = 0;
    detailed_arch_info.state = l2_sept_get_arch_state(l2_sept_entry);
    detailed_arch_info.level = (uint8_t)level;   // Cast down is OK since level fits in 8 bits
    detailed_arch_info.vm = vm_id;

    // Return the values as simple 64b
    local_data_ptr->vmm_regs.rcx = detailed_arch_sept_entry.raw;
    local_data_ptr->vmm_regs.rdx = detailed_arch_info.raw;
}
