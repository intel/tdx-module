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
 * @file tdh_import_state_vp.c
 * @brief TDH_IMPORT_STATE_VP API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/op_state_lookup.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"
#include "metadata_handlers/metadata_generic.h"

/* Initialize VCPU-scope metadata.
   - Initialize fields marked as "IE*" ("IE", "IES", "IESME" etc.) in the TDVPS and TD VMCS spreadsheets.
   - Note that some fields are initialized during VMCS preparation and VCPU association
     functions prepare_td_vmcs(), associate_vcpu_initial() and associate_vcpu().
*/
static void init_imported_vp_state(tdr_t* tdr_p, tdcs_t *tdcs_p, tdvps_t *tdvps_p)
{
    tdvps_p->management.last_exit_tsc = ia32_rdtsc();
    tdvps_p->management.xfam = tdcs_p->executions_ctl_fields.xfam;

    init_tdvps_fields(tdcs_p, tdvps_p);

    init_td_vmcs(tdr_p, tdcs_p, tdvps_p, true, 0);
}

api_error_type tdh_import_state_vp(uint64_t target_tdvpr_pa, uint64_t hpa_and_size_pa,
                                   uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();

    // tdvps
    tdvps_t              *tdvps_p = NULL;      // Pinter to the tdvps structure
    pa_t                  tdvpr_pa;            // Physical address of the tdvpr page
    pamt_block_t          tdvpr_pamt_block;    // tdvpr pamt block
    bool_t                tdvpr_locked_flag = false;

    // TDR and TDCS
    tdr_t                *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t                  tdr_pa;               // Physical address of the owner TDR page
//    pamt_block_t       tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t         *tdr_pamt_p = NULL;    // Pinter to owner tdr pamt entry
    tdcs_t               *tdcs_p = NULL;        // Pointer to the TDCS structure
//    bool_t                tdr_locked_flag = false;

    bool_t                op_state_locked_flag = false;

    // MBMD
    mbmd_t               *mbmd_p = NULL;
    hpa_and_size_t        mbmd_hpa_and_size;

    // Page List
    page_list_info_t      page_list_info;
    uint32_t              page_list_i;
    pa_t                  page_list_pa;
    pa_t                 *page_list_p = NULL;

    // Single Metadata List Page
    pa_t                  md_list_pa;
    md_list_header_t     *md_list_hdr_p = NULL;

    md_field_id_t         field_id = {.raw = 0};
    md_field_id_t         next_field_id;

    api_error_type        return_val = TDX_OPERAND_INVALID;

    md_list_t             md_list;

    // Migration Stream
    migs_index_and_cmd_t  migs_i_and_cmd;
    uint16_t              migs_i = 0;
    migsc_t              *migsc_p = NULL;
    pa_t                  migsc_pa;
    bool_t                migsc_locked_flag = false;

    // Input register operands
    tdvpr_pa.raw = target_tdvpr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    page_list_info.raw = page_or_list_pa;
    migs_i_and_cmd.raw = migs_i_and_cmd_pa;

    uint64_t original_rcx = local_data_ptr->vmm_regs.rcx;
    uint64_t original_rdx = local_data_ptr->vmm_regs.rdx;

    // By default, 0 pages are exported
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Process the control structures and check status
    pamt_entry_t *tdvpr_pamt_p = NULL;    // Pinter to tdvpr pamt entry
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa, OPERAND_ID_RCX, TDX_LOCK_EXCLUSIVE, PT_TDVPR,
                                                        &tdvpr_pamt_block, &tdvpr_pamt_p, &tdvpr_locked_flag);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDVPR - error = %llx\n", return_val);
        goto EXIT;
    }

    tdr_pa.raw = 0;
    tdr_pa.page_4k_num = tdvpr_pamt_p->owner;
    bool_t is_tdr_locked = false;
    return_val = lock_and_map_implicit_tdr(tdr_pa, OPERAND_ID_TDR, TDX_RANGE_RO, TDX_LOCK_SHARED, &tdr_pamt_p, &is_tdr_locked, &tdr_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state        pamt_implicit_release_lock(tdr_pamt_p, TDX_LOCK_SHARED);
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_SHARED,
                                               false, TDH_IMPORT_STATE_VP_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }
    op_state_locked_flag = true;

    // Get the TD's ephemeral HKID
    uint16_t curr_hkid = tdr_p->key_management_fields.hkid;
    // Map the multi-page TDVPS structure
    tdvps_p = map_tdvps(tdvpr_pa, curr_hkid, tdcs_p->management_fields.num_l2_vms, TDX_RANGE_RW);

    if (!tdvps_p)
    {
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    // Process the migration stream

    // Check that the migration stream index is correct
    if (((uint32_t)migs_i_and_cmd.migs_index >= tdcs_p->migration_fields.num_migs - 1) ||
        (migs_i_and_cmd.reserved_31_16 != 0) ||
        (migs_i_and_cmd.reserved_62_32 != 0))
    {
        TDX_ERROR("migration stream index is incorrect (0x%llx)\n", migs_i_and_cmd.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    migs_i = migs_i_and_cmd.migs_index;

    lfence();
    // Lock the MIGSC link
    if (!(migsc_lock(&tdcs_p->f_migsc_links[migs_i])))
    {
        TDX_ERROR("Failed to lock the migsc for index %u\n", migs_i);
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
        goto EXIT;
    }
    migsc_locked_flag = true;

    // Map the MIGSC
    migsc_pa.raw = 0;
    migsc_pa.page_4k_num = tdcs_p->f_migsc_links[migs_i].migsc_hpa;

    migsc_p = (migsc_t *)map_pa_with_hkid(migsc_pa.raw_void,
            tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    if (migs_i_and_cmd.command == MIGS_INDEX_COMMAND_NEW)
    {
        // This is a new invocation, not a resumption

        // Initialize the MIGSC if needed
        if (!tdcs_p->f_migsc_links[migs_i].initialized)
        {
            tdcs_p->f_migsc_links[migs_i].initialized = true;
            migsc_init(migsc_p, &tdcs_p->migration_fields.mig_dec_working_key);
        }

        // Mark this flow as non-interrupted
        migsc_p->interrupted_state.valid = false;

        /*
         * From this point on, any failure will abort the import session
         * since some session state may have been impacted
         */

        // Check the VCPU state
        if (tdvps_p->management.state != VCPU_UNINITIALIZED)
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            TDX_ERROR("VCPU in incorrect state (0x%u)\n", tdvps_p->management.state);
            return_val = api_error_fatal(TDX_VCPU_STATE_INCORRECT);
            goto EXIT;
        }

        /*
         * Check and map the mbmd buffer in shared memory, read the mbmd into the migration
         * stream context and check it
         */
        if (mbmd_hpa_and_size.size < sizeof(mbmd_t))
        {
            TDX_ERROR("mbmd size (0x%llu) is too small\n", mbmd_hpa_and_size.size);
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return_val = api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }
        mbmd_hpa_and_size.size = 0;

        // Verify the MBMD physical address is canonical, shared, and aligned to 128B
        pa_t mbmd_hpa = { .raw = mbmd_hpa_and_size.raw };
        if (TDX_SUCCESS != shared_hpa_check_with_pwr_2_alignment(mbmd_hpa, MBMD_ALIGN))
        {
            TDX_ERROR("Failed on source shared HPA 0x%llx check\n", mbmd_hpa_and_size.raw);
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return_val = api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_R8);
            goto EXIT;
        }

        // Map the mbmd
        mbmd_p = (mbmd_t*)map_pa(mbmd_hpa.raw_void, TDX_RANGE_RO);

        // Read the mbmd into the migration stream context
        copy_mbmd(&migsc_p->mbmd, mbmd_p);

        // CHeck the MBMD in the MIGSC
        if ((migsc_p->mbmd.header.mig_version != tdcs_p->migration_fields.mig_working_version) ||
            (migsc_p->mbmd.header.size != sizeof(mbmd_t)) ||
            (migsc_p->mbmd.header.migs_index != migs_i) ||
            (migsc_p->mbmd.header.mb_type != MB_TYPE_MUTABLE_VCPU_STATE) ||
            (migsc_p->mbmd.header.reserved_1 != 0) ||
            (migsc_p->mbmd.header.mb_counter != migsc_p->expected_mb_counter) ||
            (migsc_p->mbmd.header.mig_epoch != tdcs_p->migration_fields.mig_epoch) ||
            (migsc_p->mbmd.vp_state.reserved != 0))
        {
            TDX_ERROR("Failed on migration bundle metada check\n");
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return_val = api_error_fatal(TDX_INVALID_MBMD);
            goto EXIT;
        }

        // Accumulate a MAC over the MAC’ed fields of the MBMD
        reset_to_next_iv(migsc_p, migsc_p->mbmd.header.iv_counter, migs_i);
        migsc_p->mbmd.header.iv_counter = 0;   // not included in the mac and not required anymore
        migsc_p->mbmd.header.migs_index = 0;   // Not included in the MAC and not required anymore
        if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (uint8_t*)&migsc_p->mbmd.vp_state,
                MBMD_SIZE_NO_MAC(migsc_p->mbmd.vp_state)) != AES_GCM_NO_ERROR)
        {
            FATAL_ERROR();
        }

        page_list_i = 0;

        prepare_td_vmcs(tdvps_p, 0);

        // Associate the CVPU with the current LP and update TD MVCS
        associate_vcpu_initial(tdvps_p, tdcs_p);
        set_vm_vmcs_as_active(tdvps_p, 0);

        // Initialize VCPU-scope metadata fields marked as "IE" and "IES" in the TDVPS and TD VMCS spreadsheets,
        // not including L2 state
        init_imported_vp_state(tdr_p, tdcs_p, tdvps_p);

        // Set the initial field ID.
        field_id.raw = MD_FIELD_ID_NA;
        field_id.context_code = MD_CTX_VP;

        /* Advance the migration stream's EXPECTED_MB_COUNTER to avoid a replay.
           From this point on, every error aborts the import session. */
        migsc_p->expected_mb_counter++;

        // Initialize the sticky error indications in MIGSC
        migsc_p->interrupted_state.status = TDX_SUCCESS;
        migsc_p->interrupted_state.extended_err_info[0] = 0;
        migsc_p->interrupted_state.extended_err_info[1] = 0;
    }
    else // migs_i_and_cmd.command == MIGS_INDEX_COMMAND_RESUME
    {
        // Check the interrupted flag, then clear it
        if (!migsc_p->interrupted_state.valid)
        {
            return_val = TDX_INVALID_RESUMPTION;
            goto EXIT;
        }

        migsc_p->interrupted_state.valid = false;

        // Check that the same function is resumed with the same parameters
        if ((migsc_p->interrupted_state.func.raw != local_data_ptr->vmm_regs.rax) ||
            (migsc_p->interrupted_state.page_list_info.raw != page_list_info.raw) ||
            (migsc_p->interrupted_state.tdvpr_pa.raw != tdvpr_pa.raw))
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return_val = api_error_fatal(TDX_INVALID_RESUMPTION);
            goto EXIT;
        }

        // Check the VCPU state
        if ((tdvps_p->management.state != VCPU_IMPORT) && (tdvps_p->management.state != VCPU_DISABLED))
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            TDX_ERROR("VCPU in incorrect state (0x%ux)\n", tdvps_p->management.state);
            return_val = api_error_fatal(TDX_VCPU_STATE_INCORRECT);
            goto EXIT;
        }

        // Associate the VCPU with the current LP if not already associated
        bool_t new_association = false;
        return_val = associate_vcpu(tdvps_p, tdcs_p, &new_association);

        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("associate_vcpu failed with error 0x%llx\n", return_val);
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return_val = api_error_fatal(return_val);
            goto EXIT;
        }

        // Restore the saved state
        page_list_i = migsc_p->interrupted_state.num_processed;

        // Restore the td field ID from MIGSC, we use the right one later
        field_id.raw = migsc_p->interrupted_state.field_id.raw;
    }

    // Check and map the page list. first condition is always true and left here for code completeness
    if (((uint64_t)page_list_info.last_entry < (MIN_VP_STATE_IMPORT_PAGES - 1)) ||
        (page_list_info.reserved_1 != 0) ||
        (page_list_info.reserved_2 != 0))
    {
        TDX_ERROR("Invalid page_list_info (0x%llx)\n", page_list_info.raw);
        tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
        return_val = api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_R9);
        goto EXIT;
    }

    page_list_pa.raw = 0;
    page_list_pa.page_4k_num = page_list_info.hpa;

    // Verify the page list physical address is canonical and shared (it is aligned to 4KB by definition)
    if ((return_val = shared_hpa_check(page_list_pa, TDX_PAGE_SIZE_IN_BYTES)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA 0x%llx check\n", page_list_pa.raw);
        tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
        return_val = api_error_with_operand_id_fatal(return_val, OPERAND_ID_R9);
        goto EXIT;
    }

    // Map the page list
    page_list_p = (pa_t *)map_pa(page_list_pa.raw_void, TDX_RANGE_RO);

    /*
     * Set the field ID context for the dump operation below.
     * sys_field_is doesn't need a set context.
     */
    md_context_ptrs_t md_ctx;
    md_ctx.tdcs_ptr = tdcs_p;
    md_ctx.tdr_ptr = tdr_p;
    md_ctx.tdvps_ptr = tdvps_p;

    do
    {
        /*--------------------------------------
           Import the next metadata list page
        --------------------------------------*/

        // Copy the page list entry and size into internal variables
        md_list_pa.raw = page_list_p[page_list_i].raw;

        // Verify the metadata page physical address is a valid shared HPA aligned on 4KB
        if (shared_hpa_check_with_pwr_2_alignment(md_list_pa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS)
        {
            TDX_ERROR("Failed on source shared HPA 0x%llx check\n", md_list_pa.raw);
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return_val = api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_PAGE);
            goto EXIT;
        }

        // Map the metadata list
        if (md_list_hdr_p)
        {
            free_la(md_list_hdr_p);
        }
        md_list_hdr_p = (md_list_header_t *)map_pa(md_list_pa.raw_void, TDX_RANGE_RO);

        // Decrypt the metadata list
        if (aes_gcm_decrypt(&migsc_p->aes_gcm_context, (uint8_t*)md_list_hdr_p , (uint8_t*)&md_list, _4KB) != AES_GCM_NO_ERROR)
        {
            FATAL_ERROR();
        }

        // Do a sanity check on the list buffer size
        if (md_list.hdr.list_buff_size > _4KB)
        {
            /* Store the error information in the MIGSC, it will be reported later only if MAC check passes.
                   Do not overwrite existing error status. */
            if (migsc_p->interrupted_state.status == TDX_SUCCESS)
            {
                migsc_p->interrupted_state.status = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_PAGE);
            }
            md_list.hdr.list_buff_size = _4KB;

        }

        md_access_qualifier_t access_qual = {.raw = 0};

        uint64_t tmp_ext_error_info[2];

        // Import the metadata list
        return_val = md_write_list(MD_CTX_VP, field_id,
                                   _4KB,
                                   true, /* check missing */
                                   true, /* skip non writable */
                                   page_list_i == page_list_info.last_entry, /* is last */
                                   md_ctx,
                                   //md_list_hdr_p,
                                   &md_list.hdr,
                                   MD_IMPORT_MUTABLE,
                                   access_qual, &next_field_id, tmp_ext_error_info,
                                   true);

        // Restore SEAM VMCS after it was possible switched to VM VMCS by metadata accesses
        set_seam_vmcs_as_active();

        if (return_val != TDX_SUCCESS)
        {
            /* Store the error information in the MIGSC, it will be reported later only if MAC check passes.
                   Do not overwrite existing error status. */
            if (migsc_p->interrupted_state.status == TDX_SUCCESS)
            {
                migsc_p->interrupted_state.status = return_val;
                migsc_p->interrupted_state.extended_err_info[0] = tmp_ext_error_info[0];
                migsc_p->interrupted_state.extended_err_info[1] = tmp_ext_error_info[1];
            }
        }

        field_id = next_field_id;
        page_list_i++; // Update to the index of the next page in the list

        // If we haven't gone through all the pages, check for a pending interrupt
        if ((page_list_i <= page_list_info.last_entry) && is_interrupt_pending_host_side())
        {
            /*
             * There are more pages but there is a pending interrupt.
             * Save the state for next invocation
             */
            migsc_p->interrupted_state.valid = true;
            migsc_p->interrupted_state.func.raw = local_data_ptr->vmm_regs.rax;
            migsc_p->interrupted_state.page_list_info.raw = page_list_info.raw;

            migsc_p->interrupted_state.field_id.raw = next_field_id.raw;

            migsc_p->interrupted_state.num_processed = page_list_i;

            migsc_p->interrupted_state.tdvpr_pa = tdvpr_pa;

            /*
             * Update the VCPU state to mark it as being imported. This prevents the VCPU
             * from being used if the import is not resumed and completed
             * If the VCPU state was imported as disabled, keep it disabled.
             */
            if (tdvps_p->management.state != VCPU_DISABLED)
            {
                tdvps_p->management.state = VCPU_IMPORT;
            }

            local_data_ptr->vmm_regs.rcx = original_rcx;
            local_data_ptr->vmm_regs.rdx = original_rdx;
            return_val = TDX_INTERRUPTED_RESUMABLE;
            goto EXIT;
        }
    } while ((uint64_t)page_list_i <= page_list_info.last_entry);

    // All metadata has been imported

    /*
     * Check that the accumulated MAC value is the same
     * as the MAC field's value provided in mbmd
     */
    uint8_t mac[MAC256_LEN];
    if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }

    if (!tdx_memcmp_safe(mac, migsc_p->mbmd.vp_state.mac, sizeof(mac)))
    {
        TDX_ERROR("MAC field provided in MBMD doesn't match the accumulated MAC\n");
        tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
        return_val = api_error_fatal(TDX_INCORRECT_MBMD_MAC);
        goto EXIT;
    }

    /* Now that we have checked that the MAC is correct, if an error was detected earlier during the
           parsing of the decrypted buffers, it is reported and the import session is aborted. */
    if (migsc_p->interrupted_state.status != TDX_SUCCESS)
    {
        local_data_ptr->vmm_regs.rcx = migsc_p->interrupted_state.extended_err_info[0];
        local_data_ptr->vmm_regs.rdx = migsc_p->interrupted_state.extended_err_info[1];
        tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
        return_val = api_error_fatal(migsc_p->interrupted_state.status);
        goto EXIT;
    }

    // Increment the number of imported VCPUs in the TD
    // Do a sanity check - should not fail
    if (_lock_xadd_32b(&tdcs_p->migration_fields.num_migrated_vcpus, 1) >= tdcs_p->management_fields.num_vcpus)
    {
        tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
        return_val = api_error_fatal(TDX_ALL_VCPUS_IMPORTED);
        goto EXIT;
    }

    // Update the VCPU state
    // If the VCPU state was imported as disabled, keep it disabled.
    if (tdvps_p->management.state != VCPU_DISABLED)
    {
        tdvps_p->management.state = VCPU_READY;
    }

    // Update the migration stream counters and mark as non-interrupted
    (void)_lock_xadd_64b(&tdcs_p->migration_fields.total_mb_count, 1);

    return_val = TDX_SUCCESS;

EXIT:

    set_seam_vmcs_as_active();

    // Release all acquired locks
    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->f_migsc_links[migs_i]);
    }

    if (tdr_pamt_p != NULL)
    {
        pamt_implicit_release_lock(tdr_pamt_p, TDX_LOCK_SHARED);
        free_la(tdr_p);
    }

    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_p, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }

    if (op_state_locked_flag)
    {
        release_sharex_lock_hp(&(tdcs_p->management_fields.op_state_lock), TDX_LOCK_SHARED);
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (page_list_p != NULL)
    {
        free_la(page_list_p);
    }

    if (md_list_hdr_p != NULL)
    {
        free_la(md_list_hdr_p);
    }

    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    if (migsc_p != NULL)
    {
        free_la(migsc_p);
    }

    if (tdvps_p)
    {
        free_la(tdvps_p);
    }

    return return_val;
}

