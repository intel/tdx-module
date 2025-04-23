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
 * @file tdh_import_state_immutable
 * @brief TDHIMPORTSTATEIMMUTABLE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "auto_gen/op_state_lookup.h"
#include "helpers/migration.h"
#include "helpers/helpers.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "metadata_handlers/metadata_generic.h"

static api_error_type handle_command_by_type(migs_index_and_cmd_t migs_i_and_cmd, tdcs_t* tdcs_p, migsc_t* migsc_p,
                                             hpa_and_size_t* mbmd_hpa_and_size, mbmd_t** mbmd_p, migs_iv_t* iv, uint32_t* page_list_i,
                                             md_field_id_t* field_id, bool_t* sys_imported, page_list_info_t page_list_info)
{
    if (migs_i_and_cmd.command == MIGS_INDEX_COMMAND_NEW)
    {
        /*
         * Start the import session.
         */

         /*
         * Check that a valid migration key has been set by the Migration TD.
         * If this is not the first migration session, then the migration key must have been
         * set after the previous migration session has started.
         * Concurrency protected by locking the OP_STATE.
         */
        if (!tdcs_p->migration_fields.mig_dec_key_set)
        {
            return TDX_MIGRATION_DECRYPTION_KEY_NOT_SET;
        }

        /* Initialize the migration context
        */
        tdcs_p->migration_fields.mig_enc_working_key = tdcs_p->migration_fields.mig_enc_key;
        /* Generate a new 256-bit encryption key for the next migration session
           Use a temporary variable to avoid overwriting TDCS.MIG_ENC_KEY in case
           there's an error, so TDH.EXPORT.STATE.IMMUTABLE can be called again. */
        key256_t tmp_end_key;
        if (!generate_256bit_random(&tmp_end_key))
        {
            return TDX_RND_NO_ENTROPY;
        }
        tdcs_p->migration_fields.mig_enc_key = tmp_end_key;

        basic_memset_to_zero(&tmp_end_key, sizeof(tmp_end_key));

        tdcs_p->migration_fields.mig_dec_working_key = tdcs_p->migration_fields.mig_dec_key;
        tdcs_p->migration_fields.mig_dec_key_set = false;
        tdcs_p->migration_fields.mig_working_version = tdcs_p->migration_fields.mig_version;

        // Mark all migration streams (both forward and backward) as uninitialized
        uint16_t migs_i = 0;
        for (migs_i = 0; migs_i < tdcs_p->migration_fields.num_migs; migs_i++)
        {
            tdcs_p->migsc_links[migs_i].initialized = 0;
        }

        tdcs_p->migration_fields.mig_epoch = 0;
        tdcs_p->migration_fields.total_mb_count = 0;

        // Mark this flow as non-interrupted
        migsc_p->interrupted_state.valid = false;

        migsc_init(migsc_p, &tdcs_p->migration_fields.mig_dec_working_key);
        tdcs_p->f_migsc_links[0].initialized = true;

        /*
        * Check and map the MBMD buffer in shared memory,
        * and read the MBMD into the migration stream context
        */

        if (mbmd_hpa_and_size->size < sizeof(mbmd_t))
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            TDX_ERROR("mbmd size (%d) is too small\n", mbmd_hpa_and_size->size);
            return api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        }

        mbmd_hpa_and_size->size = 0;
        pa_t mbmd_hpa_and_size_pa = { .raw = mbmd_hpa_and_size->raw };

        // Verify the MBMD physical address is canonical, shared, and aligned to MBMD_ALIGNB
        api_error_type return_val = TDX_SUCCESS;
        if ((return_val = shared_hpa_check_with_pwr_2_alignment(mbmd_hpa_and_size_pa, MBMD_ALIGN)) != TDX_SUCCESS)
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            TDX_ERROR("mbmd pa (0x%llx) not %d aligned\n", mbmd_hpa_and_size_pa, MBMD_ALIGN);
            return api_error_with_operand_id_fatal(return_val, OPERAND_ID_R8);
        }

        // Map the MBMD and read into the migration stream context
        *mbmd_p = (mbmd_t*)map_pa((void*)mbmd_hpa_and_size->raw, TDX_RANGE_RO);
        copy_mbmd(&migsc_p->mbmd, *mbmd_p);

        /* Check the MBMD in the MIGSC
        */
        if ((migsc_p->mbmd.header.mig_version != tdcs_p->migration_fields.mig_working_version) ||
            (migsc_p->mbmd.header.size != sizeof(mbmd_t)) ||
            (migsc_p->mbmd.header.migs_index != 0) ||
            (migsc_p->mbmd.header.mb_type != MB_TYPE_IMMUTABLE_TD_STATE) ||
            (migsc_p->mbmd.header.reserved_1 != 0) ||
            (migsc_p->mbmd.header.mb_counter != 0) ||
            (migsc_p->mbmd.header.mig_epoch != 0) ||
            (migsc_p->mbmd.immutable_td_state.reserved_0 != 0) ||
            (migsc_p->mbmd.immutable_td_state.reserved_1 != 0) ||
            (migsc_p->mbmd.immutable_td_state.num_sys_md_pages == 0))
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            TDX_ERROR("INVALID_MBMD\n");
            return api_error_fatal(TDX_INVALID_MBMD);
        }

        if ((uint32_t)migsc_p->mbmd.immutable_td_state.num_f_migs > tdcs_p->migration_fields.num_migs - 1)   // Allow for 1 backward mig. stream
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return api_error_fatal(TDX_NUM_MIGS_HIGHER_THAN_CREATED);
        }

        // Prepare the IV
        iv->iv_counter = migsc_p->mbmd.header.iv_counter;
        iv->migs_index = 0;
        iv->reserved = 0;

        // Accumulate a MAC over the MAC’ed fields of the MBMD
        migsc_p->mbmd.header.iv_counter = 0; // Not included in the MAC and not required anymore
        if (aes_gcm_reset(&migsc_p->aes_gcm_context, iv) != AES_GCM_NO_ERROR)
        {
            FATAL_ERROR();
        }
        if (aes_gcm_process_aad(&migsc_p->aes_gcm_context, (uint8_t*)&migsc_p->mbmd.immutable_td_state,
                                MBMD_SIZE_NO_MAC(migsc_p->mbmd.immutable_td_state)) != AES_GCM_NO_ERROR)
        {
            FATAL_ERROR();
        }

        *page_list_i = 0;

        // We first import the SYS metadata.  Set the initial field ID.
        field_id->raw = MD_FIELD_ID_NA;
        field_id->context_code = MD_CTX_SYS;
        *sys_imported = false;

        /* Advance the migration stream's EXPECTED_MB_COUNTER to avoid a replay.
           From this point on, every error aborts the import session. */
        migsc_p->expected_mb_counter = 1;

        // Initialize the sticky error indications in MIGSC
        migsc_p->interrupted_state.status = TDX_SUCCESS;
        migsc_p->interrupted_state.extended_err_info[0] = 0;
        migsc_p->interrupted_state.extended_err_info[1] = 0;
    }
    else // migs_i_and_cmd.command == MIGS_INDEX_COMMAND_RESUME
    {
        /*---------------------------------------------------------------
           This is a resumption of a previously-interrupted invocation
        ---------------------------------------------------------------*/
        tdx_module_local_t* local_data_ptr = get_local_data();

        if (!tdcs_p->f_migsc_links[migs_i_and_cmd.migs_index].initialized)
        {
            return TDX_MIGRATION_STREAM_STATE_INCORRECT;
        }

        // Check the interrupted flag, then clear it
        if (!migsc_p->interrupted_state.valid)
        {
            return TDX_INVALID_RESUMPTION;
        }

        migsc_p->interrupted_state.valid = false;

        // Check that the same function is resumed with the same parameters
        if ((migsc_p->interrupted_state.func.raw != local_data_ptr->vmm_regs.rax) ||
            (migsc_p->interrupted_state.page_list_info.raw != page_list_info.raw))
        {
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return api_error_fatal(TDX_INVALID_RESUMPTION);
        }

        // Restore the saved state
        *page_list_i = migsc_p->interrupted_state.num_processed;
        field_id->raw = migsc_p->interrupted_state.field_id.raw;
        *sys_imported = migsc_p->interrupted_state.sys_migrated;
    }

    return TDX_SUCCESS;
}

api_error_type tdh_import_state_immutable(uint64_t target_tdr_pa, uint64_t hpa_and_size_pa,
                                          uint64_t page_or_list_pa, uint64_t  migs_i_and_cmd_pa
)
{
    // Local data for return values
    tdx_module_local_t* local_data_ptr = get_local_data();

    // TDR and TDCS
    tdr_t* tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t                 tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t         tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t* tdr_pamt_entry_ptr = NULL;
    tdcs_t* tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t               tdr_locked_flag = false;

    // MBMD
    mbmd_t* mbmd_p = NULL;
    hpa_and_size_t       mbmd_hpa_and_size;

    // Page List
    page_list_info_t     page_list_info;
    uint32_t             page_list_i;
    pa_t                 page_list_pa;
    hpa_and_last_t* page_list_p = NULL;

    // Single Metadata List Page
    pa_t                 md_list_pa;
    md_list_header_t* md_list_hdr_p = NULL;
    bool_t               sys_imported;

    // Field IDs for SYS and TD
    md_list_t            md_list;
    md_field_id_t        field_id;

    // Migration Stream
    migs_index_and_cmd_t migs_i_and_cmd;
    migsc_t* migsc_p = NULL;
    pa_t                 migsc_pa;
    bool_t               migsc_locked_flag = false;
    migs_iv_t            iv = { 0 };

    api_error_type       return_val = TDX_OPERAND_INVALID;

    // Input operands
    tdr_pa.raw = target_tdr_pa;
    mbmd_hpa_and_size.raw = hpa_and_size_pa;
    page_list_info.raw = page_or_list_pa;
    migs_i_and_cmd.raw = migs_i_and_cmd_pa;

    uint64_t original_rcx = local_data_ptr->vmm_regs.rcx;
    uint64_t original_rdx = local_data_ptr->vmm_regs.rdx;

    // Default output register operands
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Boot NT4 bit should not be set
    ia32_misc_enable_t misc_enable;
    misc_enable.raw = ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR);

    if (misc_enable.limit_cpuid_maxval != 0)
    {
        TDX_ERROR("limit cpuid maxval bit should not be set\n");
        return_val = TDX_LIMIT_CPUID_MAXVAL_SET;
        goto EXIT;
    }

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_NO_LOCK,
                                               false, TDH_IMPORT_STATE_IMMUTABLE_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    if (tdcs_p->migration_fields.num_migs < MIN_MIGS)
    {
        return_val = TDX_MIN_MIGS_NOT_CREATED;
        goto EXIT;
    }
    /*
     * Process the Migration Stream
     */
     // Check that the migration stream index is correct
    if ((migs_i_and_cmd.migs_index != 0) ||
        (migs_i_and_cmd.reserved_31_16 != 0) ||
        (migs_i_and_cmd.reserved_62_32 != 0))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R10);
        goto EXIT;
    }

    // Lock the MIGSC link
    if (!(migsc_lock(&tdcs_p->f_migsc_links[0])))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_MIGSC);
        goto EXIT;
    }
    migsc_locked_flag = true;

    // Map the MIGSC
    migsc_pa.raw = 0;
    migsc_pa.page_4k_num = tdcs_p->f_migsc_links[0].migsc_hpa;
    migsc_p = (migsc_t*)map_pa_with_hkid(migsc_pa.raw_void,
                                         tdr_p->key_management_fields.hkid,
                                         TDX_RANGE_RW);


    if (TDX_SUCCESS != (return_val = handle_command_by_type(migs_i_and_cmd, tdcs_p, migsc_p, &mbmd_hpa_and_size, &mbmd_p,
                                                            &iv, &page_list_i, &field_id, &sys_imported, page_list_info)))
    {
        goto EXIT;
    }

    /*-------------------------------
       Check and map the page list
    -------------------------------*/

    uint64_t min_last_entry = (uint64_t)MIN_TD_IMMUTABLE_STATE_IMPORT_PAGES +
        migsc_p->mbmd.immutable_td_state.num_sys_md_pages - 1;
    if ((page_list_info.last_entry < min_last_entry) ||
        (page_list_info.reserved_1 != 0) || (page_list_info.reserved_2 != 0))
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
    page_list_p = (hpa_and_last_t*)map_pa(page_list_pa.raw_void, TDX_RANGE_RO);

    /*------------------------------------------------------------------------
       Import the TD Immutable State as multiple metadata list pages.
       Two types of metadata are imported: Global-scope (SYS) and TD-scope.
    ------------------------------------------------------------------------*/
    md_context_ptrs_t md_ctx;
    md_ctx.tdcs_ptr = tdcs_p;
    md_ctx.tdr_ptr = tdr_p;
    md_ctx.tdvps_ptr = NULL;

    do
    {
        /*--------------------------------------
           Import the next metadata list page
        --------------------------------------*/

        md_list_pa.raw = page_list_p[page_list_i].raw;

        // Verify the metadata page physical address is a valid shared HPA aligned on 4KB
        if (shared_hpa_check_with_pwr_2_alignment(md_list_pa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS)
        {
            TDX_ERROR("Failed on HPA 0x%llx check\n", md_list_pa.raw);
            tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
            return_val = api_error_with_operand_id_fatal(TDX_OPERAND_INVALID, OPERAND_ID_PAGE);
            goto EXIT;
        }

        // Map the metadata list
        if (md_list_hdr_p)
        {
            free_la(md_list_hdr_p);
        }
        md_list_hdr_p = (md_list_header_t*)map_pa(md_list_pa.raw_void, TDX_RANGE_RO);

        // Decrypt the metadata list into a temporary buffer
        if (aes_gcm_decrypt(&migsc_p->aes_gcm_context, (uint8_t*)md_list_hdr_p, (uint8_t*)&md_list, _4KB) != AES_GCM_NO_ERROR)
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

        md_access_qualifier_t access_qual = { .raw = 0 };

        uint64_t tmp_ext_error_info[2];

        if (!sys_imported)
        {
            // Import the SYS metadata list:
            if (page_list_i == migsc_p->mbmd.immutable_td_state.num_sys_md_pages - 1)
            {
                sys_imported = true;
            }

            return_val = md_write_list(MD_CTX_SYS, field_id,
                                       _4KB,
                                       true /* check missing */,
                                       true /* skip non writable */,
                                       sys_imported, /* is last */
                                       md_ctx, &md_list.hdr,
                                       MD_IMPORT_IMMUTABLE, access_qual,
                                       &field_id, tmp_ext_error_info,
                                       true);

            if (sys_imported)
            {
                field_id.raw = MD_FIELD_ID_NA;
                field_id.context_code = MD_CTX_TD;
            }
        }
        else // sys_imported
        {
            // Import the TD metadata list:

            return_val = md_write_list(MD_CTX_TD, field_id,
                                       _4KB,
                                       true /* check missing */,
                                       true /* skip non writable */,
                                       page_list_i == page_list_info.last_entry /* is last */,
                                       md_ctx, &md_list.hdr,
                                       MD_IMPORT_IMMUTABLE, access_qual,
                                       &field_id, tmp_ext_error_info,
                                       true);
        }

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

        page_list_i++; // Update to the index of the next page in the list

        // If we haven't gone through all the pages, check for a pending interrupt
        if ((page_list_i <= page_list_info.last_entry) && is_interrupt_pending_host_side())
        {
            // There is a pending interrupt.  Save the state for the next invocation.
            migsc_p->interrupted_state.valid = true;
            migsc_p->interrupted_state.func.raw = local_data_ptr->vmm_regs.rax;
            migsc_p->interrupted_state.page_list_info = page_list_info;
            migsc_p->interrupted_state.num_processed = page_list_i;
            migsc_p->interrupted_state.field_id = field_id;
            migsc_p->interrupted_state.sys_migrated = sys_imported;

            local_data_ptr->vmm_regs.rcx = original_rcx;
            local_data_ptr->vmm_regs.rdx = original_rdx;
            return_val = TDX_INTERRUPTED_RESUMABLE;
            goto EXIT;
        }
    } while ((uint64_t)page_list_i <= page_list_info.last_entry);

    /*----------------------------------
       All metadata has been imported
    ----------------------------------*/

    /* Check that the accumulated MAC value is the same as the MAC field’s
       value provided in the MBMD. */
    uint8_t   mac[MAC256_LEN];
    if (aes_gcm_finalize(&migsc_p->aes_gcm_context, mac) != AES_GCM_NO_ERROR)
    {
        FATAL_ERROR();
    }
    if (!tdx_memcmp_safe(mac, migsc_p->mbmd.immutable_td_state.mac, MAC256_LEN))
    {
        TDX_ERROR("MAC comparison failed\n");
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

    /* Initialize TD-Scope metadata
       - Applies to all the fields marked in the TDR/TDCS spreadsheet as "IB" and "IBS"
    */
    return_val = check_and_init_imported_td_state_immutable(tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        tdcs_p->management_fields.op_state = OP_STATE_FAILED_IMPORT;
        goto EXIT;
    }

    // Update the migration stream counters and mark as non-interrupted
    tdcs_p->migration_fields.total_mb_count = 1;

    // Start the in-order import phase
    tdcs_p->management_fields.op_state = OP_STATE_MEMORY_IMPORT;

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks
    if (mbmd_p != NULL)
    {
        free_la(mbmd_p);
    }

    if (page_list_p != NULL)
    {
        free_la(page_list_p);
    }

    if (migsc_locked_flag)
    {
        migsc_unlock(&tdcs_p->f_migsc_links[0]);
    }

    if (migsc_p != NULL)
    {
        free_la(migsc_p);
    }

    if (md_list_hdr_p != NULL)
    {
        free_la(md_list_hdr_p);
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_p);
    }

    return return_val;
}
