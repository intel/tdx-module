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
 * @file kcbar_defs.h
 * @brief
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDXIO_KCBAR_DEFS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDXIO_KCBAR_DEFS_H_

#include "tdx_basic_defs.h"
#include "data_structures/tdxio/ide_stream_defs.h"

typedef union
{
    struct
    {
        // Number_Streams_Supported – Indicates the total
        // number of PCIe/CXL.io Stream entries supported by the
        // subsystem, encoded as:
        // 0_0000_0000b: 1 Stream supported
        // 0_0000_0001b: 2 Streams supported
        // …
        // The number of Per-Stream Configuration blocks must
        // match the number indicated in this field.
        uint32_t num_stream_supported : 9; // 0:8
        uint32_t rsvd : 1;
        // Number_Tx_Key_Slots – Indicates the total number of
        // transmitter key slot entries supported by the subsystem,
        // encoded as:
        // 0_0000_0000b: 1 key slot implemented
        // …
        // The number of Tx key slots must match the number
        // indicated in this field.
        // The index number for a given Tx key slot is defined as
        // an offset from the start of the Tx key slots
        uint32_t num_tx_key_slots : 10; // 10:19

        // Number_Rx_Key_Slots – Indicates the total number of
        // receiver key slot entries supported by the subsystem,
        // encoded as:
        // 0_0000_0000b: 1 key slot implemented
        // The number of Rx key slots must match the number
        // indicated in this field.
        // The index number for a given Rx key slot is defined as
        // an offset from the start of the Rx key slots
        uint32_t num_rx_key_slots : 10; // 20:29
        uint32_t rsvd2 : 2; // 30:31
    };
    uint32_t raw;
} io_module_stream_cap_t;
tdx_static_assert(sizeof(io_module_stream_cap_t) == 4, io_module_stream_cap_t);

typedef union
{
    struct
    {
        // Tx_Key_Set_Select – Must be set by software to
        // indicate which key set pointer register (below) is to be
        // used for transmitted TLPs:
        // 00b: Do not use either key set
        // 01b: Transmit using key set 0
        // 10b: Transmit using key set 1
        // 11b: Do not use either key set
        // If software writes the same value to this field as the field
        // already contains, the hardware must take no action as a
        // result of the write.
        uint32_t key_set_select : 2; // 0:1
        uint32_t rsvd_1 : 6; // 2:7

        // Tx_Prime_Key_Set_0 – Software must write a 1b to this
        // bit after programming the Tx Key Set 0 Indices for all of
        // PR, NPR and CPL, and their corresponding Key Slot and
        // IFV value registers.
        // When this bit has been set to 1b, hardware must
        // implement whatever steps are required to make Key Set
        // 0 available for use and, once that process is complete,
        // set the Tx_Ready_Key_Set_0 bit.
        uint32_t tx_prime_key_set_0 : 1; // 8

        uint32_t rsvd_2 : 7; // 9:15

        // Tx_Prime_Key_Set_1 – Software must write a 1b to this
        // bit after programming the Tx Key Set 1 Indices for all of
        // PR, NPR and CPL, and their corresponding Key Slot and
        // IFV value registers.
        // When this bit has been to 1b, hardware must implement
        // whatever steps are required to make the indicated Key
        // Set available for use and, once that process is complete,
        // set the Tx_Ready_Key_Set_1 bit.
        uint32_t tx_prime_key_set_1 : 1; // 16
    } stream_tx_control;
    struct
    {
        uint32_t rsvd_1 : 8; // 0:7
        // Rx_Prime_Key_Set_0 – Software must write a 1b to this
        // bit after programming the Rx Key Set 0 Indices for all of
        // PR, NPR and CPL, and their corresponding Key Slot and
        // IFV value registers.
        // When this bit has been to 1b, hardware must implement
        // whatever steps are required to make Key Set 0 available
        // for use and, once that process is complete, set the
        // Rx_Ready_Key_Set_0 bit
        uint32_t rx_prime_key_set_0 : 1; // 8

        uint32_t rsvd_2 : 7; // 9:15

        // Rx_Prime_Key_Set_1 – Software must write a 1b to this
        // bit after programming the Rx Key Set 1 Indices for all of
        // PR, NPR and CPL, and their corresponding Key Slot and
        // IFV value registers.
        // When this bit has been to 1b, hardware must implement
        // whatever steps are required to make the indicated Key
        // Set available for use and, once that process is complete,
        // set the Rx_Ready_Key_Set_1 bit.
        uint32_t rx_prime_key_set_1 : 1; // 16
    } stream_rx_control;
    struct
    {
        uint8_t rsvd; // 0:7
        uint8_t prime_key_set_0 : 1; // 8
        uint8_t rsvd_2 : 7; // 9:15
        uint8_t prime_key_set_1 : 1; // 16
    } common;
    uint32_t raw;
} stream_txrx_control_t;
tdx_static_assert(sizeof(stream_txrx_control_t) == 4, stream_txrx_control_t);

typedef union
{
    struct
    {
        // Tx_Key_Set_Status – Must be updated by hardware to
        // indicate the key set status:
        // 00b: No TLP has been transmitted using either key set
        // 01b: Active transmission using key set 0
        // 10b: Active transmission using key set 1
        // 11b: Transitioning between key sets
        // Software must not modify a key set in active use, and
        // most not modify either key set when this field reads 11b.
        uint32_t key_set_status : 2;
        uint32_t rsvd : 6;
        // Tx_Ready_Key_Set_0 – Hardware must set this bit to
        // indicate that all internal processing steps required to
        // make Key Set 0 available for use are complete, and that
        // Key Set 0 is ready for use.
        // This bit must be cleared if the Tx_Prime_Key_Set_0 is
        // set to 1 and hardware is not immediately ready, the key
        // set pointers are modified, the pointer to key/IV values are
        // modified, the Stream goes to Insecure state, or any error
        // states.
        // This bit is intended for software use only. Hardware
        // should not read this bit or use it to trigger any flow.
        uint32_t ready_key_set_0 : 1;

        // Tx_Ready_Key_Set_1 – Hardware must set this bit to
        // indicate that all internal processing steps required to
        // make Key Set 1 available for use are complete, and that
        // Key Set 1 is ready for use.
        // This bit must be cleared if the Tx_Prime_Key_Set_1 is
        // set to 1 and hardware is not immediately ready, the key
        // set pointers are modified, the pointer to key/IV values are
        // modified, the Stream goes to Insecure state, or any error
        // states.
        // This bit is intended for software use only. Hardware
        // should not read this bit or use it to trigger any flow.
        uint32_t ready_key_set_1 : 1;
    };
    uint32_t raw;
} stream_txrx_status_t;
tdx_static_assert(sizeof(stream_txrx_status_t) == 4, stream_txrx_status_t);

// For GNR, each PCIe/CXL.io subsystem shall implement:
//• 4 Streams
//• 15 transmitter key slots
//• 15 receiver key slots

#define NUM_OF_STREAM_CFG_BLOCKS_IN_KEY_CONFIG (4)
#define NUM_OF_KEYSLOT_IN_KEY_CONFIG (16)

typedef struct
{
    stream_control_t control;
    stream_txrx_control_t tx_ctrl;
    stream_txrx_status_t tx_status;
    stream_txrx_control_t rx_ctrl;
    stream_txrx_status_t rx_status;
    stream_keyset_slot_id_t tx_key_set_0;
    stream_keyset_slot_id_t tx_key_set_1;
    stream_keyset_slot_id_t rx_key_set_0;
    stream_keyset_slot_id_t rx_key_set_1;
} stream_config_reg_block_t;
tdx_static_assert(sizeof(stream_config_reg_block_t) == 36, stream_config_reg_block_t);

typedef struct
{
    io_module_stream_cap_t capabilities;
    // Variable size depends on capabilities.stream_cap.num_stream_supported + 1
    stream_config_reg_block_t stream_config_reg_block;
} kcbar_t;

#define KCBAR_ENABLE_BIT (0)
#define KCBAR_SIZE (_1KB * 128)

#endif /* SRC_COMMON_DATA_STRUCTURES_TDXIO_KCBAR_DEFS_H_ */
