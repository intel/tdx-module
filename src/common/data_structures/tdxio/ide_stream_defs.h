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
 * @file ide_stream_defs.h
 * @brief
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDXIO_IDE_STREAM_DEFS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDXIO_IDE_STREAM_DEFS_H_

#include "accessors/ia32_accessors.h"
#include "data_structures/tdxio/rp_cfg_page_defs.h"
#include "data_structures/tdxio/spdm_defs.h"

#define MAX_IDE_STREAM_ID (256)
#define NUM_DF_PER_BUS    (256)

#define IDE_KM_DEFUALT_LEN (0x8)

#pragma pack(push, 1)

typedef enum
{
    IDE_STREAM_LINK_IDE = 0,
    IDE_STREAM_SEL_IDE  = 1
} ide_stream_type_e;
typedef uint8_t ide_stream_type_t;

typedef enum
{
    // Posted Requests
    SUBSTREAM_PR  = 0,
    // Non-posted requests
    SUBSTREAM_NPR = 1,
    // Completions
    SUBSTREAM_CPL = 2
} sub_stream_id_e;
typedef uint8_t sub_stream_id_t;

typedef union
{
  struct
  {
    uint8_t index         :7;
    uint8_t page_selector :1;
  };
  uint8_t raw;
} stream_id_t;
tdx_static_assert(sizeof(stream_id_t) == 1, stream_id_t);

typedef union
{
    stream_id_t stream_id;
    // Done to preserve alignment
    struct
    {
        uint64_t :8;
        uint64_t rsvd: 56;
    };
    uint64_t raw;
} stream_id_reg_t;
tdx_static_assert(sizeof(stream_id_reg_t) == 8, stream_id_reg_t);

typedef union
{
  struct
  {
        uint8_t config_lock :1;   // [0]
        uint8_t stream_block :1;  // [1]
        uint8_t reserved :5;      // [7:2]
        ide_stream_type_t stream_type :1; // [7] 0 - link, 1- sel
  };
  uint8_t raw;
} ide_stream_status_t;
tdx_static_assert(sizeof(ide_stream_status_t) == 1, ide_stream_status_t);

#define STREAM_ALGO_AES_GCM_256_96B_MAC (0b00000)

typedef union
{
  struct
  {
//      Selective IDE Stream Enable – When Set, enables this
//      IDE Stream. The following must be programmed before this
//      bit is Set:
//      Selected Algorithm (below)
//      Requester ID Limit in IDE RID Association Register 1
//      Requester ID Base in IDE RID Association Register 2
//      V bit in IDE RID Association Register 2
//      If this bit is Set when the V bit is Clear, the IDE Stream must
//      transition to Fail_Insecure.
//      It is strongly recommended that the IDE Address
//      Association Registers also be programmed prior to Setting
//      this bit.
//      Default value is 0b.
    uint8_t enabled:1;
    uint8_t reserved0:1;
//    Tx Aggregation Mode NPR – If Aggregation Supported is
//    Set then this field selects the level of aggregation for
//    Transmitted Non-Posted Requests for this Stream, encoded
//    as:
//     00b – No aggregation
//     01b – Up to 2 Non-Posted Requests
//     10b – Up to 4 Non-Posted Requests
//     11b – Up to 8 Non-Posted Requests
//    Reserved If Aggregation Supported is Clear.
//    Default value is 00b
    uint8_t tx_aggr_mode_npr:2;
//    Tx Aggregation Mode PR – If Aggregation Supported is
//    Set then this field selects the level of aggregation for
//    Transmitted Posted Requests for this Stream, encoded as:
//     00b – No aggregation
//     01b – Up to 2 Posted Requests
//     10b – Up to 4 Posted Requests
//     11b – Up to 8 Posted Requests
//    Reserved If Aggregation Supported is Clear.
//    Default value is 00b
    uint8_t tx_aggr_mode_pr:2;
//    Tx Aggregation Mode CPL – If Aggregation Supported is
//    Set then this field selects the level of aggregation for
//    Transmitted Completions for this Stream, encoded as:
//     00b – No aggregation
//     01b – Up to 2 Completions
//     10b – Up to 4 Completions
//     11b – Up to 8 Completions
//    Reserved If Aggregation Supported is Clear.
//    Default value is 00b

    uint8_t tx_aggr_mode_cpl:2;
//    PCRC Enable – When Set, Transmitted IDE TLPs
//    associated with this Stream must include PCRC, and
//    Received TLPs must be checked for PRCR failure.
//    Reserved if PCRC Supported is Clear.
//    Default value is 0b.
    uint16_t pcrc_en:1;

    uint16_t cfg_sel_ide:1; //TODO: this is missing from PCI-SIG spec
    uint16_t reserved1:4;
//    Selected Algorithm – Selects the algorithm to be used for
//    securing IDE TLPs for this IDE Stream. Must be
//    programmed to the same value in both the Upstream and
//    Downstream Ports. Must be configured while Selective IDE
//    Stream Enable is Clear. When Selective IDE Stream
//    Enable is Set, the setting is sampled, and this field
//    becomes RO with reads returning the sampled value.
//     0 0000b – AES-GCM 256 key size, 96b MAC Others –
//    Reserved
    uint16_t algorithm:5;
//    TC – System firmware/software must program this field to
//    indicate the TC associated with this Selective IDE Register
//    block.
//    Default value is 000b
    uint16_t tc:3;
//    Default Stream – When Set, ATS and Memory
//    Request/Completion TLPs using the Traffic Class indicated
//    in the TC field are associated with this Stream, unless the
//    TLP matches some other Stream for the indicated TC.
//    It is not permitted to configure more than one Stream to be
//    associated with the same TC. If this is done, hardware must
//    select one of the Streams to be associated with the TC – the
//    selection is implementation-specific.
//    Applicable for Endpoint Upstream Ports only. Reserved for
//    other Port types.
//    Default value is 0b.
    uint16_t default_stream:1;
    uint16_t reserved2:1;
//    Stream ID – Indicates the Stream ID associated with the
//    Selective IDE Stream. Software must program the same
//    Stream ID into both Ports associated with a given Selective
//    IDE Stream.
//    Default value is 00h.
    stream_id_t stream_id;
  };
  uint32_t raw;
} ide_stream_ctrl_t; //Selective IDE stream control ?
tdx_static_assert(sizeof(ide_stream_ctrl_t) == 4, ide_stream_ctrl_t);

typedef union
{
    struct
    {
        ide_stream_ctrl_t ide_stream_ctrl;
        uint32_t rsvd;
    };
    uint64_t raw;
} ide_stream_ctrl_reg_t;
tdx_static_assert(sizeof(ide_stream_ctrl_reg_t) == 8, ide_stream_ctrl_reg_t);

typedef union
{
    struct
    {
      uint8_t ide_id;         // Bit 7: 0 - IDE_ID – ID of the RP IDE config. register block
      uint8_t rp_df_num;      // Bit 15:8 - RP_DF_NUM – Device and fn. number of RP
      uint8_t key_id;         // Bit 23:16 - KEY_ID – ID of key config bar stream registers
      uint8_t rsvd        :7; // Bit 30:24 – Reserved
      uint8_t stream_type :1; // Bit 31 – STREAM_TYPE – 0: LINK_IDE, 1: SEL_IDE
    };
    uint32_t raw;
} ide_stream_cfg_t;
tdx_static_assert(sizeof(ide_stream_cfg_t) == 4, ide_stream_cfg_t);

typedef union
{
    struct
    {
        ide_stream_cfg_t ide_stream_cfg;
        uint32_t rsvd;
    };
    uint64_t raw;
} ide_stream_cfg_reg_t;
tdx_static_assert(sizeof(ide_stream_cfg_reg_t) == 8, ide_stream_cfg_reg_t);

typedef union
{
    struct
    {
      uint16_t limit;
      uint16_t base;
    };
    uint32_t raw;
} rid_range_t;
tdx_static_assert(sizeof(rid_range_t) == 4, rid_range_t);

typedef union
{
  struct
  {
    uint8_t rsvd0;
    uint16_t rid_limit;
    uint8_t rsvd1;
  };
  uint32_t raw;
} rid_assoc_1_t;
tdx_static_assert(sizeof(rid_assoc_1_t) == 4, rid_assoc_1_t);

typedef union
{
    struct
    {
        rid_assoc_1_t rid_assoc_1;
        uint32_t rsvd;
  };
  uint64_t raw;
} rid_assoc_1_reg_t;
tdx_static_assert(sizeof(rid_assoc_1_reg_t) == 8, rid_assoc_1_reg_t);

typedef union
{
  struct
  {
    uint8_t valid:1;
    uint8_t rsvd0:7;
    uint16_t rid_base;
    uint8_t rsvd1;
  };
  uint32_t raw;
} rid_assoc_2_t;
tdx_static_assert(sizeof(rid_assoc_2_t) == 4, rid_assoc_2_t);

typedef union
{
    struct
    {
        rid_assoc_2_t rid_assoc_2;
        uint32_t rsvd;
  };
  uint64_t raw;
} rid_assoc_2_reg_t;
tdx_static_assert(sizeof(rid_assoc_2_reg_t) == 8, rid_assoc_2_reg_t);

typedef union
{
    struct
    {
        uint32_t valid :1;
        uint32_t rsvd :7;
        uint32_t mem_base_lower :12;
        uint32_t mem_limit_lower :12;
    };
    uint32_t raw;
} ide_addr_assoc_1_t;
tdx_static_assert(sizeof(ide_addr_assoc_1_t) == 4, ide_addr_assoc_1_t);

typedef union
{
    struct
    {
        ide_addr_assoc_1_t ide_addr_assoc_1;
        uint32_t rsvd;
    };
    uint64_t raw;
} ide_addr_assoc_1_reg_t;
tdx_static_assert(sizeof(ide_addr_assoc_1_reg_t) == 8, ide_addr_assoc_1_reg_t);

/**
 * @struct ide_addr_assoc_reg_2_t
 */
typedef union
{
    uint32_t mem_limit_upper;
    uint32_t raw;
} ide_addr_assoc_2_t;
tdx_static_assert(sizeof(ide_addr_assoc_2_t) == 4, ide_addr_assoc_2_t);

typedef union
{
    struct
    {
        ide_addr_assoc_2_t ide_addr_assoc_2;
        uint32_t rsvd;
    };
    uint64_t raw;
} ide_addr_assoc_2_reg_t;
tdx_static_assert(sizeof(ide_addr_assoc_2_reg_t) == 8, ide_addr_assoc_2_reg_t);

/**
 * @struct ide_addr_assoc_reg_3_t
 */
typedef union
{
    uint32_t mem_base_upper;
    uint32_t raw;
} ide_addr_assoc_3_t;
tdx_static_assert(sizeof(ide_addr_assoc_3_t) == 4, ide_addr_assoc_3_t);

typedef union
{
    struct
    {
        ide_addr_assoc_3_t ide_addr_assoc_3;
        uint32_t rsvd;
    };
    uint64_t raw;
} ide_addr_assoc_3_reg_t;
tdx_static_assert(sizeof(ide_addr_assoc_3_reg_t) == 8, ide_addr_assoc_3_reg_t);

typedef union
{
    struct
    {
        uint32_t en : 1;
        uint32_t rsvd: 23;
    };
    // Done to preserve alignment
    struct
    {
        uint8_t :8;
        uint16_t :16;
        stream_id_t stream_id;
    };
    uint32_t raw;
} stream_control_t;
tdx_static_assert(sizeof(stream_control_t) == 4, stream_control_t);

typedef union
{
    struct
    {
        // 0   KEY_SET
        // 0: Key Set 0 (KS0)
        // 1: Key Set 1 (KS1)
        uint8_t key_set :1;
        // 1   RxTxB   Direction – with reference to device
        // 0: DEV_RX
        // 1: DEV_TX
        uint8_t direction :1;
        uint8_t rsvd : 2;
        // 7:4 SUB_STREAM_ID   Sub stream ID
        // 0 – PR – Posted Requests
        // 2 – NPR – Non-posted requests //TODO: possible typo in FAS, should be BIT1 ?
        // 4 – CPL - Completions         //TODO: possible typo in FAS, should be BIT2 ?
        uint8_t sub_stream_id : 4;
    };
    uint8_t raw;
} ide_km_param_t;
tdx_static_assert(sizeof(ide_km_param_t) == 1, ide_km_param_t);

enum ide_object_id_e
{
    IDE_OBJECT_ID_QUERY        = 0,
    IDE_OBJECT_ID_KEY_PROG     = 2,
    IDE_OBJECT_ID_KP_ACK       = 3,
    IDE_OBJECT_ID_K_SET_GO     = 4,
    IDE_OBJECT_ID_K_SET_STOP   = 5,
    IDE_OBJECT_ID_K_GOSTOP_ACK = 6,
    IDE_OBJECT_INVALID         = 255 //Psudo-IDE object
};
typedef uint8_t ide_object_id_t;

#define IDE_KEY_SIZE_IN_BYTES  (32)
#define IDE_KEY_SIZE_IN_DWORDS (IDE_KEY_SIZE_IN_BYTES / 4)
#define IDE_IV_SIZE_IN_BYTES   (8)
#define IDE_IV_INIT_BYTE_IDX   (4)
#define IDE_IV_INIT_VALUE      (1)

typedef uint256_t key_slot_t;
tdx_static_assert(sizeof(key_slot_t) == IDE_KEY_SIZE_IN_BYTES, key_slot_t);

typedef struct
{
    uint8_t bytes[IDE_IV_SIZE_IN_BYTES];
} iv_slot_t;
tdx_static_assert(sizeof(iv_slot_t) == IDE_IV_SIZE_IN_BYTES, iv_slot_t);

#define IDE_KM_MSG_PROTOCOL_ID (0)
#define IDE_KM_DEFUALT_OBJ_SIZE (8)
#define IDE_KM_KEYPROG_OBJ_SIZE (IDE_IV_SIZE_IN_BYTES + IDE_KEY_SIZE_IN_BYTES + IDE_KM_DEFUALT_OBJ_SIZE)

typedef struct
{
    spdm_doe_headers_t spdm_doe_headers;
    uint8_t payload; // Variable size
} idekm_msg_t;

typedef struct
{
    uint8_t protocol_id; // Must be 0
    ide_object_id_t object_id;
    uint16_t rsvd0; // This accounts for PAYLOAD[0], must be 0
    stream_id_t stream_id;
    uint8_t rsvd1; // Must be 0
    ide_km_param_t ide_km_param;
    uint8_t rsvd2; // Must be 0
} k_gostop_ack_obj_t;
tdx_static_assert(sizeof(k_gostop_ack_obj_t) == IDE_KM_DEFUALT_OBJ_SIZE, k_gostop_ack_obj_t);

typedef struct
{
    k_gostop_ack_obj_t k_gostop_ack_obj;
    key_slot_t ide_key;
    iv_slot_t iv;
} keyprog_obj_t;
tdx_static_assert(sizeof(keyprog_obj_t) == IDE_KM_KEYPROG_OBJ_SIZE, keyprog_obj_t);

typedef union
{
    ide_km_param_t ide_km_param;
    // Done to preserve alignment
    struct
    {
        uint64_t :8;
        uint64_t rsvd: 56;
    };
    uint64_t raw;
} ide_km_param_reg_t;
tdx_static_assert(sizeof(ide_km_param_reg_t) == 8, ide_km_param_reg_t);

#define SIZE_OF_IDE_KM_MSG_BUFFER_IN_BYTES (512)
#define ALL_IDE_KEYS_VALID_MASK (0x7)
#define MAX_TX_PRIMED_KEYS (3)

enum ide_stream_key_set_sel_e {
    KS0 = 0,
    KS1 = 1
};
typedef uint8_t ide_stream_key_set_sel_t;

enum ide_stream_key_sub_stream_e
{
    IDE_SUB_STREAM_PR  = 0,
    IDE_SUB_STREAM_NPR = 1,
    IDE_SUB_STREAM_CPL = 2
};

enum ide_stream_direction_e {
    DEV_RX = 0,
    DEV_TX = 1
};
typedef uint8_t ide_stream_direction_t;

typedef union
{
  struct
  {
    uint64_t sub_stream     :2; //uses ide_stream_key_sub_stream_e
    uint64_t reserved       :60;
    uint64_t key_set_select :1; // uses ide_stream_key_set_sel_e
    uint64_t direction      :1; //uses ide_key_direction_e
  };
  uint64_t raw;
} ide_stream_key_set_t;
tdx_static_assert(sizeof(ide_stream_key_set_t) == 8, ide_stream_key_set_t);

#define IDE_SUB_STREAM_SLOT_BITMASK (0x1FF)

typedef union
{
    struct
    {
        uint32_t pr:10;
        uint32_t npr:10;
        uint32_t cpl:10;
        uint32_t rsvd:2;
    };
    uint32_t raw;
} stream_keyset_slot_id_t;
tdx_static_assert(sizeof(stream_keyset_slot_id_t) == 4, stream_keyset_slot_id_t);

//Taken from PCI-SIG
typedef union
{
    struct
    {
//        Link IDE Stream Supported – When Set, indicates that the
//        Port support Link IDE Streams, and that one or more Link
//        IDE Stream Registers block(s) immediately follow the IDE
//        Status Register, per the value in the Number of TCs
//        Supported for Link IDE field.
        uint8_t lnk_ide_supported :1;


//        Selective IDE Streams Supported – When Set, indicates
//        that the Port support Selective IDE Streams, and that one or
//        more Selective IDE Stream Registers block(s) are
//        implemented, per the value in the Number of Selective IDE
//        Streams Supported field.
        uint8_t sel_ide_supported :1;

//        Flow-Through IDE Stream Supported – For a Switch or
//        Root Port, when Set indicates support for passing Selective
//        IDE Streams to all other Switch or Root Ports.
//        If this bit is Set and both Link IDE Stream Supported and
//        Selective IDE Streams Supported are Clear, then no Link
//        IDE register blocks or Selective IDE register blocks are
//        required.
//        Reserved for Endpoints
        uint8_t ft_supported : 1;

        uint8_t rsvd0 :1;

//        Aggregation Supported – If Link IDE Stream Supported
//        or Selective IDE Streams Supported are Set, then this bit,
//        when Set, indicates the Port supports aggregation.
//        Undefined if Link IDE Stream Supported and Selective
//        IDE Streams Supported are both Clear.

        uint8_t aggr_supported:1;
//        PCRC Supported – When Set, indicates that the Port
//        supports the generation and checking of PCRC.
        uint8_t pcrc_supported:1;

        uint8_t rsvd1 :2;

//        Supported Algorithms – Indicates the supported
//        algorithms for securing IDE TLPs, encoded as:
//         0 0000b – AES-GCM 256 key size, 96b MAC
//         Others – Reserved
        uint8_t supported_algo:5;

//        Number of TCs Supported for Link IDE – If Link IDE
//        Stream Supported is Set, indicates the number of TCs
//        supported for Link IDE Streams encoded as:
//        000b – One TC supported
//        001b – 2 TCs supported
//        010b – 3 TCs supported
//        011b – 4 TCs supported
//        100b – 5 TCs supported
//        101b – 6 TCs supported
//        110b – 7 TCs supported
//        111b – 8 TCs supported
//        If Link IDE Stream Supported is Clear, this field is
//        undefined.
        uint8_t num_lnk_ide:3;

//        Number of Selective IDE Streams Supported -
//        If Selective IDE Streams Supported is Set then this field
//        indicates number of Selective IDE Streams Supported such
//        that 0=1 Stream.
//        A corresponding number of Selective IDE Stream Register
//        blocks must be implemented. If Link IDE Stream Supported
//        is Clear, then these blocks must immediately follow the IDE
//        Status Register. If Link IDE Stream Supported is Set, then
//        these blocks must immediately follow the Link IDE Stream
//        Control and Status Registers.
//        The value is undefined if Selective IDE Streams
//        Supported is Clear

        uint8_t num_sel_ide;

        uint8_t rsvd2;
    };
    uint32_t raw;
} ide_cap_t;
tdx_static_assert(sizeof(ide_cap_t) == 4, ide_cap_t);

//Taken from PCI-SIG
typedef union
{
    struct
    {
        uint32_t rsvd0 :2;
//        Flow-Through IDE Stream Enabled – For Switch Ports
//        and Root Ports, Enables the Port for flow-through operation
//        of IDE Stream.
//        Reserved for other types of Ports
        uint32_t ft_supported :1;

    };
    uint32_t raw;
} ide_ctrl_t;
tdx_static_assert(sizeof(ide_ctrl_t) == 4, ide_ctrl_t);

// Taken from PCI-SIG
typedef union
{
    struct
    {
//        Link IDE Stream Enable – When Set, enables Link IDE
//        Stream.
//        It is permitted for the default value to be 1b if and only if
//        implementation-specific means can ensure that the Link IDE
//        Stream will default into a state where operation in the
//        Secure state is possible.
        uint8_t en:1;
        uint8_t rsvd0:1;
//        Tx Aggregation Mode NPR – If Aggregation Supported is
//        Set then this field selects the level of aggregation for
//        Transmitted Non-Posted Requests for this Stream, encoded
//        as:
//         00b – No aggregation
//         01b – Up to 2 Non-Posted Requests
//         10b – Up to 4 Non-Posted Requests
//         11b – Up to 8 Non-Posted Requests
//        Reserved If Aggregation Supported is Clear.
//        Default value is 00b
        uint8_t tx_aggr_mode_npr : 2;
//        Tx Aggregation Mode PR – If Aggregation Supported is
//        Set then this field selects the level of aggregation for
//        Transmitted Posted Requests for this Stream, encoded as:
//         00b – No aggregation
//         01b – Up to 2 Posted Requests
//         10b – Up to 4 Posted Requests
//         11b – Up to 8 Posted Requests
//        Reserved If Aggregation Supported is Clear.
//        Default value is 00b
        uint8_t tx_aggr_mode_pr : 2;
//        Tx Aggregation Mode CPL – If Aggregation Supported is
//        Set then this field selects the level of aggregation for
//        Trasmitted Completions for this Stream, encoded as:
//         00b – No aggregation
//         01b – Up to 2 Completions
//         10b – Up to 4 Completions
//         11b – Up to 8 Completions
//        Reserved If Aggregation Supported is Clear.
//        Default value is 00b
        uint8_t tx_aggr_mode_cpl : 2;
//        PCRC Enable – When Set, Transmitted IDE TLPs
//        associated with this Stream must include PCRC, and
//        Received TLPs must be checked for PRCR failure.
//        Reserved if PCRC Supported is Clear.
//        Default value is 0b.
        uint16_t pcrc_en : 1;
        uint16_t rsvd1:5;
//        Selected Algorithm – Selects the algorithm to be used for
//        securing IDE TLPs for this IDE Stream. Must be
//        programmed to the same value in both the Upstream and
//        Downstream Ports. Must be configured while Link IDE
//        Stream Enable is Clear. When Link IDE Stream Enable is
//        Set, the setting is sampled, and this field becomes RO with
//        reads returning the sampled value.
//         0 0000b – AES-GCM 256 key size, 96b MAC
//         Others – Reserved
        uint16_t selected_algo : 5;
//        TC – System firmware/software must program this field to
//        indicate the TC associated with this Link IDE Register block.
//        Default value is 000b
        uint16_t tc :3;
        uint16_t rsvd2:2;
//        Stream ID – Indicates the Stream ID associated with this
//        Link IDE Stream. Software must program the same Stream
//        ID into both Ports associated with a given Link IDE Stream.
//        Default value is 00h.
        stream_id_t stream_id;
    };
    uint32_t raw;
} lnk_ide_stream_control_reg_t;
tdx_static_assert(sizeof(lnk_ide_stream_control_reg_t) == 4, lnk_ide_stream_control_reg_t);

//Taken from PCI-SIG
typedef union
{
    struct
    {
//        Link/Selective IDE Stream State – When Link/Selective IDE Stream Enable is
//        Set, this field indicates the state of the Port. Encodings:
//         0000b – Start / Unknown
//         0010b – Secure
//         1000b – Fail_Insecure
//         Others – Reserved – Software must handle reserved
//        values as indicating unknown state
//        When Link IDE Stream Enable is Clear, the value of this
//        field must be 0000b
        uint32_t state :4;
        uint32_t rsvd  :27;
//        Received Integrity Check Fail Message – When Set,
//        indicates that one or more Integrity Check Fail Message(s)
//        have been Received for this Stream.
        uint32_t recv_intg_check_fail_msg:1;
    };
    uint32_t raw;
} ide_stream_status_reg_t;
tdx_static_assert(sizeof(ide_stream_status_reg_t) == 4, ide_stream_status_reg_t);

typedef struct
{
    lnk_ide_stream_control_reg_t control;
    ide_stream_status_reg_t status;
} lnk_ide_stream_reg_block_t;
tdx_static_assert(sizeof(lnk_ide_stream_reg_block_t) == 8, lnk_ide_stream_reg_block_t);

//Taken from PCI-SIG
typedef union
{
    struct
    {
//        Number of Address Association Register Blocks –
//        Indicates the number of Selective IDE Address Association
//        register blocks for this Selective IDE Stream.
//        The number of Selective IDE Address Association register
//        blocks for a given IDE Stream is hardware implementation specific,
//        and is permitted to be any number between 0 and 15.
        uint32_t num_addr_assoc_reg_blocks : 4;
        uint32_t rsvd : 28;
    };
    uint32_t raw;
} ide_stream_capability_t;
tdx_static_assert(sizeof(ide_stream_capability_t) == 4, ide_stream_capability_t);

typedef struct
{
    ide_addr_assoc_1_t addr_assoc1;
    ide_addr_assoc_2_t addr_assoc2;
    ide_addr_assoc_3_t addr_assoc3;
} ide_addr_assoc_reg_block_t;
tdx_static_assert(sizeof(ide_addr_assoc_reg_block_t) == 12, ide_addr_assoc_reg_block_t);

typedef struct
{
    ide_stream_capability_t capability;
    ide_stream_ctrl_t control; // Read only
    ide_stream_status_reg_t status; // Read only
    rid_assoc_1_t rid_assoc1;
    rid_assoc_2_t rid_assoc2;
    // ide_addr_assoc_reg_block_t addr_assoc_block; //number of elements is dynamic
} sel_ide_stream_reg_block_t;

//IDE Extended Capability structure
typedef struct
{
    pcie_cap_id_t ide_ecap;
    ide_cap_t ide_cap;
    ide_ctrl_t ide_ctrl;
    // lnk_ide_stream_reg_block_t lnk_ide_stream_block; // number of elements is dynamic
    // sel_ide_stream_reg_block_t sel_ide_stream_block; // number of elements is dynamic
} ide_ecap_t;

#pragma pack(pop)

typedef struct
{
    ide_stream_status_t stream_sts;
    uint8_t rp_df_num;
    uint8_t ide_id;
    uint8_t key_id;
    ide_stream_ctrl_t ide_stream_ctrl;
    rid_range_t ide_rid_assoc_reg;
    ide_addr_assoc_1_t ide_addr_assoc_reg1;
    ide_addr_assoc_2_t ide_addr_assoc_reg2; //mem_limit_upper
    ide_addr_assoc_3_t ide_addr_assoc_reg3; //mem_base_upper
    pa_t stream_exinfo_pa;
} stream_info_t;

typedef struct
{
    // Temporary message buffer to create IDE KM request or process IDE KM response. Of type IDE_KM_REQ_RSP_T
    uint8_t idekm_msg_buffer[SIZE_OF_IDE_KM_MSG_BUFFER_IN_BYTES]; // [0:511]
    // Index of SPDM session bound to this stream
    uint8_t spdm_id;                                              // [512]
    // Set to OBJECT_ID of outstanding request
    ide_object_id_t outstanding_req_object_id;                    // [513]
    // IDE Key Management Protocol parameters of the outstanding request object
    ide_km_param_t outstanding_req_km_param;                      // [514]
    // Must be 0
    uint8_t reserved[5];                                          // [515:519]
    // Number of DEVIFCS structures associated with this stream
    uint64_t devif_ref_cnt;                                       // [520:527]
    // Tracks if keys have been configured Array of 4 UINT8_T where each field is a bitfield. First index is direction and second is key set
    // Bit 0 – PR_KEY, Bit 2 – NPR_KEY, Bit 4 – CPL_KEY
    uint8_t key_valid[2][2];                                      // [528:531]
    // Tracks if keys have been given a GO Array of 4 UINT8_T where each field is a bitfield. First index is direction and second is key set
    // Bit 0 – PR_KEY, Bit 2 – NPR_KEY, Bit 4 – CPL_KEY
    uint8_t key_go[2][2];                                         // [532:535]
    // Incremented each time a TX key (down stream) is primed
    // Used to enable the stream once all 3 TX keys were configured
    uint8_t primed_tx_key_counter;                                // [536]
    // Must be 0
    uint8_t reserved2[3559];                                      // [537:4096]
} stream_exinfo_t;
tdx_static_assert(sizeof(stream_exinfo_t) == _4KB, stream_exinfo_t);

#endif /* SRC_COMMON_DATA_STRUCTURES_TDXIO_IDE_STREAM_DEFS_H_ */
