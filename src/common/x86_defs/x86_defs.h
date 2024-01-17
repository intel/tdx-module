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
 * @file x86_defs.h
 * @brief x86 definitions
 */

#ifndef SRC_COMMON_X86_DEFS_X86_DEFS_H_
#define SRC_COMMON_X86_DEFS_X86_DEFS_H_


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"

#define SPR_A0_FMS          0x806F0
#define SPR_B0_FMS          0x806F1
#define SPR_C0_FMS          0x806F2
#define SPR_D0_FMS          0x806F3

#define INTEL64_MAX_INST_LEN 16// Max length of x86 instruction

#define CR2_RESET_STATE  0x0ULL

#define XCR0_RESET_STATE 0x1ULL
#define DR0_RESET_STATE  0x0ULL
#define DR1_RESET_STATE  0x0ULL
#define DR2_RESET_STATE  0x0ULL
#define DR3_RESET_STATE  0x0ULL
#define DR6_RESET_STATE  0xFFFF0FF0ULL

#define CODE_SEGMENT_TYPE_WITH_CRA_BITS   0b1111

typedef union {
    struct
    {
        uint64_t  limit_low    : 16;
        uint64_t  base_low     : 24;
        uint64_t  type         : 4;
        uint64_t  s            : 1;
        uint64_t  dpl          : 2;
        uint64_t  p            : 1;
        uint64_t  limit_high   : 4;
        uint64_t  avl          : 1;
        uint64_t  l            : 1;
        uint64_t  db           : 1;
        uint64_t  g            : 1;
        uint64_t  base_high    : 8;
    };

  uint64_t raw;
} ia32_segment_descriptor_t;
tdx_static_assert(sizeof(ia32_segment_descriptor_t) == 8, ia32_segment_descriptor_t);

#define IA32_IDT_GATE_TYPE_INTERRUPT_32   0xEU

typedef union {
    struct
    {
        uint64_t  offset_low   : 16;
        uint64_t  selector     : 16;
        uint64_t  reserved_0   : 8;
        uint64_t  gate_type    : 5;
        uint64_t  dpl          : 2;
        uint64_t  present      : 1;
        uint64_t  offset_high  : 16;
        uint64_t  offset_upper : 32;
        uint64_t  reserved_1   : 32;
    };
    struct
    {
        uint64_t  raw_low;
        uint64_t  raw_high;
    };
} ia32_idt_gate_descriptor;
tdx_static_assert(sizeof(ia32_idt_gate_descriptor) == 16, ia32_idt_gate_descriptor);

typedef union
{
   struct
   {
        uint32_t type   : 4;   // Bits 3:0
        uint32_t s      : 1;   // Bit 4
        uint32_t dpl    : 2;   // Bits 6:5
        uint32_t p      : 1;   // Bit 7
        uint32_t rsv    : 3;   // Bits 10:8
        uint32_t null   : 1;   // Bit 11
        uint32_t avl    : 1;   // Bit 12
        uint32_t l      : 1;   // Bit 13
        uint32_t db     : 1;   // Bit 14
        uint32_t g      : 1;   // Bit 15
        uint32_t usable : 1;   // Bit 16
        uint32_t rsvd   : 15;  // Bits 31:17
    };

    uint32_t raw;
} seg_arbyte_t;
tdx_static_assert(sizeof(seg_arbyte_t) == 4, seg_arbyte_t);

typedef union {
    struct
    {
        uint64_t
        pe          : 1,  //bit 0
        mp          : 1,  //bit 1
        em          : 1,  //bit 2
        ts          : 1,  //bit 3
        et          : 1,  //bit 4
        ne          : 1,  //bit 5
        reserved_0  : 10, //bits 6-15
        wp          : 1,  //bit 16
        reserved_1  : 1,  //bit 17
        am          : 1,  //bit 18
        reserved_2  : 10, //bits 19-28
        nw          : 1,  //bit 29
        cd          : 1,  //bit 30
        pg          : 1,  //bit 31
        reserved_3  : 32; //bits 32-63
    };
    uint64_t raw;
} ia32_cr0_t;
tdx_static_assert(sizeof(ia32_cr0_t) == 8, ia32_cr0_t);

#define CR0_IGNORED_MASK 0x1FFAFFC0

typedef union {
    struct
    {
        uint64_t
            reserved_0 : 3,
            pwt        : 1,
            pcd        : 1,
            reserved_1 : 7,
            base       : 52;
    };
    uint64_t raw;
} ia32_cr3_t;
tdx_static_assert(sizeof(ia32_cr3_t) == 8, ia32_cr3_t);


typedef union {
    struct
    {
        uint64_t
            vme        : 1,   // Bit 0
            pvi        : 1,   // Bit 1
            tsd        : 1,   // Bit 2
            de         : 1,   // Bit 3
            pse        : 1,   // Bit 4
            pae        : 1,   // Bit 5
            mce        : 1,   // Bit 6
            pge        : 1,   // Bit 7
            pce        : 1,   // Bit 8
            osfxsr     : 1,   // Bit 9
            osxmmexcpt : 1,   // Bit 10
            umip       : 1,   // Bit 11
            la57       : 1,   // Bit 12
            vmxe       : 1,   // Bit 13
            smxe       : 1,   // Bit 14
            reserved_0 : 1,   // Bit 15
            fsgsbase   : 1,   // Bit 16
            pcide      : 1,   // Bit 17
            osxsave    : 1,   // Bit 18
            keylocker  : 1,   // Bit 19
            smep       : 1,   // Bit 20
            smap       : 1,   // Bit 21
            pke        : 1,   // Bit 22
            cet        : 1,   // Bit 23
            pks        : 1,   // Bit 24
            uintr      : 1,   // Bit 25
            reserved_1 : 38;  // Bits 26:63
    };
    uint64_t raw;
} ia32_cr4_t;
tdx_static_assert(sizeof(ia32_cr4_t) == 8, ia32_cr4_t);

/** General-Purpose Registers Index **/
#define GPR_RSP_IDX 4 // RSP Index

typedef union {
    struct
    {
        uint64_t
            cf         : 1,
            reserved_0 : 1, // must be 1
            pf         : 1,
            reserved_1 : 1, // must be 0
            af         : 1,
            reserved_2 : 1, // must be 0
            zf         : 1,
            sf         : 1,
            tf         : 1,
            ief        : 1,
            df         : 1,
            of         : 1,
            iopl       : 2,
            nt         : 1,
            reserved_3 : 1, // must be 0
            rf         : 1,
            vm         : 1,
            ac         : 1,
            vif        : 1,
            vip        : 1,
            id         : 1,
            reserved_4 : 42; // must be 0
    };
    uint64_t raw;
} ia32_rflags_t;
tdx_static_assert(sizeof(ia32_rflags_t) == 8, ia32_rflags_t);

#define RFLAGS_ARITHMETIC_FLAGS_MASK           0x000008D5   // CF, PF, AF, ZF, SF, OF

typedef union {
    struct
    {
        uint64_t
            x87_fpu_mmx        : 1, // 0
            sse                : 1, // 1
            avx                : 1, // 2
            mpx_bndreg         : 1, // 3
            mpx_bndcsr         : 1, // 4
            avx3_kmask         : 1, // 5
            avx3_zmm_hi        : 1, // 6
            avx3_zmm           : 1, // 7
            pt                 : 1, // 8
            pk                 : 1, // 9
            enqcmd             : 1, // 10
            cet_u              : 1, // 11
            cet_s              : 1, // 12
            hdc                : 1, // 13
            uli                : 1, // 14
            lbr                : 1, // 15
            hwp                : 1, // 16
            amx_xtilecfg       : 1, // 17
            amx_xtiledata      : 1, // 18
            reserved_1         : 45;
    };
    uint64_t raw;
} ia32_xcr0_t;
tdx_static_assert(sizeof(ia32_xcr0_t) == 8, ia32xcr0_t);

#define XCR0_USER_BIT_MASK                  0x000602FF
#define XCR0_SUPERVISOR_BIT_MASK            0x0001FD00
#define XCR0_MAX_VALID_BIT                  18
#define XCR0_LBR_BIT                        15
#define XCR0_PT_BIT                         8

#define IA32E_PAGING_STRUCT_ADDR_MASK    ((uint64_t) 0x000FFFFFFFFFF000LLU)
#define IA32E_256T_ADDR_MASK             ((uint64_t) 0x000F000000000000LLU)
#define IA32E_512G_ADDR_MASK             ((uint64_t) 0x000FFF8000000000LLU)
#define IA32E_1G_ADDR_MASK               ((uint64_t) 0x000FFFFFC0000000LLU)
#define IA32E_2M_ADDR_MASK               ((uint64_t) 0x000FFFFFFFE00000LLU)
#define IA32E_1G_RSRV_ADDR_MASK          ((uint64_t) 0x000000003FFFE000LLU)
#define IA32E_2M_RSRV_ADDR_MASK          ((uint64_t) 0x00000000001FE000LLU)
#define IA32E_1G_OFFSET                  ((uint64_t) 0x000000003FFFFFFFLLU)
#define IA32E_2M_OFFSET                  ((uint64_t) 0x00000000001FFFFFLLU)
#define IA32E_4K_OFFSET                  ((uint64_t) 0x0000000000000FFFLLU)

// Page alignment masks
#define MEM_MASK_4KB 0xFFFFFFFFFFFFF000
#define MEM_MASK_2MB 0xFFFFFFFFFFE00000
#define MEM_MASK_1GB 0xFFFFFFFFC0000000

#define IA32E_4K_PAGE_OFFSET             12
#define IA32E_2M_PAGE_OFFSET             21
#define IA32E_1G_PAGE_OFFSET             30

typedef union access_rights_u {

    struct {
        uint8_t r       :   1;
        uint8_t w       :   1;
        uint8_t x       :   1;
    };

    struct {
        uint8_t rwx     :   3;
        uint8_t ignore  :   5;
    };

    uint8_t raw;
} access_rights_t;
tdx_static_assert(sizeof(access_rights_t) == 1, access_rights_t);

typedef union pfec_u {
    struct
    {
        uint32_t p         : 1;  // 0
        uint32_t wr        : 1;  // 1
        uint32_t us        : 1;  // 2
        uint32_t r         : 1;  // 3
        uint32_t id        : 1;  // 4
        uint32_t pk        : 1;  // 5
        uint32_t ss        : 1;  // 6
        uint32_t rsvd1     : 8;  // 14-7
        uint32_t sgx       : 1;  // 15
        uint32_t rsvd2     : 15; // 31-16
    };
    uint32_t raw;
} pfec_t;
tdx_static_assert(sizeof(pfec_t) == 4, pfec_t);

/**
 *   @brief Memory type enumeration
 */
typedef enum {
    MT_UC      = 0,
    MT_WC      = 1,
    MT_RSVD0   = 2,
    MT_RSVD1   = 3,
    MT_WT      = 4,
    MT_WP      = 5,
    MT_WB      = 6,
    MT_UCM     = 7
} memory_type_t;

/**
 *   @brief Definition of GPA EPT entry level
 */
typedef enum {
    LVL_PT      = 0,    // EPT 4KB leaf entry level
    LVL_PD      = 1,    // EPT page directory or 2MB leaf entry level
    LVL_PDPT    = 2,    // EPT page table directory or 1GB leaf entry level
    LVL_PML4    = 3,    // EPT Page map entry level 4
    LVL_PML5    = 4,    // EPT Page map entry level 5
    LVL_MAX     = 5,
} ept_level_t;

typedef union ia32e_pxe_u {
    struct {
        uint64_t
            p         :   1,  // 0
            rw        :   1,  // 1
            us        :   1,  // 2
            pwt       :   1,  // 3
            pcd       :   1,  // 4
            a         :   1,  // 5
            d         :   1,  // 6
            pat       :   1,  // 7
            g         :   1,  // 8
            ignore_0  :   3,  // 9-11
            addr      :   40, // 12-51
            ignore_1  :   7,  // 52-58
            protkey   :   4,  // 59-62
            xd        :   1;  // 63
  } fields_4k;
  uint64_t raw;
} ia32e_pxe_t;
tdx_static_assert(sizeof(ia32e_pxe_t) == 8, ia32e_pxe_t);

typedef union ia32e_ept_u {
    struct {
        uint64_t
            r            :   1,  // 0
            w            :   1,  // 1
            x            :   1,  // 2
            reserved_0   :   5,  // 3-7
            accessed     :   1,  // 8
            dirty        :   1,  // 9
            xu           :   1,  // 10
            ignore_0     :   1,  // 11
            base         :   40, // 12-51
            ignore_1     :   12; // 52-63
    } fields_ps;
    struct {
        uint64_t
            r            :   1,  // 0
            w            :   1,  // 1
            x            :   1,  // 2
            mt           :   3,  // 3-5
            ipat         :   1,  // 6
            leaf         :   1,  // 7 - Set to 1
            accessed     :   1,  // 8
            ignore_0     :   1,  // 9
            xu           :   1,  // 10
            ignore_1     :   1,  // 11
            reserved_0   :   18, // 12-29
            base         :   22, // 30-51
            ignore_2     :   11, // 52-62
            supp_ve      :   1;  // 63
    } fields_1g;
    struct {
        uint64_t
            r            :   1,  // 0
            w            :   1,  // 1
            x            :   1,  // 2
            mt           :   3,  // 3-5
            ipat         :   1,  // 6
            leaf         :   1,  // 7 - Set to 1
            accessed     :   1,  // 8
            ignore_0     :   1,  // 9
            xu           :   1,  // 10
            ignore_1     :   1,  // 11
            reserved_0   :   9,  // 12-20
            base         :   31, // 21-51
            ignore_2     :   11, // 52-62
            supp_ve      :   1;  // 63
    } fields_2m;
    struct {
        uint64_t
            r            :   1,  // 0
            w            :   1,  // 1
            x            :   1,  // 2
            mt           :   3,  // 3-5
            ipat         :   1,  // 6
            ignore_0     :   1,  // 7 - Set to 1
            accessed     :   1,  // 8
            ignore_1     :   1,  // 9
            xu           :   1,  // 10
            ignore_2     :   1,  // 11
            base         :   40, // 12-51
            ignore_3     :   11, // 52-62
            supp_ve      :   1;  // 63
    } fields_4k;
    uint64_t raw;
    struct {
        uint64_t
            rwx          :   3,  // 0-2
            ignore       :   61; // 3-63
    } present;
} ia32e_ept_t;
tdx_static_assert(sizeof(ia32e_ept_t) == 8, ia32e_sept_t);

#define SEPT_ENTRY_R_BIT_POSITION         0
#define SEPT_ENTRY_W_BIT_POSITION         1
#define SEPT_ENTRY_X_BIT_POSITION         2
#define SEPT_ENTRY_XS_BIT_POSITION        2
#define SEPT_ENTRY_MT0_BIT_POSITION       3   // Memory Type
#define SEPT_ENTRY_MT1_BIT_POSITION       4   // Memory Type
#define SEPT_ENTRY_MT2_BIT_POSITION       5   // Memory Type
#define SEPT_ENTRY_IPAT_BIT_POSITION      6   // IPAT
#define SEPT_ENTRY_PS_BIT_POSITION        7   // Non-Leaf(0) / Leaf(1)
#define SEPT_ENTRY_A_BIT_POSITION         8   // Accessed bit
#define SEPT_ENTRY_TDGL_BIT_POSITION      8   // Guest-side lock
#define SEPT_ENTRY_D_BIT_POSITION         9   // Dirt bit
#define SEPT_ENTRY_XU_BIT_POSITION        10
#define SEPT_ENTRY_TDEL_BIT_POSITION      11  // Entry Lock
#define SEPT_ENTRY_TDHP_BIT_POSITION      52  // Host Priority, used together with TDEL
#define SEPT_ENTRY_TDEX_BIT_POSITION      53  // Exported
#define SEPT_ENTRY_TDBW_BIT_POSITION      54  // Blocked for Writing
#define SEPT_ENTRY_TDB_BIT_POSITION       55  // Blocked
#define SEPT_ENTRY_TDP_BIT_POSITION       56  // Pending
#define SEPT_ENTRY_VPW_BIT_POSITION       57  // Verify Paging-Write
#define SEPT_ENTRY_PW_BIT_POSITION        58  // Paging-Write
#define SEPT_ENTRY_TDWR_BIT_POSITION      59  // Saved W bit value
#define SEPT_ENTRY_SSS_BIT_POSITION       60  // Supervisor Shadow Stack
#define SEPT_ENTRY_TDSA_BIT_POSITION      60  // SEPT Alias (Link)
#define SEPT_ENTRY_TDIO_BIT_POSITION      62  // Private(0) / MMIO(1)
#define SEPT_ENTRY_SVE_BIT_POSITION       63  // Suppress #VE

#define SEPT_ENTRY_MT_BITS_SIZE           3

typedef union ia32e_sept_u {
    struct {
        uint64_t
            r_ps         :   1,  // 0
            w_ps         :   1,  // 1
            x_ps         :   1,  // 2
            reserved_0   :   5,  // 3-7
            ignore_0     :   1,  // 8
            reserved_1   :   3,  // 9-11
            base_ps      :   40, // 12-51
            reserved_52  :   4,  // 52-55
            tdp_ps       :   1,  // 56 - Pending
            reserved_2   :   7;  // 57-63
    } fields_ps;
    struct {
        uint64_t
            reserved_0_1g :   30, // 0-29
            base_1g       :   22, // 30-51
            unused_1g     :   12;
    } fields_1g;
    struct {
        uint64_t
            reserved_0_2m :   21, // 0-20
            base_2m       :   31, // 21-51
            unused_2m     :   12;
    } fields_2m;
    struct {
        uint64_t
            r          :   1,  // 0
            w          :   1,  // 1
            x          :   1,  // 2
            mt         :   3,  // 3-5 - Set to 110 (WB)
            ipat       :   1,  // 6 - Set to 1
            leaf       :   1,  // 7 - Non-Leaf(0) / Leaf(1), always 1 for 4KB (level 0)
            a          :   1,  // 8 - Accessed
            d          :   1,  // 9 - Dirty, set and cleared by the TDX module in all the *EXPORTED_* states
            reserved_0 :   1,  // 10 - Xu, not enabled for L1 SEPT
            tdel       :   1,  // 11 - Entry Lock
            base       :   40, // 12-51
            hp         :   1,  // 52 - Host Priority, used together with TDEL
            tdex       :   1,  // 53 - Exported
            tdbw       :   1,  // 54 - Blocked for Writing
            tdb        :   1,  // 55 - Blocked
            tdp        :   1,  // 56 - Pending
            vpw        :   1,  // 57 - Verify Paging-Write
            pw         :   1,  // 58 - Paging-Write
            ignored_0  :   1,  // 59
            sss_tdsa   :   1,  // 60 - Supervisor Shadow Stack / SEPT Alias (Link)
            tdup       :   1,  // 61 - 1: Page is not pinned in memory even though I/O devices may be attached to the TD
            reserved_1 :   1,  // 62
            supp_ve    :   1;  // 63
    };
    uint64_t raw;
    struct {
        uint64_t
            rwx          :   3,   // 0-2
            ignore_0     :   9,   // 3-11
            accept_counter : 9,   // 12-20 – Number of 4KB chunks that have been initialized by TDG.MEM.PAGE.ACCEPT
            ignore_1     :   37,  // 21-57
            tdal         :   3,   // 58-60
            ignore_2     :   3;   // 61-63
    }; // Misc bits
    struct {
        uint64_t
            reserved_0         :  6,  // 0-5
            state_encoding_5_6 :  2,  // 6-7   - bits [5:6] of state encoding
            reserved_1         :  1,  // 8
            state_encoding_0   :  1,  // 9     – Dirty – bit 0 of state encoding
            reserved_2         :  43, // 10-52
            state_encoding_1_4 :  4,  // 53-56 – bits[1:4] of state encoding
            reserved_3         :  6,  // 57-62
            supp_ve            :  1;  // 63
    } state_encoding;
    struct {
        uint64_t
            placeholder_11_0 : 12,  // Bits 11:0
            mig_epoch        : 32,  // Bits 43:12 - Migration epoch
            mig_epoch_valid  : 1,   // Bit  44    - Indicates that MIG_EPOCH is valid
            reserved_51_45   : 7,   // Bits 51:45
            placeholder_63_52: 12;  // Bits 63:52
    }; // Mig epoch bits
    struct
    {
        uint64_t
            r           : 1,  // Bit 0
            w           : 1,  // Bit 1
            x           : 1,  // Bit 2
            mt0_tdrd    : 1,  // Bit 3 : MT[0] / Saved R bit value
            mt1_tdxs    : 1,  // Bit 4 : MT[1] / Saved Xs bit value
            mt2_tdxu    : 1,  // Bit 5 : MT[2] / Saved Xu bit value
            ipat_tdmem  : 1,  // Bit 6 : Ignore PAT / 0: Regular memory / 1: MMIO
            ps          : 1,  // Bit 7 : 0: Non-Leaf / 1: Leaf (also for 4KB pages)
            a           : 1,  // Bit 8 : Accessed
            d           : 1,  // Bit 9 : Dirty
            xu          : 1,  // Bit 10
            reserved_11 : 1,  // Bit 11
            hpa         : 40, // Bits 51:12
            reserved_52 : 1,  // Bit 52
            reserved_53 : 1,  // Bit 53
            reserved_54 : 1,  // Bit 54
            tdb         : 1,  // Bit 55 : Blocked
            reserved_56 : 1,  // Bit 56
            vgp         : 1,  // Bit 57 : Verify Guest Paging
            pwa         : 1,  // Bit 58 : Paging-Write Access
            tdwr        : 1,  // Bit 59 : Saved W bit value
            sss         : 1,  // Bit 60 : Supervisor Shadow Stack
            reserved_61 : 1,  // Bit 61
            reserved_62 : 1,  // Bit 62 : Reserved (BlockDMA)
            sve         : 1;  // Bit 63 : Suppress #VE
    } l2_encoding;
} ia32e_sept_t;
tdx_static_assert(sizeof(ia32e_sept_t) == 8, ia32e_sept_t);

typedef union ia32e_eptp_u {
    struct {
        uint64_t
            ept_ps_mt          :   3,  // 0-2
            ept_pwl            :   3,  // 3-5
            enable_ad_bits     :   1,  // 6
            enable_sss_control :   1,  // 7
            reserved_0         :   4,  // 8-11
            base_pa            :   40, // 12-51
            reserved_1         :   12; // 52-63
    } fields;
    uint64_t raw;
} ia32e_eptp_t;
tdx_static_assert(sizeof(ia32e_eptp_t) == 8, ia32e_eptp_t);

#define NUM_OF_4K_PAGES_IN_2MB          512

typedef union ia32e_paging_table_u {
  ia32e_sept_t sept[512];
  ia32e_ept_t   ept[512];
} ia32e_paging_table_t;


#define MAX_PA                  52ULL
#define MIN_PA_FOR_PML5         49ULL
#define MAX_PA_FOR_GPAW         MAX_PA
#define MAX_PA_FOR_GPA_NOT_WIDE 48ULL
#define NULL_PA                 ~(0ULL) // -1

typedef union pa_u {
    struct {
        union {

            // Full PA that includes the HKID
            uint64_t full_pa : MAX_PA;

            /*struct {
                uint64_t
                  // Relevant physical address, without the HKID
                  addr : (MAX_PA - HKID_RSVD),
                  // Upper HKID part
                  non_tdx_hkid : (HKID_RSVD - TDX_RSVD),
                  tdx_hkid : TDX_RSVD;
            };

            struct {
                uint64_t
                  // Relevant physical address, without the HKID
                  addr2 : (MAX_PA - HKID_RSVD),
                  // Upper HKID part
                  hkid : HKID_RSVD;
            };*/

            // Helper accessors for paging functions
            struct {
              uint64_t
                page_offset :   12,
                pt_index    :   9,
                pd_index    :   9,
                pdpt_index  :   9,
                pml4_index  :   9,
                pml5_index  :   9;
            } fields_4k;
            struct {
              uint64_t
                page_offset :   21,
                pd_index    :   9,
                pdpt_index  :   9,
                pml4_index  :   9,
                pml5_index  :   9;
            } fields_2m;

            // Helper accessors for PAMT indexes
            struct {
                uint64_t
                  page_offset :   12,
                  idx         :   18;
            } pamt_4k;

            struct {
                uint64_t
                  page_offset :   21,
                  idx         :   9;
            } pamt_2m;

            // Helper accessors to determine page index, depending on page size
            struct {
                uint64_t
                  low_12_bits : 12,
                  page_4k_num : (MAX_PA - 12);
            };
            struct {
                uint64_t
                  low_21_bits : 21,
                  page_2m_num : (MAX_PA - 21);
            };
            struct {
                uint64_t
                  low_30_bits : 30,
                  page_1g_num : (MAX_PA - 30);
            };

        };

        //uint64_t rsvd : 12;
    };

    uint64_t raw;
    void* raw_void;
} pa_t;
tdx_static_assert(sizeof(pa_t) == 8, pa_t);

#define MOVDIR64_CHUNK_SIZE     64
#define CACHELINE_SIZE          64

typedef struct
{
    uint16_t  fcw;
    uint16_t  fsw;
    uint8_t   ftw;
    uint8_t   reserved_0;
    uint16_t  fop;
    uint64_t  fip;
    uint64_t  fdp;
    uint32_t  mxcsr;
    uint32_t  mxcsr_mask;
    uint128_t st_mm[8];
    uint128_t xmm[16];
    uint8_t   reserved_1[96];
} xsave_legacy_region_t;
tdx_static_assert(sizeof(xsave_legacy_region_t) == 512, xsave_legacy_region_t);

typedef struct
{
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint8_t reserved[48];
} xsave_header_t;
tdx_static_assert(sizeof(xsave_header_t) == 64, xsave_header_t);

typedef struct
{
    xsave_legacy_region_t legacy_region;
    xsave_header_t xsave_header;
    uint8_t extended_region[11712];
} xsave_area_t;
tdx_static_assert(sizeof(xsave_area_t) == 0x3000, xsave_area_t);

typedef struct
{
    uint64_t from_ip;
    uint64_t to_ip;
    uint64_t info;
} xsave_lbr_entry_t;

typedef struct
{
    uint64_t  lbr_ctl;
    uint64_t  lbr_depth;
    uint64_t  lbr_tos;
    xsave_lbr_entry_t   ler;
    xsave_lbr_entry_t   lbr[32];
} xsave_lbr_t;

/**
 * Exception Handling - Interrupt information vectors
 */
//Following definitions reflect values of structure vmx_entry_inter_info_t
#define DF_INTERRUPTION_INFO            0x80000B08ULL //Vector=E_DF, Interruption_type=HARDWARE, Deliver error code = True
#define PF_INTERRUPTION_INFO            0x80000B0EULL //Vector=E_PF, Interruption_type=HARDWARE, Deliver error code = True
#define GP_INTERRUPTION_INFO            0x80000B0DULL //Vector=E_GP, Interruption_type=HARDWARE, Deliver error code = True
#define VE_INTERRUPTION_INFO            0x80000314ULL //Vector=E_VE, Interruption_type=HARDWARE
#define UD_INTERRUPTION_INFO            0x80000306ULL //Vector=E_UD, Interruption_type=HARDWARE

typedef enum
{
    E_DE = 0,
    E_DB = 1,
    E_NMI = 2,
    E_BP = 3,
    E_OF = 4,
    E_BR = 5,
    E_UD = 6,
    E_NM = 7,
    E_DF = 8,
    E_RESERVED1 = 9,
    E_TS = 10,
    E_NP = 11,
    E_SS = 12,
    E_GP = 13,
    E_PF = 14,
    E_RESERVED2 = 15,
    E_MF = 16,
    E_AC = 17,
    E_MC = 18,
    E_XM = 19,
    E_VE = 20,
    E_CP = 21
} exception_t;

typedef union
{
    struct
    {
        uint32_t rsvd :14; // 0-13
        uint32_t max_num_of_lps_sharing_cache :12; // 14-25
        uint32_t rsvd1 :4;
    };
    uint32_t raw;
} cpu_cache_params_t;
tdx_static_assert(sizeof(cpu_cache_params_t) == 4, cpu_cache_params_t);

typedef union loadiwkey_ctl_u
{
    struct
    {
        uint32_t dont_backup_wk : 1;
        uint32_t non_random_wk  : 1;
        uint32_t reserved       : 30;
    };
    uint32_t raw;
} loadiwkey_ctl_t;
tdx_static_assert(sizeof(loadiwkey_ctl_t) == 4, loadiwkey_ctl_t);

/**
 * CPUID definitions
 */
#define CPUID_MAX_INPUT_VAL_LEAF 0
#define CPUID_VER_INFO_LEAF 1

#define CPUID_DET_CACHE_PARAMS_LEAF 4
#define CPUID_DET_CACHE_PARAMS_SUBLEAF 3

#define CPUID_KEYLOCKER_SUPPORT_LEAF 7
#define CPUID_KEYLOCKER_SUPPORT_SUBLEAF 0

#define CPUID_EXT_FEATURES_LEAF 7
#define CPUID_EXT_FEATURES_SUBLEAF  0
#define CPUID_EXT_FEATURES2_SUBLEAF 1

#define CPUID_PERFMON_LEAF              0xA
#define CPUID_PERFMON_MIN_SUPPORTED_VER   5
#define CPUID_PERFMON_EAX_MASK_LOW          0xF
#define CPUID_PERFMON_EAX_MASK_HIGH         0x0
#define CPUID_PERFMON_EAX_EXPECTED_LOW      0x5
#define CPUID_PERFMON_EAX_EXPECTED_HIGH     0x0

#define CPUID_PERFMON_EDX_MASK_LOW          0x0
#define CPUID_PERFMON_EDX_MASK_HIGH         (0x1FULL << 32ULL)
#define CPUID_PERFMON_EDX_EXPECTED_LOW      0x0
#define CPUID_PERFMON_EDX_EXPECTED_HIGH     (MAX_FIXED_CTR << 32ULL)

#define CPUID_MAXPA_EAX_MASK_LOW            0xFF00
#define CPUID_MAXPA_EAX_MASK_HIGH           0x0
#define CPUID_MAXPA_EAX_EXPECTED_LOW_57     0x3900
#define CPUID_MAXPA_EAX_EXPECTED_LOW_48     0x3000
#define CPUID_MAXPA_EAX_EXPECTED_HIGH       0x0

#define CPUID_EXT_STATE_ENUM_LEAF       0xD
#define CPUID_EXT_STATE_ENUM_MAIN_SUBLEAF 0
#define CPUID_EXT_STATE_ENUM_XSAVES_SUBLEAF 1

#define CPUID_TSC_ATTRIBUTES_LEAF       0x15

#define CPUID_KEYLOCKER_ATTRIBUTES_LEAF 0x19

#define CPUID_LBR_CAPABILITIES_LEAF 0x1C

#define CPUID_GET_TOPOLOGY_LEAF 0x1F
#define CPUID_GET_TOPOLOGY_INVALID_SUBLEAF 0

#define CPUID_RESERVED_START 0x40000000
#define CPUID_RESERVED_END   0x4FFFFFFF

#define CPUID_MAX_EXTENDED_VAL_LEAF 0x80000000 // Extended start
#define CPUID_GET_MAX_PA_LEAF 0x80000008
#define CPUID_MAX_PA_BITS BITS(7,0)

#define CPUID_MIN_LAST_CPU_BASE_LEAF     0x1F        // Minimal last value of Intel CPUID range supported by the CPU
#define CPUID_LAST_BASE_LEAF             0x23        // Last value of virtualized Intel CPUID range
#define CPUID_FIRST_EXTENDED_LEAF        0x80000000  // AMD CPUID range first leaf value
#define CPUID_LAST_EXTENDED_LEAF         0x80000008  // AMD CPUID range last leaf value

#define CPUID_WAITPKG_BIT 5
#define CPUID_KEYLOCKER_EN_BIT 23

typedef union
{
    struct
    {
        uint32_t stepping_id        : 4;
        uint32_t model              : 4;
        uint32_t family             : 4;
        uint32_t processor_type     : 2;
        uint32_t rsvd0              : 2;
        uint32_t extende_model_id   : 4;
        uint32_t extended_family_id : 8;
        uint32_t rsvd1              : 4;
    };
    uint32_t raw;
} fms_info_t; //cpuid_01_eax
tdx_static_assert(sizeof(fms_info_t) == 4, fms_info_t);

#define CPUID_S_MASK          0x0000000FULL   // Mask for the Stepping field
#define CPUID_FMS_MASK        0x0FFF0FFFULL   // Mask for the Family/Model/Stepping fields

typedef union
{
    struct
    {
        uint32_t level_number : 8;
        uint32_t level_type   : 8;
        uint32_t rsvd         : 16;
    };
    uint32_t raw;
} cpuid_topology_level_t;  //cpuid_04_03_ecx
tdx_static_assert(sizeof(cpuid_topology_level_t) == 4, cpuid_topology_level_t);

typedef enum
{
    LEVEL_TYPE_INVALID = 0,
    LEVEL_TYPE_SMT     = 1,
    LEVEL_TYPE_CORE    = 2,
    LEVEL_TYPE_MODULE  = 3,
    LEVEL_TYPE_TILE    = 4,
    LEVEL_TYPE_DIE     = 5,
    LEVEL_TYPE_MAX     = 6
} cpuid_topology_level_type_e;

typedef union
{
    struct
    {
        uint32_t shift_count : 5;
        uint32_t rsvd        : 27;
    };
    uint32_t raw;
} cpuid_topology_shift_t;
tdx_static_assert(sizeof(cpuid_topology_shift_t) == 4, cpuid_topology_shift_t);

typedef union cpuid_0a_eax_u
{
    struct
    {
        uint32_t version           : 8; // Bits 7:0
        uint32_t num_gp_counters   : 8; // Bits 15:8
        uint32_t gp_counters_width : 8; // Bits 23:16
        uint32_t num_ebx_flags     : 8; // Bits 31:24
    };
    uint32_t raw;
} cpuid_0a_eax_t;
tdx_static_assert(sizeof(cpuid_0a_eax_t) == 4, cpuid_0a_eax_t);

typedef union cpuid_0a_ecx_u
{
    struct
    {
        uint32_t fc_ditmap     : 4; // Bits 3:0
        uint32_t reserved      : 28;
    };
    uint32_t raw;
} cpuid_0a_ecx_t;
tdx_static_assert(sizeof(cpuid_0a_ecx_t) == 4, cpuid_0a_ecx_t);

typedef union cpuid_0a_edx_u
{
    struct
    {
        uint32_t num_fcs               : 5; // Bits 4:0
        uint32_t fc_width              : 8; // Bits 12:5
        uint32_t reserved_0            : 2;
        uint32_t any_thread_deprecated : 1; // Bit 15
        uint32_t reserved_1            : 8;
        uint32_t bit_vector_length     : 8; // Bits 31:24
    };
    uint32_t raw;
} cpuid_0a_edx_t;
tdx_static_assert(sizeof(cpuid_0a_edx_t) == 4, cpuid_0a_edx_t);

typedef union cpuid_0d_ecx_u
{
    struct
    {
        uint32_t ia32_xss       : 1;   // Bit 0
        uint32_t align_64       : 1;   // Bit 1
        uint32_t xfd_faulting   : 1;   // Bit 2
        uint32_t reserved       : 29;  // Bits 3-31
    };
    uint32_t raw;
} cpuid_0d_ecx_t;
tdx_static_assert(sizeof(cpuid_0d_ecx_t) == 4, cpuid_0d_ecx_t);

typedef union cpuid_19_ecx_u
{
    struct
    {
        uint32_t loadiwk_no_backup : 1;   // Bit 0
        uint32_t iwk_randomization : 1;   // Bit 1
        uint32_t reserved          : 30;  // Bits 31-2

    };
    uint32_t raw;
} cpuid_19_ecx_t;
tdx_static_assert(sizeof(cpuid_19_ecx_t) == 4, cpuid_19_ecx_t);

typedef union
{
    struct
    {
        uint32_t brand_index            : 8;
        uint32_t clflush_line_size      : 8;
        uint32_t maximum_addresable_ids : 8;
        uint32_t initial_apic_id        : 8;
    };
    uint32_t raw;
} cpuid_01_ebx_t;
tdx_static_assert(sizeof(cpuid_01_ebx_t) == 4, cpuid_01_ebx_t);

typedef union
{
    struct
    {
        uint32_t sse3 : 1;
        uint32_t pclmulqdq : 1;
        uint32_t dtes64 : 1;
        uint32_t monitor : 1;
        uint32_t ds_cpl  : 1;
        uint32_t vmc : 1;
        uint32_t smx : 1;
        uint32_t est : 1;
        uint32_t tm2 : 1;
        uint32_t ssse3 : 1;
        uint32_t cnxt_id     : 1;
        uint32_t sdbg : 1;
        uint32_t fma : 1;
        uint32_t cmpxchg16b : 1;
        uint32_t xtpr_update_control : 1;
        uint32_t pdcm : 1;
        uint32_t reserved_16 : 1;
        uint32_t pcid : 1;
        uint32_t dca : 1;
        uint32_t sse4_1 : 1;
        uint32_t sse4_2 : 1;
        uint32_t x2apic : 1;
        uint32_t movbe : 1;
        uint32_t popcnt : 1;
        uint32_t tsc_deadline    : 1;
        uint32_t aesni : 1;
        uint32_t xsave : 1;
        uint32_t osxsave : 1;
        uint32_t avx : 1;
        uint32_t f16c : 1;
        uint32_t rdrand : 1;
        uint32_t reserved_31 : 1;
    };
    uint32_t raw;
} cpuid_01_ecx_t;
tdx_static_assert(sizeof(cpuid_01_ecx_t) == 4, cpuid_01_ecx_t);

typedef union
{
    struct
    {
        uint32_t xsaveopt_support                : 1;
        uint32_t xsavec_support                  : 1;
        uint32_t xgetbv_1_support                : 1;
        uint32_t xsaves_xrstors_ia32_xss_support : 1;
        uint32_t xfd_support                     : 1;
        uint32_t reserved                        : 27;
    };
    uint32_t raw;
} cpuid_0d_01_eax_t;
tdx_static_assert(sizeof(cpuid_0d_01_eax_t) == 4, cpuid_0d_01_eax_t);

typedef union cpuid_07_00_ebx_u
{
    struct
    {
        uint32_t fsgsbase         : 1;   // Bit 0
        uint32_t ia32_tsc_adjust  : 1;   // Bit 1
        uint32_t sgx              : 1;   // Bit 2
        uint32_t bmi1             : 1;   // Bit 3
        uint32_t hle              : 1;   // Bit 4
        uint32_t avx2             : 1;   // Bit 5
        uint32_t fdp_excptn_only  : 1;   // Bit 6
        uint32_t smep             : 1;   // Bit 7
        uint32_t bmi2             : 1;   // Bit 8
        uint32_t enh_rep_movsb    : 1;   // Bit 9
        uint32_t invpcid          : 1;   // Bit 10
        uint32_t rtm              : 1;   // Bit 11
        uint32_t rdt_m            : 1;   // Bit 12
        uint32_t dep_fcu_cs_ds    : 1;   // Bit 13
        uint32_t mpx              : 1;   // Bit 14
        uint32_t rdt_a            : 1;   // Bit 15
        uint32_t avx512f          : 1;   // Bit 16
        uint32_t avx512dq         : 1;   // Bit 17
        uint32_t rdseed           : 1;   // Bit 18
        uint32_t adx              : 1;   // Bit 19
        uint32_t smap             : 1;   // Bit 20
        uint32_t avx512_ifma      : 1;   // Bit 21
        uint32_t reserved         : 1;   // Bit 22
        uint32_t clflushopt       : 1;   // Bit 23
        uint32_t clwb             : 1;   // Bit 24
        uint32_t pt               : 1;   // Bit 25
        uint32_t avx512pf         : 1;   // Bit 26
        uint32_t avx512er         : 1;   // Bit 27
        uint32_t avx512cd         : 1;   // Bit 28
        uint32_t sha              : 1;   // Bit 29
        uint32_t avx512bw         : 1;   // Bit 30
        uint32_t avx512vl         : 1;   // Bit 31
    };
    uint32_t raw;
} cpuid_07_00_ebx_t;
tdx_static_assert(sizeof(cpuid_07_00_ebx_t) == 4, cpuid_07_00_ebx_t);

typedef union cpuid_07_00_ecx_u
{
    struct
    {
        uint32_t prefetchwt1        : 1;   // Bit 0
        uint32_t avx512vmbi         : 1;   // Bit 1
        uint32_t umip               : 1;   // Bit 2
        uint32_t pku                : 1;   // Bit 3
        uint32_t ospke              : 1;   // Bit 4
        uint32_t waitpkg            : 1;   // Bit 5
        uint32_t vmbi2              : 1;   // Bit 6
        uint32_t cet_ss             : 1;   // Bit 7
        uint32_t gfni               : 1;   // Bit 8
        uint32_t vaes               : 1;   // Bit 9
        uint32_t vpclmulqdq         : 1;   // Bit 10
        uint32_t vnni               : 1;   // Bit 11
        uint32_t bitalg_support     : 1;   // Bit 12
        uint32_t tme                : 1;   // Bit 13
        uint32_t dfma_for_avx512    : 1;   // Bit 14
        uint32_t fzm                : 1;   // Bit 15
        uint32_t la57               : 1;   // Bit 16
        uint32_t mawau_for_mpx      : 5;   // Bits 17-21
        uint32_t rdpid              : 1;   // Bit 22
        uint32_t kl_supported       : 1;   // Bit 23
        uint32_t buslock            : 1;   // Bit 24
        uint32_t cldemote           : 1;   // Bit 25
        uint32_t mprr               : 1;   // Bit 26
        uint32_t movdiri            : 1;   // Bit 27
        uint32_t movidr64b          : 1;   // Bit 28
        uint32_t enqstr             : 1;   // Bit 29
        uint32_t sgxle              : 1;   // Bit 30
        uint32_t pks                : 1;   // Bit 31
    };
    uint32_t raw;
} cpuid_07_00_ecx_t;
tdx_static_assert(sizeof(cpuid_07_00_ecx_t) == 4, cpuid_07_00_ecx_t);


typedef union cpuid_07_00_edx_u
{
    struct
    {
        uint32_t sgx_tem                            : 1;   // Bit 0
        uint32_t sgx_keys                           : 1;   // Bit 1
        uint32_t avx512_4vnniw                      : 1;   // Bit 2
        uint32_t avx512_4fmaps                      : 1;   // Bit 3
        uint32_t fast_short_rep_mov                 : 1;   // Bit 4
        uint32_t uli_unit                           : 1;   // Bit 5
        uint32_t reserved0                          : 2;   // Bits 6-7
        uint32_t avx512_vp2intersect                : 1;   // Bit 8
        uint32_t reserved2                          : 5;   // Bits 9-13
        uint32_t serialize_inst                     : 1;   // Bit 14
        uint32_t hetero_part                        : 1;   // Bit 15
        uint32_t hle_suspend                        : 1;   // Bit 16
        uint32_t reserved3                          : 1;   // Bit 17
        uint32_t pconfig_mktme                      : 1;   // Bit 18
        uint32_t architectrual_lbr_support           : 1;   // Bit 19
        uint32_t cet                                : 1;   // Bit 20
        uint32_t reserved4                          : 1;   // Bit 21
        uint32_t tmul_amx_bf16                      : 1;   // Bit 22
        uint32_t reserved5                          : 1;   // Bit 23
        uint32_t tmul_amx_tile                      : 1;   // Bit 24
        uint32_t tmul_amx_int8                      : 1;   // Bit 25
        uint32_t ibrs_support                       : 1;   // Bit 26
        uint32_t stibp_support                      : 1;   // Bit 27
        uint32_t lid_flush_ia32_flush_cmd_support   : 1;   // Bit 28
        uint32_t ia32_arch_capabilities_support     : 1;   // Bit 29
        uint32_t ia32_core_capabilities_present     : 1;   // Bit 30
        uint32_t ssbd_support                       : 1;   // Bit 31
    };
    uint32_t raw;
} cpuid_07_00_edx_t;
tdx_static_assert(sizeof(cpuid_07_00_edx_t) == 4, cpuid_07_00_edx_t);

typedef union cpuid_07_01_eax_u
{
    struct
    {
        uint32_t unspecified_5_0   : 6;
        uint32_t lass              : 1; // Bit 6
        uint32_t unspecified_7     : 1;
        uint32_t perfmon_ext_leaf  : 1; // Bit 8
        uint32_t unspecified_25_9  : 17;
        uint32_t lam               : 1;  // Bit 26
        uint32_t unspecified_31_27 : 5;
    };
    uint32_t raw;
} cpuid_07_01_eax_t;
tdx_static_assert(sizeof(cpuid_07_01_eax_t) == 4, cpuid_07_01_eax_t);

typedef union cpuid_07_02_edx_u
{
    struct
    {
        uint32_t psfd          : 1;   // Bit 0
        uint32_t ipred_ctrl    : 1;   // Bit 1
        uint32_t rrsba_ctrl    : 1;   // Bit 2
        uint32_t ddpd          : 1;   // Bit 3
        uint32_t bhi_ctrl      : 1;   // Bit 4
        uint32_t mcdt_no       : 1;   // Bit 5
        uint32_t reserved_0    : 26;  // Bits 31:6
    };
    uint32_t raw;
} cpuid_07_02_edx_t;
tdx_static_assert(sizeof(cpuid_07_02_edx_t) == 4, cpuid_07_02_edx_t);

typedef union cpuid_80000001_edx_u
{
    struct
    {
        uint32_t reserved_0     : 11;   // Bits 10:0
        uint32_t syscall_sysret : 1;   // Bit 12
        uint32_t reserved_1     : 8;   // Bits 19:12
        uint32_t xd             : 1;   // Bit 20
        uint32_t reserved_2     : 5;   // Bits 25:21
        uint32_t huge_page      : 1;   // Bit 26
        uint32_t rdtscp_tsx_aux : 1;   // Bit 27
        uint32_t reserved_3     : 1;   // Bit 28
        uint32_t intel64        : 1;   // Bit 29
        uint32_t reserved_4     : 2;   // Bits 31:30
    };
    uint32_t raw;
} cpuid_80000001_edx_t;

#define LA57_LINEAR_ADDRESS_WIDTH           57
#define LEGACY_LINEAR_ADDRESS_WIDTH         48

typedef union cpuid_80000008_eax_u
{
    struct
    {
        uint32_t pa_bits  : 8;
        uint32_t la_bits  : 8;
        uint32_t reserved : 16;
    };
    uint32_t raw;
} cpuid_80000008_eax_t;

typedef union
{
    struct
    {
        uint64_t l0          : 1; // Bit 0
        uint64_t g0          : 1; // Bit 1
        uint64_t l1          : 1; // Bit 2
        uint64_t g1          : 1; // Bit 3
        uint64_t l2          : 1; // Bit 4
        uint64_t g2          : 1; // Bit 5
        uint64_t l3          : 1; // Bit 6
        uint64_t g3          : 1; // Bit 7
        uint64_t le          : 1; // Bit 8
        uint64_t ge          : 1; // Bit 9
        uint64_t rsvd_0      : 3; // Bits 10-12
        uint64_t gd          : 1; // Bit 13
        uint64_t rsvd_1      : 2; // Bits 14-15
        uint64_t rw0         : 2; // Bits 16-17
        uint64_t ln0         : 2; // Bits 18-19
        uint64_t rw1         : 2; // Bits 20-21
        uint64_t ln1         : 2; // Bits 22-23
        uint64_t rw2         : 2; // Bits 24-25
        uint64_t ln2         : 2; // Bits 26-27
        uint64_t rw3         : 2; // Bits 28-29
        uint64_t ln3         : 2; // Bits 30-31
        uint64_t rsvd_2      : 32;// Bits 32-63
    };
    uint64_t raw;
} dr7_t;

typedef enum apic_destination_shorthand_e
{
    DEST_SHORTHAND_NONE  = 0,
    DEST_SHORTHAND_SELF  = 1,
    DEST_SHORTHAND_ALL   = 2,
    DEST_SHORTHAND_OTHER = 3
} apic_destination_shorthand_t;

typedef enum apic_delivery_mode_e
{
    APIC_DELIVERY_FIXED      = 0,
    APIC_DELIVERY_LOWPRIO    = 1,
    APIC_DELIVERY_SMI        = 2,
    APIC_DELIVERY_NMI        = 4,
    APIC_DELIVERY_INIT       = 5,
    APIC_DELIVERY_SIPI       = 6
} apic_delivery_mode_t;

typedef union ia32_apic_base_u
{
    struct
    {
        uint64_t rsvd0            : 8;  // 0:7
        uint64_t bsp              : 1;  // 8
        uint64_t rsvd1            : 1;  // 9
        uint64_t extd             : 1;  // 10
        uint64_t enable           : 1;  // 11
        uint64_t apic_base        : 40; // 12:51
        uint64_t rsvd2            : 12; // 52:63
    };
    uint64_t raw;
    struct
    {
        uint32_t raw_low;
        uint32_t raw_high;
    };
} ia32_apic_base_t;

typedef union ia32_xapic_id_u
{
    struct
    {
        uint32_t rsvd0            : 24; // 0:23
        uint32_t apic_id          : 8;  // 24:31
    };

    uint32_t raw;
} ia32_xapic_id_t;
tdx_static_assert(sizeof(ia32_xapic_id_t) == 4, ia32_xapic_id_t);

typedef union ia32_apic_icr_u
{
    struct
    {
        struct
        {
            uint32_t vector           : 8;  // 0:7
            uint32_t delivery_mode    : 3;  // 8:10
            uint32_t destination_mode : 1;  // 11
            uint32_t delivery_status  : 1;  // 12
            uint32_t rsvd0            : 1;  // 13
            uint32_t level            : 1;  // 14
            uint32_t trigger_mode     : 1;  // 15
            uint32_t rsvd1            : 2;  // 16:17
            uint32_t dest_shorthand   : 2;  // 18:19
            uint32_t rsvd2            : 12; // 20:31
        };

        union
        {
            uint32_t x2apic_dest_field;     // 32:63

            struct
            {
                uint32_t rsvd3            : 24; // 32:55
                uint32_t xapic_dest_field : 8;  // 56:63
            };
        };
    };
    uint64_t raw;
    struct
    {
        uint32_t raw_low;
        uint32_t raw_high;
    };
} ia32_apic_icr_t;
tdx_static_assert(sizeof(ia32_apic_icr_t) == 8, ia32_apic_icr_t);

typedef union ia32_apic_register_u
{
    struct
    {
        volatile uint32_t value;
        volatile uint32_t reserved[3];
    };

    volatile uint64_t raw[2];
} ia32_apic_register_t;
tdx_static_assert(sizeof(ia32_apic_register_t) == 4*4, ia32_apic_register_t);

#define APIC_MMIO_APICID_OFFSET         0x020
#define APIC_MMIO_PPR_OFFSET            0x0A0
#define APIC_MMIO_ISR_OFFSET            0x100
#define APIC_MMIO_IRR_OFFSET            0x200
#define APIC_MMIO_ICR_LOW_OFFSET        0x300
#define APIC_MMIO_ICR_HIGH_OFFSET       0x310
#define APIC_MMIO_EOI_OFFSET            0x0B0

#define APIC_IRR_ISR_SIZE               8

#define POLY_MASK_32 0xB4BCD35C

#define HW_EXCEPTION       3

#endif /* SRC_COMMON_X86_DEFS_X86_DEFS_H_ */
