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
 * @file vtbar_defs.h
 * @brief
 */

#ifndef DEVIFMT_DEFS_H_
#define DEVIFMT_DEFS_H_

#include "tdx_basic_types.h"
#include "tdisp_defs.h"
#include "memory_handlers/pamt_manager.h"

typedef enum
{
	DEVIFMT_L0 		= 0,
	DEVIFMT_L1 		= 1,
	DEVIFMT_L2 		= 2,
	DEVIFMT_L3 		= 3,
	DEVIFMT_ROOT_L 	= 4
} devif_mt_lvl_e;
typedef uint8_t devif_mt_lvl_t;

#pragma pack(push, 1)

typedef union
{
	struct
	{
		uint32_t level 		: 3; 	// Level: DEVIFMT_LEVEL
		uint32_t reserved 	: 29; 	// Reserved, must be 0
		union
		{
			fucntion_id_t function_id; // FUNCTION_ID
			struct
			{
				uint32_t l0_idx 	: 9;
				uint32_t l1_idx 	: 9;
				uint32_t l2_idx 	: 9;
				uint32_t l3_idx 	: 5;
			};
		};
	};
	uint64_t raw;
} devifmt_idx_t;
tdx_static_assert(sizeof(devifmt_idx_t) == 8, devifmt_idx_t);

#define DEVIFMT_COUNT_PER_PAGE (TDX_PAGE_SIZE_IN_BYTES / sizeof(devifmt_entry_t))

#define DEVIFMT_LOCK_BIT_IDX (1U)
#define DEVIFMT_HP_BIT_IDX (2U)
typedef union
{
	struct
	{
		uint64_t p 		: 1; // Present bit
		uint64_t lock	: 1; // Exclusive Lock bit
		uint64_t hp	    : 1; // Host priority lock
		uint64_t rsvd1 	: 9; // Reserved, must be 0
		uint64_t pa 	: 40; // HPA pointer to DEVIFMT child or DEVIFCS root page
		uint64_t rsvd2 	: 12; // Reserved, must be 0
	};
	uint64_t raw;
} devifmt_entry_t;
tdx_static_assert(sizeof(devifmt_entry_t) == 8, devifmt_entry_t);

#define DEVIFMT_HP_LOCK_MODE    (false)
#define DEVIFMT_GUEST_LOCK_MODE (true)

#pragma pack(pop)

typedef struct
{
	devifmt_idx_t devifmt_idx;							   // See devifmt_idx_t
	bool_t is_entry_locked;								   // Indicating if the last entry visited is locked
	devifmt_entry_t *devifmt_path_arr[DEVIFMT_ROOT_L + 1]; // Array of pointers to all DEVIFMT entries visited per DEVIFMT walk
	pamt_entry_t *pamt_path_arr[DEVIFMT_ROOT_L];		   // Array of pointers to PAMT entries visited and locked per DEVIFMT walk
	pamt_block_t pamt_block_arr[DEVIFMT_ROOT_L];		   // Array of PAMT blocks visited per DEVIFMT walk
} devifmt_walk_res_t;

#endif // DEVIFMT_DEFS_H_
