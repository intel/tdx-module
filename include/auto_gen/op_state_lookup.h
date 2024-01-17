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
 *  This File is Automatically generated by the TDX xls extract tool
 *  based on architecture commit id "5c1d21c9" 
 *  Spreadsheet Format Version - '2'
 **/

#ifndef _AUTO_GEN_OP_STATE_LOOKUP_H_
#define _AUTO_GEN_OP_STATE_LOOKUP_H_



#include "tdx_api_defs.h"



#define MAX_SEAMCALL_LEAF 128
#define MAX_TDCALL_LEAF 32
#define NUM_OP_STATES 11


typedef enum
{
    OP_STATE_UNINITIALIZED = 0,
    OP_STATE_INITIALIZED = 1,
    OP_STATE_RUNNABLE = 2,
    OP_STATE_LIVE_EXPORT = 3,
    OP_STATE_PAUSED_EXPORT = 4,
    OP_STATE_POST_EXPORT = 5,
    OP_STATE_MEMORY_IMPORT = 6,
    OP_STATE_STATE_IMPORT = 7,
    OP_STATE_POST_IMPORT = 8,
    OP_STATE_LIVE_IMPORT = 9,
    OP_STATE_FAILED_IMPORT = 10
} op_state_e;

typedef struct state_flags_s
{
    bool_t tlb_tracking_required;
    bool_t any_initialized;
    bool_t any_finalized;
    bool_t export_in_order;
    bool_t import_in_order;
    bool_t import_out_of_order;
    bool_t import_in_progress;
} state_flags_t;


extern const bool_t seamcall_state_lookup[MAX_SEAMCALL_LEAF][NUM_OP_STATES];

extern const bool_t servtd_bind_othertd_state_lookup[NUM_OP_STATES];

extern const bool_t tdcall_state_lookup[MAX_TDCALL_LEAF][NUM_OP_STATES];

extern const state_flags_t state_flags_lookup[NUM_OP_STATES];

#endif /* _AUTO_GEN_OP_STATE_LOOKUP_H_ */
