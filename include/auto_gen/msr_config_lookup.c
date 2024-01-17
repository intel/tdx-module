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
 *  Spreadsheet Format Version - '6'
 **/

#include "auto_gen/msr_config_lookup.h"


const msr_lookup_t msr_lookup[MAX_NUM_MSR_LOOKUP] = {

 {
  // 0 - IA32_TIME_STAMP_COUNTER 
  .start_address  = 0x10, .end_address = 0x10,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_VE 
 },
 {
  // 1 - IA32_SPEC_CTRL 
  .start_address  = 0x48, .end_address = 0x48,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 2 - IA32_PRED_CMD 
  .start_address  = 0x49, .end_address = 0x49,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 3 - IA32_MKTME_PARTITIONING 
  .start_address  = 0x87, .end_address = 0x87,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 4 - IA32_SGXLEPUBKEYHASHx 
  .start_address  = 0x8c, .end_address = 0x8f,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 5 - MSR_WBINVDP 
  .start_address  = 0x98, .end_address = 0x98,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 6 - MSR_WBNOINVDP 
  .start_address  = 0x99, .end_address = 0x99,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 7 - MSR_INTR_PENDING 
  .start_address  = 0x9a, .end_address = 0x9a,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 8 - IA32_SMM_MONITOR_CTL 
  .start_address  = 0x9b, .end_address = 0x9b,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 9 - IA32_SMBASE 
  .start_address  = 0x9e, .end_address = 0x9e,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 10 - IA32_MISC_PACKAGE_CTLS 
  .start_address  = 0xbc, .end_address = 0xbc,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_VE 
 },
 {
  // 11 - IA32_XAPIC_DISABLE_STATUS 
  .start_address  = 0xbd, .end_address = 0xbd,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 12 - IA32_PMCx 
  .start_address  = 0xc1, .end_address = 0xc8,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 13 - IA32_UMWAIT_CONTROL 
  .start_address  = 0xe1, .end_address = 0xe1,
  .rd_bit_meaning = MSR_BITMAP_DYN_UMWAIT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_UMWAIT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 14 - IA32_ARCH_CAPABILITIES 
  .start_address  = 0x10a, .end_address = 0x10a,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 15 - IA32_FLUSH_CMD 
  .start_address  = 0x10b, .end_address = 0x10b,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 16 - IA32_TSX_CTRL 
  .start_address  = 0x122, .end_address = 0x122,
  .rd_bit_meaning = MSR_BITMAP_DYN_TSX, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_TSX, .wr_action = MSR_ACTION_GP 
 },
 {
  // 17 - IA32_SYSENTER_CS 
  .start_address  = 0x174, .end_address = 0x174,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 18 - IA32_SYSENTER_ESP 
  .start_address  = 0x175, .end_address = 0x175,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 19 - IA32_SYSENTER_EIP 
  .start_address  = 0x176, .end_address = 0x176,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 20 - IA32_PERFEVTSELx 
  .start_address  = 0x186, .end_address = 0x18d,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 21 - IA32_OVERCLOCKING_STATUS 
  .start_address  = 0x195, .end_address = 0x195,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 22 - IA32_MISC_ENABLE 
  .start_address  = 0x1a0, .end_address = 0x1a0,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_VE 
 },
 {
  // 23 - MSR_OFFCORE_RSPx 
  .start_address  = 0x1a6, .end_address = 0x1a7,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 24 - IA32_XFD 
  .start_address  = 0x1c4, .end_address = 0x1c4,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFD, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFD, .wr_action = MSR_ACTION_GP 
 },
 {
  // 25 - IA32_XFD_ERR 
  .start_address  = 0x1c5, .end_address = 0x1c5,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFD, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFD, .wr_action = MSR_ACTION_GP 
 },
 {
  // 26 - IA32_DEBUGCTL 
  .start_address  = 0x1d9, .end_address = 0x1d9,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_OTHER 
 },
 {
  // 27 - IA32_PLATFORM_DCA_CAP 
  .start_address  = 0x1f8, .end_address = 0x1f8,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 28 - IA32_CPU_DCA_CAP 
  .start_address  = 0x1f9, .end_address = 0x1f9,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 29 - IA32_DCA_0_CAP 
  .start_address  = 0x1fa, .end_address = 0x1fa,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 30 - MSR_SLAM_ENABLE 
  .start_address  = 0x276, .end_address = 0x276,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 31 - IA32_PAT 
  .start_address  = 0x277, .end_address = 0x277,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 32 - IA32_FIXED_CTRx 
  .start_address  = 0x309, .end_address = 0x310,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 33 - IA32_PERF_METRICS 
  .start_address  = 0x329, .end_address = 0x329,
  .rd_bit_meaning = MSR_BITMAP_DYN_OTHER, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_OTHER, .wr_action = MSR_ACTION_GP 
 },
 {
  // 34 - IA32_PERF_CAPABILITIES 
  .start_address  = 0x345, .end_address = 0x345,
  .rd_bit_meaning = MSR_BITMAP_DYN_OTHER, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 35 - IA32_FIXED_CTR_CTRL 
  .start_address  = 0x38d, .end_address = 0x38d,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 36 - IA32_PERF_GLOBAL_STATUS 
  .start_address  = 0x38e, .end_address = 0x38e,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 37 - IA32_PERF_GLOBAL_CTRL 
  .start_address  = 0x38f, .end_address = 0x38f,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 38 - IA32_PERF_GLOBAL_STATUS_RESET 
  .start_address  = 0x390, .end_address = 0x390,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 39 - IA32_PERF_GLOBAL_STATUS_SET 
  .start_address  = 0x391, .end_address = 0x391,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 40 - IA32_PERF_GLOBAL_INUSE 
  .start_address  = 0x392, .end_address = 0x392,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 41 - IA32_PEBS_ENABLE 
  .start_address  = 0x3f1, .end_address = 0x3f1,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 42 - MSR_PEBS_MATRIX_VECT 
  .start_address  = 0x3f2, .end_address = 0x3f2,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 43 - MSR_PEBS_LD_LATENCY 
  .start_address  = 0x3f6, .end_address = 0x3f6,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 44 - MSR_PEBS_FRONTEND 
  .start_address  = 0x3f7, .end_address = 0x3f7,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 45 - IA32_VMX_BASIC 
  .start_address  = 0x480, .end_address = 0x480,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 46 - IA32_VMX_PINBASED_CTLS 
  .start_address  = 0x481, .end_address = 0x481,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 47 - IA32_VMX_PROCBASED_CTLS 
  .start_address  = 0x482, .end_address = 0x482,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 48 - IA32_VMX_EXIT_CTLS 
  .start_address  = 0x483, .end_address = 0x483,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 49 - IA32_VMX_ENTRY_CTLS 
  .start_address  = 0x484, .end_address = 0x484,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 50 - IA32_VMX_MISC 
  .start_address  = 0x485, .end_address = 0x485,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 51 - IA32_VMX_CR0_FIXED0 
  .start_address  = 0x486, .end_address = 0x486,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 52 - IA32_VMX_CR0_FIXED1 
  .start_address  = 0x487, .end_address = 0x487,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 53 - IA32_VMX_CR4_FIXED0 
  .start_address  = 0x488, .end_address = 0x488,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 54 - IA32_VMX_CR4_FIXED1 
  .start_address  = 0x489, .end_address = 0x489,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 55 - IA32_VMX_VMCS_ENUM 
  .start_address  = 0x48a, .end_address = 0x48a,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 56 - IA32_VMX_PROCBASED_CTLS2 
  .start_address  = 0x48b, .end_address = 0x48b,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 57 - IA32_VMX_EPT_VPID_CAP 
  .start_address  = 0x48c, .end_address = 0x48c,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 58 - IA32_VMX_TRUE_PINBASED_CTLS 
  .start_address  = 0x48d, .end_address = 0x48d,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 59 - IA32_VMX_TRUE_PROCBASED_CTLS 
  .start_address  = 0x48e, .end_address = 0x48e,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 60 - IA32_VMX_TRUE_EXIT_CTLS 
  .start_address  = 0x48f, .end_address = 0x48f,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 61 - IA32_VMX_TRUE_ENTRY_CTLS 
  .start_address  = 0x490, .end_address = 0x490,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 62 - IA32_VMX_VMFUNC 
  .start_address  = 0x491, .end_address = 0x491,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 63 - IA32_VMX_PROCBASED_CTLS3 
  .start_address  = 0x492, .end_address = 0x492,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_OTHER,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 64 - IA32_A_PMCx 
  .start_address  = 0x4c1, .end_address = 0x4c8,
  .rd_bit_meaning = MSR_BITMAP_DYN_PERFMON, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PERFMON, .wr_action = MSR_ACTION_GP 
 },
 {
  // 65 - IA32_SGX_SVN_STATUS 
  .start_address  = 0x500, .end_address = 0x500,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 66 - IA32_RTIT_OUTPUT_BASE 
  .start_address  = 0x560, .end_address = 0x560,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 67 - IA32_RTIT_OUTPUT_MASK_PTRS 
  .start_address  = 0x561, .end_address = 0x561,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 68 - IA32_RTIT_CTL 
  .start_address  = 0x570, .end_address = 0x570,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 69 - IA32_RTIT_STATUS 
  .start_address  = 0x571, .end_address = 0x571,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 70 - IA32_RTIT_CR3_MATCH 
  .start_address  = 0x572, .end_address = 0x572,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 71 - IA32_RTIT_ADDR0_A 
  .start_address  = 0x580, .end_address = 0x580,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 72 - IA32_RTIT_ADDR0_B 
  .start_address  = 0x581, .end_address = 0x581,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 73 - IA32_RTIT_ADDR1_A 
  .start_address  = 0x582, .end_address = 0x582,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 74 - IA32_RTIT_ADDR1_B 
  .start_address  = 0x583, .end_address = 0x583,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 75 - IA32_RTIT_ADDR2_A 
  .start_address  = 0x584, .end_address = 0x584,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 76 - IA32_RTIT_ADDR2_B 
  .start_address  = 0x585, .end_address = 0x585,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 77 - IA32_RTIT_ADDR3_A 
  .start_address  = 0x586, .end_address = 0x586,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 78 - IA32_RTIT_ADDR3_B 
  .start_address  = 0x587, .end_address = 0x587,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_PT, .wr_action = MSR_ACTION_GP 
 },
 {
  // 79 - IA32_DS_AREA 
  .start_address  = 0x600, .end_address = 0x600,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 80 - IA32_U_CET 
  .start_address  = 0x6a0, .end_address = 0x6a0,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .wr_action = MSR_ACTION_GP 
 },
 {
  // 81 - IA32_S_CET 
  .start_address  = 0x6a2, .end_address = 0x6a2,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .wr_action = MSR_ACTION_GP 
 },
 {
  // 82 - IA32_PL0_SSP 
  .start_address  = 0x6a4, .end_address = 0x6a4,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .wr_action = MSR_ACTION_GP 
 },
 {
  // 83 - IA32_PL1_SSP 
  .start_address  = 0x6a5, .end_address = 0x6a5,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .wr_action = MSR_ACTION_GP 
 },
 {
  // 84 - IA32_PL2_SSP 
  .start_address  = 0x6a6, .end_address = 0x6a6,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .wr_action = MSR_ACTION_GP 
 },
 {
  // 85 - IA32_PL3_SSP 
  .start_address  = 0x6a7, .end_address = 0x6a7,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .wr_action = MSR_ACTION_GP 
 },
 {
  // 86 - IA32_INTERRUPT_SSP_TABLE_ADDR 
  .start_address  = 0x6a8, .end_address = 0x6a8,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_CET, .wr_action = MSR_ACTION_GP 
 },
 {
  // 87 - IA32_TSC_DEADLINE 
  .start_address  = 0x6e0, .end_address = 0x6e0,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 88 - IA32_PKRS 
  .start_address  = 0x6e1, .end_address = 0x6e1,
  .rd_bit_meaning = MSR_BITMAP_DYN_PKS, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_PKS, .wr_action = MSR_ACTION_GP 
 },
 {
  // 89 - Reserved for xAPIC MSRs 
  .start_address  = 0x800, .end_address = 0x801,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 90 - Reserved for xAPIC MSRs 
  .start_address  = 0x804, .end_address = 0x807,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 91 - IA32_X2APIC_TPR 
  .start_address  = 0x808, .end_address = 0x808,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 92 - Reserved for xAPIC MSRs 
  .start_address  = 0x809, .end_address = 0x809,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 93 - IA32_X2APIC_PPR 
  .start_address  = 0x80a, .end_address = 0x80a,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 94 - IA32_X2APIC_EOI 
  .start_address  = 0x80b, .end_address = 0x80b,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 95 - Reserved for xAPIC MSRs 
  .start_address  = 0x80c, .end_address = 0x80c,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 96 - Reserved for xAPIC MSRs 
  .start_address  = 0x80e, .end_address = 0x80e,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 97 - IA32_X2APIC_ISRx 
  .start_address  = 0x810, .end_address = 0x817,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 98 - IA32_X2APIC_TMRx 
  .start_address  = 0x818, .end_address = 0x81f,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 99 - IA32_X2APIC_IRRx 
  .start_address  = 0x820, .end_address = 0x827,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 100 - Reserved for xAPIC MSRs 
  .start_address  = 0x829, .end_address = 0x82e,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 101 - Reserved for xAPIC MSRs 
  .start_address  = 0x831, .end_address = 0x831,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 102 - IA32_X2APIC_SELF_IPI 
  .start_address  = 0x83f, .end_address = 0x83f,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 103 - Reserved for xAPIC MSRs 
  .start_address  = 0x840, .end_address = 0x87f,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 104 - Reserved for xAPIC MSRs 
  .start_address  = 0x880, .end_address = 0x8bf,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 105 - Reserved for xAPIC MSRs 
  .start_address  = 0x8c0, .end_address = 0x8ff,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 106 - IA32_TME_CAPABILITY 
  .start_address  = 0x981, .end_address = 0x981,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 107 - IA32_TME_ACTIVATE 
  .start_address  = 0x982, .end_address = 0x982,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 108 - IA32_TME_EXCLUDE_MASK 
  .start_address  = 0x983, .end_address = 0x983,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 109 - IA32_TME_EXCLUDE_BASE 
  .start_address  = 0x984, .end_address = 0x984,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP_OR_VE,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP_OR_VE 
 },
 {
  // 110 - IA32_UINTR_RR 
  .start_address  = 0x985, .end_address = 0x985,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .wr_action = MSR_ACTION_GP 
 },
 {
  // 111 - IA32_UINTR_HANDLER 
  .start_address  = 0x986, .end_address = 0x986,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .wr_action = MSR_ACTION_GP 
 },
 {
  // 112 - IA32_UINTR_STACKADJUST 
  .start_address  = 0x987, .end_address = 0x987,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .wr_action = MSR_ACTION_GP 
 },
 {
  // 113 - IA32_UINTR_MISC 
  .start_address  = 0x988, .end_address = 0x988,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .wr_action = MSR_ACTION_GP 
 },
 {
  // 114 - IA32_UINTR_PD 
  .start_address  = 0x989, .end_address = 0x989,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .wr_action = MSR_ACTION_GP 
 },
 {
  // 115 - IA32_UINTR_TT 
  .start_address  = 0x98a, .end_address = 0x98a,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_ULI, .wr_action = MSR_ACTION_GP 
 },
 {
  // 116 - IA32_DEBUG_INTERFACE 
  .start_address  = 0xc80, .end_address = 0xc80,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_VE 
 },
 {
  // 117 - IA32_BNDCFGS 
  .start_address  = 0xd90, .end_address = 0xd90,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 118 - IA32_PASID 
  .start_address  = 0xd93, .end_address = 0xd93,
  .rd_bit_meaning = MSR_BITMAP_FIXED_1, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_GP 
 },
 {
  // 119 - IA32_XSS 
  .start_address  = 0xda0, .end_address = 0xda0,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_OTHER 
 },
 {
  // 120 - IA32_LBR_INFO 
  .start_address  = 0x1200, .end_address = 0x12ff,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .wr_action = MSR_ACTION_GP 
 },
 {
  // 121 - IA32_LBR_CTL 
  .start_address  = 0x14ce, .end_address = 0x14ce,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .wr_action = MSR_ACTION_GP 
 },
 {
  // 122 - IA32_LBR_DEPTH 
  .start_address  = 0x14cf, .end_address = 0x14cf,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .wr_action = MSR_ACTION_GP 
 },
 {
  // 123 - IA32_LBR_x_FROM_IP 
  .start_address  = 0x1500, .end_address = 0x15ff,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .wr_action = MSR_ACTION_GP 
 },
 {
  // 124 - IA32_LBR_x_TO_IP 
  .start_address  = 0x1600, .end_address = 0x16ff,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFAM_LBR, .wr_action = MSR_ACTION_GP 
 },
 {
  // 125 - IA32_UARCH_MISC_CTL 
  .start_address  = 0x1b01, .end_address = 0x1b01,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 126 - IA32_EFER 
  .start_address  = 0xc0000080, .end_address = 0xc0000080,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_1, .wr_action = MSR_ACTION_OTHER 
 },
 {
  // 127 - IA32_STAR 
  .start_address  = 0xc0000081, .end_address = 0xc0000081,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 128 - IA32_LSTAR 
  .start_address  = 0xc0000082, .end_address = 0xc0000082,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 129 - IA32_FMASK 
  .start_address  = 0xc0000084, .end_address = 0xc0000084,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 130 - IA32_FSBASE 
  .start_address  = 0xc0000100, .end_address = 0xc0000100,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 131 - IA32_GSBASE 
  .start_address  = 0xc0000101, .end_address = 0xc0000101,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 132 - IA32_KERNEL_GS_BASE 
  .start_address  = 0xc0000102, .end_address = 0xc0000102,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 },
 {
  // 133 - IA32_TSC_AUX 
  .start_address  = 0xc0000103, .end_address = 0xc0000103,
  .rd_bit_meaning = MSR_BITMAP_FIXED_0, .rd_action = MSR_ACTION_FATAL_ERROR,
  .wr_bit_meaning = MSR_BITMAP_FIXED_0, .wr_action = MSR_ACTION_FATAL_ERROR 
 }
};

