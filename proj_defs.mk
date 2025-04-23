#// Copyright (C) 2023 Intel Corporation                                          
#//                                                                               
#// Permission is hereby granted, free of charge, to any person obtaining a copy  
#// of this software and associated documentation files (the "Software"),         
#// to deal in the Software without restriction, including without limitation     
#// the rights to use, copy, modify, merge, publish, distribute, sublicense,      
#// and/or sell copies of the Software, and to permit persons to whom             
#// the Software is furnished to do so, subject to the following conditions:      
#//                                                                               
#// The above copyright notice and this permission notice shall be included       
#// in all copies or substantial portions of the Software.                        
#//                                                                               
#// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS       
#// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   
#// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL      
#// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES             
#// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,      
#// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE            
#// OR OTHER DEALINGS IN THE SOFTWARE.                                            
#//                                                                               
#// SPDX-License-Identifier: MIT

# proj_defs.mk - Project related defintions

PROJ_FLAGS =

FAULT_SAFE_MAGIC_INDICATOR=0xFF0F0F0F0F0F0FFF
PROJ_FLAGS += -DFAULT_SAFE_MAGIC_INDICATOR=$(FAULT_SAFE_MAGIC_INDICATOR)

################################################################
## Versioning

ifdef TDX_MODULE_BUILD_DATE
PROJ_FLAGS += -DTDX_MODULE_BUILD_DATE=$(TDX_MODULE_BUILD_DATE)
else
PROJ_FLAGS += -DTDX_MODULE_BUILD_DATE=$(shell date +%Y%m%d)
endif

ifdef TDX_MODULE_BUILD_NUM
PROJ_FLAGS += -DTDX_MODULE_BUILD_NUM=$(TDX_MODULE_BUILD_NUM)
else
PROJ_FLAGS += -DTDX_MODULE_BUILD_NUM=0
endif

ifdef TDX_MODULE_SEAM_SVN
PROJ_FLAGS += -DTDX_MINOR_SEAM_SVN=$(TDX_MODULE_SEAM_SVN)
else
PROJ_FLAGS += -DTDX_MINOR_SEAM_SVN=0
endif

PROJ_FLAGS += -DTDX_MODULE_MAJOR_VER=1
PROJ_FLAGS += -DTDX_MODULE_MINOR_VER=5

ifdef TDX_MODULE_UPDATE_VER
PROJ_FLAGS += -DTDX_MODULE_UPDATE_VER=$(TDX_MODULE_UPDATE_VER)
else
PROJ_FLAGS += -DTDX_MODULE_UPDATE_VER=5
endif

ifdef TDX_MODULE_INTERNAL_VER
PROJ_FLAGS += -DTDX_MODULE_INTERNAL_VER=$(TDX_MODULE_INTERNAL_VER)
else
PROJ_FLAGS += -DTDX_MODULE_INTERNAL_VER=0
endif

################################################################

################################################################
## TDX features

ifdef TDX_MODULE_HV
PROJ_FLAGS += -DTDX_MODULE_HV=$(TDX_MODULE_HV)
else
PROJ_FLAGS += -DTDX_MODULE_HV=0
endif

ifdef TDX_MIN_UPDATE_HV
PROJ_FLAGS += -DTDX_MIN_UPDATE_HV=$(TDX_MIN_UPDATE_HV)
else
PROJ_FLAGS += -DTDX_MIN_UPDATE_HV=0
endif

ifdef TDX_NO_DOWNGRADE
PROJ_FLAGS += -DTDX_NO_DOWNGRADE=$(TDX_NO_DOWNGRADE)
else
PROJ_FLAGS += -DTDX_NO_DOWNGRADE=0
endif

################################################################

################################################################
## Debug features

ifdef DBG_TRACE
PROJ_FLAGS += -DDEBUGFEATURE_TDX_DBG_TRACE
endif

################################################################

################################################################
## Miscelaneous features

PROJ_FLAGS += -D_NO_IPP_DEPRECATED

################################################################

################################################################
## Production-only features

ifdef PRODUCTION_SIGN
ifndef RELEASE
  $(error Cannot create production-signed TDX module in non-RELEASE build)
endif
PRODUCTION_FLAGS = -DPRODUCTION_SIGN
else
PRODUCTION_FLAGS =
endif

################################################################


#Architecture git data
COMMIT_ID = 40ef60d2
ARCHITECTURE_BRANCH_NAME = TDX_Module_1.5.05_v0.89
CPUID_EXCEL_VERSION_SUPPORTED = 7
MSR_EXCEL_VERSION_SUPPORTED = 6
TDVPS_EXCEL_VERSION_SUPPORTED = 27
TDR_TDCS_EXCEL_VERSION_SUPPORTED = 25
TD_VMCS_EXCEL_VERSION_SUPPORTED = 26
GLOBAL_SYS_EXCEL_VERSION_SUPPORTED = 2
ERRORS_VERSION_SUPPORTED = 5
OP_STATE_VERSION_SUPPORTED = 2
SEPT_STATE_VERSION_SUPPORTED = 6
L2_VMCS_VERSION_SUPPORTED = 25
