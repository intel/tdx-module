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

# src_defs.mk - Sources, targets definitions and locations


# Makefile location - which is the project root dir
MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
__PROJ_DIR := $(dir $(MAKEFILE_PATH))
# Remove the trailing slash '/' at the end of the directory string
PROJ_DIR := $(patsubst %/,%,$(__PROJ_DIR))

# Binary output location and name
RELEASE_DIR := $(PROJ_DIR)/bin/release
DEBUG_DIR := $(PROJ_DIR)/bin/debug
TARGET_NAME := libtdx.so
RELEASE_TARGET := $(RELEASE_DIR)/$(TARGET_NAME)
DEBUG_TARGET := $(DEBUG_DIR)/$(TARGET_NAME)
OBJ_DIR_NAME := obj


# Source directories
SRC_DIRS := include include/auto_gen src/common src/common/accessors src/common/crypto \
			src/common/data_structures src/common/debug src/common/helpers src/common/memory_handlers \
			src/common/metadata_handlers src/common/x86_defs src/td_dispatcher src/td_dispatcher/vm_exits \
			src/td_transitions src/vmm_dispatcher src/vmm_dispatcher/api_calls \
			src/common/exception_handling src/td_dispatcher/vm_exits_l2 \
			src/vmm_dispatcher/migration_api_calls

SRC_DIRS := $(foreach dir,$(SRC_DIRS),$(PROJ_DIR)/$(dir))


VPATH := $(SRC_DIRS)

# Source and headers files
C_SRC_FILES = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
ASM_SRC_FILES = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.S))
SRC_FILES = $(C_SRC_FILES) $(ASM_SRC_FILES)
HEADER_FILES = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.h))

# Objects
__C_OBJECTS = $(patsubst %.c, %.o, $(notdir $(C_SRC_FILES)))
__ASM_OBJECTS = $(patsubst %.S, %.o, $(notdir $(ASM_SRC_FILES)))

# Libraries
CRYPTO_LIB_BUILD_FLAVOR := RELEASE
ifndef CRYPTO_LIB_VERSION
CRYPTO_LIB_VERSION      := 2021.7.1
endif
CRYPTO_LIB_MAIN_DIR     := $(PROJ_DIR)/libs/ipp/ipp-crypto-ippcp_$(CRYPTO_LIB_VERSION)
CRYPTO_LIB_SRC_DIR      := $(CRYPTO_LIB_MAIN_DIR)/sources
CRYPTO_LIB_BUILD_PATH   := $(CRYPTO_LIB_MAIN_DIR)/_build/.build/$(CRYPTO_LIB_BUILD_FLAVOR)
CRYPTO_LIB_PATH         := $(CRYPTO_LIB_BUILD_PATH)/lib
CRYPTO_LIB_FILENAME     := libippcp_s_y8.a
CRYPTO_LIB              := -lippcp_s_y8


# Headers include path
INCLUDE_PATH := -I$(PROJ_DIR)/include -I$(CRYPTO_LIB_BUILD_PATH)/include -I$(PROJ_DIR)/src -I$(PROJ_DIR)/src/common

# Tools
TOOLS_DIR := $(PROJ_DIR)/tools
PAD_BINARY_PY := $(TOOLS_DIR)/pad_binary/pad_binary.py

#Python scripts
SCRIPT := $(PROJ_DIR)/tools/tdx_auto_gen_headers/tdx_gen_headers.py
ARCHITECTURE_FILES_PATH = $(PROJ_DIR)/tools/tdx_auto_gen_headers/architecture_files
AUTO_GEN_PATH := $(PROJ_DIR)/include/auto_gen
ARCHITECTURE_REPOSITORY_CLONE_PATH = $(PROJ_DIR)/tdx-flow-code
