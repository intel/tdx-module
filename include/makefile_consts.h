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

#ifndef _MAKEFILE_CONSTS_H_
#define _MAKEFILE_CONSTS_H_

#include "tdx_basic_types.h"

/**
 * @brief The Makefile defines below were extracted to an external header file in order to prevent the generated binary from having scattered delta values in
 *          non-relevant sections.
 */
extern const uint64_t GLOBAL_TDX_MODULE_BUILD_NUM;
extern const uint64_t GLOBAL_TDX_MODULE_INTERNAL_VER;
extern const uint64_t GLOBAL_TDX_MODULE_BUILD_DATE;
extern const uint8_t GLOBAL_TDX_MINOR_SEAM_SVN;
extern const uint64_t GLOBAL_TDX_MODULE_MAJOR_VER;
extern const uint64_t GLOBAL_TDX_MODULE_MINOR_VER;
extern const uint64_t GLOBAL_TDX_MODULE_UPDATE_VER;
extern const uint64_t GLOBAL_TDX_MODULE_HV;
extern const uint64_t GLOBAL_TDX_MIN_UPDATE_HV;
extern const uint64_t GLOBAL_TDX_NO_DOWNGRADE;

#endif // _MAKEFILE_CONSTS_H_
