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
 * @file tdx_debug.h
 * @brief Debug facilities
 */

#ifndef SRC_COMMON_DEBUG_TDX_DEBUG_H_
#define SRC_COMMON_DEBUG_TDX_DEBUG_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"

#ifdef DEBUGFEATURE_TDX_DBG_TRACE

typedef __builtin_va_list va_list;

#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end

/**
 * @enum print_target_e
 *
 * @brief Enum for choosing the trace target
 */
typedef enum
{
    TARGET_TRACE_BUFFER,
    TARGET_SERIAL_PORT,
    TARGET_EXTERNAL_BUFFER
} print_target_e;

#define TRACE_BUFFER_FIRST_MESSAGE  1                // Message at index 0 is used to store additional info
#define TRACE_BUFFER_SIZE           (4 * 1024)       // 4096 messages

#define MAX_PRINT_LENGTH            256

typedef struct print_buffer_info_s
{
    uint64_t last_message_idx;
    uint64_t last_absolute_addr;
    uint64_t total_printed_messages;
} print_buffer_info_t;
tdx_static_assert(sizeof(print_buffer_info_t) <= MAX_PRINT_LENGTH, print_buffer_info_t);

#define PRINT_SEVERITY_LOG          0
#define PRINT_SEVERITY_WARN         1
#define PRINT_SEVERITY_ERROR        2
#define PRINT_SEVERITY_CUSTOM_PRINT 1000
#define PRINT_SEVERITY_MAX          ((uint64_t)-1)

typedef struct debug_message_s {
    char message[MAX_PRINT_LENGTH];
} debug_message_t;

/**
 * @struct debug_control_t
 *
 * @brief Holds the configuration for printing/debug output
 */
typedef struct debug_control_s {
    uint8_t          com_port_lock;
    uint16_t         com_port_addr;
    print_target_e   print_target;
    bool_t           initialized;
    uint8_t          trace_buffer_lock;
    debug_message_t* trace_buffer;
    uint32_t         msg_num;
    uint32_t         buffer_writer_pos;
    uint32_t         buffer_reader_pos;
    uint64_t         emergency_buffer;
    uint64_t         print_severity;
} debug_control_t;


/**
 * Internal functions - shouldn't be called directly:
 */
uint64_t _sprintf_s( char* buf_ptr, uint64_t buf_size, const char* format, va_list args);
uint64_t debug_sprintf_s(char* buf_ptr, uint64_t buf_size, const char* format, ...);
void init_com_port(debug_control_t* debug_control);
void log_to_com_port(const char* buff, uint32_t length, uint16_t print_port);


uint32_t dump_print_buffer_to_vmm_memory(uint64_t hpa, uint32_t num_of_messages_from_the_end);

/**
 * @brief Initializes the debug facilities of the modules.
 *
 * Should be called before the first trace is emmited by the module
 */
void init_debug_control(void);

/**
 * @brief Outputs a 2-byte number onto port 80 (POST-code display on the motherboard)
 */
void tdx_outport80(uint16_t id);

/**
 * @brief Prints a formatted string (similar to printf) onto the current printing destination
 */
void tdx_print(uint64_t severity, const char* format, ...);

/**
 * @brief Handler for debug configurations
 *
 * TDX module printing mechanism can send prints to several destinations:
 *
 * 1) Serial Port - that's a default target for the prints on module boot.
 *      a. Can be configured by calling:
 *              SEAMCALL(0xFE) RCX=0 RDX=1
 * 2) Internal TDX memory.
 *      It's a cyclic buffer that contains 4096 (TRACE_BUFFER_SIZE) messages.
 *      If more messages are printed by the module, the buffer will cycle from the start and overwrite.
 *      older messages.
 *      a. Can be configured by calling:
 *              SEAMCALL(0xFE) RCX=0 RDX=0
 *      b. To read to contents of this buffer, do the following call:
 *              SEAMCALL(0xFE) RCX=1 RDX=(External memory buffer physical address)
 *              R8=(Number of messages to dump from the last one)
 *         External memory buffer in that case must be at least MAX_PRINT_LENGTH * TRACE_BUFFER_SIZE byte size.
 *         If the number of messages to dump is 0, then the whole internal buffer will be dumped,
 *      c. In case of module critical shutdown errors, internal buffer can't be read with SEAMCALL, so an external
 *         emergency buffer should be configured before with the following call:
 *              SEAMCALL(0xFE) RCX=2 RDX=(External memory buffer physical address)
 *         When module hits any critical arch error, the contents of the internal buffer will be copied automatically
 *         to the pre-configured memory buffer.
 *
 * 3) External buffer in VMM memory.
 *      Will also behave as a cyclic buffer that contains 4096 (TRACE_BUFFER_SIZE) messages.
 *      If more messages are printed by the module, the buffer will cycle from the start and overwrite
 *      older messages.
 *      a. Can be configured by calling:
 *              SEAMCALL(0xFE) RCX=0 RDX=2 R8=(External memory buffer physical address)
 *
 *         i.  External memory buffer in that case must be at least MAX_PRINT_LENGTH * TRACE_BUFFER_SIZE byte size.
 *         ii. External memory buffer address must be also aligned on 256 (MAX_PRINT_LENGTH), otherwise
 *             the SEAMCALL will return -1.
 *
 *      b. The first message (index 0) at the buffer base will actually contain an info about the current
 *         buffer contents in the following format:
 *
 *         At offset 0: 8-byte index of the last printed message
 *         At offset 8: 8-byte physical address of the last printed message
 *         At offset 16: 8-byte total number of printed messages from the external buffer creation
 *
 *         Rest of the first message may contain uninitialized garbage
 *
 * Note that any external buffers can be used only after TDHSYSINITLP was executed successfully
 *
 * Printing severity is set by default to PRINT_SEVERITY_LOG, which will result in printing any possible message
 * that the module can print.
 * Configuring printing severity can be done by calling:
 *
 *      SEAMCALL(0xFE) RCX=3 RDX=(print severity)
 *
 * Where print severity can get the following values:
 *
 *      0    - PRINT_SEVERITY_LOG
 *      1    - PRINT_SEVERITY_WARN
 *      2    - PRINT_SEVERITY_ERROR
 *      1000 - PRINT_SEVERITY_CUSTOM_PRINT - used for custom prints from the module,
 *                                           and turns off other LOG/WARN/ERROR prints
 *      -1   - PRINT_SEVERITY_MAX - turns off any printing in the module
 *
 */
uint64_t td_debug_config(uint64_t leaf, uint64_t payload, uint64_t second_payload);

#define TDX_PRINT(...)                        tdx_print(PRINT_SEVERITY_CUSTOM_PRINT, __VA_ARGS__);

#define TDX_PRINT_WITH_INFO(sev, string, ...) tdx_print(sev, "%s: %s: %d: " string ,\
                                                        __FILENAME__, __func__, __LINE__,##__VA_ARGS__);

#define TDX_ERROR(...)               TDX_PRINT_WITH_INFO(PRINT_SEVERITY_ERROR, __VA_ARGS__);
#define TDX_WARN(...)                TDX_PRINT_WITH_INFO(PRINT_SEVERITY_WARN, __VA_ARGS__);
#define TDX_LOG(...)                 TDX_PRINT_WITH_INFO(PRINT_SEVERITY_LOG, __VA_ARGS__);

#else // DEBUGFEATURE_TDX_DBG_TRACE

#define TDX_PRINT(...)
#define TDX_ERROR(...)
#define TDX_LOG(...)
#define TDX_WARN(...)

#endif // DEBUGFEATURE_TDX_DBG_TRACE

//Debug Assertion
#define tdx_debug_assert(cond)

#define UNUSED(expr) (void)(expr)


#endif /* SRC_COMMON_DEBUG_TDX_DEBUG_H_ */
