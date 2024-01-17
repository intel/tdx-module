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
 * @file sprintf.c
 * @brief SPRINTF implementation
 */

#include "tdx_debug.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#ifdef DEBUGFEATURE_TDX_DBG_TRACE

/**
 * @brief convert nibble to lowercase hex char
 */
#define lowerhexchars(x) (((x) < 10) ? ('0' + (x)) : ('a' + ((x) - 10)))

/**
 * @brief convert nibble to uppercase hex char
 */
#define upperhexchars(x) (((x) < 10) ? ('0' + (x)) : ('A' + ((x) - 10)))

/**
 * @brief return the msb bit that is diffrent from zero
 */
static int find_msb( unsigned long long val )
{
    int32_t len = sizeof( val );
    int32_t msb = 0;
    int32_t i;

    for ( i = ( 8 * len ) - 1 ; i >= 0 ; i-- )
    {
        if ( ( val >> i ) & 0x1 )
        {
            // found the first high bit, break out
            msb = i;
            break;
        }
    }

    return ( msb );
}

/**
 * @brief return write val as hex to buf_ptr buffer
 */
static uint64_t print_hex(char* buf_ptr,
                          uint64_t buf_size,
                          unsigned long long val,
                          uint32_t fillsize,
                          char fillchar,
                          bool_t b_is_lower)
{
    int32_t i;
    int32_t msb;
    uint32_t write_count = 0;

    // this represents the most nibbles that we will print from the val
    // passed in. any additional nibbles that need to get pushed out will
    // be due to changes in the flags and width. set this to 1 to represent
    // that at least one nibble will get printed by us (maybe a zero)
    int32_t highest_nibble;

    // ok, I know what the value is so now it's just
    // a matter of formatting it correctly

    // find msb. need to know this so that I print
    // the correct number of non-zero nibbles
    msb = find_msb( val );

    // if the value is non-zero, round the msb up to the correct nibble.
    // highest_nibble count uses 1-based indexing.
    highest_nibble = (msb / 4) + 1;

    if (fillsize > (unsigned)highest_nibble)
    {
        //for strings that are smaller than specified field size
        for (; write_count < fillsize - highest_nibble && write_count < buf_size; write_count++)
        {
            *buf_ptr++ = fillchar;
            //(*buf_ptr_ptr)++;
        }
    }

    //// push out the remaining values. this could be a zero
    for (i = 4 * (highest_nibble - 1); i >= 0 && write_count < buf_size; i -= 4, write_count++)
    {
        if (b_is_lower)
        {
            *buf_ptr++ = (uint8_t) lowerhexchars((val >> i) & 0xF);
        }
        else
        {
            *buf_ptr++ = (uint8_t) upperhexchars((val >> i) & 0xF);
        }
    }

    return write_count;
}

/**
 * @brief return write val as decimal to buf_ptr buffer
 */
static uint64_t print_dec(char* buf_ptr,
                        uint64_t buf_size,
                        unsigned long long val,
                        uint32_t fillsize,
                        char fillchar,
                        bool_t is_positive,
                        uint32_t is_long)
{
    int32_t digits, i;
    uint64_t write_count = 0;
    //char* buf_ptr = *buf_ptr_ptr;

    unsigned long long pot10[20];

    // This is not the best way to do this but non-local data is not yet
    // supported in this environment. Therefore, it must be built on each
    // call to this routine.

    pot10[0] = 1;
    for( i = 1; i < 20; i++ )
    {
        pot10[i] = 10 * pot10[i-1];
    }

    // if the number if negative we print the minus
    if (is_positive == false)
    {
        switch(is_long)
        {
        case 2:
            val = (-(long long signed)val);
            break;
        case 1:
            val = (-(long signed)val);
            break;
        case 0:
        default:
            val = (-(signed)val);
            break;
        }

        if (fillsize > 0 && fillchar == ' ') // one char will be taken for '-'
        {
            fillsize--;
        }
    }

    // estimate number of digits
    for (digits = 1; ((digits < 20) && (val >= pot10[digits])); digits++);

    // when the val is negative:
    // if the fillchar is blank space, the minus needs to be after the filling chars
    // if the fillchar is zero the minus need to be before the filling chars
    // example 1:
    //  val = -3
    //  fillchar = ' '
    //  fill size = 8
    //  outcome: "      -3"
    // example 1:
    //  val = -3
    //  fillchar = '0'
    //  fill size = 8
    //  outcome: "-0000003"

    if (!is_positive && fillchar == '0') // we need to print '-' and we need to print it NOW (since filling is non-blank)
    {
        if (write_count < buf_size)
        {
            *buf_ptr++ = '-';
            write_count++;
        }
        is_positive = true; // we printed '-' - we may forget about it :-)
    }

    if (fillsize > (unsigned)digits)
    {
        for (; write_count < fillsize - digits && write_count < buf_size; write_count++)
        {
            *buf_ptr++ = fillchar;
        }
    }

    if (!is_positive) // we need to print '-' (the number is negative and we still didn't print it)
    {
        if (write_count < buf_size)
        {
            *buf_ptr++ = '-';
            write_count++;
        }
    }

    for (digits = digits - 1; digits >= 0 && write_count < buf_size; digits--, write_count++)
    {
        uint8_t quot;
        for (quot = 0; val >= pot10[digits]; val -= pot10[digits], quot++);
        *buf_ptr++ = (char)(quot + '0');
    }

    return write_count;
}

/**
 * @brief return the string length
 */
static inline uint32_t strlen_s(char const * str, uint32_t string_max_size)
{
    uint32_t s_len = 0;
    while ((*str++) && (s_len < string_max_size))
    {
        s_len++;
    }
    return s_len;
}

/**
 * @brief return write val as string to buf_ptr buffer
 */
static uint64_t print_string(char* buf_ptr, uint64_t buf_size, const char* s, uint32_t fillsize, char fillchar)
{
    uint64_t write_count = 0;

    uint32_t s_len = strlen_s(s, (uint32_t)buf_size);

    if (fillsize != 0)
    {
        if (fillsize > s_len)
        {
            //for strings that are smaller than specified field size
            for (; write_count < fillsize - s_len && write_count < buf_size; write_count++)
            {
                *buf_ptr++ = fillchar;
            }
        }
    }
    if (s_len != 0)
    {
        for (; s_len--  && write_count < buf_size; write_count++)
        {
            *buf_ptr++ = *s++;
        }
    }


    return write_count;
}

/**
 * @brief Similar to C std sprintf function
 */
uint64_t _sprintf_s( char* buf_ptr, uint64_t buf_size, const char* format, va_list args)
{
    // sprintf algorithm
    uint64_t total_write_count = 0;

    while(total_write_count < buf_size - 1)
    {
        uint64_t w_count = 0;
        char ch;
        // stage 1, look for the % sign
        if ((ch = *format++) == '%')
        {
            ch = *format++;
            uint32_t fillsize = 0;
            uint32_t char_left = (uint32_t)(buf_size - total_write_count - 1);
            uint32_t maxsize = char_left; // NOTE: used only in %s
            uint32_t dot = 0;
            char fillchar = ' ';
            uint32_t is_long = 0;
            switch (ch)
            {
            case '0':
                fillchar = '0';
                ch = *format++;
                break;

            case ' ':
                ch = *format++;
                break;

            case '.':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case 's':
            case 'p':
            case 'c':
            case 'X':
            case 'x':
            case 'u':
            case 'd':
            case 'i':
            case 'l':
                break;
            }


            uint32_t size = fillsize;
            while (((ch >= '0') && (ch <= '9')) || ch == '.')
            {
                if (ch == '.')
                {
                    dot = 1;
                    fillsize = size;
                    size = 0;
                }
                else
                {
                    size = size * 10 + ch - '0';
                }
                ch = *format++;
            }
            if (dot)
            {
               maxsize = size;
               if (maxsize > char_left)
               {
                   maxsize = char_left;
               }
            }
            else
            {
                   fillsize = size;
            }


            if (ch == 'l')
            {
                is_long = 1;
                ch = *format++;
                if (ch == 'l')
                {
                    is_long = 2;
                    ch = *format++;
                }
            }

            long long val;
            bool_t b_is_lower = true;
            if (ch =='X')
            {
                b_is_lower = false;
                ch = 'x';
            }
            bool_t is_positive = true;
            switch (ch)
            {
            case 'c':
                *buf_ptr++ = (char)va_arg( args, int );
                total_write_count++;
                break;

            case 'p':
                if (fillsize == 0)
                {
                    fillsize = 8;
                }
                if (fillchar == '\0')
                {
                    fillchar = '0';
                }
                is_long = 2;// to print 64 address bits
                //fall through to print HEX
            case 'x':
                if (is_long == 2)
                {
                    val = va_arg( args, unsigned long long );
                }
                else if (is_long == 1)
                {
                    val = va_arg( args, unsigned long );
                }
                else
                {
                    val = va_arg( args, unsigned int );
                }
                w_count += print_hex(buf_ptr, buf_size - total_write_count - 1, val, fillsize, fillchar, b_is_lower);
                buf_ptr += w_count;
                total_write_count += w_count;
                break;
            case 'u':
                if (is_long == 2)
                {
                    val = va_arg( args, unsigned long long );
                }
                else if (is_long == 1)
                {
                    val = va_arg( args, unsigned long );
                }
                else
                {
                    val = va_arg( args, unsigned int );
                }
                w_count += print_dec(buf_ptr, buf_size - total_write_count - 1, val, fillsize, fillchar, true, is_long);
                buf_ptr += w_count;
                total_write_count += w_count;
                break;

            case 'd':
            case 'i':
                if (is_long == 2)
                {
                    val = va_arg( args, long long );
                }
                else if (is_long == 1)
                {
                    val = va_arg( args, long );
                }
                else
                {
                    val = va_arg( args, int );
                }
                if (val < -val)
                {
                    is_positive = false;
                }
                w_count += print_dec(buf_ptr, buf_size - total_write_count - 1, val, fillsize, fillchar, is_positive, is_long);
                buf_ptr += w_count;
                total_write_count += w_count;
                break;

            case 's':
                {
                    const char *s = va_arg( args, const char * );
                    w_count += print_string(buf_ptr, maxsize, s, fillsize, fillchar);
                    buf_ptr += w_count;
                    total_write_count += w_count;
                    break;
                }
            }
        }
        else
        {
             if ((ch == '\n') && (total_write_count < buf_size - 2))
            {
                *buf_ptr++ = '\r';
                total_write_count++;
            }
            *buf_ptr++ = ch;
            if (ch == '\0')
            {
                return total_write_count;
            }
            total_write_count++;
        }

    }
    *buf_ptr = '\0';
    return total_write_count;
}

/**
 * @brief Similar to C std sprintf function
 */
uint64_t debug_sprintf_s(char* buf_ptr, uint64_t buf_size, const char* format, ...)
{
    va_list args;
    va_start( args, format );
    uint64_t write_count = _sprintf_s(buf_ptr, buf_size, format, args);
    va_end( args );
    return write_count;
}

#endif

#pragma clang diagnostic pop
