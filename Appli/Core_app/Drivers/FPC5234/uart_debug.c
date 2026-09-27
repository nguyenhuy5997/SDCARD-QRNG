/*
 * Copyright (c) 2024 Fingerprint Cards AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "uart_debug.h"

#include <stdarg.h>
#include <stdio.h>

#include "platform.h"
#include "board.h"

/* Goes through platform_uart.h + BOARD_DEBUG_UART instead of huart3/HAL
 * directly -- same board.h constant app_main.c's app_log() uses, so this
 * driver's debug output and the app-layer self-test log share one UART
 * (by design: this board only wires up two, and BOARD_FPC2530_UART is
 * spoken for by the sensor link -- see board.h). No #if HOST_IF_* guard
 * here: unlike uart_host.c/i2c_host.c/spi_host.c this isn't a transport
 * choice, it is always the debug channel. */

#define MAX_LINE_LEN 100

void uart_debug_printf(const char *format, ...)
{
    va_list arglist;
    char tmp[MAX_LINE_LEN];
    int len;

    va_start(arglist, format);
    len = vsnprintf(tmp, MAX_LINE_LEN - 1, format, arglist);
    va_end(arglist);
    if (len > 0) {
        (void)platform_uart_transmit(BOARD_DEBUG_UART, (uint8_t *)tmp, (uint16_t)len, 1000U);
    }
}

void uart_debug_vprintf(const char *fmt, va_list args)
{
    char tmp[MAX_LINE_LEN];
    int len;

    len = vsnprintf(tmp, MAX_LINE_LEN - 2, fmt, args);
    if (len > 0) {
        tmp[len] = '\n';
        (void)platform_uart_transmit(BOARD_DEBUG_UART, (uint8_t *)tmp, (uint16_t)(len + 1), 1000U);
    }
}

void uart_debug_init(void)
{
    (void)platform_uart_init(BOARD_DEBUG_UART);
}

#endif /* EVT2_ENABLE_BIOMETRIC */
