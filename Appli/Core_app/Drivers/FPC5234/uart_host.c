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

/**
 * @file    uart_host.c
 * @brief   UART for Host communication.
 *
 * Rewritten to go through Core_app/Platform + Core_app/BSP/board.h instead
 * of touching huart1/HAL directly -- the same boundary
 * Core_app/Drivers/SE05x/platform/stm32h7/src/i2c_stm32h7.c keeps for the
 * SE052F: this file implements the vendor-defined contract (uart_host.h,
 * consumed by fpc_hal.c) purely in terms of platform_uart.h/platform_gpio.h/
 * platform_time.h and the BOARD_FPC2530_* constants from board.h. It must
 * never call an HAL_*() function or reference a CubeMX-generated handle
 * (huart1, hdma_usart1_rx, ...) itself.
 *
 * Two pieces of the original FPC reference implementation were dropped
 * rather than ported, because Platform deliberately does not expose the
 * capability they need (adding it would mean reaching past Platform's
 * "generated init configures the peripheral, Platform only runs it"
 * boundary -- see platform_uart.h):
 *  - host_uart_irq_handler(): hooked the raw USART ISR (IDLE flag,
 *    ATOMIC_SET_BIT on CR1) to count IDLE-line events for debug/statistics
 *    only -- it never fed into uart_host_receive()'s actual byte-copy
 *    logic (that already worked purely off the DMA write position, see
 *    below) and was not wired to any IRQHandler even in the original
 *    project. Not part of the public contract in uart_host.h either.
 *  - uart_host_reinit(): poked huart1.Instance->BRR directly to recompute
 *    the baud-rate register. Also not declared in uart_host.h/called from
 *    anywhere. Runtime baud-rate change would need a new Platform
 *    primitive (platform_uart.h explicitly leaves baud rate to generated
 *    init); add one there first if this is ever actually needed.
 */
#if defined(HOST_IF_UART)
/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "uart_host.h"

#include <stdbool.h>
#include <string.h>

#include "platform.h"
#include "board.h"

#define MIN_DELAY_BETWEEN_CS_TOGGLE_AND_UART_TRANSFER_MS 2

#ifndef MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#endif

#define DMA_BUF_SIZE 128

/* DMA-written, CPU-read via a raw pointer (uart_host_receive() below) --
 * must live in the non-cacheable .dma_noncache region once D-Cache is
 * enabled, see STM32H753ZITX_FLASH.ld's doc comment on that section. */
static uint8_t uart_rx_fifo[DMA_BUF_SIZE] __attribute__((section(".dma_noncache")));
/* Read position inside uart_rx_fifo, i.e. how much of the circular DMA
 * buffer the caller has already consumed -- everything from here up to
 * platform_uart_rx_stream_pos()'s current position is unread. */
static uint16_t rx_read_pos;

/**
 * USART init function.
 */
void uart_host_init(void)
{
    (void)platform_uart_init(BOARD_FPC2530_UART);

    rx_read_pos = 0;
    (void)platform_uart_start_rx_stream(BOARD_FPC2530_UART, uart_rx_fifo, DMA_BUF_SIZE);
}

int uart_host_transmit(uint8_t *data, size_t size, uint32_t timeout, int flush)
{
    (void)flush;

    if (size > UINT16_MAX) {
        return -1;
    }

    uint32_t tickstart = platform_get_tick_ms();

    /* Toggle CS to wake up the device and wait before starting transfer. */
    platform_gpio_write(BOARD_FPC2530_CS_GPIO, false);
    platform_gpio_write(BOARD_FPC2530_CS_GPIO, true);
    platform_delay_ms(MIN_DELAY_BETWEEN_CS_TOGGLE_AND_UART_TRANSFER_MS);

    if (platform_uart_transmit_dma(BOARD_FPC2530_UART, data, (uint16_t)size) != PLATFORM_OK) {
        return -1;
    }

    while (platform_uart_dma_tx_busy(BOARD_FPC2530_UART)) {
        if (timeout != 0 && (platform_get_tick_ms() - tickstart > timeout)) {
            /* Platform has no TX-DMA abort primitive (see platform_uart.h) --
             * report the timeout and leave the transfer running; the next
             * platform_uart_transmit_dma() call returns PLATFORM_BUSY until
             * it finishes on its own. */
            return -1;
        }
    }

    return 0;
}

int uart_host_receive(uint8_t *data, size_t size, uint32_t timeout)
{
    uint32_t tickstart = platform_get_tick_ms();

    if (!size) {
        return 0;
    }

    while (size) {
        uint16_t cur_pos = platform_uart_rx_stream_pos(BOARD_FPC2530_UART, DMA_BUF_SIZE);

        if (cur_pos != rx_read_pos) {
            uint32_t length;

            if (rx_read_pos < cur_pos) {
                length = MIN((uint32_t)(cur_pos - rx_read_pos), size);
            } else {
                /* Buffer wrapped: copy up to the end first, the rest is
                 * picked up on a later iteration once rx_read_pos wraps. */
                length = MIN((uint32_t)(DMA_BUF_SIZE - rx_read_pos), size);
            }
            memcpy(data, &uart_rx_fifo[rx_read_pos], length);
            data += length;
            size -= length;
            rx_read_pos = (uint16_t)(rx_read_pos + length);
            if (rx_read_pos >= DMA_BUF_SIZE) {
                rx_read_pos = 0;
            }
            continue; /* more bytes may already be sitting in the buffer */
        }

        if (timeout != 0 && (platform_get_tick_ms() - tickstart > timeout)) {
            return -1;
        }
    }

    return 0;
}

uint32_t uart_host_rx_data_available(void)
{
    return (platform_uart_rx_stream_pos(BOARD_FPC2530_UART, DMA_BUF_SIZE) != rx_read_pos) ? 1U : 0U;
}

void uart_host_rx_data_clear(void)
{
    (void)platform_uart_stop_rx_stream(BOARD_FPC2530_UART);
    rx_read_pos = 0;
    (void)platform_uart_start_rx_stream(BOARD_FPC2530_UART, uart_rx_fifo, DMA_BUF_SIZE);
}
#endif /* HOST_IF_UART */

#endif /* EVT2_ENABLE_BIOMETRIC */
