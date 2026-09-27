/**
 * @file    platform_uart.h
 * @brief   MCU-agnostic UART interface of the Platform HAL.
 *
 * Baud rate/parity/stop bits/pin configuration is the code generator's
 * job (e.g. STM32CubeMX's MX_USARTx_UART_Init() in main.c) and is not
 * part of this API. platform_uart_init() only attaches to an instance
 * that code already brought up.
 *
 * Blocking transmit/receive are guaranteed to work on every backend. The
 * streaming (DMA) API is best-effort: a backend may only wire it up for
 * the UART instance(s) that have DMA available in hardware and must
 * return PLATFORM_NOT_SUPPORTED for the others.
 */
#ifndef PLATFORM_UART_H
#define PLATFORM_UART_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "platform.h"

/** Logical UART instances exposed by the board. The MCU-specific backend
 *  maps each id to a physical peripheral already configured elsewhere. */
typedef enum {
    PLATFORM_UART_1 = 0,
    PLATFORM_UART_3,
    PLATFORM_UART_COUNT,
} platform_uart_id_t;

/** Attach to an instance already brought up by generated init code.
 *  Returns PLATFORM_ERROR if that init has not run yet. Safe to call
 *  more than once. */
platform_status_t platform_uart_init(platform_uart_id_t id);

/** Detach from the instance. Does not touch clocks/GPIO/HAL peripheral
 *  state -- those stay owned by generated init code. */
platform_status_t platform_uart_deinit(platform_uart_id_t id);

/** Blocking send/receive, `timeout_ms` per HAL semantics (0 = poll once). */
platform_status_t platform_uart_transmit(platform_uart_id_t id, const uint8_t *data, uint16_t len, uint32_t timeout_ms);
platform_status_t platform_uart_receive(platform_uart_id_t id, uint8_t *data, uint16_t len, uint32_t timeout_ms);

/**
 * Start a continuous circular-DMA reception into `buffer`, ring-buffer
 * style. Call platform_uart_rx_stream_pos() to find out how many bytes
 * have been written so far. Returns PLATFORM_NOT_SUPPORTED if the
 * instance has no DMA wired.
 */
platform_status_t platform_uart_start_rx_stream(platform_uart_id_t id, uint8_t *buffer, uint16_t size);
platform_status_t platform_uart_stop_rx_stream(platform_uart_id_t id);

/** Current write position (0..size-1) inside the buffer passed to
 *  platform_uart_start_rx_stream(), for consumers to poll. */
uint16_t platform_uart_rx_stream_pos(platform_uart_id_t id, uint16_t size);

/** One-shot DMA transmit of `len` bytes. Poll platform_uart_dma_tx_busy()
 *  to know when the buffer can be reused. Returns PLATFORM_NOT_SUPPORTED
 *  if the instance has no DMA wired. */
platform_status_t platform_uart_transmit_dma(platform_uart_id_t id, const uint8_t *data, uint16_t len);
bool platform_uart_dma_tx_busy(platform_uart_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_UART_H */
