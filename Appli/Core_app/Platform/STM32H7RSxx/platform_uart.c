/**
 * @file    platform_uart.c
 * @brief   STM32H7RSxx implementation of the Platform UART interface.
 *
 * Clock, GPIO, DMA linking and HAL_UART_Init() are done by bsp_h7s3.c's
 * MX_USART1_UART_Init() / MX_USART3_UART_Init() (EVT2: CubeMX Src/main.c),
 * called from main() before any application code runs; the matching NVIC
 * lines are enabled there too. This file only implements the runtime
 * business operations (transmit/receive) on the `huart1`/`huart3` handles
 * that code already initialized -- it never calls HAL_UART_Init()/
 * HAL_UART_DeInit() or reconfigures DMA handles itself.
 *
 * H7RS differences vs EVT2 (H753, DMA1 Stream1 TX / Stream2 RX):
 *  - USART1 RX uses a GPDMA1 linked-list channel in circular mode (the H7RS
 *    DMA has no plain "circular" stream mode), TX a normal GPDMA1 channel.
 *  - __HAL_DMA_GET_COUNTER() reads GPDMA CBR1.BNDT, a BYTE count; for these
 *    byte-wide UART transfers that equals the item count EVT2 relied on, so
 *    platform_uart_rx_stream_pos() is unchanged.
 *  - TX DMA source: see platform_uart_transmit_dma() -- bounce buffer in
 *    .dma_noncache, because the caller's buffer may be on the main stack,
 *    which this port keeps in DTCM (GPDMA access to DTCM is not assumed).
 */
#include "platform.h"
#include "bsp_hal.h"

#include <string.h>

#if defined(HAL_UART_MODULE_ENABLED)

/* DTCM window on STM32H7S3 (64KB at 0x20000000 with the default TCM option
 * bytes -- matches the linker script's DTCM region). */
#define PLATFORM_UART_DTCM_BASE 0x20000000UL
#define PLATFORM_UART_DTCM_END  0x20010000UL

/* TX DMA bounce buffer -- see platform_uart_transmit_dma(). 32-byte aligned
 * like the rest of .dma_noncache (cache-line size). */
static uint8_t s_tx_bounce[512] __attribute__((section(".dma_noncache"), aligned(32)));

/* Weak: a UART handle exists only when that USART is in the .ioc (CubeMX) or bsp_h7s3.c (USART1, biometric builds).
 * A missing one resolves to NULL and platform_uart_init() rejects it. */
extern UART_HandleTypeDef huart1 __attribute__((weak));
extern UART_HandleTypeDef huart3 __attribute__((weak));

typedef struct {
    UART_HandleTypeDef *handle;
    bool has_dma; /* Only USART1 has DMA linked by the generated MSP init. */
} uart_hw_desc_t;

static const uart_hw_desc_t s_uart_hw[PLATFORM_UART_COUNT] = {
    [PLATFORM_UART_1] = { &huart1, true },
    [PLATFORM_UART_3] = { &huart3, false },
};

static bool s_uart_ready[PLATFORM_UART_COUNT];

static bool uart_id_valid(platform_uart_id_t id)
{
    return id < PLATFORM_UART_COUNT && s_uart_ready[id];
}

static platform_status_t hal_to_platform_status(HAL_StatusTypeDef status)
{
    switch (status) {
    case HAL_OK:      return PLATFORM_OK;
    case HAL_BUSY:    return PLATFORM_BUSY;
    case HAL_TIMEOUT: return PLATFORM_TIMEOUT;
    case HAL_ERROR:
    default:          return PLATFORM_ERROR;
    }
}

platform_status_t platform_uart_init(platform_uart_id_t id)
{
    if (id >= PLATFORM_UART_COUNT) {
        return PLATFORM_INVALID_PARAM;
    }
    if (s_uart_ready[id]) {
        return PLATFORM_OK;
    }
    if (s_uart_hw[id].handle == NULL) {
        return PLATFORM_NOT_SUPPORTED;
    }
    if (HAL_UART_GetState(s_uart_hw[id].handle) == HAL_UART_STATE_RESET) {
        /* MX_USARTx_UART_Init() has not run yet -- a call-order bug in
         * the caller, not something Platform can fix by initializing
         * the peripheral itself. */
        return PLATFORM_ERROR;
    }

    s_uart_ready[id] = true;
    return PLATFORM_OK;
}

platform_status_t platform_uart_deinit(platform_uart_id_t id)
{
    if (!uart_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }

    s_uart_ready[id] = false;
    return PLATFORM_OK;
}

platform_status_t platform_uart_transmit(platform_uart_id_t id, const uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    if (!uart_id_valid(id) || data == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    return hal_to_platform_status(HAL_UART_Transmit(s_uart_hw[id].handle, (uint8_t *)data, len, timeout_ms));
}

platform_status_t platform_uart_receive(platform_uart_id_t id, uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    if (!uart_id_valid(id) || data == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    return hal_to_platform_status(HAL_UART_Receive(s_uart_hw[id].handle, data, len, timeout_ms));
}

platform_status_t platform_uart_start_rx_stream(platform_uart_id_t id, uint8_t *buffer, uint16_t size)
{
    if (!uart_id_valid(id) || buffer == NULL || size == 0) {
        return PLATFORM_INVALID_PARAM;
    }
    if (!s_uart_hw[id].has_dma) {
        return PLATFORM_NOT_SUPPORTED;
    }

    /* Discard any byte already latched in RDR before arming DMA. The RX
     * line can pick up a stray edge (noise on a floating/undriven line
     * before the far end starts actively driving it, e.g. while it is
     * still held in reset) between HAL_UART_Init() and this call; if
     * RXNE is already set at that point, DMA consumes that one stale
     * byte as position 0 the instant DMAR is enabled, permanently
     * shifting every real byte after it by one position. Reading RDR
     * clears RXNE if it was set, and is a harmless no-op otherwise. */
    (void)s_uart_hw[id].handle->Instance->RDR;

    return hal_to_platform_status(HAL_UART_Receive_DMA(s_uart_hw[id].handle, buffer, size));
}

platform_status_t platform_uart_stop_rx_stream(platform_uart_id_t id)
{
    if (!uart_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }
    if (!s_uart_hw[id].has_dma) {
        return PLATFORM_NOT_SUPPORTED;
    }

    return hal_to_platform_status(HAL_UART_DMAStop(s_uart_hw[id].handle));
}

uint16_t platform_uart_rx_stream_pos(platform_uart_id_t id, uint16_t size)
{
    if (!uart_id_valid(id) || !s_uart_hw[id].has_dma || size == 0) {
        return 0;
    }

    UART_HandleTypeDef *huart = s_uart_hw[id].handle;
    if (huart->hdmarx == NULL) {
        return 0;
    }

    uint32_t remaining = __HAL_DMA_GET_COUNTER(huart->hdmarx);
    if (remaining > size) {
        return 0;
    }
    return (uint16_t)(size - remaining);
}

platform_status_t platform_uart_transmit_dma(platform_uart_id_t id, const uint8_t *data, uint16_t len)
{
    if (!uart_id_valid(id) || data == NULL) {
        return PLATFORM_INVALID_PARAM;
    }
    if (!s_uart_hw[id].has_dma) {
        return PLATFORM_NOT_SUPPORTED;
    }

    UART_HandleTypeDef *huart = s_uart_hw[id].handle;
    if (huart->gState != HAL_UART_STATE_READY) {
        /* Previous DMA transmit still running -- report BUSY BEFORE touching
         * s_tx_bounce below, which that transfer may still be reading. */
        return PLATFORM_BUSY;
    }

    /* `data` is whatever buffer the caller happens to pass (the vendored
     * FPC5234 SDK has many call sites) -- possibly a local on the main
     * stack. This port keeps the main stack in DTCM (linker script); DMA
     * access to DTCM is deliberately NOT relied on here (not verified
     * against RM0477 for GPDMA1). Anything in AXI SRAM is D-cacheable, so a
     * dirty line would make the DMA send stale bytes.
     *  - Short frames (the normal case): copy into s_tx_bounce, which lives
     *    in the MPU non-cacheable .dma_noncache window -- no cache
     *    maintenance, no DTCM question.
     *  - Longer frames from AXI SRAM: clean exactly that range and DMA from
     *    it directly (EVT2's original approach).
     *  - Longer frames from DTCM: fall back to a blocking CPU transmit. */
    if (len <= sizeof(s_tx_bounce)) {
        memcpy(s_tx_bounce, data, len);
        return hal_to_platform_status(HAL_UART_Transmit_DMA(huart, s_tx_bounce, len));
    }
    uint32_t addr = (uint32_t)data;
    if (addr >= PLATFORM_UART_DTCM_BASE && addr < PLATFORM_UART_DTCM_END) {
        return hal_to_platform_status(HAL_UART_Transmit(huart, (uint8_t *)data, len, 1000U));
    }
    uint32_t aligned_addr = addr & ~0x1FUL;
    SCB_CleanDCache_by_Addr((uint32_t *)aligned_addr, (int32_t)(len + (addr - aligned_addr)));
    return hal_to_platform_status(HAL_UART_Transmit_DMA(huart, (uint8_t *)data, len));
}

bool platform_uart_dma_tx_busy(platform_uart_id_t id)
{
    if (!uart_id_valid(id) || !s_uart_hw[id].has_dma) {
        return false;
    }

    UART_HandleTypeDef *huart = s_uart_hw[id].handle;
    if (huart->hdmatx == NULL) {
        return false;
    }

    return __HAL_DMA_GET_COUNTER(huart->hdmatx) != 0;
}

#else /* !HAL_UART_MODULE_ENABLED */

/* No USART in the .ioc (e.g. the STM32H7S3V8Y6TR board: no debug UART, no fingerprint sensor): CubeMX leaves the
 * HAL UART module out, so every UART is unsupported. */
platform_status_t platform_uart_init(platform_uart_id_t id) { (void)id; return PLATFORM_NOT_SUPPORTED; }
platform_status_t platform_uart_deinit(platform_uart_id_t id) { (void)id; return PLATFORM_NOT_SUPPORTED; }
platform_status_t platform_uart_transmit(platform_uart_id_t id, const uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    (void)id; (void)data; (void)len; (void)timeout_ms;
    return PLATFORM_NOT_SUPPORTED;
}
platform_status_t platform_uart_receive(platform_uart_id_t id, uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    (void)id; (void)data; (void)len; (void)timeout_ms;
    return PLATFORM_NOT_SUPPORTED;
}
platform_status_t platform_uart_start_rx_stream(platform_uart_id_t id, uint8_t *buffer, uint16_t size)
{
    (void)id; (void)buffer; (void)size;
    return PLATFORM_NOT_SUPPORTED;
}
platform_status_t platform_uart_stop_rx_stream(platform_uart_id_t id) { (void)id; return PLATFORM_NOT_SUPPORTED; }
uint16_t platform_uart_rx_stream_pos(platform_uart_id_t id, uint16_t size) { (void)id; (void)size; return 0U; }
platform_status_t platform_uart_transmit_dma(platform_uart_id_t id, const uint8_t *data, uint16_t len)
{
    (void)id; (void)data; (void)len;
    return PLATFORM_NOT_SUPPORTED;
}
bool platform_uart_dma_tx_busy(platform_uart_id_t id) { (void)id; return false; }

#endif /* HAL_UART_MODULE_ENABLED */
