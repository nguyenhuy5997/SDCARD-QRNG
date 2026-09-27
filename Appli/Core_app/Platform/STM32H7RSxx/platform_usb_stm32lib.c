/**
 * @file    platform_usb_stm32lib.c
 * @brief   platform_usb.h backend: ST's STM32 USB Device Library + CDC.
 *
 * Compiles to nothing unless platform_usb_config.h selects this backend
 * (PLATFORM_USB_BACKEND_STM32LIB) -- see that file's doc comment.
 *
 * Clock/descriptor/endpoint init is owned by USB_DEVICE/App+Target
 * (based on ST's NUCLEO-H7S3L8 CDC_Standalone, USB_OTG_HS + embedded PHY -- see
 * USB_DEVICE/Target/usbd_conf.c's doc comment) and MX_USB_DEVICE_Init(),
 * called from main() (Core/Src/main.c) before any application code runs -- this file
 * only attaches to that already-initialized `hUsbDeviceHS` and
 * implements the business operations (buffered TX/RX), same pattern
 * every other Platform module in this project follows.
 *
 * The RX ring buffer lives HERE, not in USB_DEVICE/App/usbd_cdc_if.c's
 * USER CODE sections the way upstream references (vQRNG1.0,
 * usb_encrypt_host/firmware) keep it -- deliberate: this project's rule
 * is that generated/vendored files stay thin passthroughs and Platform
 * owns all business logic (see e.g. platform_gpio.c's EXTI callback
 * bridge for the same pattern). usbd_cdc_if.c's CDC_Receive_HS() calls
 * platform_usb_cdc_rx_isr_push() below (declared only as a private
 * extern in that file, not part of any shared Core_app header) instead
 * of maintaining its own buffer.
 */
#include "platform_usb_config.h"

#if PLATFORM_USB_BACKEND == PLATFORM_USB_BACKEND_STM32LIB

#include "platform.h"
#include "usbd_cdc_if.h"
#include "usb_device.h"

#include <string.h>

/* Raised 32768 -> 65536 (2026-09-19) alongside
 * Core_app/Middleware/CommandProtocol/command_protocol.h's
 * CMD_PROTO_MAX_PAYLOAD going 32768 -> 49152, to give real H.264
 * keyframes (measured up to ~30010B on real hardware during a real
 * call, see CLAUDE.md's 2026-09-19 session) comfortable headroom
 * instead of sitting right at the old ceiling. This ring must stay a
 * POWER OF 2 (see USB_RX_RING_MASK below, and the "why not %" comment
 * on it) -- there is no valid size between 32768 and 65536, so raising
 * this at all means this exact jump, not an arbitrary "somewhat
 * bigger" value. 65536 is large enough to absorb one full worst-case
 * frame's raw (still-escaped, so up to ~2x the payload) bytes as a
 * burst without the main loop needing to keep up in real time -- same
 * reasoning as the original 32768 choice below, just rescaled. Matters
 * because this ring is a single-producer (USB IRQ), single-consumer
 * (command_protocol_poll(), called once per main-loop iteration)
 * buffer with NO backpressure to the host -- if it fills,
 * platform_usb_cdc_rx_isr_push() below silently drops the rest of
 * that USB packet rather than corrupt unread data, which would show up
 * as a CRC failure (frame just silently dropped, decoder_feed()
 * resyncs at the next FLAG) on whatever frame was mid-flight.
 * RAM cost check done before this change (2026-09-19): build's .bss was
 * 357440B of RAM_D1's 512KB (~162KB free) before this. See
 * command_protocol.h's CMD_PROTO_MAX_PAYLOAD doc comment for the full
 * accounting -- this ring's own +32768B plus the OTHER
 * CMD_PROTO_MAX_PAYLOAD-derived static buffers (after removing two
 * redundant ones media_protocol.c no longer needs) comes to ~128KB
 * total, leaving ~34KB free. Considered moving some of these buffers to
 * RAM_D2/DTCM instead of shrinking the redundant ones, but confirmed
 * that's unnecessary: USB_OTG_HS's DMA is explicitly disabled in this
 * project (USB_DEVICE/Target's `hpcd_USB_OTG_HS.Init.dma_enable =
 * DISABLE`), so none of these buffers are DMA-touched and bank
 * placement was never the real RAM lever here. Re-check RAM headroom
 * (a fresh Release build's .map file, `.bss` size vs RAM_D1's 512K)
 * before pushing either constant higher again. */
#define USB_RX_RING_SIZE 65536U
#define USB_RX_RING_MASK (USB_RX_RING_SIZE - 1U)

static volatile uint8_t s_rx_ring[USB_RX_RING_SIZE];
static volatile size_t s_rx_head; /* next write index -- only CDC_Receive_HS (USB IRQ context) touches this */
static volatile size_t s_rx_tail; /* next read index -- only platform_usb_receive() (main-loop context) touches this */

static bool s_ready;

platform_status_t platform_usb_init(void)
{
    if (s_ready) {
        return PLATFORM_OK;
    }
    if (hUsbDeviceHS.dev_state == 0U) {
        /* MX_USB_DEVICE_Init() has not run yet (dev_state is still its
         * zero-initialized BSS value -- 0 matches none of the real
         * USBD_STATE_* values, which all start at 0x01) -- a call-order
         * bug in the caller, not something Platform can fix by
         * initializing the peripheral itself. */
        return PLATFORM_ERROR;
    }

    s_ready = true;
    return PLATFORM_OK;
}

/* Single-producer (USB IRQ), single-consumer (main loop) ring buffer --
 * no lock needed as long as that producer/consumer split is respected. */
void platform_usb_cdc_rx_isr_push(const uint8_t *data, uint32_t len)
{
    /* Bitmask, not `% USB_RX_RING_SIZE` -- this runs in USB IRQ context
     * once per received byte (called from CDC_Receive_HS(), typically
     * every <=512-byte HS OUT packet; EVT2/FS: 64-byte); a real division here (if the
     * compiler ever fails to fold a runtime-visible modulo-by-power-of-2
     * into an AND, e.g. after some future edit changes USB_RX_RING_SIZE
     * to a non-constant or the optimization level drops) would cost far
     * more than the couple of cycles this guarantees instead. Matters
     * more once a higher-throughput consumer (e.g. the planned encrypted
     * video-call stream) pushes through here than it did for QRNG's
     * request/response traffic. */
    for (uint32_t i = 0; i < len; i++) {
        size_t next_head = (s_rx_head + 1U) & USB_RX_RING_MASK;
        if (next_head == s_rx_tail) {
            break; /* ring full -- drop the rest of this packet rather than overwrite unread data */
        }
        s_rx_ring[s_rx_head] = data[i];
        s_rx_head = next_head;
    }
}

size_t platform_usb_bytes_available(void)
{
    size_t head = s_rx_head;
    size_t tail = s_rx_tail;
    return (head >= tail) ? (head - tail) : (USB_RX_RING_SIZE - tail + head);
}

platform_status_t platform_usb_receive(uint8_t *buf, size_t maxlen, size_t *received)
{
    if (buf == NULL || received == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    size_t n = 0;
    while (n < maxlen && s_rx_tail != s_rx_head) {
        buf[n++] = s_rx_ring[s_rx_tail];
        s_rx_tail = (s_rx_tail + 1U) & USB_RX_RING_MASK;
    }
    *received = n;
    return PLATFORM_OK;
}

platform_status_t platform_usb_transmit(const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    if (buf == NULL) {
        return PLATFORM_INVALID_PARAM;
    }
    if (len > 0xFFFFU) {
        return PLATFORM_INVALID_PARAM; /* CDC_Transmit_HS's Len is uint16_t */
    }

    uint32_t start = platform_get_tick_ms();
    uint8_t result;
    do {
        result = CDC_Transmit_HS((uint8_t *)(uintptr_t)buf, (uint16_t)len);
        if (result != (uint8_t)USBD_BUSY) {
            break;
        }
    } while (timeout_ms == 0U ? false : (platform_get_tick_ms() - start) < timeout_ms);

    return (result == (uint8_t)USBD_OK) ? PLATFORM_OK : (result == (uint8_t)USBD_BUSY ? PLATFORM_BUSY : PLATFORM_ERROR);
}

platform_status_t platform_usb_wait_tx_ready(uint32_t timeout_ms)
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }

    USBD_CDC_HandleTypeDef *hcdc = (USBD_CDC_HandleTypeDef *)hUsbDeviceHS.pClassData;
    if (hcdc == NULL) {
        return PLATFORM_ERROR;
    }

    uint32_t start = platform_get_tick_ms();
    while (hcdc->TxState != 0U) {
        if (timeout_ms == 0U || (platform_get_tick_ms() - start) >= timeout_ms) {
            return PLATFORM_TIMEOUT;
        }
    }
    return PLATFORM_OK;
}

bool platform_usb_is_connected(void)
{
    return s_ready && (hUsbDeviceHS.dev_state == USBD_STATE_CONFIGURED);
}

#endif /* PLATFORM_USB_BACKEND == PLATFORM_USB_BACKEND_STM32LIB */
