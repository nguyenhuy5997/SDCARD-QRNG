/**
 * @file    platform_usb.h
 * @brief   MCU-and-stack-agnostic USB CDC (virtual COM port) byte transport.
 *
 * Same interface regardless of which backend platform_usb_config.h
 * selects (ST's STM32 USB Device Library or TinyUSB) -- Middleware/App
 * code above this header never knows or cares which one is active.
 *
 * Clock/descriptor/endpoint config is each backend's own generated-or-
 * vendored init (USB_DEVICE/App+Target for the STM32LIB backend); this
 * header only exposes the byte-stream operations a command/control
 * protocol (see Core_app/Middleware/CommandProtocol) actually needs.
 *
 * Scope: one CDC channel. If/when a composite device (e.g. CDC + a
 * throughput-oriented media class) is needed, that is a new header next
 * to this one (e.g. platform_usb_media.h) plus backend-internal
 * descriptor changes -- not a change to this interface.
 */
#ifndef PLATFORM_USB_H
#define PLATFORM_USB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "platform.h"

/** Attach to (and, for the active backend, bring up) the USB CDC device
 *  stack. Safe to call more than once. */
platform_status_t platform_usb_init(void);

/** Transmit of `len` bytes. Returns PLATFORM_BUSY if a previous transfer
 *  was still in flight after waiting up to `timeout_ms` for it to clear
 *  (0 = don't wait, fail immediately if busy) -- caller decides whether
 *  to retry or drop. IMPORTANT: returning PLATFORM_OK means this
 *  transfer was successfully *started*, not that the hardware has
 *  finished reading `buf` yet -- that happens asynchronously afterward.
 *  A caller that reuses one buffer across calls (rather than a fresh one
 *  each time) must not overwrite it after this returns without first
 *  calling platform_usb_wait_tx_ready() -- see that function's doc
 *  comment. */
platform_status_t platform_usb_transmit(const uint8_t *buf, size_t len, uint32_t timeout_ms);

/** Block (up to `timeout_ms`; 0 = don't wait, check once) until the
 *  buffer passed to the most recent platform_usb_transmit() call is safe
 *  to overwrite -- i.e. the USB peripheral has actually finished reading
 *  it, not just accepted the transfer. Required before reusing a single
 *  static buffer across repeated platform_usb_transmit() calls (see
 *  Core_app/Middleware/CommandProtocol/command_protocol.c's send_frame(),
 *  the motivating caller: back-to-back sends -- e.g. a continuous QRNG
 *  stream -- rewriting that shared buffer while the previous frame was
 *  still being clocked out corrupted it in flight, silently dropped at
 *  the receiver on CRC mismatch). Returns PLATFORM_TIMEOUT if still busy
 *  after `timeout_ms`. Not needed if every platform_usb_transmit() call
 *  is given its own distinct buffer. */
platform_status_t platform_usb_wait_tx_ready(uint32_t timeout_ms);

/** Number of received bytes currently buffered and not yet read via
 *  platform_usb_receive(). */
size_t platform_usb_bytes_available(void);

/** Copy up to `maxlen` buffered received bytes into `buf`, removing them
 *  from the internal buffer. `*received` is set to how many bytes were
 *  actually copied (0..maxlen) -- never blocks, never partially fails. */
platform_status_t platform_usb_receive(uint8_t *buf, size_t maxlen, size_t *received);

/** True once the host has configured the device (enumeration complete)
 *  -- not a guarantee a terminal application has actually opened the
 *  port (DTR), just that the USB link itself is up. */
bool platform_usb_is_connected(void);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_USB_H */
