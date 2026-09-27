/**
 * @file    platform_usb_tinyusb.c
 * @brief   platform_usb.h backend: TinyUSB + CDC (STUB -- not yet wired up).
 *
 * Compiles to nothing unless platform_usb_config.h selects this backend
 * (PLATFORM_USB_BACKEND_TINYUSB) -- see that file's doc comment.
 *
 * STATUS: placeholder only. TinyUSB itself is not vendored into this
 * project yet (needs Core_app/Drivers/ThirdParty/tinyusb -- the dwc2
 * port + core, fetched from https://github.com/hathach/tinyusb and
 * committed directly per the "vendor, don't submodule" decision) and
 * this file's actual glue (tusb_config.h, board-specific dwc2 init,
 * CDC class callbacks, wiring OTG_FS_IRQHandler to TinyUSB's ISR instead
 * of HAL_PCD_IRQHandler) is not written. Selecting this backend right
 * now intentionally fails the build via #error below instead of silently
 * linking an empty/broken platform_usb_* API.
 *
 * When this gets implemented, it must expose exactly the same
 * platform_usb.h contract as platform_usb_stm32lib.c (same ring-buffer-
 * in-Platform ownership split, same function behavior) so nothing above
 * Platform needs to change when switching backends.
 */
#include "platform_usb_config.h"

#if PLATFORM_USB_BACKEND == PLATFORM_USB_BACKEND_TINYUSB
#error "platform_usb_tinyusb.c is a stub -- vendor TinyUSB into Core_app/Drivers/ThirdParty/tinyusb and implement this backend before selecting PLATFORM_USB_BACKEND_TINYUSB."
#endif
