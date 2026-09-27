/**
 * @file    platform_usb_config.h
 * @brief   Single selection point for which USB stack backs platform_usb.h.
 *
 * Exactly one of platform_usb_stm32lib.c / platform_usb_tinyusb.c compiles
 * to anything -- the other becomes an empty translation unit -- based on
 * this one macro. Only one USB stack can own the OTG_FS peripheral/IRQ at
 * a time, so this is a build-time choice, not a runtime one. To switch
 * backends: change the #define below and rebuild -- no other file needs
 * to change, and nothing needs excluding/including in the IDE project.
 */
#ifndef PLATFORM_USB_CONFIG_H
#define PLATFORM_USB_CONFIG_H

#define PLATFORM_USB_BACKEND_STM32LIB 1
#define PLATFORM_USB_BACKEND_TINYUSB  2

/* ---- The one thing to change to switch backends ---- */
#define PLATFORM_USB_BACKEND PLATFORM_USB_BACKEND_STM32LIB

#endif /* PLATFORM_USB_CONFIG_H */
