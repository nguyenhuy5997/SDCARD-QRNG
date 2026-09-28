/**
 * @file    platform.h
 * @brief   Public entry point of the Platform hardware abstraction layer (HAL).
 *
 * This header only defines types shared by every Platform module and pulls
 * in the per-peripheral interfaces. It never depends on a vendor SDK
 * (STM32Cube HAL, CMSIS, ...) — only the MCU-specific implementation under
 * Platform/<family>/ (e.g. Platform/STM32H7xx/) is allowed to do so. This is
 * what lets Core_app/Drivers and everything above it stay portable across
 * MCU families: swapping the Platform/<family> folder is the only change
 * needed.
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/** Common return status for every Platform API. */
typedef enum {
    PLATFORM_OK = 0,
    PLATFORM_ERROR,
    PLATFORM_BUSY,
    PLATFORM_TIMEOUT,
    PLATFORM_INVALID_PARAM,
    PLATFORM_NOT_SUPPORTED,
} platform_status_t;

#include "platform_gpio.h"
#include "platform_uart.h"
#include "platform_i2c.h"
#include "platform_adc.h"
#include "platform_time.h"
#include "platform_timer.h"
#include "platform_rng.h"
#include "platform_dac.h"
#include "platform_hash.h"
#include "platform_crypto.h"
#include "platform_usb.h"
#include "platform_temp.h"

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_H */
