/**
 * @file    platform_gpio.h
 * @brief   MCU-agnostic GPIO interface of the Platform HAL.
 *
 * Pin mode/speed/pull/alternate-function configuration is the code
 * generator's job (e.g. STM32CubeMX's MX_GPIO_Init() in main.c) and is not
 * part of this API. Platform only implements the runtime read/write/toggle
 * operations on pins that are already configured elsewhere.
 */
#ifndef PLATFORM_GPIO_H
#define PLATFORM_GPIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "platform.h"

/** Physical port a pin belongs to. Only the ports available on the target
 *  package need to be implemented by the MCU-specific backend. */
typedef enum {
    PLATFORM_GPIO_PORT_A = 0,
    PLATFORM_GPIO_PORT_B,
    PLATFORM_GPIO_PORT_C,
    PLATFORM_GPIO_PORT_D,
    PLATFORM_GPIO_PORT_E,
    PLATFORM_GPIO_PORT_F,
    PLATFORM_GPIO_PORT_G,
    PLATFORM_GPIO_PORT_H,
    PLATFORM_GPIO_PORT_I,
    PLATFORM_GPIO_PORT_J,
    PLATFORM_GPIO_PORT_K,
    PLATFORM_GPIO_PORT_M, /* STM32H7RS: ports M..P exist, I..L do not */
    PLATFORM_GPIO_PORT_N,
    PLATFORM_GPIO_PORT_O,
    PLATFORM_GPIO_PORT_P,
    PLATFORM_GPIO_PORT_COUNT,
} platform_gpio_port_t;

/** A single GPIO line: port + pin number (0..15). */
typedef struct {
    platform_gpio_port_t port;
    uint8_t pin;
} platform_gpio_t;

/** Drive an output pin high (true) or low (false). */
platform_status_t platform_gpio_write(platform_gpio_t gpio, bool state);

/** Read the current logic level of a pin. */
bool platform_gpio_read(platform_gpio_t gpio);

/** Toggle an output pin. */
platform_status_t platform_gpio_toggle(platform_gpio_t gpio);

/** Callback invoked (from ISR context, via the backend's single
 *  HAL_GPIO_EXTI_Callback() override) when `gpio`'s EXTI line fires. Edge
 *  polarity (rising/falling/both) is configured by generated
 *  MX_GPIO_Init(), not by this API -- call platform_gpio_read(gpio) inside
 *  the callback if you need to know which edge it was. */
typedef void (*platform_gpio_exti_callback_t)(platform_gpio_t gpio);

/** Register `callback` to run when `gpio`'s EXTI interrupt fires. Only one
 *  callback per pin *number* (0..15) can be registered at a time: the
 *  STM32 EXTI controller routes each pin number to a single source port
 *  (SYSCFG_EXTICRx), so two BOARD_* pins that share a pin number on
 *  different ports cannot both be registered simultaneously -- registering
 *  again for the same pin number replaces the previous callback. Pass
 *  NULL to unregister. Driver code must go through this instead of
 *  defining HAL_GPIO_EXTI_Callback() itself -- only the backend may do
 *  that, since just one definition of that weak symbol can exist in the
 *  final link. */
platform_status_t platform_gpio_register_exti_callback(platform_gpio_t gpio,
                                                         platform_gpio_exti_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_GPIO_H */
