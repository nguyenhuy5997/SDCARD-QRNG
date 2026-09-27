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
 * @file    hal_common.c
 * @brief   Implementation of common hal functions.
 */

/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "hal_common.h"

#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "platform.h"
#include "board.h"


volatile bool fpc2530_irq_active;
#if EVT2_DIAGNOSTICS /* user-button test hook */
static uint32_t button_down_start = 0;
#endif
static uint32_t button_down_time = 0;
static bool button_down = false;

uint32_t hal_check_button_pressed(void)
{
    uint32_t button_time = button_down_time;
    if (!button_down) {
        button_down_time = 0;
    }
    return button_down ? 0 : button_time;
}

void hal_set_led_status(hal_led_status_t status)
{
}

/* EXTI wiring goes through platform_gpio_register_exti_callback() instead
 * of defining HAL_GPIO_EXTI_Callback() here -- Core_app/Platform's
 * platform_gpio.c is the only file allowed to define that symbol (see its
 * doc comment). hal_common_init() below does the registration; nothing
 * fires until that has run. */
static void fpc2530_irq_callback(platform_gpio_t gpio)
{
    (void)gpio;
    fpc2530_irq_active = true;
}

#if EVT2_DIAGNOSTICS /* user-button test hook */
static void user_button_callback(platform_gpio_t gpio)
{
    /* BOARD_USER_BUTTON_GPIO reads high while released, low while pressed
     * (GPIO_NOPULL + external pull-up, IT_RISING_FALLING in MX_GPIO_Init())
     * -- same polarity the previous separate Rising/Falling callbacks each
     * hardcoded for one edge; reading the level here after the edge fired
     * covers both in one place. */
    if (!platform_gpio_read(gpio)) {
        button_down_start = platform_get_tick_ms();
        button_down = true;
    } else {
        button_down_time = platform_get_tick_ms() - button_down_start;
        button_down = false;
    }
}
#endif

void hal_common_init(void)
{
    (void)platform_gpio_register_exti_callback(BOARD_FPC2530_IRQ_GPIO, fpc2530_irq_callback);
#if EVT2_DIAGNOSTICS /* user-button test hook */
    (void)platform_gpio_register_exti_callback(BOARD_USER_BUTTON_GPIO, user_button_callback);
#endif
}
/* Reset and interface-select go through Core_app/Platform + board.h, same
 * as Core_app/Drivers/SE05x/platform/stm32h7/src/ax_reset_stm32h7.c does
 * for the SE052F's enable/reset pin -- board.h is the only place that
 * knows these are PC0/PG14 on this board. */
void hal_reset_device(void)
{
    platform_gpio_write(BOARD_FPC2530_RST_GPIO, false);
    platform_delay_ms(10);
    platform_gpio_write(BOARD_FPC2530_RST_GPIO, true);
}

void hal_set_if_config(hal_if_config_t config)
{
    switch(config) {
        case HAL_IF_CONFIG_UART:
            platform_gpio_write(BOARD_FPC2530_IF_CFG_1_GPIO, true);
            /* platform_gpio_write(BOARD_FPC2530_IF_CFG_2_GPIO, false); */
            break;
        case HAL_IF_CONFIG_I2C:
            platform_gpio_write(BOARD_FPC2530_IF_CFG_1_GPIO, true);
            /* platform_gpio_write(BOARD_FPC2530_IF_CFG_2_GPIO, true); */
            break;
        case HAL_IF_CONFIG_SPI:
        default:
            platform_gpio_write(BOARD_FPC2530_IF_CFG_1_GPIO, false);
            /* platform_gpio_write(BOARD_FPC2530_IF_CFG_2_GPIO, false); */
            break;
    }
}

#endif /* EVT2_ENABLE_BIOMETRIC */
