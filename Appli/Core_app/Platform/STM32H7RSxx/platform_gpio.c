/**
 * @file    platform_gpio.c
 * @brief   STM32H7xx implementation of the Platform GPIO interface.
 *
 * Pin mode/speed/pull/AF and port clock setup are done by the
 * CubeMX-generated MX_GPIO_Init() in bsp_h7s3.c (EVT2: Src/main.c), called from main()
 * before any application code runs. This file only implements the
 * runtime business operations (write/read/toggle, EXTI callback dispatch)
 * on pins that are already configured by that generated code -- it never
 * touches RCC or calls HAL_GPIO_Init()/HAL_GPIO_DeInit() itself. It does,
 * however, own the one HAL_GPIO_EXTI_Callback() weak override for the
 * whole firmware -- see platform_gpio_register_exti_callback().
 */
#include "platform.h"
#include "bsp_hal.h"

static GPIO_TypeDef *const s_port_table[PLATFORM_GPIO_PORT_COUNT] = {
    [PLATFORM_GPIO_PORT_A] = GPIOA,
    [PLATFORM_GPIO_PORT_B] = GPIOB,
    [PLATFORM_GPIO_PORT_C] = GPIOC,
    [PLATFORM_GPIO_PORT_D] = GPIOD,
    [PLATFORM_GPIO_PORT_E] = GPIOE,
    [PLATFORM_GPIO_PORT_F] = GPIOF,
    [PLATFORM_GPIO_PORT_G] = GPIOG,
    [PLATFORM_GPIO_PORT_H] = GPIOH,
#if defined(GPIOI)
    [PLATFORM_GPIO_PORT_I] = GPIOI,
#endif
#if defined(GPIOJ)
    [PLATFORM_GPIO_PORT_J] = GPIOJ,
#endif
#if defined(GPIOK)
    [PLATFORM_GPIO_PORT_K] = GPIOK,
#endif
#if defined(GPIOM)
    [PLATFORM_GPIO_PORT_M] = GPIOM,
#endif
#if defined(GPION)
    [PLATFORM_GPIO_PORT_N] = GPION,
#endif
#if defined(GPIOO)
    [PLATFORM_GPIO_PORT_O] = GPIOO,
#endif
#if defined(GPIOP)
    [PLATFORM_GPIO_PORT_P] = GPIOP,
#endif
};

static bool gpio_is_valid(platform_gpio_t gpio)
{
    return (gpio.port < PLATFORM_GPIO_PORT_COUNT) && (s_port_table[gpio.port] != NULL) && (gpio.pin <= 15U);
}

platform_status_t platform_gpio_write(platform_gpio_t gpio, bool state)
{
    if (!gpio_is_valid(gpio)) {
        return PLATFORM_INVALID_PARAM;
    }

    HAL_GPIO_WritePin(s_port_table[gpio.port], (uint16_t)(1U << gpio.pin),
                       state ? GPIO_PIN_SET : GPIO_PIN_RESET);
    return PLATFORM_OK;
}

bool platform_gpio_read(platform_gpio_t gpio)
{
    if (!gpio_is_valid(gpio)) {
        return false;
    }

    return HAL_GPIO_ReadPin(s_port_table[gpio.port], (uint16_t)(1U << gpio.pin)) == GPIO_PIN_SET;
}

platform_status_t platform_gpio_toggle(platform_gpio_t gpio)
{
    if (!gpio_is_valid(gpio)) {
        return PLATFORM_INVALID_PARAM;
    }

    HAL_GPIO_TogglePin(s_port_table[gpio.port], (uint16_t)(1U << gpio.pin));
    return PLATFORM_OK;
}

/* Indexed by pin number (0..15) -- see platform_gpio_register_exti_callback()'s
 * doc comment on why one slot per pin number (not per port+pin) is correct. */
static platform_gpio_exti_callback_t s_exti_callback[16];
static platform_gpio_t s_exti_gpio[16];

platform_status_t platform_gpio_register_exti_callback(platform_gpio_t gpio, platform_gpio_exti_callback_t callback)
{
    if (!gpio_is_valid(gpio)) {
        return PLATFORM_INVALID_PARAM;
    }

    s_exti_callback[gpio.pin] = callback;
    s_exti_gpio[gpio.pin] = gpio;
    return PLATFORM_OK;
}

/* The one weak HAL_GPIO_EXTI_Callback() override for the whole firmware --
 * generated MX_GPIO_Init()/stm32h7xx_it.c's *_IRQHandler()s already call
 * HAL_GPIO_EXTI_IRQHandler(), which calls this. Every EXTI-driven driver
 * (Core_app/Drivers/FPC5234, ...) must reach it only through
 * platform_gpio_register_exti_callback() -- no other file may define this
 * symbol, or the link fails. */
void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin)
{
    for (uint8_t pin = 0; pin < 16U; pin++) {
        if ((GPIO_Pin & (uint16_t)(1U << pin)) != 0U && s_exti_callback[pin] != NULL) {
            s_exti_callback[pin](s_exti_gpio[pin]);
        }
    }
}
