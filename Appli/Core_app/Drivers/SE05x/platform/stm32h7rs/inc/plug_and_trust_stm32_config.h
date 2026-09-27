#ifndef PLUG_AND_TRUST_STM32_CONFIG_H
#define PLUG_AND_TRUST_STM32_CONFIG_H

#include "platform.h"
#include "board.h" /* BOARD_SE052_I2C, BOARD_SE052_EN_GPIO -- Core_app/BSP, the project's single board pin/bus map */

/* SMCOM_I2C_ADDRESS in phNxpEsePal_i2c.h / sci2c_cfg.h is 0x90, already in
 * the 8-bit/HAL DevAddress format; 0x48 is its 7-bit form, only used if a
 * caller ever passes a 7-bit address directly (see i2c_stm32h7.c). */
#define PLUG_AND_TRUST_STM32_I2C_ADDRESS_8BIT 0x90U
#define PLUG_AND_TRUST_STM32_I2C_ADDRESS_7BIT 0x48U
#define PLUG_AND_TRUST_STM32_I2C_TIMEOUT_MS 1000U

/* RNG is only needed for Platform SCP03 (see README.md "Enabling Platform
 * SCP03"). Core_app/Platform does not have an RNG module yet, so this is
 * the one remaining exception that still reaches into the CubeMX-generated
 * main.h/hrng directly instead of going through Platform/BSP; revisit
 * once a platform_rng.h (and a BOARD_RNG entry in board.h) exists.
 * Define PLUG_AND_TRUST_STM32_ENABLE_SCP03 as a project-wide preprocessor
 * symbol (alongside enabling RNG in CubeMX / MX_RNG_Init()) to turn this
 * on. */
#if defined(PLUG_AND_TRUST_STM32_ENABLE_SCP03)
#include "bsp_hal.h"
extern RNG_HandleTypeDef hrng;
#define PLUG_AND_TRUST_STM32_RNG_HANDLE (&hrng)
#endif

#endif /* PLUG_AND_TRUST_STM32_CONFIG_H */
