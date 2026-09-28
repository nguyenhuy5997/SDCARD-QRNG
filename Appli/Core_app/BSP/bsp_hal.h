/**
 * @file    bsp_hal.h
 * @brief   The one HAL entry point Core_app's MCU-specific code includes on STM32H7RSxx (replaces EVT2's
 *          `#include "stm32h7xx_hal.h"` + `#include "main.h"` pair).
 *
 * Since 2026-09-26 the peripherals, their HAL handles and the pin macros (SE05x_ENABLE_Pin, LED_ENABLE_Pin, ...) come from
 * CubeMX (exercise1.ioc -> Core/Src/main.c, Core/Inc/main.h). Change pins and peripheral settings in the .ioc and
 * regenerate; keep board.h's platform_gpio_t view of the same pins in sync by hand.
 * bsp_h7s3.c only holds what CubeMX does not generate (see its doc comment).
 */
#ifndef BSP_HAL_H
#define BSP_HAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "main.h" /* CubeMX: HAL + pin macros + Error_Handler() */

/* ---- HAL handles (defined by CubeMX in Core/Src/main.c) ---- */
extern ADC_HandleTypeDef  hadc2;
extern CRYP_HandleTypeDef hcryp;
extern HASH_HandleTypeDef hhash;
extern RNG_HandleTypeDef  hrng;
extern CRC_HandleTypeDef  hcrc;
extern I2C_HandleTypeDef  hi2c1;
extern TIM_HandleTypeDef  htim1;
extern DTS_HandleTypeDef  hdts;
#if EVT2_ENABLE_BIOMETRIC
extern UART_HandleTypeDef huart1; /* bsp_h7s3.c (the board has no USART in the .ioc) */
#endif

/* ---- FPC2530 fingerprint sensor pins: not in the .ioc (EVT2_ENABLE_BIOMETRIC, see board.h) ----
 * FPC2530_IRQ and FPC2530_IF_CFG_1 corrected 2026-09-25: checked against the real board (the same fixed-pin shield
 * moved from a NUCLEO-H753ZI to this NUCLEO-H7S3L8) they land on PF11/PF15, not EVT2's PF10/PG14. */
#define FPC2530_RST_N_Pin          GPIO_PIN_0
#define FPC2530_RST_N_GPIO_Port    GPIOC
#define FPC2530_CS_N_Pin           GPIO_PIN_3
#define FPC2530_CS_N_GPIO_Port     GPIOA
#define FPC2530_IRQ_Pin            GPIO_PIN_11
#define FPC2530_IRQ_GPIO_Port      GPIOF
#define FPC2530_IRQ_EXTI_IRQn      EXTI11_IRQn
#define FPC2530_IF_CFG_1_Pin       GPIO_PIN_15
#define FPC2530_IF_CFG_1_GPIO_Port GPIOF

/** Very first call in main() (USER CODE 1, before CubeMX's MPU_Config()): clocks the AHB SRAM, zero-fills
 *  .ahb_sram_bss (not covered by the startup code) and cleans/invalidates the D-Cache. */
void bsp_early_init(void);

/** Hardware CubeMX does not own: the FPC2530 sensor (pins, EXTI11, USART1 + DMA) with EVT2_ENABLE_BIOMETRIC=1,
 *  nothing otherwise. Called after the generated MX_*_Init() calls. */
void bsp_init(void);

#if EVT2_DIAGNOSTICS
/** Boot-time checks of what the H7S3 port changed (GCM/SHA-256/RNG KATs, memory layout) -- bsp_port_self_test.c. */
bool bsp_port_self_test(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BSP_HAL_H */
