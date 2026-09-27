/**
 * @file    board.h
 * @brief   Single source of truth for this board's pin/bus assignments.
 *
 * Every chip pin/peripheral assignment for THIS BOARD lives here and only
 * here. Changing a pin, or swapping the MCU/board, means editing this one
 * file -- drivers under Core_app/Drivers (any of them) must never
 * hand-encode a port/pin/bus id themselves; they reference the named
 * BOARD_* constants below.
 *
 * Each entry mirrors a macro CubeMX generates into Inc/main.h from the
 * .ioc pinout -- re-check this file after regenerating main.h from a changed .ioc.
 */
#ifndef BSP_BOARD_H
#define BSP_BOARD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

/* ---- Custom board, STM32H7S3V8Y6TR (WLCSP101), 2026-09-26 ----
 * Pins come from the board schematic (exercise1.ioc, which CubeMX turns into main.h). Not on this board and removed:
 * ST33 secure element, user button, debug UART (USART3), PD13, and the fingerprint sensor wiring. */

#if EVT2_ENABLE_BIOMETRIC
#error "EVT2_ENABLE_BIOMETRIC: the FPC2530 fingerprint sensor is not wired on the STM32H7S3V8Y6TR board (no pins/USART in exercise1.ioc)"
#endif

/* ---- SE05x secure element -- Core_app/Drivers/SE05x ---- */
#define BOARD_SE052_I2C        PLATFORM_I2C_1                                   /* main.h: hi2c1 / I2C1 PB6/PB7 */
#define BOARD_SE052_EN_GPIO    ((platform_gpio_t){ PLATFORM_GPIO_PORT_C, 14U }) /* main.h: SE05x_ENABLE_Pin (PC14) */

/* ---- AD5398 current-sink DAC -- Core_app/Drivers/AD5398, drives the QRNG noise source ---- */
#define BOARD_AD5398_I2C       PLATFORM_I2C_1                                   /* shares I2C1 with the SE05x */
#define BOARD_AD5398_PD_GPIO   ((platform_gpio_t){ PLATFORM_GPIO_PORT_O, 2U })  /* main.h: LED_SINK_Pin (PO2); high = power down
                                                                         * (AD5398 datasheet: "PD is active high") */

/* ---- QRNG analog front end enables: active high, low (off) after reset -- see qrng_service_adc_noise.c ---- */
#define BOARD_PS_FIRST_STAGE_EN_GPIO  ((platform_gpio_t){ PLATFORM_GPIO_PORT_A, 8U })  /* main.h: PS_FIRST_STAGE_ENABLE_Pin (PA8) */
#define BOARD_PS_SECOND_STAGE_EN_GPIO ((platform_gpio_t){ PLATFORM_GPIO_PORT_B, 14U }) /* main.h: PS_SECOND_STAGE_ENABLE_Pin (PB14) */
#define BOARD_LED_EN_GPIO             ((platform_gpio_t){ PLATFORM_GPIO_PORT_M, 11U }) /* main.h: LED_ENABLE_Pin (PM11) */

/* SAFETY LOCK (2026-09-26, hardware problem on the board): 0 = the analog noise front end must stay OFF.
 * qrng_service_init() then never drives the three enables above high, puts the AD5398 into power-down (register PD
 * bit + BOARD_AD5398_PD_GPIO) and reports QRNG_ERROR, so nothing is ever read from the noise source. Media nonces
 * fall back to the hardware TRNG (media_protocol.c) and PQC randombytes() does the same. Set to 1 only after the
 * hardware is fixed and the power-up sequence is filled in (qrng_analog_front_end()). */
#define BOARD_QRNG_ANALOG_ENABLE 0

/* OSC_ENABLE (PC15) gates the 24 MHz HSE oscillator (USB PHY clock). Boot drives it high before SystemClock_Config()
 * and the Appli keeps it high (GPIO default in the .ioc); Core_app never touches it. */

/* ---- UARTs ----
 * No debug UART on this board: BOARD_DEBUG_UART is not defined, and app_log() does nothing. */

/* ---- ADC ---- */
#define BOARD_ADC              PLATFORM_ADC_2  /* logical id only -- the .ioc owns the pin/channel: PA5 = ADC2_INP18
                                                 * (PA5 does not reach ADC1), TIM1 TRGO (first edge only, continuous
                                                 * mode) + circular GPDMA1 channel 0 */

/* ---- Timers ---- */
#define BOARD_ADC_TRIGGER_TIMER PLATFORM_TIMER_1 /* main.h/main.c: htim1, paces BOARD_ADC via TRGO -- must be
                                                   * platform_timer_start()-ed for ADC conversions to happen */

/* ---- QRNG analog noise source -- Core_app/Middleware/QRNG/ADC_Noise ----
 * The noise source is BOARD_ADC sampling the analog noise circuit, enabled through the PS_*_STAGE / LED enables
 * above. H7S3 has no DAC peripheral (platform_dac.c returns PLATFORM_NOT_SUPPORTED), so the AD5398 sets the drive
 * current (BOARD_QRNG_DRIVE_CURRENT_UA). */
#define BOARD_QRNG_DAC          PLATFORM_DAC_1  /* EVT2/H753 only */
/* Noise-source drive current set through the AD5398 by qrng_service_init(). 20 mA is the operating point the
 * noise circuit needs to produce good noise; it is a property of this board's analog front-end. */
#define BOARD_QRNG_DRIVE_CURRENT_UA 20000U

#ifdef __cplusplus
}
#endif

#endif /* BSP_BOARD_H */
