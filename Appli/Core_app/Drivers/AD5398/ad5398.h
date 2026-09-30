/**
 * @file    ad5398.h
 * @brief   AD5398 driver: 10-bit, 120 mA current-sink DAC on I2C.
 *
 * Sets the drive current of the QRNG's analog noise source (see
 * Core_app/Middleware/QRNG/ADC_Noise/qrng_service_adc_noise.c). On H7S3 it replaces the MCU DAC
 * used on EVT2/H753, because the H7RS family has no DAC.
 *
 * Talks only to Core_app/Platform (platform_i2c/platform_gpio) and takes the bus and power-down
 * pin from board.h (BOARD_AD5398_I2C, BOARD_AD5398_PD_GPIO). No HAL handle is used directly.
 *
 * Device register (one 16-bit word, MSB first, same layout for read and write):
 *   bit 15      current enable: 1 = output on, 0 = output off (as in the Linux regulator driver,
 *               drivers/regulator/ad5398.c, AD5398_CURRENT_EN_MASK -- NOT a power-down bit)
 *   bits 13..4  D9..D0: sink current = D * 120 mA / 1024
 *   bits 3..0   don't care
 * The PD pin (treated as active high here -- not yet checked on this board) also switches the output off,
 * independently of bit 15.
 */
#ifndef AD5398_H
#define AD5398_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "platform.h"

/** Full-scale sink current, in microamps. */
#define AD5398_FULL_SCALE_UA 120000U

/** Attach to BOARD_AD5398_I2C, hold the PD pin high (output off), and check that the device answers its address.
 *  The bus itself must already be set up (bsp_init()). Safe to call more than once. */
platform_status_t ad5398_init(void);

/** Set the sink current to the nearest 10-bit step (about 117 uA per step) and switch the output
 *  on (PD pin low, enable bit 15 set in the same write). Reads the register back to
 *  confirm the write.
 *  Returns PLATFORM_INVALID_PARAM above AD5398_FULL_SCALE_UA. */
platform_status_t ad5398_set_current_ua(uint32_t current_ua);

/** Read back the programmed current (in microamps) and whether the output is on (enable bit 15
 *  set). Either pointer may be NULL. */
platform_status_t ad5398_get_current_ua(uint32_t *current_ua, bool *enabled);

/** Switch the output off: clear enable bit 15 and drive the PD pin high. The programmed code is kept. */
platform_status_t ad5398_power_down(void);

#ifdef __cplusplus
}
#endif

#endif /* AD5398_H */
