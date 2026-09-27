/**
 * @file    platform_dac.h
 * @brief   MCU-agnostic DAC interface of the Platform HAL.
 *
 * Channel/alignment configuration is the code generator's job (e.g.
 * STM32CubeMX's MX_DACx_Init() in main.c) and is not part of this API.
 * platform_dac_init() only attaches to an instance already brought up.
 */
#ifndef PLATFORM_DAC_H
#define PLATFORM_DAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "platform.h"

/** Logical DAC instances exposed by the board. */
typedef enum {
    PLATFORM_DAC_1 = 0,
    PLATFORM_DAC_COUNT,
} platform_dac_id_t;

/** Attach to a DAC already brought up by generated init code. Returns
 *  PLATFORM_ERROR if that init has not run yet. Safe to call more than
 *  once. */
platform_status_t platform_dac_init(platform_dac_id_t id);

/** Start/stop the DAC's analog output. */
platform_status_t platform_dac_start(platform_dac_id_t id);
platform_status_t platform_dac_stop(platform_dac_id_t id);

/** Set the output value (12-bit right-aligned, 0..4095). */
platform_status_t platform_dac_set_value(platform_dac_id_t id, uint16_t value);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_DAC_H */
