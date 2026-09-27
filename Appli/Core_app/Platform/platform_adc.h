/**
 * @file    platform_adc.h
 * @brief   MCU-agnostic ADC interface of the Platform HAL.
 *
 * Resolution/channel/trigger-source configuration is the code
 * generator's job (e.g. STM32CubeMX's MX_ADCx_Init() in main.c) and is
 * not part of this API. platform_adc_init() only attaches to an
 * instance that code already brought up; platform_adc_read()'s timeout
 * is meaningful only if that instance is configured for a
 * software-reachable trigger -- an instance generated with an external
 * hardware trigger (e.g. a timer TRGO) will time out until that trigger
 * actually fires, by design.
 */
#ifndef PLATFORM_ADC_H
#define PLATFORM_ADC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "platform.h"

/** Logical ADC instances exposed by the board. */
typedef enum {
    PLATFORM_ADC_1 = 0,
    PLATFORM_ADC_2,
    PLATFORM_ADC_COUNT,
} platform_adc_id_t;

/** Attach to an instance already brought up by generated init code.
 *  Returns PLATFORM_ERROR if that init has not run yet. Safe to call
 *  more than once. */
platform_status_t platform_adc_init(platform_adc_id_t id);

/** Detach from the instance. Does not touch clocks/HAL peripheral state
 *  -- those stay owned by generated init code. */
platform_status_t platform_adc_deinit(platform_adc_id_t id);

/** Blocking single conversion on the instance's configured channel. */
platform_status_t platform_adc_read(platform_adc_id_t id, uint32_t *value, uint32_t timeout_ms);

/**
 * Start continuous circular-DMA sampling into `buffer` (`length` samples),
 * ring-buffer style — use platform_adc_dma_pos() to poll how far the
 * buffer has been filled.
 */
platform_status_t platform_adc_start_dma(platform_adc_id_t id, uint16_t *buffer, uint32_t length);
platform_status_t platform_adc_stop_dma(platform_adc_id_t id);

/** Current write position (0..length-1) inside the buffer passed to
 *  platform_adc_start_dma(). */
uint32_t platform_adc_dma_pos(platform_adc_id_t id, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_ADC_H */
