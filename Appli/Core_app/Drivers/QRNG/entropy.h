/**
 * @file    entropy.h
 * @brief   Entropy source context and NIST 800-90B online health tests.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Inc\entropy.h, unchanged
 * except QRNG_-prefixed constants -- this file has no HAL/vendor
 * dependency at all (never did upstream either) and stays that way: the
 * backend (Core_app/Middleware/QRNG/ADC_Noise/qrng_service_adc_noise.c)
 * is the one that knows about DMA/Platform and drives `raw_pool`/
 * `buffer_1_ready`/`buffer_2_ready` below by polling
 * platform_adc_dma_pos() -- this file has no idea an ADC exists.
 */
#ifndef QRNG_ENTROPY_H
#define QRNG_ENTROPY_H

#include "qrng_constant.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint16_t sample_t;

typedef enum {
    ENTROPY_HEALTH_OK,
    ENTROPY_HEALTH_RCT_ERROR,
    ENTROPY_HEALTH_APT_ERROR,
} entropy_health_t;

typedef struct entropy_context_t {
    uint16_t *raw_pool;         /* Pointer to the ADC sample buffer half currently owned by the caller */
    volatile uint8_t buffer_1_ready; /* Set when the first half of the buffer is ready */
    volatile uint8_t buffer_2_ready; /* Set when the second half of the buffer is ready */
    uint8_t is_source_ready;    /* Health status of entropy source */
    uint32_t healthy_samples;   /* Number of samples that have passed the online health test */
    entropy_health_t health_status;
} entropy_context_t;

/**
 * @brief Initialize the entropy context for processing data
 */
void entropy_init(entropy_context_t *es);

/**
 * @brief Wait for and claim whichever buffer half became ready
 * (buffer_1_ready or buffer_2_ready), setting `raw_pool` to point at it.
 */
void entropy_get_samples(entropy_context_t *es);

/**
 * @brief Run the Online Health Test (NIST 800-90B Repetitive Count Test
 * + Adaptive Proportion Test) over the currently claimed buffer half.
 */
void entropy_run_health_checks(entropy_context_t *es, bool enable);

/**
 * @brief Reset the entropy context to start collecting new entropy.
 */
void entropy_reset(entropy_context_t *es);

/**
 * @brief Check if the online health test has flagged an error.
 */
static inline bool entropy_health_check_error(entropy_context_t *es)
{
    return (es->health_status != ENTROPY_HEALTH_OK);
}

#endif /* QRNG_ENTROPY_H */
