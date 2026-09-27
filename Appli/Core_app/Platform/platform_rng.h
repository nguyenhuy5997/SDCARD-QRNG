/**
 * @file    platform_rng.h
 * @brief   MCU-agnostic hardware RNG interface of the Platform HAL.
 *
 * Clock/config is the code generator's job (e.g. STM32CubeMX's
 * MX_RNG_Init() in main.c) and is not part of this API.
 * platform_rng_init() only attaches to an instance already brought up.
 */
#ifndef PLATFORM_RNG_H
#define PLATFORM_RNG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "platform.h"

/** Attach to the RNG already brought up by generated init code. Returns
 *  PLATFORM_ERROR if that init has not run yet. Safe to call more than
 *  once. */
platform_status_t platform_rng_init(void);

/** Fill `buf` with `len` random bytes from the hardware TRNG. */
platform_status_t platform_rng_get_bytes(uint8_t *buf, size_t len);

/** Convenience: a single random 32-bit word. */
platform_status_t platform_rng_get_word(uint32_t *word);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_RNG_H */
