/**
 * @file    platform_rng.c
 * @brief   STM32H7xx implementation of the Platform RNG interface.
 *
 * Clock (HSI48) and HAL_RNG_Init() are done by the CubeMX-generated
 * MX_RNG_Init() in bsp_h7s3.c (EVT2: Src/main.c), called from main() before any
 * application code runs.
 *
 * IMPORTANT: this file is not RNG's only user -- Core_app/Drivers/
 * FPC5234/fpc_hal_crypto.c's fpc_hal_crypto_gen_random() (vendor code)
 * also drives it, through its own separate, local `RNG_HandleTypeDef
 * hrng = {0}` (a different C struct, same hardware: both set
 * `.Instance = RNG`), and calls HAL_RNG_DeInit() on it when done. That
 * disables RCC_AHB3ENR_RNGEN (H7RS; AHB2ENR on H7) -- the peripheral's one shared clock-enable
 * bit -- regardless of which handle asked for it, leaving this file's
 * `hrng` silently clocked-off even though `hrng.State` (a separate
 * struct field the other handle's DeInit never touches) still reads
 * HAL_RNG_STATE_READY. A plain HAL_RNG_GenerateRandomNumber() call would
 * then just time out waiting for RNG_FLAG_DRDY forever (2ms timeout,
 * retried indefinitely by callers like
 * Core_app/Drivers/QRNG/toeplitz_util.c's generate_toeplitz_bits()) --
 * exactly the same class of bug as
 * Core_app/Platform/STM32H7xx/platform_crypto.c's shared-CRYP problem,
 * see that file's doc comment for the full mechanism. ensure_clock()
 * below defends against it the same way: force `hrng.State =
 * HAL_RNG_STATE_RESET` before HAL_RNG_Init() so MspInit (and its
 * __HAL_RCC_RNG_CLK_ENABLE()) always re-runs. This file still never
 * calls HAL_RNG_DeInit() itself, to avoid inflicting the same problem
 * back onto FPC5234.
 */
#include "platform.h"
#include "bsp_hal.h"
#include <string.h>

extern RNG_HandleTypeDef hrng;

static bool s_ready;

static platform_status_t ensure_clock(void)
{
    hrng.State = HAL_RNG_STATE_RESET;
    return (HAL_RNG_Init(&hrng) == HAL_OK) ? PLATFORM_OK : PLATFORM_ERROR;
}

platform_status_t platform_rng_init(void)
{
    if (s_ready) {
        return PLATFORM_OK;
    }
    if (HAL_RNG_GetState(&hrng) == HAL_RNG_STATE_RESET) {
        /* MX_RNG_Init() has not run yet -- a call-order bug in the
         * caller, not something Platform can fix by initializing the
         * peripheral itself. */
        return PLATFORM_ERROR;
    }

    s_ready = true;
    return PLATFORM_OK;
}

platform_status_t platform_rng_get_word(uint32_t *word)
{
    if (!s_ready || word == NULL) {
        return s_ready ? PLATFORM_INVALID_PARAM : PLATFORM_ERROR;
    }
    if (ensure_clock() != PLATFORM_OK) {
        return PLATFORM_ERROR;
    }

    return (HAL_RNG_GenerateRandomNumber(&hrng, word) == HAL_OK) ? PLATFORM_OK : PLATFORM_ERROR;
}

platform_status_t platform_rng_get_bytes(uint8_t *buf, size_t len)
{
    if (!s_ready || buf == NULL) {
        return s_ready ? PLATFORM_INVALID_PARAM : PLATFORM_ERROR;
    }
    if (ensure_clock() != PLATFORM_OK) {
        return PLATFORM_ERROR;
    }

    while (len > 0U) {
        uint32_t word;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &word) != HAL_OK) {
            return PLATFORM_ERROR;
        }

        size_t chunk = (len < sizeof(word)) ? len : sizeof(word);
        memcpy(buf, &word, chunk);
        buf += chunk;
        len -= chunk;
    }

    return PLATFORM_OK;
}
