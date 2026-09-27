/**
 * @file    platform_hash.c
 * @brief   STM32H7RSxx implementation of the Platform hash/HMAC interface.
 *
 * Ported from EVT2's STM32H7xx version. The H7RS HASH HAL is the newer API
 * generation (same as U5/H5): the algorithm is an Init field
 * (Init.Algorithm) instead of being baked into the function name, and the
 * entry points are HAL_HASH_Start()/HAL_HASH_HMAC_Start() instead of H7's
 * HAL_HASHEx_SHA256_Start()/HAL_HMACEx_SHA256_Start(). Verified against
 * stm32h7rsxx_hal_hash.c (V1.3.0): HAL_HASH_Start() clears HASH_CR_MODE
 * itself and HAL_HASH_HMAC_Start() sets HMAC mode + LKEY and loads
 * Init.pKey/KeySize, so re-running HAL_HASH_Init() per call (to pick the
 * data type/algorithm) keeps the same shape as the H7 original. H7's
 * HASH_DATATYPE_8B is spelled HASH_BYTE_SWAP in this HAL (same CR.DATATYPE
 * value: 8-bit data, bytes swapped).
 *
 * Clock and the base HAL_HASH_Init() are done by bsp_h7s3.c's
 * MX_HASH_Init(), called from main() before any
 * application code runs. platform_hmac_sha256() re-runs HAL_HASH_Init()
 * with the caller's key on every call -- unlike the other Platform
 * modules, the HMAC key is itself an operation parameter here (like an
 * I2C device address), not board configuration, so this is a business
 * operation, not touching what MX_HASH_Init() owns (clock/instance).
 * This file never calls HAL_HASH_DeInit() (that would run the generated
 * HAL_HASH_MspDeInit() and disable the clock out from under every other
 * user of this peripheral).
 *
 * Tried and reverted: caching the last key and skipping HAL_HASH_Init()
 * when extractor_run()'s HMAC path (Core_app/Drivers/QRNG/extractor.c)
 * calls this 32x per draw with an unchanged key, on the theory that
 * HAL_HASH_Init()'s register reconfiguration was redundant work. On real
 * hardware (via Core_app/App/protocol_adapters/qrng_protocol.c's
 * BENCH_ENTROPY) this measured SLOWER, not faster (726.7 draws/s vs
 * 853.8 draws/s baseline) -- HAL_HMACEx_SHA256_Start() apparently does
 * more work, or waits longer, when the peripheral wasn't just
 * re-initialized, more than offsetting whatever HAL_HASH_Init() itself
 * costs. Verified correct either way (RFC 4231 KAT still matched with
 * the cache path exercised), just not the speed win it looked like on
 * paper -- if revisiting this, benchmark on real hardware again rather
 * than trusting the "redundant work" reasoning alone.
 */
#include "platform.h"
#include "bsp_hal.h"

extern HASH_HandleTypeDef hhash;

static bool s_ready;

platform_status_t platform_hash_init(void)
{
    if (s_ready) {
        return PLATFORM_OK;
    }
    if (HAL_HASH_GetState(&hhash) == HAL_HASH_STATE_RESET) {
        /* MX_HASH_Init() has not run yet -- a call-order bug in the
         * caller, not something Platform can fix by initializing the
         * peripheral itself. */
        return PLATFORM_ERROR;
    }

    s_ready = true;
    return PLATFORM_OK;
}

platform_status_t platform_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                                        uint8_t digest[32])
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    if (key == NULL || data == NULL || digest == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    hhash.Init.DataType = HASH_BYTE_SWAP;
    hhash.Init.Algorithm = HASH_ALGOSELECTION_SHA256;
    hhash.Init.pKey = (uint8_t *)key;
    hhash.Init.KeySize = (uint32_t)key_len;

    if (HAL_HASH_Init(&hhash) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    if (HAL_HASH_HMAC_Start(&hhash, data, (uint32_t)data_len, digest, HAL_MAX_DELAY) != HAL_OK) {
        return PLATFORM_ERROR;
    }

    return PLATFORM_OK;
}

platform_status_t platform_sha256(const uint8_t *data, size_t data_len, uint8_t digest[32])
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    if (data == NULL || digest == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    /* CubeMX's generated MX_HASH_Init() commonly leaves DataType at
     * HASH_DATATYPE_32B (no swap) -- wrong for a plain uint8_t byte
     * buffer on this little-endian core, silently producing a different
     * digest than hashlib.sha256()/java.security.MessageDigest over the
     * same bytes (same class of bug platform_hmac_sha256() above already
     * forces HASH_BYTE_SWAP for). Force it here too. */
    hhash.Init.DataType = HASH_BYTE_SWAP;
    hhash.Init.Algorithm = HASH_ALGOSELECTION_SHA256;

    if (HAL_HASH_Init(&hhash) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    if (HAL_HASH_Start(&hhash, (uint8_t *)data, (uint32_t)data_len, digest, HAL_MAX_DELAY) != HAL_OK) {
        return PLATFORM_ERROR;
    }

    return PLATFORM_OK;
}
