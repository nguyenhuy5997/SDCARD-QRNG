/**
 * @file    hmac_sha256.h
 * @brief   HMAC-SHA256 extractor.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Inc\hmac_sha256.h.
 * Upstream supported two backends (HMAC_USE_STMCRYPT, the ST proprietary
 * X-CUBE-CRYPTOLIB, or HMAC_USE_HARDWARE_ACCEL calling HAL_HASH/
 * HAL_HMACEx_SHA256_Start directly, noted there as "Only available on
 * STM32H753" -- exactly this chip). This port always uses the hardware
 * path, through Core_app/Platform/platform_hash.h instead of HAL
 * directly, so this file has no HAL dependency and needs no extra
 * prebuilt library.
 */
#ifndef QRNG_HMAC_SHA256_H
#define QRNG_HMAC_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qrng_constant.h"

/** No-op (kept for call-site symmetry with the Toeplitz/AES extractors
 *  -- the hardware path needs no persistent context setup). */
void hmac_sha256_init(void);

/** Set the key used by hmac_sha256_extractor(). */
void hmac_sha256_set_key(const uint8_t *key, uint32_t keySize);

/** Run HMAC-SHA256 (key from hmac_sha256_set_key()) over `input`
 *  (`inLen` bytes), writing the 32-byte MAC to `output`. Returns false if
 *  the underlying platform_hmac_sha256() call fails (e.g.
 *  platform_hash_init() was never called) -- `output` is left untouched
 *  in that case, never silently filled with stale/uninitialized data. */
bool hmac_sha256_extractor(const uint8_t *input, uint32_t inLen, uint8_t output[QRNG_HMAC_BLOCK_SIZE]);

#endif /* QRNG_HMAC_SHA256_H */
