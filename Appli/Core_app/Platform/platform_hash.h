/**
 * @file    platform_hash.h
 * @brief   MCU-agnostic hash/HMAC interface of the Platform HAL.
 *
 * Clock/config is the code generator's job (e.g. STM32CubeMX's
 * MX_HASH_Init() in main.c) and is not part of this API.
 * platform_hash_init() only attaches to an instance already brought up.
 */
#ifndef PLATFORM_HASH_H
#define PLATFORM_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "platform.h"

/** Attach to the HASH peripheral already brought up by generated init
 *  code. Returns PLATFORM_ERROR if that init has not run yet. Safe to
 *  call more than once. */
platform_status_t platform_hash_init(void);

/** HMAC-SHA256 of `data` (`data_len` bytes) using `key` (`key_len`
 *  bytes, any length). `digest` must point at 32 bytes. */
platform_status_t platform_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                                        uint8_t digest[32]);

/** Plain (unkeyed) SHA-256 of `data` (`data_len` bytes). `digest` must
 *  point at 32 bytes. Used by media_protocol.c's BATCH-mode END_STREAM to
 *  verify the sender's declared stream hash -- plain, not HMAC, since
 *  that check is an integrity check against transport corruption (the
 *  sender already knows its own plaintext), not an authenticity check
 *  (AES-256-GCM's tag is what provides that, on the ciphertext). */
platform_status_t platform_sha256(const uint8_t *data, size_t data_len, uint8_t digest[32]);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_HASH_H */
