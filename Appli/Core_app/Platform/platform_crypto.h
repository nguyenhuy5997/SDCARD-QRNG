/**
 * @file    platform_crypto.h
 * @brief   MCU-agnostic block-cipher interface of the Platform HAL.
 *
 * Clock/config is the code generator's job (e.g. STM32CubeMX's
 * MX_CRYP_Init() in main.c) and is not part of this API.
 * platform_crypto_init() only attaches to an instance already brought up.
 */
#ifndef PLATFORM_CRYPTO_H
#define PLATFORM_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "platform.h"

/** Attach to the CRYP (AES accelerator) peripheral already brought up by
 *  generated init code. Returns PLATFORM_ERROR if that init has not run
 *  yet. Safe to call more than once. */
platform_status_t platform_crypto_init(void);

/** AES-128 CBC-MAC of `data` (`data_len` bytes, must be a non-zero
 *  multiple of 16) using `key` (16 bytes) and a zero IV -- runs
 *  AES-128-CBC encryption over the whole buffer and keeps only the
 *  final 16-byte ciphertext block, per the standard CBC-MAC
 *  construction. `mac` must point at 16 bytes. */
platform_status_t platform_aes128_cbc_mac(const uint8_t key[16], const uint8_t *data, size_t data_len,
                                           uint8_t mac[16]);

/** Same computation as calling platform_aes128_cbc_mac() `num_blocks`
 *  times back-to-back -- `num_blocks` independent CBC-MAC sub-operations,
 *  each over `block_len` bytes (must be a non-zero multiple of 16) of
 *  `data`, all under the same 16-byte `key` and a fresh zero IV per
 *  sub-block. `mac_out` must point at `num_blocks * 16` bytes (one MAC
 *  per sub-block, concatenated in order). Amortizes the CRYP
 *  peripheral's key-load across all sub-blocks instead of repeating it
 *  per call -- see platform_crypto.c's doc comment. */
platform_status_t platform_aes128_cbc_mac_batch(const uint8_t key[16], const uint8_t *data, size_t block_len,
                                                 size_t num_blocks, uint8_t *mac_out);

/** AES-256-GCM encrypt `len` bytes of `plain` under `key` (32 bytes) and a
 *  96-bit `nonce`, writing `len` bytes of ciphertext to `cipher_out` and the
 *  16-byte authentication tag to `tag_out`. `nonce` must never repeat under
 *  the same key (standard GCM requirement -- the media-protocol layer is
 *  responsible for picking a fresh nonce per call, e.g. a per-session random
 *  prefix plus a monotonically increasing counter). `cipher_out` may alias
 *  `plain` (in place). Returns PLATFORM_ERROR on any CRYP HAL failure. */
platform_status_t platform_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *plain,
                                               uint32_t len, uint8_t *cipher_out, uint8_t tag_out[16]);

/** AES-256-GCM decrypt+verify `len` bytes of `cipher` under `key` (32 bytes)
 *  and a 96-bit `nonce`, writing `len` bytes of plaintext to `plain_out`
 *  ONLY if the 16-byte `tag` verifies -- on a tag mismatch this returns
 *  PLATFORM_ERROR and `plain_out` must be treated as undefined (do not feed
 *  it to a decoder/renderer: it is exactly the "encrypted video call"
 *  tamper case this function exists to catch). `plain_out` may alias
 *  `cipher` (in place). */
platform_status_t platform_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *cipher,
                                               uint32_t len, const uint8_t tag[16], uint8_t *plain_out);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_CRYPTO_H */
