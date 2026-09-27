/**
 * @file    aes_cbc_mac.h
 * @brief   AES-128 CBC-MAC extractor.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Inc\aes_128_cbc_mac.h --
 * upstream's default backend (AES_USE_ARMCORTEXM) is hand-written
 * Cortex-M assembly needing custom linker script sections
 * (__aes_tables_start__/__aes_tables_end__) this project's linker script
 * does not define; the alternative software backends need either ST's
 * proprietary X-CUBE-CRYPTOLIB or vendoring a third-party AES library.
 * This port instead uses STM32H753's own CRYP hardware AES accelerator,
 * through Core_app/Platform/platform_crypto.h -- already generated and
 * brought up by CubeMX (Src/main.c's MX_CRYP_Init(), the same `hcryp`
 * instance) and otherwise unused, so this needs no new dependency and no
 * linker surgery, matching how hmac_sha256.h uses platform_hash.h.
 *
 * AES-128 CBC-MAC is a standard, deterministic construction (encrypt the
 * whole buffer under AES-128-CBC with a zero IV, keep the last
 * ciphertext block) -- computing it in hardware instead of software
 * produces the identical result for the same key/input, verified against
 * the published FIPS-197 Appendix B AES-128 test vector (see
 * Core_app/App/app_main.c's qrng_service_self_test_aes() call site).
 */
#ifndef QRNG_AES_CBC_MAC_H
#define QRNG_AES_CBC_MAC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qrng_constant.h"

/** No-op (kept for call-site symmetry with the Toeplitz/HMAC extractors
 *  -- the hardware path needs no persistent context setup). */
void aes_cbc_mac_init(void);

/** Set the 16-byte key used by aes_cbc_mac_extractor(). */
void aes_cbc_mac_set_key(const uint8_t key[QRNG_AES_BLOCK_SIZE]);

/** Run AES-128 CBC-MAC (key from aes_cbc_mac_set_key(), zero IV) over
 *  `input` (`inLen` bytes, must be a non-zero multiple of
 *  QRNG_AES_BLOCK_SIZE), writing the 16-byte MAC to `output`. Returns
 *  false if the underlying platform_aes128_cbc_mac() call fails (e.g.
 *  platform_crypto_init() was never called) -- `output` is left
 *  untouched in that case, never silently filled with stale/uninitialized
 *  data. */
bool aes_cbc_mac_extractor(const uint8_t *input, uint32_t inLen, uint8_t output[QRNG_AES_BLOCK_SIZE]);

/** Same result as calling aes_cbc_mac_extractor() `num_blocks` times over
 *  consecutive `block_len`-byte slices of `input` (`block_len` must be a
 *  non-zero multiple of QRNG_AES_BLOCK_SIZE), writing each 16-byte MAC
 *  back-to-back into `output` (must point at `num_blocks * 16` bytes) --
 *  just without the redundant per-call CRYP key reload, see
 *  platform_aes128_cbc_mac_batch(). Returns false (leaving `output`
 *  untouched) if the underlying platform call fails. */
bool aes_cbc_mac_extractor_batch(const uint8_t *input, uint32_t block_len, uint32_t num_blocks, uint8_t *output);

#endif /* QRNG_AES_CBC_MAC_H */
