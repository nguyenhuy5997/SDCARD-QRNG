/**
 * @file    extractor.h
 * @brief   Wrapper selecting the Toeplitz, HMAC-SHA256 or AES-128 CBC-MAC
 *          extractor.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Inc\extractor.h.
 *
 * Deviation from upstream: QRNG_EXTRACTOR_USE_AES here always uses the
 * STM32H753 CRYP hardware accelerator (see aes_cbc_mac.h's doc comment),
 * not upstream's software backends (AES_USE_ARMCORTEXM/_STMCRYPT/
 * _TINYCRYPT) -- same result for the same key/input (AES-128 CBC-MAC is
 * a deterministic standard construction), just computed in hardware.
 *
 * Also unlike upstream, extractor_reseed() takes the reseed data as an
 * explicit parameter instead of reaching for an `extern entropy_context_t
 * es` global -- this file has no dependency on entropy.h/entropy_context_t
 * at all now.
 */
#ifndef QRNG_EXTRACTOR_H
#define QRNG_EXTRACTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define EXTRACTOR_SET_KEY_FAILED 0
#define EXTRACTOR_SET_KEY_SUCCESS 1

/** Generate the initial HMAC key, AES key and Toeplitz matrix (from the
 *  hardware TRNG via Core_app/Platform/platform_rng.h). Call once, after
 *  platform_rng_init(), platform_hash_init() and platform_crypto_init()
 *  have all succeeded. */
void extractor_init(void);

/** Run the extractor (QRNG_EXTRACTOR_USE_TOEPLITZ, _USE_HMAC_SHA256 or
 *  _USE_AES) over one ADC buffer half. `input` must be
 *  QRNG_ADC_SAMPLES/4 words (one half-buffer, samples reinterpreted as
 *  32-bit words); `output` receives QRNG_ADC_SAMPLES/4/QRNG_EXTRACTOR_RATIO
 *  words. Returns false if a HMAC-SHA256/AES hardware call failed partway
 *  through (Toeplitz is pure math and cannot fail) -- `output` may be
 *  partially filled in that case; callers must treat the whole draw as
 *  untrustworthy, not just the block(s) that actually failed. */
bool extractor_run(uint8_t algorithm, const uint32_t *input, uint32_t *output);

/** Reseed the extractor's internal key/matrix using `seed_data`
 *  (QRNG_HMAC_INPUT_EXTRACTOR_SIZE bytes for HMAC-SHA256 or AES; ignored
 *  for Toeplitz, which reseeds from the hardware TRNG instead) for
 *  better long-term random quality. Returns false (key left unchanged)
 *  if the underlying platform_hmac_sha256()/platform_aes128_cbc_mac()
 *  call failed -- HMAC-SHA256/AES only; the Toeplitz branch still does
 *  not report platform_rng_get_word() failures (reseed_toeplitz() below
 *  is a separate, pre-existing gap, not touched by this fix). */
bool extractor_reseed(uint8_t algorithm, const uint32_t *seed_data);

/** Set the HMAC/AES key or Toeplitz matrix from user input.
 *  @retval EXTRACTOR_SET_KEY_FAILED   `inLen` does not match what `algorithm` expects
 *  @retval EXTRACTOR_SET_KEY_SUCCESS  key/matrix set successfully */
uint8_t extractor_set_key(uint8_t algorithm, const uint8_t *input, uint32_t inLen);

#endif /* QRNG_EXTRACTOR_H */
