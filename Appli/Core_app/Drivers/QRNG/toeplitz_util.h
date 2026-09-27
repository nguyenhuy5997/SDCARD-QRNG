/**
 * @file    toeplitz_util.h
 * @brief   Toeplitz matrix generation and quality check.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Inc\toeplitz_util.h.
 * generate_toeplitz_bits() used to take a raw `RNG_HandleTypeDef *` and
 * call HAL_RNG_GenerateRandomNumber() on it directly; it now goes
 * through Core_app/Platform/platform_rng.h instead, so this file has no
 * HAL dependency at all.
 */
#ifndef QRNG_TOEPLITZ_UTIL_H
#define QRNG_TOEPLITZ_UTIL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t ones_count;
    float bit_ratio;
    float balance_deviation;
    size_t max_run_length;
} toeplitz_quality_t;

/**
 * @brief Generate the (m + n - 1)-bit vector that defines an m x n
 * binary Toeplitz matrix, using the hardware TRNG (via
 * platform_rng_get_word()) whitened with a Xorshift PRNG.
 *
 * @param[out] toeplitz_words  Result buffer, at least ((m+n-1)+31)/32 words.
 * @param[in]  m  Number of output bits (matrix rows).
 * @param[in]  n  Number of input bits (matrix columns).
 * @retval 0   success
 * @retval -1  invalid parameter
 * @retval -2  platform_rng_get_word() failed
 */
int generate_toeplitz_bits(uint32_t *toeplitz_words, size_t m, size_t n);

/** @brief Evaluate the statistical quality (bit balance, longest run) of
 *  a generated Toeplitz vector. */
toeplitz_quality_t check_toeplitz_quality(const uint32_t *toeplitz_words, size_t m, size_t n);

#endif /* QRNG_TOEPLITZ_UTIL_H */
