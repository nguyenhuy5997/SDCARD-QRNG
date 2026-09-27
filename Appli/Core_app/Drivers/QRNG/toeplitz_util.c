/**
 * @file    toeplitz_util.c
 * @brief   Toeplitz matrix generation and quality check.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Src\toeplitz_util.c.
 * generate_toeplitz_bits() used to take a raw `RNG_HandleTypeDef *hrng`
 * parameter and call HAL_RNG_GenerateRandomNumber(hrng, ...) on it
 * directly three times; each call is now platform_rng_get_word()
 * instead (Core_app/Platform/platform_rng.h), so this file has no HAL
 * dependency at all -- platform_rng_init() must already have succeeded
 * before calling this (the QRNG backend does that during its own init).
 */
#include "toeplitz_util.h"
#include "platform.h"

#include <math.h>
#include <string.h>

static inline uint32_t get_bit_u32(const uint32_t *arr, size_t bit_index)
{
    size_t w = bit_index >> 5;
    uint32_t b = (uint32_t)(bit_index & 31u);
    return (arr[w] >> b) & 1u;
}

static size_t count_ones(const uint32_t *data, size_t len_bits)
{
    size_t count = 0;
    for (size_t i = 0; i < len_bits; i++) {
        count += get_bit_u32(data, i);
    }
    return count;
}

int generate_toeplitz_bits(uint32_t *toeplitz_words, size_t m, size_t n)
{
    if (toeplitz_words == NULL) {
        return -1;
    }

    size_t len_bits = m + n - 1;
    size_t len_words = (len_bits + 31) / 32;

    /* Xorshift PRNG seeded once from the HW RNG, XORed into every word
     * pulled from the HW RNG afterwards -- whitens away any local bias
     * the HW RNG might have. */
    static uint32_t xorshift_state = 0;

    if (xorshift_state == 0) {
        if (platform_rng_get_word(&xorshift_state) != PLATFORM_OK) {
            return -2;
        }
        if (xorshift_state == 0) {
            xorshift_state = 0xACE41234U;
        }
    }

    for (size_t i = 0; i < len_words; i++) {
        uint32_t hw_rand = 0;
        if (platform_rng_get_word(&hw_rand) != PLATFORM_OK) {
            return -2;
        }

        xorshift_state ^= (xorshift_state << 13);
        xorshift_state ^= (xorshift_state >> 17);
        xorshift_state ^= (xorshift_state << 5);

        toeplitz_words[i] = hw_rand ^ xorshift_state;
    }

    /* Quick balance check: if the overall bit ratio is too skewed,
     * XOR in one more HW RNG sample to rebalance. */
    size_t total_ones = 0;
    for (size_t i = 0; i < len_words; i++) {
        total_ones += (size_t)__builtin_popcount(toeplitz_words[i]);
    }

    float ratio = (float)total_ones / (float)(len_words * 32);
    if (ratio < 0.48f || ratio > 0.52f) {
        uint32_t fixer;
        if (platform_rng_get_word(&fixer) != PLATFORM_OK) {
            return -2;
        }
        for (size_t i = 0; i < len_words; i++) {
            toeplitz_words[i] ^= (fixer + (uint32_t)i);
        }
    }

    size_t bits_in_last_word = len_bits % 32;
    if (bits_in_last_word != 0) {
        toeplitz_words[len_words - 1] &= (1UL << bits_in_last_word) - 1;
    }

    return 0;
}

toeplitz_quality_t check_toeplitz_quality(const uint32_t *toeplitz_words, size_t m, size_t n)
{
    toeplitz_quality_t quality = { 0 };
    size_t len_bits = m + n - 1;

    if (len_bits == 0) {
        return quality;
    }

    quality.ones_count = count_ones(toeplitz_words, len_bits);
    quality.bit_ratio = (float)quality.ones_count / (float)len_bits;
    quality.balance_deviation = fabsf(quality.bit_ratio - 0.5f);

    uint32_t last_bit = get_bit_u32(toeplitz_words, 0);
    size_t current_run = 1;
    size_t max_run = 1;

    for (size_t i = 1; i < len_bits; i++) {
        uint32_t current_bit = get_bit_u32(toeplitz_words, i);
        if (current_bit == last_bit) {
            current_run++;
            if (current_run > max_run) {
                max_run = current_run;
            }
        }
        else {
            current_run = 1;
            last_bit = current_bit;
        }
    }
    quality.max_run_length = max_run;

    return quality;
}
