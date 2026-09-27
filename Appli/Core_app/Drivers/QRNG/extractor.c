/**
 * @file    extractor.c
 * @brief   Wrapper selecting the Toeplitz or HMAC-SHA256 extractor.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Src\extractor.c -- see
 * extractor.h's doc comment for what changed (no AES branch, reseed
 * takes seed data explicitly, keys come from platform_rng.h instead of
 * vQRNG_generate_random_words()/a raw `extern RNG_HandleTypeDef hrng`).
 */
#include <string.h>
#include "extractor.h"
#include "qrng_constant.h"
#include "toeplitz.h"
#include "toeplitz_util.h"
#include "hmac_sha256.h"
#include "aes_cbc_mac.h"
#include "platform.h"

static toeplitz_quality_t s_toeplitz_quality;
static uint32_t s_toeplitz_matrix[QRNG_TOEPLITZ_WORDS];
static uint8_t s_hmac_key[QRNG_HMAC_BLOCK_SIZE];
static uint8_t s_aes_key[QRNG_AES_BLOCK_SIZE];

static inline void memxor(uint32_t *dest, const uint32_t *src, size_t len);
static void reseed_toeplitz(void);

void extractor_init(void)
{
    (void)platform_rng_get_bytes(s_hmac_key, sizeof(s_hmac_key));
    (void)platform_rng_get_bytes(s_aes_key, sizeof(s_aes_key));

    hmac_sha256_init();
    hmac_sha256_set_key(s_hmac_key, sizeof(s_hmac_key));

    aes_cbc_mac_init();
    aes_cbc_mac_set_key(s_aes_key);

    reseed_toeplitz();
}

bool extractor_run(uint8_t algorithm, const uint32_t *input, uint32_t *output)
{
    bool ok = true;

    if (algorithm == QRNG_EXTRACTOR_USE_HMAC_SHA256) {
        for (uint32_t i = 0; i < QRNG_ADC_SAMPLES; i += QRNG_HMAC_INPUT_EXTRACTOR_SIZE) {
            if (!hmac_sha256_extractor((const uint8_t *)input + i, QRNG_HMAC_INPUT_EXTRACTOR_SIZE,
                                        (uint8_t *)output + i / QRNG_EXTRACTOR_RATIO)) {
                ok = false;
            }
        }
    }
    else if (algorithm == QRNG_EXTRACTOR_USE_AES) {
        ok = aes_cbc_mac_extractor_batch((const uint8_t *)input, QRNG_AES_INPUT_EXTRACTOR_SIZE,
                                          QRNG_ADC_SAMPLES / QRNG_AES_INPUT_EXTRACTOR_SIZE, (uint8_t *)output);
    }
    else { /* QRNG_EXTRACTOR_USE_TOEPLITZ, the default -- pure math, cannot fail */
        for (uint32_t i = 0; i < QRNG_ADC_SAMPLES / 4; i += QRNG_TOEPLITZ_INPUT_EXTRACTOR_SIZE / 4) {
            toeplitz_extractor_ultra_fast(
                input + i, QRNG_EXTRACTOR_RATIO * QRNG_OUTPUT_WORDS, output + i / QRNG_EXTRACTOR_RATIO, QRNG_OUTPUT_WORDS);
        }
    }

    return ok;
}

bool extractor_reseed(uint8_t algorithm, const uint32_t *seed_data)
{
    bool ok = true;

    if (algorithm == QRNG_EXTRACTOR_USE_HMAC_SHA256) {
        uint8_t hmac_block[QRNG_HMAC_BLOCK_SIZE];
        memset(hmac_block, 0, sizeof(hmac_block));
        ok = hmac_sha256_extractor((const uint8_t *)seed_data, QRNG_HMAC_INPUT_EXTRACTOR_SIZE, hmac_block);
        if (ok) {
            memxor((uint32_t *)s_hmac_key, (uint32_t *)hmac_block, sizeof(s_hmac_key));
            hmac_sha256_set_key(s_hmac_key, sizeof(s_hmac_key));
        }
    }
    else if (algorithm == QRNG_EXTRACTOR_USE_AES) {
        uint8_t aes_block[QRNG_AES_BLOCK_SIZE];
        memset(aes_block, 0, sizeof(aes_block));
        ok = aes_cbc_mac_extractor((const uint8_t *)seed_data, QRNG_AES_INPUT_EXTRACTOR_SIZE, aes_block);
        if (ok) {
            memxor((uint32_t *)s_aes_key, (uint32_t *)aes_block, sizeof(s_aes_key));
            aes_cbc_mac_set_key(s_aes_key);
        }
    }
    else {
        reseed_toeplitz();
    }

    return ok;
}

uint8_t extractor_set_key(uint8_t algorithm, const uint8_t *input, uint32_t inLen)
{
    if (algorithm == QRNG_EXTRACTOR_USE_HMAC_SHA256) {
        if (inLen != sizeof(s_hmac_key)) {
            return EXTRACTOR_SET_KEY_FAILED;
        }
        memcpy(s_hmac_key, input, inLen);
        hmac_sha256_set_key(s_hmac_key, sizeof(s_hmac_key));
    }
    else if (algorithm == QRNG_EXTRACTOR_USE_AES) {
        if (inLen != sizeof(s_aes_key)) {
            return EXTRACTOR_SET_KEY_FAILED;
        }
        memcpy(s_aes_key, input, inLen);
        aes_cbc_mac_set_key(s_aes_key);
    }
    else {
        if (inLen != sizeof(s_toeplitz_matrix)) {
            return EXTRACTOR_SET_KEY_FAILED;
        }
        memcpy(s_toeplitz_matrix, input, inLen);
        toeplitz_build_lookup(s_toeplitz_matrix);
    }

    return EXTRACTOR_SET_KEY_SUCCESS;
}

static void reseed_toeplitz(void)
{
    do {
        (void)generate_toeplitz_bits(s_toeplitz_matrix, QRNG_QUANTUM_INPUT_BITS, QRNG_QUANTUM_OUTPUT_BITS);
        s_toeplitz_quality = check_toeplitz_quality(s_toeplitz_matrix, QRNG_QUANTUM_INPUT_BITS, QRNG_QUANTUM_OUTPUT_BITS);
    } while (s_toeplitz_quality.balance_deviation > QRNG_BALANCE_DEVIATION_THRESHOLD);

    toeplitz_build_lookup(s_toeplitz_matrix);
}

static inline void memxor(uint32_t *dest, const uint32_t *src, size_t len)
{
    uint32_t *end = dest + (len / sizeof(uint32_t));
    while (dest < end) {
        *dest++ ^= *src++;
    }
}
