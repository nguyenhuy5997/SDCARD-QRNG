/**
 * @file    toeplitz.c
 * @brief   Toeplitz matrix-vector multiply (GF(2)) extractor.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Src\toeplitz.c -- trimmed
 * to the two functions extractor.c actually calls; see toeplitz.h's doc
 * comment for what was dropped. The unused `#include "bsp_hal.h"`
 * in the original (nothing in this file called into HAL) is gone too.
 */
#include <string.h>
#include "toeplitz.h"
#include "qrng_constant.h"

/* Upstream vQRNG1.0 keeps this table out of DTCM ("measurably hurt
 * bitrate in upstream's own testing"). Re-tested on this board/build
 * (STM32H753ZI, D-Cache disabled -- see Src/main.c) via real hardware
 * BENCH_ENTROPY(TOEPLITZ) runs -- see this file's git history/PR
 * description for the before/after numbers measured here. If revisiting
 * this, benchmark on real hardware again rather than trusting either
 * finding blindly -- the right placement can depend on D-Cache state,
 * DMA/bus contention, and other things that differ per board/config. */
static uint32_t toeplitz_lookup[256][QRNG_OUTPUT_WORDS] __attribute__((section(".dtcm_bss")));

static inline void process_byte_ultra(uint8_t byte, uint32_t bit_shift, uint32_t *out_words);

void toeplitz_build_lookup(const uint32_t *toeplitz_words)
{
    memset(toeplitz_lookup, 0, sizeof(toeplitz_lookup));
    for (int b = 0; b < 256; b++) {
        for (int bit = 0; bit < 8; bit++) {
            if ((b >> bit) & 1) {
                for (int t = 0; t < QRNG_OUTPUT_WORDS; t++) {
                    uint32_t word = toeplitz_words[t];
                    toeplitz_lookup[b][t] ^= word << bit;
                    if (t + 1 < QRNG_OUTPUT_WORDS) {
                        toeplitz_lookup[b][t + 1] ^= word >> (32 - bit);
                    }
                }
            }
        }
    }
}

/* `out_len` mirrors the upstream signature (and extractor.c's call
 * site), but -- exactly as upstream -- the computation below only ever
 * uses the compile-time QRNG_OUTPUT_WORDS/QRNG_QUANTUM_OUTPUT_BITS
 * constants, never this parameter. Kept for call-site compatibility;
 * callers must still only ever pass QRNG_OUTPUT_WORDS. */
void toeplitz_extractor_ultra_fast(const uint32_t *adc_words, uint16_t in_len, uint32_t *out_words, uint16_t out_len)
{
    (void)out_len;

    uint32_t temp[1000];
    for (int i = 0; i < in_len; i++) {
        temp[i] = (i < QRNG_DELAY) ? adc_words[i] : adc_words[i] ^ adc_words[i - QRNG_DELAY];
    }

    for (int w = 0; w < in_len; w++) {
        uint32_t adc_word = temp[w];
        if (adc_word == 0) {
            continue;
        }

        uint8_t b0 = adc_word & 0xFF;
        uint8_t b1 = (adc_word >> 8) & 0xFF;
        uint8_t b2 = (adc_word >> 16) & 0xFF;
        uint8_t b3 = (adc_word >> 24) & 0xFF;

        uint32_t base_shift = (uint32_t)w << 5;

        if (b0) {
            process_byte_ultra(b0, base_shift, out_words);
        }
        if (b1) {
            process_byte_ultra(b1, base_shift + 8, out_words);
        }
        if (b2) {
            process_byte_ultra(b2, base_shift + 16, out_words);
        }
        if (b3) {
            process_byte_ultra(b3, base_shift + 24, out_words);
        }
    }
}

static inline void process_byte_ultra(uint8_t byte, uint32_t bit_shift, uint32_t *out_words)
{
    if (bit_shift >= QRNG_QUANTUM_OUTPUT_BITS) {
        return;
    }

    uint32_t word_offset = bit_shift >> 5;
    uint32_t bit_offset = bit_shift & 0x1F;
    uint32_t *output_ptr = &out_words[word_offset];
    const uint32_t *lookup_ptr = toeplitz_lookup[byte];

    if (bit_offset == 0) {
        output_ptr[0] ^= lookup_ptr[0];
        if (QRNG_OUTPUT_WORDS > (int)word_offset + 1) {
            output_ptr[1] ^= lookup_ptr[1];
        }
        if (QRNG_OUTPUT_WORDS > (int)word_offset + 2) {
            output_ptr[2] ^= lookup_ptr[2];
        }
        if (QRNG_OUTPUT_WORDS > (int)word_offset + 3) {
            output_ptr[3] ^= lookup_ptr[3];
        }
    }
    else {
        uint32_t sl = bit_offset;
        uint32_t sr = 32 - sl;

        output_ptr[0] ^= lookup_ptr[0] << sl;
        if (QRNG_OUTPUT_WORDS > (int)word_offset + 1) {
            output_ptr[1] ^= (lookup_ptr[0] >> sr) | (lookup_ptr[1] << sl);
        }
        if (QRNG_OUTPUT_WORDS > (int)word_offset + 2) {
            output_ptr[2] ^= (lookup_ptr[1] >> sr) | (lookup_ptr[2] << sl);
        }
        if (QRNG_OUTPUT_WORDS > (int)word_offset + 3) {
            output_ptr[3] ^= (lookup_ptr[2] >> sr) | (lookup_ptr[3] << sl);
        }
    }
}
