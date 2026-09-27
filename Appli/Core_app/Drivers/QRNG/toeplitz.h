/**
 * @file    toeplitz.h
 * @brief   Toeplitz matrix-vector multiply (GF(2)) extractor.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Inc\toeplitz.h -- trimmed
 * to the two functions extractor.c actually calls
 * (toeplitz_build_lookup, toeplitz_extractor_ultra_fast). Upstream had
 * four more extractor variants (toeplitz_extractor,
 * _optimized/_dma_optimized/_final) that were never called from
 * anywhere in that project either; not ported here.
 */
#ifndef QRNG_TOEPLITZ_H
#define QRNG_TOEPLITZ_H

#include <stdint.h>

/** Precompute the byte-wise lookup table (toeplitz_lookup[256][OUTPUT_WORDS])
 *  used by toeplitz_extractor_ultra_fast() -- call once after
 *  generate_toeplitz_bits() (or whenever the matrix changes, e.g. on
 *  reseed). */
void toeplitz_build_lookup(const uint32_t *toeplitz_words);

/** Multiply the Toeplitz matrix by `in_len` input words, producing
 *  `out_len` output words in GF(2). */
void toeplitz_extractor_ultra_fast(const uint32_t *adc_words, uint16_t in_len, uint32_t *out_words, uint16_t out_len);

#endif /* QRNG_TOEPLITZ_H */
