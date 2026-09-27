/**
 * @file    qrng_constant.h
 * @brief   Algorithm settings for the QRNG entropy/extractor pipeline.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Inc\constant.h -- trimmed
 * to only the algorithm-relevant settings. The USB command protocol,
 * state machine and ring buffer settings from the original file are not
 * part of this port: Core_app/Middleware/QRNG/qrng_service.h exposes
 * this pipeline as plain C function calls instead, so App decides how
 * (or whether) to expose it over USB/UART on its own.
 *
 * The AES-128 CBC-MAC extractor (EXTRACTOR_USE_AES upstream) is
 * implemented here via Core_app/Platform/platform_crypto.h (STM32H753's
 * CRYP hardware accelerator) instead of upstream's software backends --
 * see aes_cbc_mac.h's doc comment for why.
 */
#ifndef QRNG_CONSTANT_H
#define QRNG_CONSTANT_H

#include <stdint.h>

/* ---- ADC / entropy source ---- */
#define QRNG_ADC_SAMPLES 2048 /* Number of uint16_t samples per DMA half/full buffer pass */
#define QRNG_ADC_RESOLUTION 16

#define QRNG_SYSTEM_MAX_RETRIES 5

/* ---- Toeplitz extractor settings ---- */
#define QRNG_QUANTUM_INPUT_BITS 2048
#define QRNG_QUANTUM_OUTPUT_BITS 1024

#define QRNG_BALANCE_DEVIATION_THRESHOLD 0.01f

#define QRNG_ADC_WORDS ((QRNG_QUANTUM_INPUT_BITS + 31) / 32)
#define QRNG_TOEPLITZ_WORDS (((QRNG_QUANTUM_INPUT_BITS + QRNG_QUANTUM_OUTPUT_BITS - 1) + 31) / 32)
#define QRNG_OUTPUT_WORDS ((QRNG_QUANTUM_OUTPUT_BITS + 31) / 32)

#define QRNG_TOEPLITZ_BLOCK_SIZE (QRNG_OUTPUT_WORDS * 4)
#define QRNG_TOEPLITZ_INPUT_EXTRACTOR_SIZE (QRNG_TOEPLITZ_BLOCK_SIZE * QRNG_EXTRACTOR_RATIO)

#define QRNG_MIN_ENTROPY_THRESHOLD 0.5f

/* Delay-line offset used by toeplitz_extractor_ultra_fast()'s
 * whitening XOR step -- see toeplitz.c. */
#define QRNG_DELAY 8

#define QRNG_EXTRACTOR_RESEED_INTERVAL 1000 /* extractor_run() calls between automatic reseeds */

/* ---- HMAC-SHA256 extractor settings ---- */
#define QRNG_HMAC_BLOCK_SIZE 32 /* SHA-256 */
#define QRNG_HMAC_INPUT_EXTRACTOR_SIZE (QRNG_HMAC_BLOCK_SIZE * QRNG_EXTRACTOR_RATIO)

/* ---- AES-128 CBC-MAC extractor settings ---- */
#define QRNG_AES_BLOCK_SIZE 16
#define QRNG_AES_INPUT_EXTRACTOR_SIZE (QRNG_AES_BLOCK_SIZE * QRNG_EXTRACTOR_RATIO)

/* ---- Extractor selection ---- */
#define QRNG_EXTRACTOR_USE_TOEPLITZ 1
#define QRNG_EXTRACTOR_USE_HMAC_SHA256 2
#define QRNG_EXTRACTOR_USE_AES 3

#define QRNG_EXTRACTOR_RATIO 2

/* ---- Entropy health test settings (NIST 800-90B) ---- */
#define QRNG_ENTROPY_RCT_CUTOFF_VALUE 3
#define QRNG_ENTROPY_APT_WINDOW_SIZE 512
#define QRNG_ENTROPY_APT_CUTOFF_VALUE 4

/* ---- DAC settings (noise-source drive current) ---- */
#define QRNG_DAC_MIN_VALUE 63
#define QRNG_DAC_MAX_VALUE 3049
#define QRNG_DAC_DEFAULT_VALUE 1700

#endif /* QRNG_CONSTANT_H */
