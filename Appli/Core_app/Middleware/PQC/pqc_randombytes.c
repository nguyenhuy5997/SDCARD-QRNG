/**
 * @file    pqc_randombytes.c
 * @brief   randombytes() implementation for the vendored PQClean ML-KEM-768 -- see pqc_randombytes.h.
 */
#include "randombytes.h"

#include <string.h>

#include "qrng_service.h"

/* See pqc_randombytes_pin_next()'s doc comment in randombytes.h. Not a general-purpose "override the RNG"
 * facility -- single-slot, consumed by the very next call, and only ever used from pqc_sign.c's
 * pqc_sign_keygen_from_seed(), which controls its own single call into crypto_sign_keypair() and therefore knows
 * exactly which randombytes() call this will satisfy. */
static const uint8_t *s_pinned_seed;
static size_t s_pinned_len;

void pqc_randombytes_pin_next(const uint8_t *seed, size_t len)
{
    s_pinned_seed = seed;
    s_pinned_len = len;
}

int randombytes(uint8_t *output, size_t n)
{
    if (s_pinned_seed != NULL) {
        const uint8_t *seed = s_pinned_seed;
        size_t len = s_pinned_len;
        s_pinned_seed = NULL; /* one-shot, whether or not the length actually matches */
        if (len != n) {
            return -1; /* caller bug: whoever pinned this expected a different-sized draw than what actually happened */
        }
        memcpy(output, seed, n);
        return 0;
    }

    /* The project's random source: QRNG (Toeplitz -- pure math, never contends with a live AES-GCM chunk on the CRYP
     * peripheral) first, MCU TRNG fallback, so a QRNG health-test false alarm or a board with the QRNG switched off
     * does not fail ML-KEM keygen/encaps or ML-DSA signing -- see qrng_service_random_bytes(). */
    return (qrng_service_random_bytes(output, n, NULL) == QRNG_OK) ? 0 : -1;
}
