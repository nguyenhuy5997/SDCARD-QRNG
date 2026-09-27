/**
 * @file    randombytes.h
 * @brief   randombytes() hook the vendored PQClean ML-KEM-768 source calls into -- QRNG-backed.
 *
 * PQClean's crypto_kem/ml-kem-768/clean/{kem,indcpa}.c do `#include "randombytes.h"` and call a plain
 * `int randombytes(uint8_t *output, size_t n)`. Deliberately named exactly `randombytes.h` (not `pqc_*`) so it
 * satisfies that bare `#include` when this project's own Core_app/Middleware/PQC/ directory is on the include path
 * -- PQClean's own `common/randombytes.h` (an OS-random stub unsuitable for bare metal) is intentionally NOT
 * vendored; this file replaces it. pqc_randombytes.c sources randomness from Middleware/QRNG the same way every
 * other nonce/ephemeral-key draw in this project does (see media_protocol.c's nonce pool, ca_protocol.c's
 * CA_CMD_BEGIN) -- Toeplitz first, hardware TRNG (platform_rng.h) as a fallback if the QRNG draw fails, never a
 * hard failure that would leave a caller's buffer only partially filled.
 */
#ifndef PQC_RANDOMBYTES_H
#define PQC_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/** Signature PQClean's vendored sources expect (see this header's own doc comment). Always fills all `n` bytes --
 *  returns 0 on success, -1 only if both the QRNG draw and the hardware TRNG fallback failed (should not happen in
 *  practice; both underlying sources fail closed on error, this function does not fabricate output on failure).
 *
 *  If pqc_randombytes_pin_next() was called since the last randombytes() call, THIS call returns the pinned bytes
 *  instead of drawing from the QRNG -- see that function's own doc comment. */
int randombytes(uint8_t *output, size_t n);

/** Giai đoạn 4 (2026-09-24, ML-DSA for the "Ký số" feature, see CLAUDE.md): makes the NEXT randombytes() call
 *  return `seed` (`len` bytes) verbatim instead of drawing fresh QRNG entropy, then un-pins itself (a second
 *  randombytes() call goes back to drawing real entropy as usual). Exists because PQClean's ML-DSA
 *  crypto_sign_keypair() draws its ENTIRE keygen randomness as a single randombytes(seedbuf, SEEDBYTES) call
 *  (confirmed by reading crypto_sign/ml-dsa-{44,65,87}/clean/sign.c -- everything after that one call is a
 *  deterministic SHAKE-256 expansion) -- pinning that one call to a caller-supplied seed makes crypto_sign_keypair() a pure,
 *  reproducible function of the seed, which is exactly pqc_sign_keygen_from_seed() (pqc_sign.h) needs: this
 *  project stores only a 32-byte seed as the long-term ML-DSA identity secret (in an SE052F secret object, well
 *  within its ~800-byte size limit -- the 4032-byte ML-DSA-65 secret key itself never could be), and re-derives
 *  the real (pk, sk) pair from that seed fresh every time signing is needed. Cross-checked against the
 *  independent Python `dilithium-py` package's own `ML_DSA_65.key_derive(seed)`, same method Giai đoạn 0 used for
 *  ML-KEM-768's KAT vector (see pqc_sign_kat_vector.h).
 *
 *  `seed` must stay valid until the next randombytes() call actually happens -- this function does not copy it. */
void pqc_randombytes_pin_next(const uint8_t *seed, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_RANDOMBYTES_H */
