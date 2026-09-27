/**
 * @file    pqc_sign.h
 * @brief   Thin wrapper around vendored PQClean ML-DSA (FIPS 204) -- Giai đoạn 4, "Ký số" feature, see CLAUDE.md.
 *
 * Same pattern as pqc_kem.h (Giai đoạn 0-1): buffer-in/buffer-out, no heap, no dynamic dispatch beyond the
 * `pqc_sign_level_t` selector below -- each level is a SEPARATE vendored PQClean parameter set
 * (Core_app/Middleware/PQC/pqclean/ml-dsa-{44,65,87}-clean/), all three compiled in unconditionally (same
 * crypto-agility design as security_service.h's sec_ec_curve_t/sec_rsa_key_bits_t: the caller picks a level per
 * call, nothing is a compile-time choice).
 *
 * UNLIKE pqc_kem.h's ML-KEM-768 (an EPHEMERAL per-call key, discarded at end of session), ML-DSA here is a
 * LONG-TERM SIGNING IDENTITY -- the whole point of the "Ký số" feature is a persistent key a user signs many
 * files with over time, the software analogue of the EC/RSA identity keys security_service.h already manages
 * inside the SE052F. But the SE052F does not support ML-DSA (or any lattice scheme) natively, so the actual
 * signing math has to run in MCU software here, exactly like ML-KEM did -- which raises the question the KEM case
 * never had to answer: where does a LONG-LIVED ML-DSA secret key (4032 bytes for level 65, far past the SE052F's
 * ~800-byte secret-object limit) actually live?
 *
 * ANSWER: it doesn't, as such. This module never stores or accepts a raw ML-DSA secret key from a caller -- only
 * a 32-byte SEED (pqc_sign_keygen_from_seed()'s `seed` parameter). PQClean's crypto_sign_keypair() draws its
 * entire randomness as one 32-byte randombytes() call and is otherwise a pure SHAKE-256 expansion (confirmed by
 * reading crypto_sign/ml-dsa-{44,65,87}/clean/sign.c) -- so pinning that one call to a caller-supplied seed
 * (pqc_randombytes_pin_next(), randombytes.h) makes key generation a deterministic, REPRODUCIBLE function of the
 * seed. The caller (security_service.h's ML-DSA functions) stores only that 32-byte seed, in an SE052F secret
 * object (security_service_store_secret(), well within its size limit) -- and re-derives the real (pk, sk) pair
 * fresh, in MCU RAM, every time a signature or public-key readback is actually needed, wiping it again
 * immediately after. The seed is the identity; the 4032-byte expanded secret key is a disposable RAM artifact of
 * using it, never written to flash. Cross-checked against the independent Python `dilithium-py` package's
 * ML_DSA_65.key_derive(seed) -- see pqc_sign_kat_vector.h.
 */
#ifndef PQC_SIGN_H
#define PQC_SIGN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Which vendored ML-DSA parameter set. Numeric values are this project's own wire-protocol convention (see
 *  security_protocol.c's SEC_CMD_MLDSA_* sub-commands) -- NOT FIPS 204's own OID/numbering. */
typedef enum {
    PQC_SIGN_MLDSA44 = 0, /* NIST security level 2 */
    PQC_SIGN_MLDSA65 = 1, /* NIST security level 3 -- matches ML-KEM-768's level, the project's other PQC choice */
    PQC_SIGN_MLDSA87 = 2, /* NIST security level 5 */
} pqc_sign_level_t;

#define PQC_SIGN_SEED_BYTES 32U /* every level's keygen seed -- FIPS 204's SEEDBYTES is fixed across all three */

#define PQC_SIGN_MLDSA44_PUBLICKEY_BYTES 1312U
#define PQC_SIGN_MLDSA44_SECRETKEY_BYTES 2560U
#define PQC_SIGN_MLDSA44_BYTES           2420U /* max signature size */

#define PQC_SIGN_MLDSA65_PUBLICKEY_BYTES 1952U
#define PQC_SIGN_MLDSA65_SECRETKEY_BYTES 4032U
#define PQC_SIGN_MLDSA65_BYTES           3309U

#define PQC_SIGN_MLDSA87_PUBLICKEY_BYTES 2592U
#define PQC_SIGN_MLDSA87_SECRETKEY_BYTES 4896U
#define PQC_SIGN_MLDSA87_BYTES           4627U

/* Largest of the three, for callers sizing one shared scratch buffer regardless of which level gets picked at
 * runtime (e.g. security_protocol.c's response buffer). */
#define PQC_SIGN_MAX_PUBLICKEY_BYTES PQC_SIGN_MLDSA87_PUBLICKEY_BYTES
#define PQC_SIGN_MAX_SECRETKEY_BYTES PQC_SIGN_MLDSA87_SECRETKEY_BYTES
#define PQC_SIGN_MAX_BYTES           PQC_SIGN_MLDSA87_BYTES

/** Exact public-key / secret-key / max-signature size for `level`, or 0 if `level` is not a valid enumerator --
 *  callers use these instead of hardcoding a level's numbers, so a buffer sized `pqc_sign_publickey_bytes(level)`
 *  is always exactly right regardless of which level was actually requested. */
size_t pqc_sign_publickey_bytes(pqc_sign_level_t level);
size_t pqc_sign_secretkey_bytes(pqc_sign_level_t level);
size_t pqc_sign_max_signature_bytes(pqc_sign_level_t level);

/** Deterministically regenerates the (pk, sk) pair for `level` from `seed` (PQC_SIGN_SEED_BYTES bytes) -- see this
 *  header's own doc comment for why this is the ONLY key-generation entry point (no random/"fresh" keygen is
 *  exposed: an ML-DSA identity's seed is generated once, at provisioning, by the caller drawing
 *  PQC_SIGN_SEED_BYTES of QRNG entropy itself and storing it -- see security_service.h's ML-DSA functions). `pk`
 *  must hold pqc_sign_publickey_bytes(level) bytes, `sk` pqc_sign_secretkey_bytes(level) bytes. Same seed always
 *  yields the same (pk, sk) -- callers must wipe `sk` themselves the moment they are done with it (sign, or read
 *  `pk` back out of it is all it is ever needed for). Returns false on an invalid `level`. */
bool pqc_sign_keygen_from_seed(pqc_sign_level_t level, const uint8_t seed[PQC_SIGN_SEED_BYTES], uint8_t *pk, uint8_t *sk);

/** ML-DSA-signs `msg` (`msg_len` bytes, arbitrary size -- unlike security_service_ecdsa_sign()'s SE052F path,
 *  there is no APDU size limit here: this runs entirely in MCU software, so it can sign a whole message directly,
 *  not just a pre-computed digest -- though callers may still choose to sign a digest for consistency with the
 *  EC/RSA signing sub-commands' own convention). Uses ML-DSA's standard RANDOMIZED ("hedged") signing mode (fresh
 *  QRNG-backed randomness per signature, via randombytes.h -- same as PQClean's own default
 *  crypto_sign_signature()), matching FIPS 204's recommended default; deterministic signing is not exposed here
 *  since this project has no specific reason to prefer it and hedged mode is the more conservative choice against
 *  certain fault/side-channel classes. `sig` must hold pqc_sign_max_signature_bytes(level) bytes; `*sig_len` is
 *  set to the ACTUAL signature length on success (ML-DSA signatures are not always exactly the maximum size).
 *  Returns false on an invalid `level` or if the underlying randomness draw failed (see randombytes.h). */
bool pqc_sign_sign(pqc_sign_level_t level, const uint8_t *sk, const uint8_t *msg, size_t msg_len, uint8_t *sig,
                    size_t *sig_len);

/** Verifies `sig` (`sig_len` bytes) of `msg` (`msg_len` bytes) against the public key `pk`. Returns true only if
 *  `level` is valid AND the signature verifies. */
bool pqc_sign_verify(pqc_sign_level_t level, const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_SIGN_H */
