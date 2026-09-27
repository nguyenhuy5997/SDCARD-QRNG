/**
 * @file    pqc_kem.h
 * @brief   ML-KEM-768 (FIPS 203) KEM primitives -- thin wrapper over the vendored PQClean reference implementation.
 *
 * Pure buffer-in/buffer-out API, no heap, same style as Middleware/CA/ca_x509.h -- this is the ONLY header the rest
 * of the firmware (Core_app/App/protocol_adapters/ca_protocol.c) needs to know about; nothing outside this file and
 * pqc_kem.c ever names a PQCLEAN_MLKEM768_CLEAN_* symbol directly.
 *
 * SE052F does NOT implement ML-KEM -- ALL of the math here runs in software on the STM32 itself (see
 * Core_app/Middleware/PQC/pqclean/, vendored verbatim from https://github.com/PQClean/PQClean,
 * crypto_kem/ml-kem-768/clean, public domain). This is a real, if narrow, exception to this project's "every
 * secret stays in the SE052F" principle (docs/key_exchange_ca_profile.md section 6) -- see
 * Core_app/App/protocol_adapters/ca_protocol.c's own doc comment on exactly when and how briefly the secret key/
 * shared secret this file produces are allowed to exist in MCU RAM.
 *
 * Randomness: pqc_randombytes.c hooks PQClean's own `randombytes()` to Middleware/QRNG (Toeplitz), same convention
 * as every other nonce/ephemeral-key draw in this project -- see that file's own doc comment.
 */
#ifndef PQC_KEM_H
#define PQC_KEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#define PQC_KEM_PUBLICKEY_BYTES     1184U /* ML-KEM-768 encapsulation key */
#define PQC_KEM_SECRETKEY_BYTES     2400U /* ML-KEM-768 decapsulation key */
#define PQC_KEM_CIPHERTEXT_BYTES    1088U
#define PQC_KEM_SHARED_SECRET_BYTES 32U

/** Generate a fresh ML-KEM-768 key pair. `pk`/`sk` must each hold the sizes above. Draws randomness via
 *  pqc_randombytes.c (QRNG). Returns false on any underlying failure (RNG exhausted -- see that file's doc
 *  comment); PQClean's own reference implementation cannot otherwise fail. */
bool pqc_kem_keygen(uint8_t pk[PQC_KEM_PUBLICKEY_BYTES], uint8_t sk[PQC_KEM_SECRETKEY_BYTES]);

/** Encapsulate against a peer's public key `pk`: produces a fresh `ct` (send this to the peer) and the shared
 *  secret `ss` (keep this -- it is what `pqc_kem_decapsulate()` on the peer's side, given `ct`, will also compute).
 *  Draws randomness via pqc_randombytes.c (QRNG). Returns false on any underlying failure. */
bool pqc_kem_encapsulate(const uint8_t pk[PQC_KEM_PUBLICKEY_BYTES], uint8_t ct[PQC_KEM_CIPHERTEXT_BYTES],
                          uint8_t ss[PQC_KEM_SHARED_SECRET_BYTES]);

/** Decapsulate a ciphertext `ct` (received from the peer) using this side's own secret key `sk`, recovering the
 *  same shared secret `ss` the peer's pqc_kem_encapsulate() produced. Deterministic, no randomness drawn.
 *  ML-KEM's own implicit-rejection design means a malformed/tampered `ct` never returns an error here -- it
 *  silently yields a pseudorandom (but useless to an attacker) `ss` instead, by FIPS 203 design, same failure
 *  shape as a wrong AES-GCM key producing garbage plaintext rather than an error. This function itself always
 *  returns true; a real mismatch surfaces later, when the two sides' derived AES-256-GCM session keys don't agree
 *  and `CA_CMD_VERIFY_CONFIRM` (ca_protocol.c) reports a mismatch -- there is no earlier signal to check. */
bool pqc_kem_decapsulate(const uint8_t sk[PQC_KEM_SECRETKEY_BYTES], const uint8_t ct[PQC_KEM_CIPHERTEXT_BYTES],
                          uint8_t ss[PQC_KEM_SHARED_SECRET_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_KEM_H */
