/**
 * @file    security_service.h
 * @brief   Chip-agnostic secure-element service interface.
 *
 * App code that needs a hardware root of trust (random, on-chip key
 * storage, ECDSA sign/verify, SHA-256) calls only this header -- never
 * Core_app/Drivers/SE05x's NXP host library directly. Swapping the
 * secure element (a different chip, or later a software-only fallback)
 * means adding another backend under Core_app/Middleware/Security/<chip>/
 * that implements this same interface; App does not change. This mirrors
 * how Core_app/Platform decouples App from the specific MCU family.
 *
 * Scope: this is deliberately a small, commonly-needed subset of what a
 * secure element can do -- random, EC (P-256) key pairs that never leave
 * the chip, ECDSA sign/verify, and on-chip SHA-256. The SE052F backend
 * alone exposes 80+ raw APDU commands (RSA, symmetric cipher, MAC, KDF,
 * TLS offload, DESFire auth, ...) -- see
 * Core_app/Drivers/SE05x/README.md. Extend this header (and every
 * backend) the same way if App needs one of those; do not reach past
 * this header from App.
 */
#ifndef SECURITY_SERVICE_H
#define SECURITY_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    SEC_OK = 0,
    SEC_ERROR,         /* transport/chip error -- see backend logs */
    SEC_NOT_READY,      /* security_service_init() was not called, or failed */
    SEC_INVALID_PARAM,
} sec_status_t;

/** Hash algorithm selector for the *_ex/RSA sign/verify functions below.
 *  The digest is always computed by the CALLER (security_service_sha256(),
 *  or any host-side incremental hash over a large file) -- neither
 *  Se05x_API_ECDSASign nor the RSA sign path below ever hashes internally,
 *  see Se05x_API_ECDSASign's own doc comment ("hashing of data always must
 *  be done on host"). This is what makes both paths work for a file of any
 *  size: only the fixed-size digest ever reaches the chip. SHA-1 is
 *  deliberately not offered (deprecated for new signing use). */
typedef enum {
    SEC_HASH_SHA224, /* 28-byte digest */
    SEC_HASH_SHA256, /* 32-byte digest */
    SEC_HASH_SHA384, /* 48-byte digest */
    SEC_HASH_SHA512, /* 64-byte digest */
} sec_hash_t;

/** EC curve selector for security_service_ensure_ec_keypair_ex(). NIST and
 *  Brainpool curves plus secp256k1 are always available on the SE052F.
 *  EdDSA/Ed25519 is deliberately NOT offered here: it is a separately
 *  gated applet feature (kSE05x_AppletConfig_EDDSA) requiring a different
 *  auth key this project does not have -- confirmed on real hardware
 *  (SW=0x6985 on key generation), see git history for that investigation.
 *  Do not re-add it without first obtaining that key. */
typedef enum {
    SEC_EC_CURVE_P256,
    SEC_EC_CURVE_P384,
    SEC_EC_CURVE_P521,
    SEC_EC_CURVE_BRAINPOOL256,
    SEC_EC_CURVE_BRAINPOOL384,
    SEC_EC_CURVE_BRAINPOOL512,
    SEC_EC_CURVE_SECP256K1,
} sec_ec_curve_t;

/** RSA modulus size selector for security_service_ensure_rsa_keypair().
 *  The chip also supports 512/1024/1152-bit RSA, not exposed here as
 *  they're below any practical modern signing use. */
typedef enum {
    SEC_RSA_2048,
    SEC_RSA_3072,
    SEC_RSA_4096,
} sec_rsa_key_bits_t;

/** RSA signature padding scheme for security_service_rsa_sign_digest()/
 *  rsa_verify_digest(). PSS (RFC 8017 RSASSA-PSS, salt length == the
 *  chosen hash's output length, MGF1 built on that same hash) is
 *  probabilistic -- a fresh random salt from the chip's TRNG each call,
 *  so signing the same digest twice produces two different (both valid)
 *  signatures, unlike PKCS1_V15's deterministic output. */
typedef enum {
    SEC_RSA_PADDING_PKCS1_V15,
    SEC_RSA_PADDING_PSS,
} sec_rsa_padding_t;

/** Bring the secure element up: reset it, open a transport session, and
 *  authenticate it (backend-specific -- e.g. the SE052F backend
 *  authenticates Platform SCP03 before it will do any key management,
 *  since this board's chip rejects Secure-Object commands on a plain
 *  session-less connection). Safe to call more than once. */
sec_status_t security_service_init(void);

/** Close the session. security_service_init() must be called again
 *  before using any other function. */
sec_status_t security_service_deinit(void);

/** True once security_service_init() has succeeded and not been
 *  followed by security_service_deinit(). */
bool security_service_is_ready(void);

/** Where every random byte this service needs on the HOST side comes from: security_service_get_random(), the
 *  software ephemeral ECDH key (chips without ECDH), the RSA-PSS salt and the SCP03 host challenge. Returns true when
 *  `buf` was filled with `len` bytes.
 *  The App registers the project's random source here at start-up (QRNG first, MCU TRNG fallback --
 *  qrng_service_random_bytes()), because this service must not depend on the QRNG service itself. Until something is
 *  registered (or with NULL) the backend uses the MCU TRNG (platform_rng). Call before security_service_init() so the
 *  SCP03 host challenge already uses it. Randomness generated INSIDE the chip (on-chip key generation, the ECDSA
 *  nonce) is the chip's own and is not affected. */
typedef bool (*sec_random_source_t)(uint8_t *buf, size_t len);
void security_service_set_random_source(sec_random_source_t source);

/** Fill `buf` with `len` random bytes from the registered random source (see security_service_set_random_source()). */
sec_status_t security_service_get_random(uint8_t *buf, size_t len);

/** Ensure an EC (NIST P-256) key pair exists at `key_id`, generating one
 *  on-chip if it does not -- the private key never leaves the secure
 *  element. `key_id` is caller-chosen and must not collide with
 *  anything else already provisioned on the chip (see
 *  Core_app/Drivers/SE05x/tests/se052_sign_example.c for the object-ID
 *  range to pick from on the SE052F backend). */
sec_status_t security_service_ensure_ec_keypair(uint32_t key_id);

/** Permanently delete the object at `key_id` (key pair, secret, or
 *  otherwise). */
sec_status_t security_service_delete_key(uint32_t key_id);

/** True if an object already exists at `key_id` (key pair, secret, or
 *  otherwise). */
bool security_service_key_exists(uint32_t key_id);

/** Store an arbitrary secret (a symmetric key, API token, certificate,
 *  wrapped key, ...) inside the secure element at `key_id`, overwriting
 *  whatever was there. Unlike security_service_ensure_ec_keypair()'s
 *  private key, this data DOES leave the chip again on
 *  security_service_load_secret() -- it buys protection from the host's
 *  own flash/RAM being read out, not secrecy from a host that asks the
 *  chip nicely. Size limit is backend-specific (order of ~800 bytes on
 *  the SE052F). */
sec_status_t security_service_store_secret(uint32_t key_id, const uint8_t *data, size_t len);

/** Read back a secret stored with security_service_store_secret().
 *  `*len` is the buffer capacity on call, the actual stored length on
 *  success. */
sec_status_t security_service_load_secret(uint32_t key_id, uint8_t *data, size_t *len);

/** SHA-256, computed inside the secure element (no host hash library
 *  needed). `digest` must point at 32 bytes. */
sec_status_t security_service_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

/** ECDSA-sign a pre-computed SHA-256 `digest` (32 bytes) with the key
 *  pair at `key_id`. `sig` must have room for at least 72 bytes (ASN.1
 *  DER, P-256 worst case); `*sig_len` is set to the actual length on
 *  success (pass the buffer's capacity in on call). */
sec_status_t security_service_ecdsa_sign(uint32_t key_id, const uint8_t digest[32],
                                          uint8_t *sig, size_t *sig_len);

/** ECDSA-verify `sig` (`sig_len` bytes, ASN.1 DER) of `digest` (32
 *  bytes) against the public key at `key_id`. `*valid` is only
 *  meaningful when this returns SEC_OK -- a transport/chip error is
 *  distinct from "signature did not verify". */
sec_status_t security_service_ecdsa_verify(uint32_t key_id, const uint8_t digest[32],
                                            const uint8_t *sig, size_t sig_len, bool *valid);

/** Convenience: SHA-256 `data` then ECDSA-sign the digest in one call. */
sec_status_t security_service_sign_message(uint32_t key_id, const uint8_t *data, size_t len,
                                            uint8_t *sig, size_t *sig_len);

/** Convenience: SHA-256 `data` then ECDSA-verify `sig` against it. */
sec_status_t security_service_verify_message(uint32_t key_id, const uint8_t *data, size_t len,
                                              const uint8_t *sig, size_t sig_len, bool *valid);

/** Multi-curve generalization of security_service_ensure_ec_keypair(): same
 *  behavior, but on the given `curve` instead of always NIST P-256.
 *  security_service_ensure_ec_keypair() is unchanged and just calls this
 *  with SEC_EC_CURVE_P256, so existing callers (app_main.c's self-test) are
 *  unaffected.
 *
 *  The curve is created on the chip first if it is not there yet (a
 *  Weierstrass curve must exist as a chip object before a key on it can be
 *  written). All seven sec_ec_curve_t values generate keys on this
 *  project's SE052F -- verified on real hardware. */
sec_status_t security_service_ensure_ec_keypair_ex(uint32_t key_id, sec_ec_curve_t curve);

/** Multi-hash generalization of security_service_ecdsa_sign(). `digest_len`
 *  must match `hash`'s output size (28/32/48/64 bytes). Works for a
 *  message/file of ANY size: hash it on the host first (in chunks, if
 *  needed) -- only the resulting fixed-size digest is ever sent to the
 *  chip. `sig` must have room for at least 141 bytes (ASN.1 DER, P-521
 *  worst case -- 72 is enough only for P-256, security_service_ecdsa_sign()'s
 *  own curve). */
sec_status_t security_service_ecdsa_sign_ex(uint32_t key_id, sec_hash_t hash,
                                             const uint8_t *digest, size_t digest_len,
                                             uint8_t *sig, size_t *sig_len);

/** Multi-hash generalization of security_service_ecdsa_verify(). */
sec_status_t security_service_ecdsa_verify_ex(uint32_t key_id, sec_hash_t hash,
                                               const uint8_t *digest, size_t digest_len,
                                               const uint8_t *sig, size_t sig_len, bool *valid);

/** Ensure an RSA key pair exists at `key_id` with modulus size `key_bits`,
 *  generating one on-chip if it does not -- the private key never leaves
 *  the secure element, same guarantee as security_service_ensure_ec_keypair().
 *  `key_id` must not collide with an EC key pair or anything else already
 *  provisioned on the chip.
 *
 *  Verified on real hardware at both 2048 and 4096 bits (unlike
 *  security_service_ensure_ec_keypair_ex()'s curve restriction, RSA is not
 *  gated on this chip instance). This BLOCKS the firmware's single main
 *  loop for the whole call -- measured ~20s for 4096 bits on real
 *  hardware (timing varies run to run) -- so it is a one-time
 *  provisioning operation, not something to call from a latency-sensitive
 *  path; callers over a transport (e.g. tools/evt2_cli.py) must budget a
 *  generous timeout (60s there). */
sec_status_t security_service_ensure_rsa_keypair(uint32_t key_id, sec_rsa_key_bits_t key_bits);

/** Read the public key of the EC key at `key_id` as a raw uncompressed
 *  point (0x04 || X || Y -- 65 bytes for P-256). The private key never
 *  leaves the chip; this is only the public half, which exists to be
 *  shared so a peer can verify this device's ECDSA signatures.
 *  `*point_len` is the buffer capacity on call, the actual length on
 *  success. The curve is not reported back -- the caller knows which
 *  curve it created the key on. */
sec_status_t security_service_read_ec_public_key(uint32_t key_id, uint8_t *point, size_t *point_len);

/** Store a PEER's EC public key (uncompressed point 0x04||X||Y, exactly
 *  the size `curve` requires) on this chip at `key_id`, so the existing
 *  security_service_ecdsa_verify[_ex]() can verify signatures made by that
 *  peer's private key -- the verify functions only accept a key_id already
 *  on THIS chip, so this is how a signature from another device becomes
 *  verifiable by this one. Replaces an existing PUBLIC key at `key_id`, but
 *  refuses (SEC_INVALID_PARAM) if `key_id` holds anything else -- a private
 *  key, key pair or secret -- so it cannot be used to wipe this device's
 *  own keys. */
sec_status_t security_service_import_ec_public_key(uint32_t key_id, sec_ec_curve_t curve,
                                                    const uint8_t *point, size_t point_len);

/** Import a COMPLETE EC key pair (private scalar + matching public point) into the chip at `key_id`, so a key made
 *  elsewhere can be used for security_service_ecdsa_sign*(), and its public half can be read back with
 *  security_service_read_ec_public_key(). (Historical caller: the now-deleted Middleware/CA/ca_provision_once.c
 *  used this once per board to import the TEST-ONLY identity in Middleware/CA/ca_identity_cfg.h -- that file is no
 *  longer compiled into the firmware; see its own top comment. ca_service.c only reads the already-provisioned
 *  identity back from the SE052F today, it does not call this.)
 *  `priv` is the big-endian scalar (exactly the curve's size, 32 bytes for P-256); `pub` the uncompressed point
 *  0x04||X||Y. The chip does NOT check that the two match -- a mismatch silently yields a key that signs with `priv` but
 *  reads back as `pub` -- so callers should read the public key back and compare it.
 *  Fails (SEC_ERROR) if `key_id` already holds an object: delete it first, this never overwrites a key by itself.
 *  NOTE: importing only `priv` (no public half) is a different, private-only object that can sign but cannot report its
 *  public key -- see docs/qrng_identity_key_import_experiment.md. */
sec_status_t security_service_import_ec_keypair(uint32_t key_id, sec_ec_curve_t curve, const uint8_t *priv, size_t priv_len,
                                                 const uint8_t *pub, size_t pub_len);

/** Generate a fresh EC key pair inside the chip as a TRANSIENT object at `key_id`: it lives only in the chip's RAM (no flash
 *  write, gone at reset/power loss) and its private key never leaves the chip. Meant for the per-call ephemeral ECDH key of
 *  the key exchange. Replaces a previous object at `key_id` (deleted first). Read the public half with
 *  security_service_read_ec_public_key(), use it with security_service_ecdh_to_secret(), and security_service_delete_key() it when done.
 *
 *  EXCEPTION -- chips that cannot do ECDH (security_service_derives_in_chip() == false, e.g. the SE050F2 in FIPS mode):
 *  the key pair is generated and kept in MCU RAM by the backend instead (P-256 only), because a key inside such a chip
 *  cannot be used for key agreement at all. read_ec_public_key()/ecdh_to_host()/delete_key() accept its `key_id` as
 *  usual; ecdh_to_secret() does not. delete_key() wipes the private scalar. */
sec_status_t security_service_generate_ephemeral_ec_keypair(uint32_t key_id, sec_ec_curve_t curve);

/** Length of the chip's factory-unique identifier (SE05x UNIQUE_ID). */
#define SEC_UNIQUE_ID_LEN 18U

/** Read the chip's factory-unique identifier (SE05x applet resource UNIQUE_ID, 18 bytes, read-only, set by NXP). Used as
 *  the device id / certificate CN of the CA identity. */
sec_status_t security_service_read_unique_id(uint8_t uid[SEC_UNIQUE_ID_LEN]);

/** True if this chip can keep key agreement and derivation inside it: security_service_ecdh_to_secret(),
 *  security_service_hkdf_to_secret() and security_service_hkdf_export() work. False on chips whose applet has neither
 *  (applet 3.x, e.g. the SE050F2: ECDH and HKDF are refused in FIPS mode) -- there a caller must get the ECDH result with
 *  security_service_ecdh_to_host() and run HKDF itself on the MCU, then hand any key that only needs to MAC back to the
 *  chip with security_service_write_transient_hmac_key(). Fixed per build (depends on the applet version the SE05x host
 *  library is configured for), not probed at run time. */
bool security_service_derives_in_chip(void);

/* ---- Key agreement and derivation that keeps every secret INSIDE the chip ----------------------------------------
 *
 * "Secret objects" are transient HMAC-key objects in the chip's RAM. Nothing here ever returns the ECDH shared secret, and
 * derived keys stay in a secret object unless the caller explicitly exports them with security_service_hkdf_export() -- which
 * exists ONLY because the STM32's CRYP hardware needs the raw AES session keys. All secret objects are transient: gone at
 * reset, never written to flash. Delete them with security_service_delete_key() as soon as they are used. */

/** ECDH between the EC private key at `ec_key_id` (on the chip) and `peer_point` (uncompressed 0x04||X||Y, P-256), with the
 *  32-byte result written straight into a NEW transient secret object `secret_id` (an existing object there is replaced).
 *  The shared secret is never returned to the caller. */
sec_status_t security_service_ecdh_to_secret(uint32_t ec_key_id, const uint8_t *peer_point, size_t peer_len,
                                             uint32_t secret_id);

/** HKDF-SHA256 (extract-and-expand) with the secret object `ikm_id` as input keying material. `salt` 0..64 bytes, `info`
 *  1..80 bytes. The `out_len` output bytes are written into a NEW transient secret object `out_id` (replaced if present) and
 *  do not leave the chip. */
sec_status_t security_service_hkdf_to_secret(uint32_t ikm_id, const uint8_t *salt, size_t salt_len, const uint8_t *info,
                                             size_t info_len, uint32_t out_id, size_t out_len);

/** Same derivation, but the output is RETURNED to the caller in `out` (`out_len` bytes). The one legitimate use is handing
 *  AES session keys to the CRYP peripheral; the caller must wipe `out` when the call ends. Never use it for keys that only
 *  need to MAC or verify -- keep those in a secret object (security_service_hkdf_to_secret()). */
sec_status_t security_service_hkdf_export(uint32_t ikm_id, const uint8_t *salt, size_t salt_len, const uint8_t *info,
                                          size_t info_len, uint8_t *out, size_t out_len);

/** HMAC-SHA256 of `data` computed inside the chip with the secret object `key_id`. `mac` receives 32 bytes. */
sec_status_t security_service_hmac_sha256_with_secret(uint32_t key_id, const uint8_t *data, size_t data_len, uint8_t mac[32]);

/** ECDH between the EC private key at `ec_key_id` (on the chip) and `peer_point` (uncompressed 0x04||X||Y, P-256), with
 *  the 32-byte result returned to the caller in `z_out` instead of staying in a chip secret object.
 *
 *  THIS IS THE EXCEPTION security_service_ecdh_to_secret()'s own doc comment refers to ("never returns the ECDH shared
 *  secret") -- restored CONDITIONALLY (2026-09-24) for exactly one caller: ca_protocol.c's CA_CMD_DERIVE_KEYS, only on
 *  its hybrid-PQC path (SecP256r1MLKEM768, see CLAUDE.md's Giai đoạn 1). The SE052F cannot run ML-KEM itself (it runs in
 *  MCU software instead, see Core_app/Middleware/PQC/pqc_kem.h), so the two shared secrets can only be combined
 *  (`Z_ecdh || Z_kem` -> one HKDF) OUTSIDE the chip -- there is no way to hand ML-KEM's software-computed Z_kem INTO an
 *  SE052x HKDF call the way the classical-only path hands its Z straight to Se05x_API_HKDF_Extended() without it ever
 *  leaving the chip. This is a real, deliberate weakening of "every secret stays in the SE052F" for the hybrid case only
 *  -- the classical-only path (security_service_ecdh_to_secret()) is completely unchanged and still keeps Z on-chip.
 *  Callers must wipe `z_out` themselves the moment the combined IKM has been consumed.
 *
 *  Uses Se05x_API_ECDHGenerateSharedSecret() (not the _InObject variant) -- unlike ecdh_to_secret()'s path, this one has
 *  not been exercised on this project's chip before this addition (see CLAUDE.md's 2026-09-21 note: "chưa được dự án
 *  gọi"); the SE05x reference manual documents a chip-side FIPS-mode gate that can make this command unconditionally
 *  fail (SW_CONDITIONS_NOT_SATISFIED) depending on the applet's own configuration, independent of anything this host
 *  code controls -- verify on real hardware before relying on it (see app_pqc_kem_self_test()'s hybrid extension). */
sec_status_t security_service_ecdh_to_host(uint32_t ec_key_id, const uint8_t *peer_point, size_t peer_len,
                                           uint8_t z_out[32]);
/*  On a chip where security_service_derives_in_chip() is false this is the ONLY ECDH available, on every path (not just
 *  the hybrid one): it computes the result in MCU software from the RAM ephemeral key (see
 *  security_service_generate_ephemeral_ec_keypair()). SEC_INVALID_PARAM if `peer_point` is not on the curve. */

/** Write `key` (`key_len` bytes, 1..64) verbatim into a TRANSIENT HMAC-key object at `key_id` (RAM-only, gone at
 *  reset -- replaces whatever was at `key_id`, same as security_service_ecdh_to_secret()'s target object). Unlike
 *  security_service_hkdf_to_secret() (whose output is computed and stays on-chip start to finish), this hands the chip a
 *  key value that was computed OUTSIDE it -- the one legitimate use is ca_protocol.c's hybrid-PQC path, which must derive
 *  the confirmation key in MCU software (see security_service_ecdh_to_host()'s doc comment for why) but still wants
 *  CONFIRM/VERIFY_CONFIRM's HMAC itself to run on-chip afterward, unchanged, exactly like the classical path. Callers
 *  must wipe their own copy of `key` immediately after this call returns. */
sec_status_t security_service_write_transient_hmac_key(uint32_t key_id, const uint8_t *key, size_t key_len);

/** RSA counterpart of security_service_import_ec_public_key(): `modulus` is
 *  the big-endian modulus (256/384/512 bytes for RSA-2048/3072/4096),
 *  `exponent` the big-endian public exponent (1..4 bytes, normally 65537).
 *  Same replace-public-only/refuse-anything-else rule. */
sec_status_t security_service_import_rsa_public_key(uint32_t key_id, const uint8_t *modulus, size_t modulus_len,
                                                     const uint8_t *exponent, size_t exponent_len);

/** Read the public half (modulus, public exponent -- both big-endian,
 *  unsigned) of the RSA key pair at `key_id`. Needed to actually use an
 *  on-chip-generated RSA key pair for anything: since the private key
 *  never leaves the chip (by design), a peer that needs to verify this
 *  device's signatures needs the public key handed to it somehow, and
 *  this is the only way to get it out. `*modulus_len`/`*exponent_len` are
 *  buffer capacities on call, actual lengths on success (modulus is the
 *  key's byte length, e.g. 256 for RSA-2048; exponent is typically 3
 *  bytes for the common 0x010001/65537). */
sec_status_t security_service_read_rsa_public_key(uint32_t key_id, uint8_t *modulus, size_t *modulus_len,
                                                   uint8_t *exponent, size_t *exponent_len);

/** RSA-sign a pre-computed digest of the given `hash` algorithm, using
 *  `padding` (PKCS1_V15 or PSS).
 *
 *  Deliberately NOT implemented via Se05x_API_RSASign: that command hashes
 *  the *whole* message internally in one shot, with no streaming/chunked
 *  variant and no digest-input mode (confirmed against the SE05x APDU
 *  reference), so it cannot sign anything larger than a single APDU
 *  payload (~1KB). Instead this builds the padded block on the chip's
 *  HOST MCU (this firmware, always exactly the key's modulus size, e.g.
 *  256 bytes for RSA-2048, regardless of the original message size) and
 *  applies the chip's raw RSA private-key primitive
 *  (Se05x_API_RSADecrypt, kSE05x_RSAEncryptionAlgo_NO_PAD) to it -- the
 *  same pattern NXP's own reference host library
 *  (sss_se05x_asymmetric_sign_digest() in fsl_sss_util_rsa_sign_utils.c)
 *  uses for both padding schemes. Because only the small fixed-size
 *  digest and padding ever reach the chip, this works for a file of any
 *  size the same way security_service_ecdsa_sign_ex() does: hash it on
 *  the host first.
 *
 *  PSS additionally needs a random salt (drawn from the chip's own TRNG,
 *  see Se05x_API_GetRandom) and extra internal hash operations (also done
 *  via the chip, Se05x_API_DigestOneShot) beyond the caller-supplied
 *  digest -- so a PSS signature costs more chip round trips than
 *  PKCS1_V15's single RSADecrypt call.
 *
 *  `sig`/`*sig_len` follow the same in/out convention as
 *  security_service_ecdsa_sign_ex(); `*sig_len` must be at least the
 *  key's modulus size (256/384/512 bytes for 2048/3072/4096-bit keys). */
sec_status_t security_service_rsa_sign_digest(uint32_t key_id, sec_rsa_padding_t padding, sec_hash_t hash,
                                               const uint8_t *digest, size_t digest_len,
                                               uint8_t *sig, size_t *sig_len);

/** RSA-verify `sig` against a pre-computed digest: undoes the signature
 *  with the chip's raw RSA public-key primitive (Se05x_API_RSAEncrypt,
 *  kSE05x_RSAEncryptionAlgo_NO_PAD), then checks the recovered block
 *  against `padding`'s expected encoding of `digest` -- the verify-side
 *  mirror of security_service_rsa_sign_digest(). `padding` must match
 *  what the signature was actually produced with; PSS verification
 *  recovers the salt from the signature itself (per RFC 8017), it does
 *  not need to be supplied separately. `*valid` is only meaningful when
 *  this returns SEC_OK. */
sec_status_t security_service_rsa_verify_digest(uint32_t key_id, sec_rsa_padding_t padding, sec_hash_t hash,
                                                 const uint8_t *digest, size_t digest_len,
                                                 const uint8_t *sig, size_t sig_len, bool *valid);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_SERVICE_H */
