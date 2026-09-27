/**
 * @file    app_self_test.h
 * @brief   App-layer self-test entry points -- exercises the whole Core_app stack, dev/QA only.
 *
 * Split out of app_main.h/.c (2026-09-24) so a product build can link app_main.c (init + command-protocol wiring,
 * needed to actually use the services/adapters) without also linking this file: production firmware does not run
 * self-tests. main()'s boot sequence calls these explicitly (see Src/main.c); a product build simply omits those
 * calls and this file's .c is not compiled in.
 */
#ifndef APP_SELF_TEST_H
#define APP_SELF_TEST_H

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/** Exercise the stack built in Core_app end to end -- Platform (UART for
 *  status output) and Middleware/Security (SE052F secure element:
 *  random, on-chip EC key pair, sign, verify) -- reporting each step
 *  over BOARD_DEBUG_UART. Returns true if every step succeeded. */
bool app_self_test(void);

#if EVT2_ENABLE_BIOMETRIC
/** Exercise every Middleware/Biometric entry point (FPC5234 fingerprint
 *  sensor: init/is_ready, list/enroll/identify/delete_template/
 *  template_exists, navigation) the same way app_self_test() exercises
 *  Middleware/Security, reporting each step over BOARD_DEBUG_UART.
 *
 *  WARNING: unlike app_self_test() (which only ever touches its own
 *  scratch object ids), this DELETES EVERY TEMPLATE ALREADY ENROLLED ON
 *  THE DEVICE before enrolling its own scratch one -- do not run this on
 *  a device with real users' fingerprints you want to keep. It exists to
 *  exercise the full API surface end to end, not as a safe-by-default
 *  boot-time smoke test; wire it into main() only on a dev board.
 *
 *  enroll/identify/navigation still need a human to actually touch the
 *  sensor -- each is bounded by its own timeout and reported as "TIMEOUT
 *  (not a failure)" rather than hanging forever if nobody touches it.
 *  Returns true if every step that does not require a touch succeeded
 *  (i.e. transport/protocol are sound) -- an unattended run that only
 *  times out on the touch-dependent steps still returns true; only a
 *  real transport/protocol error returns false. Requires the
 *  HOST_IF_UART preprocessor symbol (see
 *  Core_app/Drivers/FPC5234/uart_host.c) to actually talk to the sensor. */
bool app_biometric_self_test(void);
#endif

/** Exercise every Middleware/QRNG entry point (ADC-noise TRNG: init/
 *  is_ready, get_noise, get_entropy under the Toeplitz, HMAC-SHA256 and
 *  AES-128 CBC-MAC extractors, reseed) the same way app_self_test()
 *  exercises Middleware/Security, reporting each step over
 *  BOARD_DEBUG_UART. No human interaction needed -- the noise source is
 *  the analog circuit itself, not a touch sensor. Returns true if every
 *  step succeeded. */
bool app_qrng_self_test(void);

/** Exercise every CMD_TYPE_QRNG sub-command in
 *  Core_app/App/protocol_adapters/qrng_protocol.c directly (bypassing USB
 *  framing -- calls qrng_protocol_handler()/qrng_protocol_poll() the same
 *  way command_protocol.c's dispatcher would, just without a real host on
 *  the other end), the same way app_qrng_self_test() exercises
 *  qrng_service.h directly one layer down. Must run after
 *  app_command_protocol_init() (needs command_protocol_init() to have run
 *  for the continuous-stream sub-commands' pushed frames to actually go
 *  out over platform_usb.h) and after app_qrng_self_test() (needs
 *  qrng_service_init() to have already succeeded). Returns true if every
 *  sub-command's dispatch/response-formatting logic behaved as
 *  documented in qrng_protocol.c. */
bool app_qrng_protocol_self_test(void);

/** Exercise every CMD_TYPE_CA sub-command in
 *  Core_app/App/protocol_adapters/ca_protocol.c directly (bypassing USB
 *  framing -- calls ca_protocol_handler() the same way command_protocol.c's
 *  dispatcher would), the same way app_qrng_protocol_self_test() exercises
 *  qrng_protocol.c. Must run after app_self_test() (needs ca_service_init()
 *  to have already provisioned the device identity) and after
 *  app_qrng_self_test() (CA_CMD_BEGIN draws its nonce from qrng_service.h).
 *
 *  This is a SINGLE-BOARD test: there is no second device identity to hand
 *  it, so the "peer" in the VERIFY_PEER/DERIVE_KEYS/CONFIRM checks is this
 *  same board's own ephemeral key and identity. That fully exercises the
 *  ECDH/HKDF/HMAC plumbing and VERIFY_PEER's parsing, chain-verification and
 *  reflection-guard logic (a peer signed by ITSELF is exactly what the
 *  reflection guard exists to reject, so the self-test asserts CA_PEER_SELF
 *  there, not CA_PEER_OK) -- but it does NOT prove VERIFY_PEER accepts a
 *  genuinely different peer's certificate chain end to end; that combination
 *  was verified once already, offboard, in the 2026-09-22 CA review ("Test 4":
 *  ca_chain_verify() on this same board's SE052F accepting a second device's
 *  real certificate/signature). Returns true if every step behaved as
 *  documented in ca_protocol.c. */
bool app_ca_protocol_self_test(void);

/** Giai đoạn 1 (2026-09-24, xem CLAUDE.md) hybrid-PQC extension of app_ca_protocol_self_test() above: same
 *  single-board simulated-peer technique, but exercising the ML-KEM-768 hybrid path through CA_CMD_BEGIN/
 *  SIGN_TRANSCRIPT/VERIFY_PEER/DERIVE_KEYS/CONFIRM/VERIFY_CONFIRM's new ca_kem_ext_t extension -- most importantly
 *  CA_CMD_DERIVE_KEYS's hybrid combiner (security_service_ecdh_to_host() + pqc_kem_decapsulate() + software HKDF),
 *  never exercised end to end before this. Must run after app_ca_protocol_self_test() (BEGIN resets any session
 *  state that leaves behind) and after app_qrng_self_test() (same QRNG dependency as that test). Returns true if
 *  every step succeeded, or if BEGIN's ML-KEM-768 keygen is unavailable this boot (best-effort, not a failure). */
bool app_ca_protocol_hybrid_self_test(void);

/** Giai đoạn 0 spike (2026-09-24, xem CLAUDE.md) for the hybrid-PQC-for-CA-handshake work: exercises
 *  Core_app/Middleware/PQC/pqc_kem.h (ML-KEM-768, vendored PQClean crypto_kem/ml-kem-768/clean) directly, two ways:
 *  (1) decapsulate a fixed cross-implementation vector (pqc_kem_kat_vector.h, generated by an independent
 *  third-party Python ML-KEM-768) and check the shared secret matches bit-for-bit -- proves the on-device C path
 *  (NTT, poly encode/decode, FO-transform, SHA3/SHAKE) agrees with someone else's implementation of the same
 *  standard, not just itself; (2) a full on-device keygen -> encapsulate -> decapsulate round trip, checking the
 *  two sides' shared secrets match and are non-zero -- covers keygen/encapsulate, which (1) does not exercise.
 *  Also logs wall-clock timing for all three operations (platform_get_tick_ms()) -- see CLAUDE.md's Giai đoạn 0 for
 *  the RAM/flash budget this is meant to inform. Returns true if both checks pass. */
bool app_pqc_kem_self_test(void);

/** Giai đoạn 4 spike (2026-09-24, xem CLAUDE.md) for PQC-for-"Ký số" (ML-DSA, FIPS 204): exercises
 *  Core_app/Middleware/PQC/pqc_sign.h across all three vendored levels (ML-DSA-44/65/87) the same two ways
 *  app_pqc_kem_self_test() exercised ML-KEM-768: (1) a fixed cross-implementation vector
 *  (pqc_sign_kat_vector.h, independent Python `dilithium-py`) -- keygen-from-seed reproduces the same public key,
 *  and verify() accepts a signature that reference independently produced; (2) a full on-device sign -> verify
 *  round trip, proving this feature's whole seed-only persistent-identity design
 *  (pqc_randombytes_pin_next(), randombytes.h -- the long-term secret is a 32-byte seed, never the full expanded
 *  secret key) actually works end to end. Also logs wall-clock timing for keygen/sign per level. Returns true if
 *  every level's both checks pass. */
bool app_pqc_sign_self_test(void);

/** Giai đoạn 4 (2026-09-24, xem CLAUDE.md): exercises security_protocol.c's ML-DSA sub-commands (0x16-0x19:
 *  ENSURE_MLDSA_KEYPAIR/MLDSA_SIGN/MLDSA_VERIFY/READ_MLDSA_PUBLIC_KEY) directly (bypassing USB framing, same
 *  technique app_qrng_protocol_self_test()/app_ca_protocol_self_test() use) for all three levels -- unlike
 *  app_pqc_sign_self_test() (which proves the ML-DSA math itself is correct), this proves the WIRE plumbing: a
 *  seed persists across separate ENSURE/SIGN/READ_PUBLIC_KEY calls (security_service_store_secret()/
 *  load_secret()), and a signature produced through this path verifies against a public key read back through
 *  it. Calls security_protocol_handler() directly (same as the other *_protocol_self_test() functions), so it
 *  does NOT need app_command_protocol_init() to have run -- only app_self_test() (security_service_init()). */
bool app_security_mldsa_protocol_self_test(void);

/** Regression test for the 2026-09-25 GCM-edge-size bug (see platform_crypto.c's aes256_gcm_run() doc
 *  comment): the CRYP/SAES hardware's own GCM (and even plain CTR) mode silently mis-computed the
 *  result for any length that wasn't an exact multiple of 16 bytes -- real H.264/HEVC video chunks hit
 *  this on essentially every chunk (never 16-aligned) while fixed-size 3200B audio chunks never did,
 *  which is what made it look video-specific on a real call. platform_aes256_gcm_encrypt()/_decrypt()
 *  were rewritten to build GCM themselves (hardware AES-256 one block at a time + software GHASH),
 *  sidestepping the broken hardware modes entirely. This test encrypts-then-decrypts on this same
 *  device at a spread of sizes (16/17/32/33/48 boundary cases, 3200 control, and several real observed
 *  failure sizes up to 7157) to catch any regression in that implementation. Cheap (pure software/single-
 *  block hardware calls, no SE05x/USB), safe to leave running on every boot. */
bool app_gcm_edge_size_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* EVT2_DIAGNOSTICS */

#endif /* APP_SELF_TEST_H */
