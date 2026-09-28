/**
 * @file    qrng_service.h
 * @brief   Chip-agnostic QRNG (analog-noise TRNG) service interface.
 *
 * App code that needs high-quality random data calls only this header
 * -- never Core_app/Drivers/QRNG's entropy/extractor algorithms or
 * Core_app/Platform's ADC/DAC/RNG/hash primitives directly. Swapping
 * the noise source (a different analog front-end, or a future
 * dedicated QRNG chip) means adding another backend under
 * Core_app/Middleware/QRNG/<backend>/ that implements this same
 * interface; App does not change. This mirrors exactly how
 * Core_app/Middleware/Security/security_service.h and
 * Core_app/Middleware/Biometric/biometric_service.h decouple App from
 * the SE052F and FPC5234.
 *
 * Ported from the command set of D:\Workspace\STM32\vQRNG1.0 (see that
 * project's README) -- that project exposes this pipeline over a USB
 * CDC byte-command protocol; this service exposes the same underlying
 * operations as plain C calls instead, so App decides how (or whether)
 * to expose it over USB/UART on its own.
 *
 * Scope: random data (raw noise or extractor-whitened entropy),
 * continuous self-test status, and extractor key/algorithm management.
 * All three extractors from the upstream project are available:
 * QRNG_EXTRACTOR_TOEPLITZ, QRNG_EXTRACTOR_HMAC_SHA256 and
 * QRNG_EXTRACTOR_AES -- the AES one uses STM32H753's CRYP hardware
 * accelerator instead of upstream's software backends, see
 * Core_app/Drivers/QRNG/aes_cbc_mac.h's doc comment for why.
 */
#ifndef QRNG_SERVICE_H
#define QRNG_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    QRNG_OK = 0,
    QRNG_ERROR,        /* transport/hardware error -- see backend logs */
    QRNG_NOT_READY,    /* qrng_service_init() was not called, or failed */
    QRNG_INVALID_PARAM,
    QRNG_HEALTH_FAIL,  /* NIST 800-90B online health test failed on this draw */
    QRNG_TIMEOUT,
} qrng_status_t;

typedef enum {
    QRNG_EXTRACTOR_TOEPLITZ = 0,   /* default */
    QRNG_EXTRACTOR_HMAC_SHA256,
    QRNG_EXTRACTOR_AES,
} qrng_extractor_t;

/** Exact size qrng_service_get_noise() fills per call -- one ADC DMA
 *  half-buffer's worth of raw 16-bit samples. */
#define QRNG_NOISE_BYTES 2048U

/** Exact size qrng_service_get_entropy() fills per call -- one
 *  extractor pass over that same half-buffer. */
#define QRNG_ENTROPY_BYTES 1024U

/** Bring the noise source up: enable the analog noise circuit (DAC +
 *  opto-isolator), start ADC/timer sampling, run the NIST 800-90B
 *  startup health test, and initialize the extractor (key/matrix
 *  generation). Safe to call more than once. */
qrng_status_t qrng_service_init(void);

/** Tear down: stop ADC/timer sampling and disable the noise circuit.
 *  qrng_service_init() must be called again before using any other
 *  function. */
qrng_status_t qrng_service_deinit(void);

/** True once qrng_service_init() has succeeded and not been followed by
 *  qrng_service_deinit(). */
bool qrng_service_is_ready(void);

/** Fill `buf` with QRNG_NOISE_BYTES bytes of raw (un-whitened) noise
 *  samples -- `len` must equal QRNG_NOISE_BYTES exactly. Subject to the
 *  same online health test as qrng_service_get_entropy() if enabled
 *  (see qrng_service_set_health_test()). */
qrng_status_t qrng_service_get_noise(uint8_t *buf, size_t len);

/** Fill `buf` with QRNG_ENTROPY_BYTES bytes of extractor-whitened,
 *  high-quality random data -- `len` must equal QRNG_ENTROPY_BYTES
 *  exactly. Returns QRNG_ERROR (buf's contents undefined -- do not use
 *  them) if the selected extractor is HMAC-SHA256 or AES and the
 *  underlying hardware call failed; the Toeplitz extractor is pure math
 *  and cannot fail this way. */
qrng_status_t qrng_service_get_entropy(uint8_t *buf, size_t len);

/** Same as qrng_service_get_entropy(), except `algorithm` overrides
 *  whichever extractor qrng_service_set_extractor() currently has
 *  selected FOR THIS ONE CALL ONLY -- the global default (what
 *  qrng_service_get_entropy() itself uses, and what a future
 *  qrng_service_set_extractor() call changes) is left untouched.
 *
 *  For a caller that needs to GUARANTEE a specific algorithm regardless
 *  of what some other, unrelated caller has configured -- e.g.
 *  Core_app/App/protocol_adapters/media_protocol.c's QRNG nonce pool
 *  needs Toeplitz every time (pure math, no CRYP/HASH hardware, so it
 *  never contends with platform_aes256_gcm_encrypt()/decrypt() sharing
 *  the same physical CRYP peripheral -- see that file's doc comment),
 *  while a USB client's own QRNG_CMD_SET_EXTRACTOR + GET_ENTROPY/
 *  STREAM_ENTROPY calls should keep working exactly as configured, even
 *  while a media/video-call session is running concurrently. Calling
 *  qrng_service_set_extractor() from such a caller instead would
 *  silently overwrite and fight the USB client's own choice every time
 *  it ran -- this function exists so that never has to happen. */
qrng_status_t qrng_service_get_entropy_with(qrng_extractor_t algorithm, uint8_t *buf, size_t len);

/** THE random source for everything in this firmware that needs random bytes (nonces, ephemeral keys, seeds, salts,
 *  challenges): QRNG first, MCU hardware TRNG (platform_rng) as fallback. Any `len`.
 *  Per chunk of up to QRNG_ENTROPY_BYTES: one qrng_service_get_entropy_with(QRNG_EXTRACTOR_TOEPLITZ, ...) draw (Toeplitz
 *  is pure math -- never contends with live AES-GCM on the CRYP peripheral); if that draw fails (QRNG not initialised,
 *  switched off by a board safety lock, health-test alarm, timeout), the chunk comes from platform_rng instead. Unused
 *  bytes of a draw are wiped, never kept for a later caller.
 *  `from_qrng` (optional, may be NULL) is set true only if every byte came from the QRNG.
 *  Returns QRNG_OK when `buf` was filled (from either source), QRNG_ERROR if both sources failed (`buf` is wiped then).
 *  Not for callers that must deliver QRNG output specifically (qrng_protocol.c's GET_ENTROPY/STREAM_ENTROPY): those keep
 *  calling qrng_service_get_entropy() and report its failure instead of silently substituting the TRNG. */
qrng_status_t qrng_service_random_bytes(uint8_t *buf, size_t len, bool *from_qrng);

/** Enable/disable the continuous online health test (NIST 800-90B RCT +
 *  APT) that qrng_service_get_noise()/get_entropy() run on every draw.
 *  Enabled by default after qrng_service_init(). */
qrng_status_t qrng_service_set_health_test(bool enable);

/** True if the most recent health-tested draw passed (or the health
 *  test is disabled -- there is nothing to fail). False after a draw
 *  returned QRNG_HEALTH_FAIL. */
bool qrng_service_is_healthy(void);

/** Select which extractor qrng_service_get_entropy() uses. Does not
 *  reseed or affect qrng_service_get_noise() (which is always raw,
 *  regardless of the selected extractor). */
qrng_status_t qrng_service_set_extractor(qrng_extractor_t algorithm);

/** Set the key/matrix for `algorithm` directly (instead of the one
 *  generated internally from the hardware TRNG at init/reseed time).
 *  `len` must match what `algorithm` expects (32 bytes for
 *  QRNG_EXTRACTOR_HMAC_SHA256, 16 bytes for QRNG_EXTRACTOR_AES;
 *  QRNG_EXTRACTOR_TOEPLITZ's raw matrix size is a Drivers/QRNG-internal
 *  detail, not exposed here -- use qrng_service_reseed_extractor() to
 *  regenerate it from the TRNG instead of supplying one by hand). */
qrng_status_t qrng_service_set_extractor_key(qrng_extractor_t algorithm, const uint8_t *key, size_t len);

/** Regenerate the current extractor's key/matrix from fresh entropy,
 *  for better long-term random quality. Returns QRNG_ERROR (key/matrix
 *  left unchanged) if the selected extractor is HMAC-SHA256 or AES and
 *  the underlying hardware call failed. */
qrng_status_t qrng_service_reseed_extractor(void);

/** Enable/disable automatic reseeding of the extractor every N calls to
 *  qrng_service_get_entropy() (N is a Core_app/Drivers/QRNG/qrng_constant.h
 *  setting). Disabled by default -- call qrng_service_reseed_extractor()
 *  manually, or enable this for periodic automatic reseeding. */
qrng_status_t qrng_service_set_auto_reseed(bool enable);

/** Exact size qrng_service_get_startup_health_record() fills -- a
 *  snapshot of the same raw ADC half-buffer the NIST 800-90B startup
 *  health test last passed on, same size as QRNG_NOISE_BYTES since it IS
 *  one such buffer. */
#define QRNG_STARTUP_HEALTH_RECORD_BYTES QRNG_NOISE_BYTES

/** Copy the raw sample snapshot captured at the moment the startup
 *  health test (NIST 800-90B RCT/APT, run once inside
 *  qrng_service_init()) last passed into `buf` -- `len` must equal
 *  QRNG_STARTUP_HEALTH_RECORD_BYTES exactly. For offline analysis of
 *  what the analog front-end looked like at bring-up, not a live draw --
 *  call qrng_service_get_noise() for that. Returns QRNG_NOT_READY if
 *  qrng_service_init() has not completed successfully since boot (or
 *  since the last qrng_service_deinit()). */
qrng_status_t qrng_service_get_startup_health_record(uint8_t *buf, size_t len);

/** ADC sample rate of the noise source, samples/s. `*boot_sps`: measured over 100 ms right after the ADC started in
 *  qrng_service_init() (0 if it never got that far) -- kept even if the startup health check failed afterwards.
 *  `*live_sps`: measured now over `window_ms` (1..1000, blocks that long; 0 when the service is not running). */
qrng_status_t qrng_service_measure_adc_rate(uint32_t window_ms, uint32_t *boot_sps, uint32_t *live_sps);

/** What the last qrng_service_init() did (kept after a failure, for bring-up of the analog front end). */
typedef struct {
    uint8_t init_status;      /* qrng_status_t returned by the last qrng_service_init() (0xFF = never ran) */
    uint8_t step;             /* last step reached: 1 DAC, 2 analog power-on, 3 settle + crypto init, 4 ADC/timer
                               * init, 5 ADC start, 6 startup health check, 7 done */
    uint8_t health_status;    /* entropy_health_t of the last startup attempt: 0 OK, 1 RCT, 2 APT, 0xFF no buffer */
    uint8_t attempts;         /* startup health-check attempts made */
    uint32_t healthy_samples; /* samples that passed the online tests in the last attempt before it tripped */
    uint32_t ad5398_ua;       /* AD5398 current read back after power-on (0 if not read) */
    uint16_t min;             /* min / max of the last attempt's 1024-sample buffer */
    uint16_t max;
    uint16_t samples[8];      /* first raw samples of that buffer */
} qrng_init_diag_t;

void qrng_service_get_init_diag(qrng_init_diag_t *out);

/** Raw ADC samples of the noise source, NO health test (bring-up/analysis of the analog front end). If the service
 *  is not running, powers the analog front end (same sequence as qrng_service_init()), waits 3 s to settle and
 *  starts the ADC; it stays on for later captures until qrng_service_raw_stop(). Copies one fresh half-buffer:
 *  `n` must be QRNG_RAW_CAPTURE_SAMPLES consecutive 12-bit samples at the ADC rate. */
#define QRNG_RAW_CAPTURE_SAMPLES 1024U
qrng_status_t qrng_service_raw_capture(uint16_t *out, size_t n);

/** Stops what qrng_service_raw_capture() started (ADC, analog front end); no effect while the service itself runs. */
qrng_status_t qrng_service_raw_stop(void);

#if EVT2_DIAGNOSTICS /* self-tests, benchmarks and diagnostics -- dev/QA only, see Core/Src/main.c */

/* ---- Porting-fidelity self-tests (algorithm math only, no live ADC/RNG) ---- */

/** Number of bytes qrng_service_self_test_toeplitz() writes to `buf` --
 *  same size as QRNG_ENTROPY_BYTES since the KAT drives the same
 *  extractor_run()-shaped loop over one full ADC-sample-sized input. */
#define QRNG_TOEPLITZ_KAT_BYTES 1024U

/** Deterministic Known-Answer Test of the Toeplitz extractor math only
 *  (toeplitz_build_lookup()/toeplitz_extractor_ultra_fast() in
 *  Core_app/Drivers/QRNG/toeplitz.c) -- does NOT touch the live ADC/DAC/
 *  RNG and does not require qrng_service_init() to have been called.
 *  Feeds a fixed, reproducible xorshift32-generated matrix (seed
 *  0x12345678) and input through the exact same iteration
 *  qrng_service_get_entropy()'s Toeplitz path uses, and writes the
 *  resulting QRNG_TOEPLITZ_KAT_BYTES to `buf`.
 *
 *  This exists to answer one question: does this port compute the
 *  identical result the original D:\Workspace\STM32\vQRNG1.0\Core\Src\
 *  toeplitz.c/toeplitz_util.c would for the same input? Compare the hex
 *  dump this produces against a hex dump from a matching KAT harness
 *  built against the unmodified original sources (same seed, same
 *  matrix/input generation, same loop) -- see app_main.c's call site
 *  for the exact byte layout logged. */
qrng_status_t qrng_service_self_test_toeplitz(uint8_t buf[QRNG_TOEPLITZ_KAT_BYTES]);

/** Known-Answer Test of the HMAC-SHA256 path (Core_app/Platform's HASH
 *  peripheral via Core_app/Drivers/QRNG/hmac_sha256.c) against RFC 4231
 *  Test Case 2 (key "Jefe", data "what do ya want for nothing?") -- a
 *  published, independent reference, not vQRNG1.0's own output: that
 *  project's default HMAC path used ST's proprietary CryptoLib rather
 *  than the hardware HASH accelerator this port uses, so there is no
 *  meaningful "original" run to diff against for this specific
 *  algorithm -- the RFC vector is the correct reference here instead.
 *  Sets *matches_rfc4231 to true iff the computed digest matches the
 *  RFC's published expected value. Returns QRNG_ERROR (not the match
 *  result) if the underlying platform_hmac_sha256() call itself fails. */
qrng_status_t qrng_service_self_test_hmac(bool *matches_rfc4231);

/** Known-Answer Test of the AES-128 CBC-MAC path (Core_app/Platform's
 *  CRYP hardware accelerator via Core_app/Drivers/QRNG/aes_cbc_mac.c)
 *  against the published FIPS-197 Appendix B AES-128 test vector,
 *  run as a single-block AES-128-CBC-MAC (zero IV, one plaintext block
 *  == plain AES-128-ECB-encrypt of that block, since P0 XOR 0 == P0) --
 *  a published, independent reference, not vQRNG1.0's own output: that
 *  project's default AES path is Cortex-M assembly this port does not
 *  use (see aes_cbc_mac.h's doc comment), so there is no meaningful
 *  "original" run to diff against here either. Sets *matches_fips197 to
 *  true iff the computed MAC matches the published expected value.
 *  Returns QRNG_ERROR (not the match result) if the underlying
 *  platform_aes128_cbc_mac() call itself fails. */
qrng_status_t qrng_service_self_test_aes(bool *matches_fips197);

/** Cross-checks platform_aes128_cbc_mac_batch()'s multi-block path (the
 *  one Core_app/Drivers/QRNG/extractor.c's AES branch actually calls,
 *  via aes_cbc_mac_extractor_batch() -- QRNG_ADC_SAMPLES /
 *  QRNG_AES_INPUT_EXTRACTOR_SIZE independent CBC-MAC sub-blocks sharing
 *  one CRYP key-load, see platform_crypto.c's doc comment) against
 *  qrng_service_self_test_aes()'s already-FIPS-197-verified single-block
 *  path: computes 2 independent MACs (distinct plaintext blocks, same
 *  key) both via platform_aes128_cbc_mac_batch(key, ..., 2, ...) and via
 *  two separate platform_aes128_cbc_mac() calls, and checks all 4
 *  results agree. A mismatch would mean the batch path's per-block
 *  direct IV-register reset (used to skip redundant HAL_CRYP_Init() key
 *  reloads across sub-blocks) is not actually resetting to a fresh zero
 *  IV between sub-blocks. Sets *matches to true iff every result agrees.
 *  Returns QRNG_ERROR (not the match result) if either underlying
 *  platform call fails. */
qrng_status_t qrng_service_self_test_aes_batch(bool *matches);

/** TEMPORARY diagnostic (added to answer "is qrng_service_get_noise()/
 *  get_entropy()'s draw rate limited by the ADC/DMA wait or by CPU-side
 *  processing?" -- see Core_app/Middleware/QRNG/ADC_Noise/
 *  qrng_service_adc_noise.c's doc comment on s_dbg_wait_cycles).
 *  Reports the average time spent in wait_for_fresh_buffer() and the
 *  average time spent afterward (health check + extractor + memcpy) per
 *  draw, in microseconds, since the last call to this function -- then
 *  resets both accumulators to 0, so repeated calls report successive
 *  windows rather than a running lifetime average. `*draw_count` is how
 *  many draws (across get_noise() and get_entropy() combined) the
 *  averages are based on; both *_us_avg are 0 if `*draw_count` comes
 *  back 0 (nothing drawn since the last call/boot). */
void qrng_service_debug_get_timing(uint32_t *wait_us_avg, uint32_t *process_us_avg, uint32_t *draw_count);

/** TEMPORARY diagnostic: finer breakdown of qrng_service_debug_get_timing()'s
 *  `process_us_avg` (health check + extractor/memcpy, lumped together)
 *  into its two actual stages. `*extractor_or_copy_us_avg` is
 *  memcpy()'s time on a get_noise() draw or extractor_run()'s time on a
 *  get_entropy() draw -- whichever the caller has been calling; only
 *  meaningful if measured over a window that calls just one of the two
 *  (same requirement as QRNG_CMD_BENCH_NOISE/_ENTROPY already have).
 *  Uses its own independent counter/reset from
 *  qrng_service_debug_get_timing() -- call either or both in any order
 *  without one disturbing the other's in-progress window. Only counts
 *  draws that reached QRNG_OK (a QRNG_HEALTH_FAIL/QRNG_ERROR draw ran
 *  the health check but not necessarily the second stage, so including
 *  it would skew `*extractor_or_copy_us_avg`'s average down). */
void qrng_service_debug_get_stage_timing(uint32_t *health_check_us_avg, uint32_t *extractor_or_copy_us_avg,
                                          uint32_t *stage_draw_count);

/** TEMPORARY diagnostic (added to answer "the configured TIM1/ADC
 *  sample rate should be much higher than qrng_service_get_noise()'s
 *  measured draws/sec -- is the ADC itself actually running that slow,
 *  or is software processing the bottleneck?"). Polls
 *  platform_adc_dma_pos() for `window_ms` with NO health-check/
 *  extractor/memcpy work in between -- isolates the DMA/ADC's own
 *  actual achieved sample rate from every software-side cost
 *  qrng_service_get_noise()/get_entropy()'s draws/sec includes. Returns
 *  0 if qrng_service_init() has not succeeded. */
uint32_t qrng_service_debug_measure_adc_rate(uint32_t window_ms);

/** TEMPORARY diagnostic (2026-09-19, chasing a real qrng_service_init()
 *  startup-health-check failure): reports what happened on the LAST
 *  run_startup_health_check() attempt inside the most recent
 *  qrng_service_init() call, whether that call ultimately succeeded or
 *  failed. `*adc_sps` is a raw ADC throughput measurement (samples/sec,
 *  via platform_adc_dma_pos() polling, no health-check/extractor work in
 *  the loop) taken right after the ADC DMA + trigger timer were started,
 *  BEFORE any health check ran -- unlike qrng_service_debug_measure_adc_rate()
 *  above, this works even if init ultimately fails (it does not require
 *  s_ready). `*last_health_status` is entropy_health_t's raw value
 *  (0=ENTROPY_HEALTH_OK, 1=RCT_ERROR, 2=APT_ERROR) from the last
 *  attempt that actually got a fresh buffer, or 0xFFFFFFFF if every
 *  attempt timed out waiting for a buffer at all (ADC/DMA/timer chain
 *  never produced one, a different failure mode from a real RCT/APT
 *  trip on live data). `*last_healthy_samples` is how many samples
 *  passed the online tests before the trip (0 if it failed on the very
 *  first sample). `sample_snapshot`/`snapshot_len` (if non-NULL) get a
 *  copy of the first `snapshot_len` (up to 8) raw ADC samples from that
 *  same last attempt's buffer, to eyeball whether the signal looks
 *  flat/stuck vs genuinely varying. All fields are all-zero (adc_sps
 *  aside) if qrng_service_init() has never been called since boot. */
void qrng_service_debug_get_boot_diag(uint32_t *adc_sps, uint32_t *last_health_status,
                                       uint32_t *last_healthy_samples,
                                       uint16_t *sample_snapshot, size_t snapshot_len);

/** TEMPORARY diagnostic: how many run_startup_health_check() attempts the
 *  most recent qrng_service_init() call actually made (0 if it has never
 *  been called since boot). Pairs with qrng_service_debug_get_attempt()
 *  below to dump a per-attempt breakdown. */
int qrng_service_debug_get_attempt_count(void);

/** TEMPORARY diagnostic: per-attempt breakdown for attempt `index`
 *  (0-based, < qrng_service_debug_get_attempt_count()) of the most
 *  recent qrng_service_init() call's run_startup_health_check() retries.
 *  `*status`/`*healthy_samples` are entropy_health_t's raw value / the
 *  healthy-sample count as of that attempt (or status=0xFFFFFFFF,
 *  healthy_samples=0 if that attempt timed out waiting for a buffer at
 *  all). `*sample0`/`*sample1` are that attempt's first two raw ADC
 *  samples (0xFFFF each if it timed out) -- since successive attempts
 *  read alternating physical buffer halves, comparing these across
 *  attempts tells apart "the buffer content is identical every attempt"
 *  (points at a DMA/cache bug: real writes not reaching CPU-visible
 *  memory) from "each attempt sees different data" (points at the
 *  analog front-end itself). No-ops (leaves outputs untouched) if index
 *  is out of range. */
void qrng_service_debug_get_attempt(int index, uint32_t *status, uint32_t *healthy_samples,
                                     uint16_t *sample0, uint16_t *sample1);

#endif /* EVT2_DIAGNOSTICS */

#ifdef __cplusplus
}
#endif

#endif /* QRNG_SERVICE_H */
