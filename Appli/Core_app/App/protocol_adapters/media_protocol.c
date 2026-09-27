/**
 * @file    media_protocol.c
 * @brief   Video-call media session state machine: dispatches the whole
 *          CMD_TYPE_MEDIA_FIRST..CMD_TYPE_MEDIA_LAST (0x03-0x10) packet
 *          range, registered via command_protocol_register_media().
 *
 * Ported from C:\Users\SingPC\usb_encrypt_host\firmware\Core\Src\app_link.c
 * (that project's own device-side session/protocol/crypto engine) after
 * genuinely verifying HAL compatibility against EVT2's own sources -- see
 * platform_crypto.c's doc comment for the AES-256-GCM check, and
 * platform_hash.c's platform_sha256() addition below for the SHA-256 one
 * -- not blind-pasted. Two structural differences from the reference, both
 * deliberate:
 *
 *   1. Framing/TX: the reference owns its OWN transport (app_protocol.c's
 *      proto_tx_writer_t streaming writer, app_link.c's hand-rolled
 *      ping-pong USB TX buffer in cdc_flush()) because it has no other
 *      transport to share. This file has neither -- every reply here goes
 *      through EVT2's existing command_protocol_send(), which already
 *      solves the same "don't overwrite a buffer the USB peripheral is
 *      still asynchronously reading" problem (see send_frame()'s doc
 *      comment in command_protocol.c) with a simpler wait-before-write
 *      strategy, since every media reply here is a single complete
 *      request/response exchange, never a multi-segment streamed write.
 *
 *   2. Crypto direction: the reference is encrypt-only -- its own
 *      PROTOCOL.md section 8: "Today, only encryption happens on the
 *      device. Decryption of a peer's stream (Android call app) happens
 *      in software on the receiving phone... there is no
 *      DECRYPT_CHUNK-style packet type in this protocol." EVT2's
 *      video-call flow is explicitly two-directional on the SAME device
 *      (encrypt this device's outgoing stream, decrypt the incoming
 *      peer's stream, both via the STM32 HW accelerator -- see
 *      command_protocol.h's CMD_TYPE_DECRYPT_CHUNK doc comment), so
 *      handle_decrypt_chunk() below has no reference counterpart --
 *      written directly from platform_crypto.h's
 *      platform_aes256_gcm_decrypt() contract.
 *
 * BATCH mode (whole-stream buffer + END_STREAM SHA-256 check + single
 * ENCRYPT_RESULT) is ported for protocol completeness/parity with a
 * host.py-style file-transfer test client, but the video call itself only
 * ever uses LIVE_AUDIO mode for both audio and video chunks (see
 * PROTOCOL.md section 4: "LIVE_AUDIO ... audio AND video -- the Android
 * call app's VideoCallEngine.kt reuses the exact same path") plus the new
 * DECRYPT_CHUNK/DECRYPTED_CHUNK pair for the inbound peer stream.
 */
#include "command_protocol.h"
#include "platform.h"
#include "platform_crypto.h"
#include "platform_hash.h"
#include "qrng_service.h"

#include <string.h>

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* TEMP diagnostic 2026-09-25 (see CLAUDE.md): a real phone call over the H7S3 port's USB_OTG_HS link gets 0%
 * successful DATA_CHUNK/DECRYPT_CHUNK replies (Android side sees "no reply ... within 200ms" for every chunk,
 * `sent=0 received=0`) even though isolated single commands (HELLO/security/qrng) work over the same link.
 * Logging is throttled (budget counters, decremented to 0 then silent) so it does not flood the UART or slow the
 * real-time path enough to cause its own timeouts during the very call being diagnosed. Remove once root-caused. */
extern void app_log(const char *msg);
extern void app_log_uint(uint32_t value);
static uint32_t s_dbg_dispatch_log_budget = 30;
static uint32_t s_dbg_live_chunk_log_budget = 10;
static uint32_t s_dbg_decrypt_chunk_log_budget = 300;
#endif /* EVT2_DIAGNOSTICS */

/* Fallback AES-256-GCM key -- DEMO KEY (all-zero), matching usb_encrypt_host's
 * APP_LINK_AES_KEY / host.py's --key default / the ported Android app's
 * AesGcm.kt#DEV_KEY convention, so the PC test peer/benchmark/old Android
 * builds without a CA handshake can still talk to this firmware.
 *
 * A REAL call no longer uses this: handle_start_stream() below pulls the
 * per-call session keys a completed CA handshake derived
 * (ca_protocol_get_session_keys(), see that file's doc comment -- ECDH +
 * HKDF in the SE052F, the two AES keys never cross USB) and stores them in
 * s_session.send_key/recv_key.
 *
 * GATED BEHIND EVT2_MEDIA_ALLOW_UNAUTHENTICATED (undefined by default -- see
 * handle_start_stream()): this key is a KNOWN, PUBLIC constant, so a build
 * that falls back to it whenever no CA handshake ran was, in effect, willing
 * to encrypt a "real" call with a key any USB host could already guess --
 * see CLAUDE.md's review point on this ("START_STREAM phải trả lỗi trừ khi
 * phiên hiện tại đã xác thực"). Define EVT2_MEDIA_ALLOW_UNAUTHENTICATED=1 for
 * a benchmark/test build (DeviceBenchmark.kt's speed test,
 * tools/device_loopback_test.py, or any peer not yet updated to do the CA
 * handshake -- see docs/key_exchange_ca_profile.md section 6.4) that needs
 * this fallback; a normal/product build leaves it undefined and
 * handle_start_stream() refuses START_STREAM outright instead of silently
 * using this key. */
static const uint8_t MEDIA_AES_KEY[32] = { 0 };

/* Defined in Core_app/App/protocol_adapters/ca_protocol.c -- not declared in any shared header, same convention as
 * app_main.c's extern'd *_protocol_handler()s. This is the one place outside ca_protocol.c that reads the CA
 * handshake's derived keys: they never cross USB, so the only legitimate consumer is another App-layer file on the
 * same MCU. Returns false (leaves the buffers untouched) if no CA session's keys are currently held. */
extern bool ca_protocol_get_session_keys(uint8_t send_key[32], uint8_t recv_key[32]);

/* Mirrors app_link.c's SESSION_TIMEOUT_MS: garbage-collect an abandoned
 * session (host/phone vanished mid-stream without RESET/ABORT_STREAM)
 * comfortably above any client's own retry budget. */
#define MEDIA_SESSION_TIMEOUT_MS 15000u

/* Mirrors APP_LINK_MAX_STREAM_BYTES -- BATCH mode only (LIVE_AUDIO, the
 * video-call path, never buffers a whole stream). Bounded by
 * ENCRYPT_RESULT needing to fit one frame: NONCE(12)+TAG(16)+ciphertext
 * must stay under CMD_PROTO_MAX_PAYLOAD (32768) with margin. */
#define MEDIA_MAX_STREAM_BYTES 16384u

/* H7S3 port (RAM reduction "B"): BATCH mode (buffer a whole stream, one
 * GCM at END_STREAM) costs 2 * MEDIA_MAX_STREAM_BYTES = 32KB of static RAM
 * for s_session.plaintext/ciphertext. The real call path (Android
 * DeviceLink.startAudioSession(), tools/pc_peer.py) only ever uses
 * LIVE_AUDIO, so this build compiles BATCH out by default: START_STREAM
 * selecting BATCH -- including a legacy 36-byte START_STREAM with no mode
 * byte, which means BATCH -- is refused with MEDIA_NACK_UNSUPPORTED_VERSION.
 * Build with -DMEDIA_ENABLE_BATCH=1 to get EVT2's full behaviour back. */
#ifndef MEDIA_ENABLE_BATCH
#define MEDIA_ENABLE_BATCH 0
#endif

/* LIVE_AUDIO per-chunk ceilings -- both derived from CMD_PROTO_MAX_PAYLOAD
 * (command_protocol.h), NOT the raw transport ceiling itself, because
 * each direction's REPLY adds fixed overhead on top of the chunk that
 * must also fit within CMD_PROTO_MAX_PAYLOAD:
 *   - DATA_CHUNK (encrypt) reply is ENCRYPTED_CHUNK: [acked_seq 4B]
 *     [nonce 12B][tag 16B][ciphertext, same length as the request] -- 32
 *     bytes more than the request. A DATA_CHUNK within 32 bytes of
 *     CMD_PROTO_MAX_PAYLOAD would make command_protocol_send() silently
 *     fail to send the reply at all (its own payload_len bounds check),
 *     so that case is NACKed up front here instead.
 *   - DECRYPT_CHUNK (decrypt) reply is DECRYPTED_CHUNK: [acked_seq 4B]
 *     [status 1B][plaintext, same length as the ciphertext carried].
 *     DECRYPT_CHUNK's own payload is [nonce 12B][tag 16B][ciphertext],
 *     so its reply (5B overhead) is always SMALLER than the transport
 *     already allowed in -- no extra ceiling needed beyond the 28-byte
 *     nonce+tag prefix. */
#define MEDIA_ENCRYPTED_CHUNK_OVERHEAD 32u /* acked_seq(4) + nonce(12) + tag(16) */
#define MEDIA_MAX_DATA_CHUNK (CMD_PROTO_MAX_PAYLOAD - MEDIA_ENCRYPTED_CHUNK_OVERHEAD)
#define MEDIA_DECRYPT_CHUNK_PREFIX 28u /* nonce(12) + tag(16) */

/* How many of the most recent DECRYPT_CHUNK nonces (the peer's incoming stream) this session remembers, to reject a
 * repeat -- see replay_window_seen_or_add()'s doc comment. 128*12 = 1536B/session, negligible next to this file's
 * other per-session buffers (MEDIA_MAX_STREAM_BYTES*2 for BATCH mode alone). */
#define MEDIA_REPLAY_WINDOW 128u

typedef enum { MEDIA_STREAM_MODE_BATCH = 0x00, MEDIA_STREAM_MODE_LIVE_AUDIO = 0x01 } media_stream_mode_t;

typedef enum {
    MEDIA_NACK_CRC_ERROR           = 0x01, /* reserved -- see command_protocol.h: a CRC failure never reaches here */
    MEDIA_NACK_OUT_OF_ORDER        = 0x02,
    MEDIA_NACK_UNKNOWN_SESSION     = 0x03,
    MEDIA_NACK_BUSY                = 0x04,
    MEDIA_NACK_BAD_LENGTH          = 0x05,
    MEDIA_NACK_UNSUPPORTED_VERSION = 0x06,
    /* START_STREAM refused: no completed CA handshake for this link, and this build was not compiled with
     * EVT2_MEDIA_ALLOW_UNAUTHENTICATED -- see handle_start_stream() and MEDIA_AES_KEY's doc comment. */
    MEDIA_NACK_NOT_AUTHENTICATED   = 0x07,
} media_nack_reason_t;

/* CMD_TYPE_DECRYPTED_CHUNK's status byte -- distinct from NACK above:
 * by the time a DECRYPTED_CHUNK reply is being built the REQUEST itself
 * was well-formed (a malformed one gets NACKed instead, same as
 * DATA_CHUNK), so this only needs to report the GCM tag verification
 * outcome. */
typedef enum { MEDIA_DECRYPT_OK = 0x00, MEDIA_DECRYPT_AUTH_FAIL = 0x01 } media_decrypt_status_t;

typedef enum { MEDIA_SESSION_IDLE = 0, MEDIA_SESSION_ACTIVE } media_session_state_t;

typedef struct {
    media_session_state_t state;
    uint16_t session_id;
    media_stream_mode_t mode;    /* BATCH (buffer whole stream) or LIVE_AUDIO (encrypt+reply per chunk) */
    uint32_t expected_seq;       /* seq of the next DATA_CHUNK we expect (BATCH only) */
    uint32_t last_processed_seq; /* lets a retransmitted (ACK-lost) chunk be re-acked without reprocessing */
    uint32_t bytes_received;
    uint32_t declared_total_len;
    uint32_t last_rx_tick;

#if MEDIA_ENABLE_BATCH
    uint8_t plaintext[MEDIA_MAX_STREAM_BYTES];
#endif

    /* Cached final result: a retransmitted END_STREAM (host's ACK or the
     * ENCRYPT_RESULT itself got lost) is answered by resending this,
     * instead of re-hashing/re-encrypting. */
    bool     result_ready;
    uint32_t result_for_seq;
    uint8_t  nonce[12];
    uint8_t  tag[16];
#if MEDIA_ENABLE_BATCH
    uint8_t  ciphertext[MEDIA_MAX_STREAM_BYTES];
#endif
    uint32_t ciphertext_len;

    /* This session's AES-256-GCM keys -- from ca_protocol_get_session_keys() if a CA handshake completed before
     * START_STREAM, else MEDIA_AES_KEY (see that constant's doc comment). send_key encrypts what THIS device is
     * sending out (DATA_CHUNK -> ENCRYPTED_CHUNK, and BATCH's END_STREAM); recv_key decrypts what the peer sent
     * (DECRYPT_CHUNK -> DECRYPTED_CHUNK). Wiped by media_session_reset(). */
    uint8_t  send_key[32];
    uint8_t  recv_key[32];

    /* Nonces of the most recently successfully-decrypted DECRYPT_CHUNKs this session -- see
     * replay_window_seen_or_add()'s doc comment. Reset (all-zero, count 0) by media_session_reset() same as
     * everything else in this struct, so a new session (new keys) never carries over an old session's window. */
    uint8_t  recv_nonce_window[MEDIA_REPLAY_WINDOW][12];
    uint32_t recv_nonce_window_count; /* valid entries: recv_nonce_window[0..count-1] */
    uint32_t recv_nonce_window_next;  /* ring cursor: next slot to overwrite once count reaches MEDIA_REPLAY_WINDOW */
} media_session_t;

static media_session_t s_session;

/* Reply-assembly scratch -- was its own `s_reply_buf[CMD_PROTO_MAX_PAYLOAD]` static here; removed
 * 2026-09-24 in favor of command_protocol_tx_scratch() (a pointer straight into command_protocol.c's own TX
 * staging buffer) -- one more step of the exact discipline that already removed this file's
 * `s_live_cipher_buf`/`s_live_plain_buf` on 2026-09-19 (see that removal's own note, kept below): a same-sized
 * buffer that only ever fed a memcpy() into command_protocol_send()'s internal staging was real, unnecessary
 * duplication (~48KB of RAM_D1), the same finding that justified the first removal, just one call frame further
 * out. Every `s_reply_buf` use below became a `command_protocol_tx_scratch()` call (same address every time,
 * since it is command_protocol.c's own file-scope static), and every command_protocol_send() that used to send
 * it became command_protocol_send_staged() (skips the memcpy command_protocol_send() would otherwise still do).
 *
 * LIVE_AUDIO's encrypt/decrypt handlers write straight into that buffer's ciphertext/plaintext region
 * (platform_aes256_gcm_encrypt()/_decrypt()'s output pointer is a plain uint8_t*, no dedicated buffer required
 * -- see platform_crypto.h) instead of through a separate scratch buffer that then gets memcpy'd here right
 * after. Removed 2026-09-19: this file used to keep `s_live_cipher_buf[MEDIA_MAX_DATA_CHUNK]` and
 * `s_live_plain_buf[CMD_PROTO_MAX_PAYLOAD]` as those scratch buffers -- real, unnecessary duplication (found
 * while sizing up CMD_PROTO_MAX_PAYLOAD for bigger real-hardware H.264 keyframes, where doubling two
 * CMD_PROTO_MAX_PAYLOAD-sized buffers was about to become the single largest RAM cost of that change) once it
 * was clear both always fed straight into a memcpy() into this exact buffer and were never read again for any
 * other purpose. Safe because handle_media_packet() runs to completion synchronously in the single-threaded
 * main loop before the next packet can arrive -- same reasoning that justifies going straight to
 * command_protocol.c's own staging buffer now. */

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* DEBUG TIMING (2026-09-19) -- mirrors qrng_protocol.c's own
 * s_dbg_draw_cycles/s_dbg_send_cycles pattern exactly (DWT->CYCCNT via
 * platform_get_cycle_count(), converted to microseconds via
 * platform_get_cpu_hz() at read time, reset-after-read). Added to answer
 * a real question this session: of a LIVE_AUDIO chunk's round-trip time,
 * how much is the AES-256-GCM hardware operation itself versus USB
 * transit/framing (the latter is already covered by
 * command_protocol_debug_get_send_timing(), generic to every
 * command_protocol_send() call including this file's replies -- these two
 * new accumulators are the missing piece: crypto compute time specifically,
 * isolated from everything else in the round trip). Only counts SUCCESSFUL
 * calls (a failed encrypt/decrypt still takes real cycles, but the reply it
 * produces is a NACK/error status, not a chunk -- mixing that timing in
 * would answer a different, less useful question). Exposed via
 * MEDIA_PING's payload (see handle_ping()) rather than a new CMD_TYPE:
 * media/stream TYPEs are a fixed, already-fully-allocated 0x03-0x10 range
 * (CMD_TYPE_MEDIA_FIRST/LAST), and PING/PONG already exists as a
 * zero-side-effect round trip to piggyback on, exactly like QRNG's own
 * debug sub-commands piggyback on CMD_TYPE_QRNG instead of taking a new
 * top-level TYPE each. */
static uint64_t s_dbg_encrypt_cycles;
static uint32_t s_dbg_encrypt_count;
static uint64_t s_dbg_decrypt_cycles;
static uint32_t s_dbg_decrypt_count;

/* Reset-after-read, same convention as qrng_service_debug_get_timing() --
 * see s_dbg_encrypt_cycles's own doc comment above. */
static void media_debug_get_crypto_timing(uint32_t *encrypt_us_avg, uint32_t *decrypt_us_avg,
                                           uint32_t *encrypt_count, uint32_t *decrypt_count)
{
    uint32_t cpu_hz = platform_get_cpu_hz();
    *encrypt_count = s_dbg_encrypt_count;
    *decrypt_count = s_dbg_decrypt_count;
    *encrypt_us_avg = (s_dbg_encrypt_count && cpu_hz)
        ? (uint32_t)((s_dbg_encrypt_cycles / s_dbg_encrypt_count) * 1000000ULL / cpu_hz) : 0U;
    *decrypt_us_avg = (s_dbg_decrypt_count && cpu_hz)
        ? (uint32_t)((s_dbg_decrypt_cycles / s_dbg_decrypt_count) * 1000000ULL / cpu_hz) : 0U;
    s_dbg_encrypt_cycles = 0U;
    s_dbg_encrypt_count = 0U;
    s_dbg_decrypt_cycles = 0U;
    s_dbg_decrypt_count = 0U;
}
#endif /* EVT2_DIAGNOSTICS */

static void media_session_reset(void)
{
    memset(&s_session, 0, sizeof(s_session));
    s_session.state = MEDIA_SESSION_IDLE;
}

void media_protocol_init(void)
{
    media_session_reset();
    /* No qrng_service_set_extractor() call here (there used to be one --
     * see git history and qrng_service_get_entropy_with()'s doc comment
     * in qrng_service.h for why it was removed): that function changes
     * the GLOBAL default qrng_service_get_entropy() itself uses, which
     * is also what a USB client's own QRNG_CMD_SET_EXTRACTOR is meant to
     * control. This file's nonce pool (media_nonce_pool_refill(),
     * media_qrng_nonce() below) instead calls
     * qrng_service_get_entropy_with(QRNG_EXTRACTOR_TOEPLITZ, ...)
     * directly, every single draw -- guaranteed Toeplitz (pure math, no
     * CRYP/HASH hardware, so it never contends with this file's own
     * platform_aes256_gcm_encrypt()/decrypt() calls sharing the same
     * physical CRYP peripheral -- see platform_crypto.c's file doc
     * comment) without ever touching, depending on, or fighting whatever
     * a USB client has separately configured for their own
     * GET_ENTROPY/STREAM_ENTROPY calls. */
}

/* ---- QRNG nonce pool -------------------------------------------------
 *
 * Every AES-256-GCM nonce this file uses comes from the project's own
 * QRNG (Core_app/Middleware/QRNG) whenever the QRNG is delivering healthy
 * entropy -- see qrng_service.h's own doc comment ("App code that needs
 * high-quality random data calls only this header"). qrng_service_init()
 * already runs before app_command_protocol_init() (Src/main.c's boot
 * sequence), so the QRNG is up before any HELLO/media traffic can reach
 * this file.
 *
 * RNG FALLBACK (explicit design decision): if the pool runs dry while the
 * QRNG's NIST 800-90B health test keeps failing (or the QRNG is not
 * ready), nonces are topped up from platform_rng.h's hardware TRNG instead
 * of stalling or failing the call -- a GCM nonce only needs to be unique,
 * and the STM32 TRNG is a fine source for that. The QRNG is still
 * checked on every refill tick, and the moment it produces a healthy draw
 * its nonces go into the pool again (ahead of any leftover RNG ones).
 * media_protocol_get_nonce_stats() reports how many nonces of each source
 * were actually used.
 *
 * A background-filled pool, not a live draw per chunk: the NIST 800-90B
 * online health test qrng_service_get_entropy() runs on every draw has a
 * documented non-zero false-alarm rate (measured ~1/300 real draws over
 * USB earlier this session -- see qrng_protocol.c's own doc comment), and
 * a live draw on the LIVE_AUDIO hot path (handle_live_chunk(), up to
 * ~45+55 combined audio+video chunks/sec) would occasionally stall that
 * one chunk's reply on a health-test retry. Pre-filling a pool from
 * media_protocol_poll() (already called every main-loop iteration) moves
 * that retry off the hot path entirely -- a health-test failure during a
 * background refill tick just means "try again next poll() tick", not
 * "this chunk waits."
 *
 * Also fixes a real inefficiency the earlier live-draw version had: one
 * qrng_service_get_entropy() call fills a full QRNG_ENTROPY_BYTES (1024B)
 * extractor-whitened draw, of which a 12-byte GCM nonce used only ~1.2%
 * and discarded the rest. One draw is now sliced into up to 85
 * (1024/12) nonces and distributed across the pool, so a single refill
 * can very nearly fill MEDIA_NONCE_POOL_CAPACITY from empty in one call.
 *
 * Pool discipline, per explicit requirement: a nonce is consumed exactly
 * once (media_nonce_pool_pop() removes and zeroes its slot -- never
 * handed out twice, and not left sitting in RAM after use), and
 * media_nonce_pool_refill() never draws/pushes more while the pool is
 * already full (checked before calling qrng_service_get_entropy() at
 * all, so a full pool costs zero extra QRNG draws, not just zero pushes). */
#define MEDIA_NONCE_POOL_CAPACITY 64u /* 64*12 = 768B RAM; one 1024B draw (85 nonces) can refill it from empty in one call */
#define MEDIA_NONCE_POOL_RNG_BATCH 16u /* RNG-fallback top-up size per poll() tick, see media_nonce_pool_push_rng() */

typedef struct {
    uint8_t nonces[MEDIA_NONCE_POOL_CAPACITY][12];
    bool from_rng[MEDIA_NONCE_POOL_CAPACITY]; /* per slot: true if it came from the RNG fallback, not the QRNG */
    uint32_t count; /* valid entries: nonces[0..count-1] */
} media_nonce_pool_t;

static media_nonce_pool_t s_nonce_pool;
#if EVT2_DIAGNOSTICS /* nonce statistics -- read only by the diagnostic getters below */
static uint32_t s_nonce_from_qrng;
static uint32_t s_nonce_from_rng;
static uint32_t s_qrng_draw_ok;      /* QRNG draws (pool refill + live) that reached QRNG_OK */
static uint32_t s_qrng_draw_fail;    /* ... that did not (health-test failure / error) */
static bool s_last_qrng_draw_ok = true; /* outcome of the most recent QRNG draw -- what the debug view shows as "QRNG healthy" */
#endif
static uint8_t s_qrng_entropy_scratch[QRNG_ENTROPY_BYTES]; /* shared by refill() and the pool-empty fallback below --
                                                             * both only ever run from the single-threaded main loop,
                                                             * never concurrently, so one static buffer is enough. */

/** Pop one nonce (LIFO -- O(1), no shift needed), zero its slot, and
 *  report which source it came from so the caller can keep honest
 *  QRNG-vs-RNG accounting. Returns false if the pool is empty. */
static bool media_nonce_pool_pop(uint8_t nonce[12], bool *from_rng)
{
    if (s_nonce_pool.count == 0u) {
        return false;
    }
    s_nonce_pool.count--;
    memcpy(nonce, s_nonce_pool.nonces[s_nonce_pool.count], 12u);
    memset(s_nonce_pool.nonces[s_nonce_pool.count], 0, 12u); /* used once -- erase, don't leave stale entropy in RAM */
    *from_rng = s_nonce_pool.from_rng[s_nonce_pool.count];
    s_nonce_pool.from_rng[s_nonce_pool.count] = false;
    return true;
}

/** Fallback top-up used ONLY when the pool is empty AND the QRNG just
 *  failed to deliver (health-test failure / error): fills a small batch
 *  from platform_rng.h's hardware TRNG so the LIVE_AUDIO hot path never
 *  has to wait on a QRNG retry. Small on purpose (a handful of TRNG words
 *  per poll() tick, not the whole pool at once) -- the QRNG is re-checked
 *  every tick regardless (see media_nonce_pool_refill()), and as soon as
 *  it produces a healthy draw its nonces are pushed on top of (and are
 *  therefore consumed before, LIFO) whatever RNG ones are still sitting
 *  here. TRNG is an independent peripheral: no CRYP/ADC contention. */
static void media_nonce_pool_push_rng(void)
{
    uint32_t room = MEDIA_NONCE_POOL_CAPACITY - s_nonce_pool.count;
    uint32_t n = (room < MEDIA_NONCE_POOL_RNG_BATCH) ? room : MEDIA_NONCE_POOL_RNG_BATCH;
    for (uint32_t i = 0; i < n; i++) {
        if (platform_rng_get_bytes(s_nonce_pool.nonces[s_nonce_pool.count], 12u) != PLATFORM_OK) {
            break;
        }
        s_nonce_pool.from_rng[s_nonce_pool.count] = true;
        s_nonce_pool.count++;
    }
}

/** Top up the pool by at most one qrng_service_get_entropy_with() draw,
 *  sliced into as many 12-byte nonces as fit in the remaining capacity.
 *  Called from media_protocol_poll() every main-loop tick -- deliberately
 *  at most one draw per call (not "keep drawing until full") so a poll()
 *  call never blocks the main loop for more than one draw's worth of
 *  QRNG time, matching this file's existing non-blocking poll contract.
 *
 *  The QRNG is ALWAYS tried first (whenever there is room): a healthy
 *  draw goes into the pool no matter how the pool got into its current
 *  state. Only if that draw fails AND the pool is completely empty does
 *  this fall back to media_nonce_pool_push_rng(). */
static void media_nonce_pool_refill(void)
{
    if (s_nonce_pool.count >= MEDIA_NONCE_POOL_CAPACITY) {
        return; /* full -- do not draw, do not push (per explicit requirement) */
    }
    /* QRNG_EXTRACTOR_TOEPLITZ passed explicitly (not via
     * qrng_service_set_extractor()) -- see qrng_service_get_entropy_with()'s
     * doc comment in qrng_service.h: guarantees this draw never touches
     * CRYP/HASH hardware (avoiding contention with this file's own GCM
     * encrypt/decrypt calls) without overwriting whatever a USB client
     * has separately configured via QRNG_CMD_SET_EXTRACTOR for their own
     * GET_ENTROPY/STREAM_ENTROPY calls. */
    qrng_status_t st = qrng_service_get_entropy_with(QRNG_EXTRACTOR_TOEPLITZ, s_qrng_entropy_scratch,
                                                      sizeof(s_qrng_entropy_scratch));
#if EVT2_DIAGNOSTICS
    s_last_qrng_draw_ok = (st == QRNG_OK);
#endif
    if (st != QRNG_OK) {
#if EVT2_DIAGNOSTICS
        s_qrng_draw_fail++;
#endif
        memset(s_qrng_entropy_scratch, 0, sizeof(s_qrng_entropy_scratch)); /* a failed draw's bytes are untrusted -- never used */
        if (s_nonce_pool.count == 0u) {
            media_nonce_pool_push_rng();
        }
        return; /* otherwise harmless: just retry the QRNG on a later poll() tick */
    }

#if EVT2_DIAGNOSTICS
    s_qrng_draw_ok++;
#endif
    uint32_t available_slots = MEDIA_NONCE_POOL_CAPACITY - s_nonce_pool.count;
    uint32_t nonces_in_draw = (uint32_t)(sizeof(s_qrng_entropy_scratch) / 12u);
    uint32_t to_add = (available_slots < nonces_in_draw) ? available_slots : nonces_in_draw;
    for (uint32_t i = 0; i < to_add; i++) {
        memcpy(s_nonce_pool.nonces[s_nonce_pool.count], &s_qrng_entropy_scratch[i * 12u], 12u);
        s_nonce_pool.from_rng[s_nonce_pool.count] = false;
        s_nonce_pool.count++;
    }
    memset(s_qrng_entropy_scratch, 0, sizeof(s_qrng_entropy_scratch));
}

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/** Cumulative count of nonces handed out per source since boot -- lets a
 *  caller/test confirm the QRNG is actually the dominant source (and see
 *  how often the RNG fallback had to step in). Not declared in any shared
 *  header; extern it where needed, same convention as this file's other
 *  App-layer entry points. */
void media_protocol_get_nonce_stats(uint32_t *from_qrng, uint32_t *from_rng)
{
    *from_qrng = s_nonce_from_qrng;
    *from_rng = s_nonce_from_rng;
}

/** Read-only snapshot of the nonce pool for the debug view
 *  (QRNG_CMD_NONCE_POOL_STATUS in qrng_protocol.c). `rng_in_pool` is how
 *  many of the currently pooled nonces came from the RNG fallback -- non-zero
 *  means the fallback has been active and those have not been consumed yet.
 *  Never exposes any nonce bytes. */
void media_protocol_get_nonce_pool_status(uint32_t *count, uint32_t *capacity, uint32_t *rng_in_pool,
                                          uint32_t *qrng_draw_ok, uint32_t *qrng_draw_fail, bool *last_draw_ok)
{
    uint32_t rng = 0U;
    for (uint32_t i = 0; i < s_nonce_pool.count; i++) {
        if (s_nonce_pool.from_rng[i]) {
            rng++;
        }
    }
    *count = s_nonce_pool.count;
    *capacity = MEDIA_NONCE_POOL_CAPACITY;
    *rng_in_pool = rng;
    *qrng_draw_ok = s_qrng_draw_ok;
    *qrng_draw_fail = s_qrng_draw_fail;
    *last_draw_ok = s_last_qrng_draw_ok;
}
#endif /* EVT2_DIAGNOSTICS */

/** Every AES-256-GCM nonce this file hands out goes through here.
 *  Order of preference: (1) the pool (QRNG-sourced, or RNG-sourced only
 *  while the QRNG was failing -- see media_nonce_pool_push_rng()), (2) if
 *  the pool happens to be empty right now, ONE live QRNG draw, (3) if that
 *  fails too (health test / error), the hardware TRNG directly. The live
 *  draw is single-attempt on purpose: this is the LIVE_AUDIO hot path, and
 *  the RNG fallback is what replaces the old "retry once" -- a chunk never
 *  waits on a second QRNG attempt. Fails (PLATFORM_ERROR) only if the TRNG
 *  itself errors, which the caller NACKs like any other transient
 *  encrypt-side failure. */
static platform_status_t media_qrng_nonce(uint8_t nonce[12])
{
    bool from_rng = false;
    if (media_nonce_pool_pop(nonce, &from_rng)) {
#if EVT2_DIAGNOSTICS
        if (from_rng) {
            s_nonce_from_rng++;
        }
        else {
            s_nonce_from_qrng++;
        }
#endif
        return PLATFORM_OK;
    }

    qrng_status_t st = qrng_service_get_entropy_with(QRNG_EXTRACTOR_TOEPLITZ, s_qrng_entropy_scratch,
                                                      sizeof(s_qrng_entropy_scratch));
#if EVT2_DIAGNOSTICS
    s_last_qrng_draw_ok = (st == QRNG_OK);
#endif
    if (st == QRNG_OK) {
        memcpy(nonce, s_qrng_entropy_scratch, 12U);
        memset(s_qrng_entropy_scratch, 0, sizeof(s_qrng_entropy_scratch));
#if EVT2_DIAGNOSTICS
        s_qrng_draw_ok++;
        s_nonce_from_qrng++;
#endif
        return PLATFORM_OK;
    }
#if EVT2_DIAGNOSTICS
    s_qrng_draw_fail++;
#endif
    memset(s_qrng_entropy_scratch, 0, sizeof(s_qrng_entropy_scratch));

    if (platform_rng_get_bytes(nonce, 12U) == PLATFORM_OK) {
#if EVT2_DIAGNOSTICS
        s_nonce_from_rng++;
#endif
        return PLATFORM_OK;
    }
    return PLATFORM_ERROR;
}

/* ---- small replies -------------------------------------------------------
 * Outer frame SEQ is always 0 for these -- the reply's own acked_seq/seq
 * field (first bytes of payload) is what a client matches against,
 * mirroring PROTOCOL.md section 5 and the reference's send_ack()/
 * send_nack()/send_encrypted_chunk() (all pass literal 0 for the SEQ
 * parameter of the outer frame). */
static void media_send_ack(uint16_t session_id, uint32_t acked_seq)
{
    uint8_t p[4] = { (uint8_t)acked_seq, (uint8_t)(acked_seq >> 8), (uint8_t)(acked_seq >> 16),
                      (uint8_t)(acked_seq >> 24) };
    command_protocol_send(CMD_TYPE_MEDIA_ACK, session_id, 0, p, sizeof(p));
}

static void media_send_nack(uint16_t session_id, uint32_t seq, media_nack_reason_t reason)
{
    uint8_t p[5] = { (uint8_t)seq, (uint8_t)(seq >> 8), (uint8_t)(seq >> 16), (uint8_t)(seq >> 24),
                      (uint8_t)reason };
    command_protocol_send(CMD_TYPE_MEDIA_NACK, session_id, 0, p, sizeof(p));
}

#if MEDIA_ENABLE_BATCH
static void media_send_encrypt_result(void)
{
    uint8_t *reply = command_protocol_tx_scratch();
    uint16_t payload_len = (uint16_t)(12u + 16u + s_session.ciphertext_len);
    memcpy(&reply[0], s_session.nonce, 12u);
    memcpy(&reply[12], s_session.tag, 16u);
    memcpy(&reply[28], s_session.ciphertext, s_session.ciphertext_len);
    command_protocol_send_staged(CMD_TYPE_ENCRYPT_RESULT, s_session.session_id, 0, payload_len);
}
#endif /* MEDIA_ENABLE_BATCH */

/* LIVE_AUDIO reply to one DATA_CHUNK: [acked_seq 4B][nonce 12B][tag 16B]
 * [ciphertext, same length as the chunk that was sent]. The ciphertext
 * bytes are NOT passed in here -- the caller's platform_aes256_gcm_encrypt()
 * already wrote them directly into &command_protocol_tx_scratch()[32] (see
 * this file's reply-assembly-scratch doc comment above), so all that's
 * left is filling in the header fields around them. */
static void media_send_encrypted_chunk(uint16_t session_id, uint32_t acked_seq, const uint8_t nonce[12],
                                        const uint8_t tag[16], uint16_t ciphertext_len)
{
    uint8_t *reply = command_protocol_tx_scratch();
    reply[0] = (uint8_t)acked_seq;
    reply[1] = (uint8_t)(acked_seq >> 8);
    reply[2] = (uint8_t)(acked_seq >> 16);
    reply[3] = (uint8_t)(acked_seq >> 24);
    memcpy(&reply[4], nonce, 12u);
    memcpy(&reply[16], tag, 16u);
    command_protocol_send_staged(CMD_TYPE_ENCRYPTED_CHUNK, session_id, 0, (uint16_t)(32u + ciphertext_len));
}

/* EVT2 extension (no reference counterpart -- see file doc comment).
 * DECRYPT_CHUNK reply: [acked_seq 4B][status 1B][plaintext, only present
 * and only meaningful if status == MEDIA_DECRYPT_OK]. Like
 * media_send_encrypted_chunk(), the plaintext bytes aren't passed in --
 * the caller's platform_aes256_gcm_decrypt() already wrote them directly
 * into &command_protocol_tx_scratch()[5] on success (see this file's
 * reply-assembly-scratch doc comment above). */
static void media_send_decrypted_chunk(uint16_t session_id, uint32_t acked_seq, media_decrypt_status_t status,
                                        uint16_t plaintext_len)
{
    uint8_t *reply = command_protocol_tx_scratch();
    reply[0] = (uint8_t)acked_seq;
    reply[1] = (uint8_t)(acked_seq >> 8);
    reply[2] = (uint8_t)(acked_seq >> 16);
    reply[3] = (uint8_t)(acked_seq >> 24);
    reply[4] = (uint8_t)status;
    uint16_t total = 5u;
    if (status == MEDIA_DECRYPT_OK) {
        total = (uint16_t)(5u + plaintext_len);
    }
    command_protocol_send_staged(CMD_TYPE_DECRYPTED_CHUNK, session_id, 0, total);
}

/* ---- packet handlers ------------------------------------------------- */

static void handle_reset(const cmd_protocol_packet_t *pkt)
{
    (void)pkt;
    media_session_reset(); /* fire-and-forget, no reply -- matches ABORT_STREAM/PROTOCOL.md section 3 */
}

static void handle_start_stream(const cmd_protocol_packet_t *pkt)
{
    if (pkt->length < 4u) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }
    uint32_t total_len = (uint32_t)pkt->payload[0] | ((uint32_t)pkt->payload[1] << 8) |
                          ((uint32_t)pkt->payload[2] << 16) | ((uint32_t)pkt->payload[3] << 24);

    /* Trailing mode byte, mirroring PROTOCOL.md section 4: absent (a
     * plain 36-byte payload) -> BATCH for backward compatibility; a
     * 37-byte payload's last byte selects the mode explicitly. */
    media_stream_mode_t mode = MEDIA_STREAM_MODE_BATCH;
    if (pkt->length >= 4u + 32u + 1u) {
        mode = (media_stream_mode_t)pkt->payload[4u + 32u];
    }

    /* Retransmit of the very first START_STREAM (host's ACK got lost):
     * same session, no progress made yet -> just re-ACK. */
    if (s_session.state == MEDIA_SESSION_ACTIVE && s_session.session_id == pkt->session_id &&
        s_session.expected_seq == 1u && s_session.bytes_received == 0u) {
        media_send_ack(pkt->session_id, pkt->seq);
        return;
    }

#if !MEDIA_ENABLE_BATCH
    if (mode == MEDIA_STREAM_MODE_BATCH) {
        /* BATCH compiled out -- see MEDIA_ENABLE_BATCH. */
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_UNSUPPORTED_VERSION);
        return;
    }
#endif
    if (mode == MEDIA_STREAM_MODE_BATCH && total_len > MEDIA_MAX_STREAM_BYTES) {
        /* No dedicated "stream too large" reason on the wire; BAD_LENGTH
         * is the closest fit (matches the reference). LIVE_AUDIO has no
         * such bound -- see handle_live_chunk(). */
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }

    /* Real call: a CA handshake (ca_protocol.c) already ran and derived this session's keys before the phone opened
     * this stream -- pick them up now. Checked BEFORE committing to a new session (media_session_reset() below):
     * an unauthenticated START_STREAM must leave whatever session was already active alone, not tear it down first
     * and then refuse. */
    uint8_t send_key[32];
    uint8_t recv_key[32];
    bool have_ca_keys = ca_protocol_get_session_keys(send_key, recv_key);
#if EVT2_DIAGNOSTICS
    app_log(have_ca_keys ? "[media dbg] START_STREAM: have_ca_keys=true mode="
                         : "[media dbg] START_STREAM: have_ca_keys=FALSE mode=");
    app_log_uint((uint32_t)mode);
    app_log("\r\n");
#endif
#ifndef EVT2_MEDIA_ALLOW_UNAUTHENTICATED
    /* Product default: no CA handshake, no stream. See MEDIA_AES_KEY's doc comment -- that key is a known public
     * constant, so silently falling back to it here used to mean an unauthenticated USB host (or a relay/app bug
     * that skipped the handshake) could open a "real" media session with a key anyone could already guess. */
    if (!have_ca_keys) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_NOT_AUTHENTICATED);
        return;
    }
#endif

    media_session_reset();
    s_session.state = MEDIA_SESSION_ACTIVE;
    s_session.session_id = pkt->session_id;
    s_session.mode = mode;
    s_session.expected_seq = 1u;
    s_session.declared_total_len = total_len;
    s_session.last_rx_tick = platform_get_tick_ms();

    if (have_ca_keys) {
        memcpy(s_session.send_key, send_key, sizeof(s_session.send_key));
        memcpy(s_session.recv_key, recv_key, sizeof(s_session.recv_key));
    }
    else {
        /* Only reachable at all when EVT2_MEDIA_ALLOW_UNAUTHENTICATED is defined -- see above. */
        memcpy(s_session.send_key, MEDIA_AES_KEY, sizeof(s_session.send_key));
        memcpy(s_session.recv_key, MEDIA_AES_KEY, sizeof(s_session.recv_key));
    }
    memset(send_key, 0, sizeof(send_key));
    memset(recv_key, 0, sizeof(recv_key));

    if (mode == MEDIA_STREAM_MODE_BATCH) {
        /* One nonce for the whole stream, used at END_STREAM. LIVE_AUDIO
         * instead generates a fresh nonce per chunk -- see handle_live_chunk(). */
        if (media_qrng_nonce(s_session.nonce) != PLATFORM_OK) {
            media_session_reset();
            media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
            return;
        }
    }

    media_send_ack(pkt->session_id, pkt->seq);
}

/* LIVE_AUDIO: encrypt+reply every DATA_CHUNK immediately with a FRESH
 * nonce (HW RNG) -- never buffered, never reused across chunks or
 * retries (reusing a nonce under the same key would break AES-GCM's
 * security guarantee). Unlike BATCH there is no expected_seq/duplicate
 * tracking: a lost ENCRYPTED_CHUNK is recovered simply by the host
 * resending the same DATA_CHUNK, re-encrypted with a NEW nonce rather
 * than caching/replaying old ciphertext -- see PROTOCOL.md section 4/8. */
static void handle_live_chunk(const cmd_protocol_packet_t *pkt)
{
    if (pkt->length > MEDIA_MAX_DATA_CHUNK) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }

    uint8_t nonce[12];
    if (media_qrng_nonce(nonce) != PLATFORM_OK) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }

    uint8_t tag[16];
    /* Encrypt straight into the reply buffer's ciphertext region -- see this file's reply-assembly-scratch doc
     * comment above for why there's no separate scratch buffer here. pkt->payload aliases command_protocol.c's
     * decoder buffer, a completely different array from command_protocol_tx_scratch()'s TX staging buffer, so
     * there is no input/output overlap. */
#if EVT2_DIAGNOSTICS
    uint32_t t_enc0 = platform_get_cycle_count();
#endif
    platform_status_t enc_status = platform_aes256_gcm_encrypt(s_session.send_key, nonce, pkt->payload, pkt->length,
                                                                &command_protocol_tx_scratch()[32], tag);
#if EVT2_DIAGNOSTICS
    uint32_t t_enc1 = platform_get_cycle_count();
#endif
    if (enc_status != PLATFORM_OK) {
#if EVT2_DIAGNOSTICS
        if (s_dbg_live_chunk_log_budget > 0U) {
            s_dbg_live_chunk_log_budget--;
            app_log("[media dbg] live_chunk: ENCRYPT FAILED, sending NACK\r\n");
        }
#endif
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }
#if EVT2_DIAGNOSTICS
    /* See s_dbg_encrypt_cycles's doc comment -- only successful calls counted. */
    s_dbg_encrypt_cycles += (uint64_t)(t_enc1 - t_enc0);
    s_dbg_encrypt_count++;
#endif

#if EVT2_DIAGNOSTICS
    if (s_dbg_live_chunk_log_budget > 0U) {
        s_dbg_live_chunk_log_budget--;
        app_log("[media dbg] live_chunk: encrypt OK len=");
        app_log_uint(pkt->length);
        app_log(" seq=");
        app_log_uint(pkt->seq);
        app_log(" -- calling media_send_encrypted_chunk()\r\n");
    }
#endif
    s_session.last_rx_tick = platform_get_tick_ms();
    media_send_encrypted_chunk(pkt->session_id, pkt->seq, nonce, tag, (uint16_t)pkt->length);
}

static void handle_data_chunk(const cmd_protocol_packet_t *pkt)
{
    if (s_session.state != MEDIA_SESSION_ACTIVE || s_session.session_id != pkt->session_id) {
#if EVT2_DIAGNOSTICS
        if (s_dbg_live_chunk_log_budget > 0U) {
            s_dbg_live_chunk_log_budget--;
            app_log("[media dbg] DATA_CHUNK: UNKNOWN_SESSION state=");
            app_log_uint((uint32_t)s_session.state);
            app_log(" want_sid=");
            app_log_uint(pkt->session_id);
            app_log(" have_sid=");
            app_log_uint(s_session.session_id);
            app_log("\r\n");
        }
#endif
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_UNKNOWN_SESSION);
        return;
    }

    if (s_session.mode == MEDIA_STREAM_MODE_LIVE_AUDIO) {
        handle_live_chunk(pkt);
        return;
    }

#if !MEDIA_ENABLE_BATCH
    /* Only LIVE_AUDIO sessions can exist in this build (handle_start_stream() refuses BATCH). */
    media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_UNSUPPORTED_VERSION);
#else
    if (s_session.bytes_received > 0u && pkt->seq == s_session.last_processed_seq) {
        media_send_ack(pkt->session_id, pkt->seq); /* duplicate: our previous ACK was lost */
        return;
    }

    if (pkt->seq != s_session.expected_seq) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_OUT_OF_ORDER);
        return;
    }

    if (s_session.bytes_received + pkt->length > MEDIA_MAX_STREAM_BYTES) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }

    memcpy(&s_session.plaintext[s_session.bytes_received], pkt->payload, pkt->length);
    s_session.bytes_received += pkt->length;
    s_session.expected_seq++;
    s_session.last_processed_seq = pkt->seq;
    s_session.last_rx_tick = platform_get_tick_ms();

    media_send_ack(pkt->session_id, pkt->seq);
#endif /* MEDIA_ENABLE_BATCH */
}

static void handle_end_stream(const cmd_protocol_packet_t *pkt)
{
    if (s_session.state != MEDIA_SESSION_ACTIVE || s_session.session_id != pkt->session_id) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_UNKNOWN_SESSION);
        return;
    }

    if (s_session.mode == MEDIA_STREAM_MODE_LIVE_AUDIO) {
        /* No-op in this mode (nothing buffered to hash/encrypt) -- streams
         * typically end via ABORT_STREAM instead, matching PROTOCOL.md
         * section 4. Still ACK so a client that always waits for one
         * doesn't stall. */
        media_send_ack(pkt->session_id, pkt->seq);
        return;
    }

#if !MEDIA_ENABLE_BATCH
    media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_UNSUPPORTED_VERSION);
#else
    if (s_session.result_ready && s_session.result_for_seq == pkt->seq) {
        /* Retransmit: either the ACK or the ENCRYPT_RESULT (or both) from
         * the first attempt got lost. Resend both; harmless if the host
         * already has one of them. */
        media_send_ack(pkt->session_id, pkt->seq);
        media_send_encrypt_result();
        return;
    }

    if (pkt->length < 4u + 32u) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }
    uint32_t total_bytes_sent = (uint32_t)pkt->payload[0] | ((uint32_t)pkt->payload[1] << 8) |
                                 ((uint32_t)pkt->payload[2] << 16) | ((uint32_t)pkt->payload[3] << 24);
    const uint8_t *expected_hash = pkt->payload + 4;

    uint8_t actual_hash[32];
    bool ok = (total_bytes_sent == s_session.bytes_received) &&
              platform_sha256(s_session.plaintext, s_session.bytes_received, actual_hash) == PLATFORM_OK &&
              memcmp(actual_hash, expected_hash, 32u) == 0;
    if (!ok) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        media_session_reset();
        return;
    }

    /* ACK right away: a client's END_STREAM wait is typically a short
     * timeout; the (possibly larger) ENCRYPT_RESULT is awaited separately
     * with its own longer timeout, which is why encryption can safely
     * happen after the ACK -- mirrors the reference's own reasoning. */
    media_send_ack(pkt->session_id, pkt->seq);

    if (platform_aes256_gcm_encrypt(s_session.send_key, s_session.nonce, s_session.plaintext, s_session.bytes_received,
                                     s_session.ciphertext, s_session.tag) != PLATFORM_OK) {
        media_session_reset(); /* client will simply time out waiting for ENCRYPT_RESULT */
        return;
    }
    s_session.ciphertext_len = s_session.bytes_received;
    s_session.result_ready = true;
    s_session.result_for_seq = pkt->seq;
    s_session.last_rx_tick = platform_get_tick_ms();

    media_send_encrypt_result();
#endif /* MEDIA_ENABLE_BATCH */
}

static void handle_abort_stream(const cmd_protocol_packet_t *pkt)
{
    if (s_session.state == MEDIA_SESSION_ACTIVE && s_session.session_id == pkt->session_id) {
        media_session_reset(); /* fire-and-forget, no reply */
    }
}

/* Non-zero payload[0] on a MEDIA_PING requests the crypto debug-timing
 * reply instead of a plain empty PONG -- see s_dbg_encrypt_cycles's doc
 * comment for why this rides on PING/PONG rather than a new CMD_TYPE. An
 * ordinary (empty-payload) PING is completely unaffected. */
#define MEDIA_PING_DEBUG_TIMING 0x01u

static void handle_ping(const cmd_protocol_packet_t *pkt)
{
#if EVT2_DIAGNOSTICS /* debug-timing PONG; a product build answers every PING with a plain empty PONG */
    if (pkt->length >= 1u && pkt->payload[0] == MEDIA_PING_DEBUG_TIMING) {
        uint32_t encrypt_us_avg, decrypt_us_avg, encrypt_count, decrypt_count;
        media_debug_get_crypto_timing(&encrypt_us_avg, &decrypt_us_avg, &encrypt_count, &decrypt_count);
        /* Generic to EVERY command_protocol_send()/receive, not media-specific --
         * see command_protocol.h's own doc comments. Piggybacked here (rather than
         * requiring a separate QRNG_CMD_STREAM_DEBUG_TIMING round trip just for
         * this) so one MEDIA_PING gives the full round-trip breakdown in one shot. */
        uint32_t recv_us_avg, recv_count;
        command_protocol_debug_get_receive_timing(&recv_us_avg, &recv_count);
        uint8_t resp[24];
        memcpy(&resp[0], &encrypt_us_avg, sizeof(encrypt_us_avg));
        memcpy(&resp[4], &decrypt_us_avg, sizeof(decrypt_us_avg));
        memcpy(&resp[8], &encrypt_count, sizeof(encrypt_count));
        memcpy(&resp[12], &decrypt_count, sizeof(decrypt_count));
        memcpy(&resp[16], &recv_us_avg, sizeof(recv_us_avg));
        memcpy(&resp[20], &recv_count, sizeof(recv_count));
        command_protocol_send(CMD_TYPE_MEDIA_PONG, pkt->session_id, pkt->seq, resp, sizeof(resp));
        return;
    }
#endif
    command_protocol_send(CMD_TYPE_MEDIA_PONG, pkt->session_id, pkt->seq, NULL, 0);
}

/** True if `nonce` is already in the session's recv-direction replay window (a genuine repeat -- reject), false if
 *  it's new (this call also records it either way, before the caller even attempts to decrypt). Checked BEFORE
 *  decrypting (cheap linear scan over <=128 12-byte entries, versus a full AES-GCM operation) so an obviously-
 *  replayed chunk costs as little as possible. Recording happens unconditionally on first sight -- not only after a
 *  successful decrypt -- which is safe because a legitimate resend of a chunk (lost/garbled in transit) always
 *  carries a FRESH nonce under this project's existing convention (see handle_live_chunk()'s own doc comment: "a
 *  lost ENCRYPTED_CHUNK is recovered ... re-encrypted with a NEW nonce rather than caching/replaying old
 *  ciphertext"), so the same nonce arriving twice is never an expected retry, only either a genuine network replay
 *  (the case this exists to catch) or corruption that happens to reuse bytes -- neither should be treated as OK.
 *
 *  WHY THIS EXISTS instead of an AAD/sequence-number scheme: handle_decrypt_chunk() used to be explicitly
 *  "STATELESS AS TO ORDERING" (see that function's own doc comment) -- a real, if narrow, gap a review pointed out:
 *  nothing stopped a malicious/compromised relay from resending an OLD, still-tag-valid (nonce, tag, ciphertext)
 *  tuple, which this device would decrypt again as if it were new incoming media. Binding an AAD/sequence number
 *  to close that gap would need a value BOTH boards agree on independently, but the two sides of a call are two
 *  different physical boards, each with its own LOCAL session_id/seq for its own USB link to its own phone -- there
 *  is no such shared value today without adding one to the network wire format (the relay frame / DECRYPT_CHUNK's
 *  own payload), which reaches into Kotlin and two Python tools this session cannot safely change and verify
 *  end-to-end without hardware. A nonce-based window needs no such change: nonces are drawn from the sender's
 *  QRNG-backed pool (media_qrng_nonce()) and meant to be used exactly once, so simply remembering the last
 *  MEDIA_REPLAY_WINDOW ones actually decrypted and refusing a repeat directly defeats the concrete replay scenario
 *  above, entirely within this device, with no wire change. */
static bool replay_window_seen_or_add(media_session_t *session, const uint8_t nonce[12])
{
    for (uint32_t i = 0; i < session->recv_nonce_window_count; i++) {
        if (memcmp(session->recv_nonce_window[i], nonce, 12u) == 0) {
            return true;
        }
    }
    memcpy(session->recv_nonce_window[session->recv_nonce_window_next], nonce, 12u);
    session->recv_nonce_window_next = (session->recv_nonce_window_next + 1u) % MEDIA_REPLAY_WINDOW;
    if (session->recv_nonce_window_count < MEDIA_REPLAY_WINDOW) {
        session->recv_nonce_window_count++;
    }
    return false;
}

/* EVT2 extension (no reference counterpart -- see file doc comment).
 * Decrypt+verify one chunk of the PEER's incoming stream. STATELESS AS TO CHUNK ORDERING (unlike DATA_CHUNK): every
 * DECRYPT_CHUNK is fully self-contained (its own nonce+tag), so an out-of-order request is harmless to just process
 * independently, and a call can freely interleave DATA_CHUNK (outgoing, this device's own stream) and DECRYPT_CHUNK
 * (incoming, the peer's stream) on the same USB link. It DOES need to know which session's recv_key to decrypt
 * with, though (per-call keys, see media_session_t's doc comment) -- so unlike before per-session keys existed, it
 * now checks pkt->session_id against the active session first, same as handle_data_chunk(). A DUPLICATE request
 * (the exact same nonce seen before) is a different matter from mere reordering -- see
 * replay_window_seen_or_add()'s doc comment for why that specific case IS rejected. */
static void handle_decrypt_chunk(const cmd_protocol_packet_t *pkt)
{
    if (s_session.state != MEDIA_SESSION_ACTIVE || s_session.session_id != pkt->session_id) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_UNKNOWN_SESSION);
        return;
    }
    if (pkt->length < MEDIA_DECRYPT_CHUNK_PREFIX) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }
    uint16_t ciphertext_len = (uint16_t)(pkt->length - MEDIA_DECRYPT_CHUNK_PREFIX);
    if (ciphertext_len > CMD_PROTO_MAX_PAYLOAD - 5u) {
        media_send_nack(pkt->session_id, pkt->seq, MEDIA_NACK_BAD_LENGTH);
        return;
    }

    const uint8_t *nonce = &pkt->payload[0];
    const uint8_t *tag = &pkt->payload[12];
    const uint8_t *ciphertext = &pkt->payload[28];

    if (replay_window_seen_or_add(&s_session, nonce)) {
        /* Same outcome as a tag failure from the caller's point of view (see media_decrypt_status_t's doc comment)
         * -- a repeat is exactly as untrustworthy as a tampered chunk, and neither should be treated as OK. */
#if EVT2_DIAGNOSTICS
        if (s_dbg_decrypt_chunk_log_budget > 0U) {
            s_dbg_decrypt_chunk_log_budget--;
            app_log("[media dbg] decrypt_chunk: REPLAY REJECTED (nonce seen before) len=");
            app_log_uint(ciphertext_len);
            app_log(" seq=");
            app_log_uint(pkt->seq);
            app_log("\r\n");
        }
#endif
        media_send_decrypted_chunk(pkt->session_id, pkt->seq, MEDIA_DECRYPT_AUTH_FAIL, 0u);
        return;
    }

    /* Decrypt straight into the reply buffer's plaintext region -- see this file's reply-assembly-scratch doc
     * comment above for why there's no separate scratch buffer here. ciphertext aliases command_protocol.c's
     * decoder buffer, a completely different array from command_protocol_tx_scratch()'s TX staging buffer, so
     * there is no input/output overlap. */
#if EVT2_DIAGNOSTICS
    uint32_t t_dec0 = platform_get_cycle_count();
#endif
    platform_status_t dec_status = platform_aes256_gcm_decrypt(s_session.recv_key, nonce, ciphertext, ciphertext_len,
                                                                tag, &command_protocol_tx_scratch()[5]);
#if EVT2_DIAGNOSTICS
    uint32_t t_dec1 = platform_get_cycle_count();
#endif
    if (dec_status != PLATFORM_OK) {
#if EVT2_DIAGNOSTICS
        if (s_dbg_decrypt_chunk_log_budget > 0U) {
            s_dbg_decrypt_chunk_log_budget--;
            app_log("[media dbg] decrypt_chunk: DECRYPT FAILED (tag mismatch/HAL error) len=");
            app_log_uint(ciphertext_len);
            app_log(" mod16=");
            app_log_uint(ciphertext_len % 16u);
            app_log(" seq=");
            app_log_uint(pkt->seq);
            app_log(" nonce0=");
            app_log_uint(nonce[0]);
            app_log(" nonce1=");
            app_log_uint(nonce[1]);
            app_log(" nonce2=");
            app_log_uint(nonce[2]);
            app_log(" nonce3=");
            app_log_uint(nonce[3]);
            app_log("\r\n");
        }
#endif
        /* Tag mismatch (tampered/corrupt ciphertext) or a HAL error --
         * either way, do not treat command_protocol_tx_scratch()[5..] as trustworthy. A
         * DECRYPTED_CHUNK with status != OK carries no plaintext (see
         * media_send_decrypted_chunk()). Not counted into the debug timing
         * -- see s_dbg_decrypt_cycles's own doc comment. */
        media_send_decrypted_chunk(pkt->session_id, pkt->seq, MEDIA_DECRYPT_AUTH_FAIL, 0u);
        return;
    }
#if EVT2_DIAGNOSTICS
    s_dbg_decrypt_cycles += (uint64_t)(t_dec1 - t_dec0);
    s_dbg_decrypt_count++;
#endif

#if EVT2_DIAGNOSTICS
    if (s_dbg_decrypt_chunk_log_budget > 0U) {
        s_dbg_decrypt_chunk_log_budget--;
        app_log("[media dbg] decrypt_chunk: decrypt OK ciphertext_len=");
        app_log_uint(ciphertext_len);
        app_log(" seq=");
        app_log_uint(pkt->seq);
        app_log(" -- calling media_send_decrypted_chunk()\r\n");
    }
#endif
    media_send_decrypted_chunk(pkt->session_id, pkt->seq, MEDIA_DECRYPT_OK, ciphertext_len);
}

static void dispatch(const cmd_protocol_packet_t *pkt)
{
#if EVT2_DIAGNOSTICS
    if (s_dbg_dispatch_log_budget > 0U) {
        s_dbg_dispatch_log_budget--;
        app_log("[media dbg] dispatch type=");
        app_log_uint(pkt->type);
        app_log(" len=");
        app_log_uint(pkt->length);
        app_log(" sess_state=");
        app_log_uint((uint32_t)s_session.state);
        app_log("\r\n");
    }
#endif
    switch (pkt->type) {
        case CMD_TYPE_START_STREAM:    handle_start_stream(pkt); break;
        case CMD_TYPE_DATA_CHUNK:      handle_data_chunk(pkt); break;
        case CMD_TYPE_END_STREAM:      handle_end_stream(pkt); break;
        case CMD_TYPE_ABORT_STREAM:    handle_abort_stream(pkt); break;
        case CMD_TYPE_MEDIA_PING:      handle_ping(pkt); break;
        case CMD_TYPE_MEDIA_RESET:     handle_reset(pkt); break;
        case CMD_TYPE_DECRYPT_CHUNK:   handle_decrypt_chunk(pkt); break;
        default:
            /* ACK/NACK/PONG/ENCRYPT_RESULT/ERROR/DECRYPTED_CHUNK are
             * device->host (or either-way-but-unused-inbound) types --
             * nothing to do if one shows up on the RX side. */
            break;
    }
}

/** Registered with command_protocol_register_media() -- see
 *  cmd_protocol_media_handler_t's doc comment in command_protocol.h.
 *  Not `static`: extern-declared directly where used (app_main.c), same
 *  convention as security_protocol_handler/biometric_protocol_handler/
 *  qrng_protocol_handler -- see that file's doc comment on why these
 *  adapters have no shared header. */
void media_protocol_handler(const cmd_protocol_packet_t *pkt)
{
    dispatch(pkt);
}

/** Call every main-loop iteration, same as qrng_protocol_poll() -- garbage
 *  collects a session that has gone quiet (client crashed/unplugged
 *  mid-stream without RESET/ABORT_STREAM), and keeps the QRNG nonce pool
 *  topped up off the hot path (see media_nonce_pool_refill()'s doc
 *  comment). */
void media_protocol_poll(void)
{
    if (s_session.state == MEDIA_SESSION_ACTIVE && !s_session.result_ready &&
        (platform_get_tick_ms() - s_session.last_rx_tick > MEDIA_SESSION_TIMEOUT_MS)) {
        media_session_reset();
    }
    media_nonce_pool_refill();
}
