/**
 * @file    command_protocol.c
 * @brief   Framed request/response command dispatcher over platform_usb.h.
 *
 * See command_protocol.h's doc comment for the wire format. This file
 * knows nothing about Security/Biometric/QRNG -- only App wires those up
 * via command_protocol_register(), keeping this a pure transport+framing
 * layer (mirrors how Core_app/Middleware/Security/security_service.h
 * etc. know nothing about USB).
 */
#include "command_protocol.h"
#include "platform.h"

#include <string.h>

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* TEMP diagnostic 2026-09-25 (see CLAUDE.md / media_protocol.c's own matching note): tracing why a real phone
 * call's media chunks get zero replies -- media_protocol.c's own dispatch() never fires during an active call
 * (its throttled logging never triggers), so the frames must be getting dropped HERE, before ever reaching the
 * media handler. Logs the three ways decoder_feed() drops a frame silently (length mismatch, CRC mismatch,
 * oversized) plus a sample of what DOES decode successfully (type only, to see if media types ever get through).
 * Throttled so it cannot itself flood the UART or slow down the very path being diagnosed. Remove once root-caused. */
extern void app_log(const char *msg);
extern void app_log_uint(uint32_t value);
static uint32_t s_dbg_len_mismatch_budget = 15;
static uint32_t s_dbg_crc_fail_budget = 15;
static uint32_t s_dbg_oversized_budget = 15;
static uint32_t s_dbg_decode_ok_budget = 30;
#endif /* EVT2_DIAGNOSTICS */

#define CMD_PROTO_FLAG     0x7Eu
#define CMD_PROTO_ESC      0x7Du
#define CMD_PROTO_ESC_XOR  0x20u
#define CMD_PROTO_HEADER_LEN 10u
#define CMD_PROTO_CRC_LEN    4u

/* CMD_PROTO_MAX_PAYLOAD itself now lives in command_protocol.h (media_protocol.c
 * needs the real numeric value too, to bound DATA_CHUNK/DECRYPT_CHUNK chunk
 * sizes against their replies' extra overhead -- see that macro's doc
 * comment there). History of the value, kept here since this file owns the
 * buffers it sizes:
 *
 * Originally 2050 (QRNG_NOISE_BYTES=2048 + the 2-byte [sub_cmd][status]
 * header every adapter response prepends -- getting that 2 bytes short
 * once silently broke every response of exactly QRNG_NOISE_BYTES, e.g.
 * GET_NOISE/GET_STARTUP_HEALTH_RECORD, since the adapter's own
 * `max_response_len < 2 + QRNG_NOISE_BYTES` guard saw `2048 < 2050` and
 * always reported failure -- kept as a cautionary note now that this is
 * no longer the binding constraint).
 *
 * Bumped to 32768 (32KB) for the encrypted video-call media channel
 * (CMD_TYPE_MEDIA_FIRST..CMD_TYPE_MEDIA_LAST, dispatched by
 * media_protocol.c via command_protocol_register_media() -- that channel
 * DOES reuse this same transport, not a separate one, per
 * command_protocol.h's file doc comment) as well as the pre-existing
 * Security/Biometric/QRNG control-plane traffic: a bigger ceiling here
 * amortizes this file's own fixed per-frame cost (now ~400-800us, mostly
 * genuine USB Full-Speed bus transfer time -- see
 * command_protocol_debug_get_send_timing()) over more payload per frame.
 *
 * NOT arbitrary -- this file deliberately does not include
 * qrng_service.h (this transport layer knows nothing about QRNG, see
 * file doc comment), so the value can't reference QRNG_NOISE_BYTES
 * directly either way. Every buffer below scales with this value, the
 * escape buffter at 2x -- total static RAM cost is ~5x this number (see
 * git history/PR description for the exact math). 100KB was
 * requested and rejected: 5*100000+58 =~500KB alone overflows
 * RAM_D1's entire 512KB bank once the rest of the firmware's ~70KB of
 * .data/.bss is added in. 32KB leaves a safe multi-hundred-KB margin.
 * If this ever needs to grow past what RAM_D1 has room for, move these
 * 4 buffers to RAM_D2 (288KB, almost entirely unused -- see
 * STM32H753ZITX_FLASH.ld's .dma_noncache section for the precedent)
 * instead of assuming RAM_D1 alone can keep absorbing it. */
#define CMD_PROTO_RX_BODY_MAX (CMD_PROTO_HEADER_LEN + CMD_PROTO_MAX_PAYLOAD + CMD_PROTO_CRC_LEN)
#define CMD_PROTO_TX_BODY_MAX (CMD_PROTO_HEADER_LEN + CMD_PROTO_MAX_PAYLOAD + CMD_PROTO_CRC_LEN)
/* Escaping can at most double the body; +2 for the leading/trailing FLAG. */

typedef struct {
    uint8_t  buf[CMD_PROTO_RX_BODY_MAX];
    uint16_t len;
    bool     in_frame;
    bool     escape_next;
#if EVT2_DIAGNOSTICS
    /* Cycle count at the FLAG byte that started the CURRENT frame -- see
     * s_dbg_recv_cycles' own doc comment below. */
    uint32_t frame_start_cycles;
#endif
} decoder_t;

static decoder_t s_decoder;

/* TX staging: HEADER+PAYLOAD+CRC for whatever is being sent right now. File-scope (not a local `static` inside
 * one function like before, 2026-09-24) so command_protocol_tx_scratch() can hand callers a pointer straight
 * into &body[CMD_PROTO_HEADER_LEN] -- a caller building a large reply (handle_packet()'s own CMD_TYPE_RESULT
 * dispatch below, or media_protocol.c's encrypted/decrypted-chunk replies) can then write it there directly and
 * call command_protocol_send_staged(), instead of keeping a same-sized scratch buffer of its own that would just
 * get memcpy'd into this exact storage by command_protocol_send() anyway. That removed two CMD_PROTO_MAX_PAYLOAD
 * -sized duplicates (handle_packet()'s old local `response[]` and media_protocol.c's `s_reply_buf`) -- ~96KB of
 * RAM_D1 for one extra memcpy() each, the same "write it where it will end up, skip the intermediate copy"
 * discipline this file's CMD_PROTO_MAX_PAYLOAD comment already applied when media_protocol.c dropped its own
 * s_live_cipher_buf/s_live_plain_buf duplicates. Safe to reuse across calls for the same reason `tx` below is:
 * this is a single-threaded dispatcher, one frame assembled and sent to completion before the next one starts. */
static uint8_t body[CMD_PROTO_TX_BODY_MAX];

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* command_protocol_debug_get_receive_timing() accumulators (2026-09-19).
 * Measures wall time from the opening FLAG byte of a frame to the moment
 * its CRC validates as complete -- i.e. however many command_protocol_poll()
 * calls (and therefore however many actual USB OUT transactions) it took
 * for every byte of one host->device request to actually arrive, PLUS this
 * decoder's own byte-by-byte processing (a handful of comparisons per byte,
 * negligible next to USB transaction timing). Deliberately NOT split
 * further into "pure wire time" vs "waiting for the next poll() call",
 * same reasoning as command_protocol_debug_get_send_timing()'s own
 * wait/build split not being pure wire time either -- the USB peripheral's
 * actual byte-level receive is interrupt-driven and asynchronous to this
 * loop, so from firmware alone there is no clean way to separate "byte sat
 * in the ring waiting to be read" from "byte was still crossing the wire"
 * -- this number is real elapsed wall time for the whole receive, not a
 * guess, just not decomposed further than that. */
static uint64_t s_dbg_recv_cycles;
static uint32_t s_dbg_recv_count;

void command_protocol_debug_get_receive_timing(uint32_t *recv_us_avg, uint32_t *count)
{
    uint32_t n = s_dbg_recv_count;
    uint32_t cpu_hz = platform_get_cpu_hz();
    *count = n;
    *recv_us_avg = (n && cpu_hz) ? (uint32_t)((s_dbg_recv_cycles / n) * 1000000ULL / cpu_hz) : 0U;
    s_dbg_recv_cycles = 0U;
    s_dbg_recv_count = 0U;
}

/* command_protocol_debug_get_send_timing() accumulators -- see that
 * function's doc comment in command_protocol.h. */
static uint64_t s_dbg_wait_cycles;
static uint64_t s_dbg_build_tx_cycles;
static uint32_t s_dbg_send_count;
#endif /* EVT2_DIAGNOSTICS */
static cmd_protocol_handler_t s_handlers[CMD_TYPE_PROVISION - CMD_TYPE_SECURITY + 1]; /* indexed by type - CMD_TYPE_SECURITY;
                                                                                 * one slot (CMD_TYPE_RESULT's) is never
                                                                                 * registered -- device->host only. */
static cmd_protocol_media_handler_t s_media_handler;
static bool s_ready;

/* Session/seq of the request currently being dispatched to a handler --
 * see command_protocol_current_session_id()'s doc comment. Only valid
 * during handle_packet()'s call into s_handlers[]. */
static uint16_t s_cur_session_id;
static uint32_t s_cur_seq;

/* Table-driven CRC-32 (same zlib/CRC-32 variant as before: poly
 * 0xEDB88320 reflected, init 0xFFFFFFFF, final XOR) -- mathematically
 * identical result to the bit-by-bit version this replaced, just 8
 * table lookups per byte instead of 8 conditional shift-XOR steps per
 * byte. Measured cause of send_frame()'s ~950us/push cost NOT actually
 * being USB hardware transfer time (that turned out to be ~1us,
 * negligible) or framing/escape overhead (~112us) but this function
 * alone, called from command_protocol_send() on every ~1034-byte QRNG
 * stream push and again from decoder_feed() on every received frame --
 * see command_protocol_debug_get_send_timing()'s doc comment and
 * tools/evt2_cli.py's `qrng stream-debug-timing` for how this was
 * isolated. Table is built lazily on first use (256 entries, ~2048
 * bit-iterations total, once ever) rather than hand-transcribed as a
 * literal array, to keep this provably the same algorithm as the
 * version it replaces instead of risking a copy-paste error in 256
 * magic constants. */
static uint32_t s_crc32_table[256];
static bool s_crc32_table_ready;

static void crc32_build_table(void)
{
    for (uint32_t i = 0; i < 256U; i++) {
        uint32_t c = i;
        for (int b = 0; b < 8; b++) {
            uint32_t mask = (uint32_t)(-(int32_t)(c & 1u));
            c = (c >> 1) ^ (0xEDB88320u & mask);
        }
        s_crc32_table[i] = c;
    }
    s_crc32_table_ready = true;
}

static uint32_t crc32_of(const uint8_t *data, size_t len)
{
    if (!s_crc32_table_ready) {
        crc32_build_table();
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = s_crc32_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;
}

static int handler_slot(uint8_t type)
{
    if (type < CMD_TYPE_SECURITY || type > CMD_TYPE_PROVISION || type == CMD_TYPE_RESULT) {
        return -1; /* CMD_TYPE_RESULT is device->host only, never a registered handler */
    }
    return (int)(type - CMD_TYPE_SECURITY);
}

cmd_protocol_status_t command_protocol_init(void)
{
    memset(&s_decoder, 0, sizeof(s_decoder));
    memset(s_handlers, 0, sizeof(s_handlers));
    s_media_handler = NULL;
    s_ready = true;
    return CMD_PROTO_OK;
}

cmd_protocol_status_t command_protocol_register(uint8_t type, cmd_protocol_handler_t handler)
{
    int slot = handler_slot(type);
    if (slot < 0 || handler == NULL) {
        return CMD_PROTO_INVALID_PARAM;
    }
    s_handlers[slot] = handler;
    return CMD_PROTO_OK;
}

cmd_protocol_status_t command_protocol_register_media(cmd_protocol_media_handler_t handler)
{
    if (handler == NULL) {
        return CMD_PROTO_INVALID_PARAM;
    }
    s_media_handler = handler;
    return CMD_PROTO_OK;
}

/** Escape+send one already-assembled body (HEADER+PAYLOAD+CRC) as a
 *  complete framed packet. Builds the whole escaped frame in a static
 *  staging buffer and sends it in one platform_usb_transmit() call --
 *  simple, not a streaming writer (this is a control-plane transport;
 *  see command_protocol.h's doc comment on why the media/stream range
 *  is deliberately not implemented here yet).
 *
 *  `tx` is `static` (reused every call) purely to avoid a 2x-oversized
 *  stack frame -- safe only because platform_usb_wait_tx_ready() is
 *  called FIRST, before a single byte of the new frame is written into
 *  it. Getting that ordering backwards (write first, wait-and-transmit
 *  after -- this file's original shape, found on inspection while
 *  investigating an unrelated host-side test anomaly) would let a
 *  fast-enough repeat caller (a continuous QRNG stream is the first one
 *  that ever pushes frames back-to-back with no host round-trip in
 *  between) overwrite `tx` while the USB peripheral is still
 *  asynchronously clocking the *previous* frame out of that same memory:
 *  platform_usb_transmit() returning PLATFORM_OK only means the transfer
 *  was accepted/started, not that the hardware is done reading the
 *  buffer (see that function's and platform_usb_wait_tx_ready()'s doc
 *  comments in platform_usb.h). Kept as a defensive fix even though the
 *  anomaly that prompted looking here turned out to have a different,
 *  mundane cause every time it was chased down -- see this function's
 *  own git history for the full trail. Two confirmed, unrelated
 *  host-side test artifacts, NOT firmware bugs: (1) a test script
 *  reading stale bytes left over from a previous run, or not filtering
 *  out this board's own app_qrng_protocol_self_test()
 *  (Core_app/App/app_main.c) generating real traffic on the same USB
 *  wire at boot; (2) a "STOP ack sometimes goes missing" report that
 *  traced -- with a timestamped host-side log -- to the *host's own*
 *  frame reader returning the first decoded frame out of one
 *  `serial.read()` call and silently discarding a second frame sitting
 *  right behind it in that same read (the leftover last stream push and
 *  the STOP ack, arriving back-to-back). Instrumenting this function's
 *  actual platform_usb_transmit() return value (not just whether the
 *  pre-write busy-check passed) confirmed 0 failed sends across 195
 *  attempts while chasing (2). Moral confirmed twice now: when a host
 *  reports a missing/reordered frame, verify the *host's* read loop
 *  drains a batch completely before suspecting this file again. */
/* H7S3 port (RAM reduction "A"): the frame is escaped into two small chunk
 * buffers used alternately and sent chunk by chunk, instead of into one
 * static `tx[CMD_PROTO_TX_FRAME_MAX]` (2 * (HEADER + CMD_PROTO_MAX_PAYLOAD +
 * CRC) + 2 = ~96KB at 49152) sent in a single transfer. Saves ~88KB of
 * AXI SRAM, which the H7S3 (455KB, no RAM_D1/RAM_D2 split) needs.
 *
 * Wire output is byte-for-byte identical (same FLAG / escaped body / FLAG),
 * only split across several CDC IN transfers; the host reads a byte stream
 * and its decoder never sees transfer boundaries. The ST CDC class ends a
 * transfer whose length is a multiple of the packet size with a ZLP, so no
 * chunk ever sits unflushed on the host side.
 *
 * Buffer reuse rule (same hazard the original's comment above describes):
 * platform_usb_transmit() only STARTS a transfer, the USB core keeps
 * reading the chunk buffer from the IRQ until it is done. A chunk buffer is
 * therefore only refilled after platform_usb_wait_tx_ready() confirmed the
 * transfer that last used it has completed: the wait before transmitting
 * chunk k proves chunk k-1 (the other buffer) is finished, and chunk k+1
 * goes into that other buffer.
 *
 * Also removes the old worst-case hazard where an escape-heavy body could
 * exceed CDC_Transmit_HS()'s uint16_t length and be dropped: each transfer
 * is now at most CMD_PROTO_TX_CHUNK bytes. */
/* 4000, not 4096: a full chunk is flushed at 3999 or 4000 bytes, neither a
 * multiple of the 512-byte HS bulk packet, so mid-frame chunks never cost
 * an extra ZLP (usbd_cdc.c sends one for packet-multiple transfers). */
#define CMD_PROTO_TX_CHUNK 4000u
static uint8_t s_tx_chunk[2][CMD_PROTO_TX_CHUNK] __attribute__((aligned(32)));

/* Set when a wait for the previous IN transfer timed out: the host has stopped reading. Until that transfer
 * completes, later frames are dropped at once instead of each waiting 300 ms again -- a single poll can hold
 * hundreds of queued requests, and 300 ms per reply kept the main loop away from the IWDG refresh for > 32 s
 * (2026-09-28, calls on the V8Y board ended in an IWDG reset). Cleared by the first wait that succeeds. */
static bool s_tx_stalled;

/** Wait for the previous transfer (not at all while the host is known to have stopped reading). */
static bool tx_wait_ready(void)
{
    const bool ok = platform_usb_wait_tx_ready(s_tx_stalled ? 0U : 300U) == PLATFORM_OK;
    s_tx_stalled = !ok;
    return ok;
}

/** Wait for the previous transfer, then start sending `len` bytes of
 *  s_tx_chunk[which]. False = the frame cannot be completed. */
static bool tx_chunk_flush(uint32_t which, uint32_t len)
{
    if (!tx_wait_ready()) {
        return false;
    }
    return platform_usb_transmit(s_tx_chunk[which], len, 100U) == PLATFORM_OK;
}

static void send_frame(const uint8_t *body, uint16_t body_len)
{
#if EVT2_DIAGNOSTICS
    uint32_t t0 = platform_get_cycle_count();
#endif

    /* The previous frame's last chunk may still be in flight in EITHER
     * buffer -- wait before writing the first byte of this one. */
    if (!tx_wait_ready()) {
        return; /* previous transfer still in flight after waiting -- drop this one rather than corrupt it */
    }

#if EVT2_DIAGNOSTICS
    uint32_t t1 = platform_get_cycle_count();
#endif

    uint32_t cur = 0U;
    uint32_t n = 0U;
    uint8_t *tx = s_tx_chunk[cur];

    tx[n++] = CMD_PROTO_FLAG;
    for (uint16_t i = 0; i < body_len; i++) {
        /* Keep room for one escape pair (2 bytes) before flushing. */
        if (n > CMD_PROTO_TX_CHUNK - 2u) {
            if (!tx_chunk_flush(cur, n)) {
                /* Host sees a truncated frame; its decoder resyncs on the next
                 * FLAG and drops it on CRC, same outcome as a dropped frame. */
                return;
            }
            cur ^= 1U;
            tx = s_tx_chunk[cur];
            n = 0U;
        }
        uint8_t byte = body[i];
        if (byte == CMD_PROTO_FLAG || byte == CMD_PROTO_ESC) {
            tx[n++] = CMD_PROTO_ESC;
            tx[n++] = byte ^ CMD_PROTO_ESC_XOR;
        }
        else {
            tx[n++] = byte;
        }
    }
    if (n >= CMD_PROTO_TX_CHUNK) {
        if (!tx_chunk_flush(cur, n)) {
            return;
        }
        cur ^= 1U;
        tx = s_tx_chunk[cur];
        n = 0U;
    }
    tx[n++] = CMD_PROTO_FLAG;

    (void)tx_chunk_flush(cur, n);

#if EVT2_DIAGNOSTICS
    uint32_t t2 = platform_get_cycle_count();
    s_dbg_wait_cycles += (uint64_t)(t1 - t0);
    s_dbg_build_tx_cycles += (uint64_t)(t2 - t1);
    s_dbg_send_count++;
#endif
}

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
void command_protocol_debug_get_send_timing(uint32_t *wait_us_avg, uint32_t *build_tx_us_avg, uint32_t *count)
{
    uint32_t n = s_dbg_send_count;
    uint32_t cpu_hz = platform_get_cpu_hz();
    *count = n;
    *wait_us_avg = (n && cpu_hz) ? (uint32_t)((s_dbg_wait_cycles / n) * 1000000ULL / cpu_hz) : 0U;
    *build_tx_us_avg = (n && cpu_hz) ? (uint32_t)((s_dbg_build_tx_cycles / n) * 1000000ULL / cpu_hz) : 0U;
    s_dbg_wait_cycles = 0U;
    s_dbg_build_tx_cycles = 0U;
    s_dbg_send_count = 0U;
}
#endif /* EVT2_DIAGNOSTICS */

/** Shared tail of command_protocol_send()/command_protocol_send_staged(): body[CMD_PROTO_HEADER_LEN..
 *  +payload_len) is already correct on entry (either just memcpy'd in, or written there directly by the
 *  caller) -- this just fills in the header fields around it, appends the CRC, and frames+sends it. */
static void finish_and_send(uint8_t type, uint16_t session_id, uint32_t seq, uint16_t payload_len)
{
    body[0] = CMD_PROTOCOL_VERSION;
    body[1] = type;
    body[2] = (uint8_t)(session_id);
    body[3] = (uint8_t)(session_id >> 8);
    body[4] = (uint8_t)(seq);
    body[5] = (uint8_t)(seq >> 8);
    body[6] = (uint8_t)(seq >> 16);
    body[7] = (uint8_t)(seq >> 24);
    body[8] = (uint8_t)(payload_len);
    body[9] = (uint8_t)(payload_len >> 8);

    uint16_t crc_offset = CMD_PROTO_HEADER_LEN + payload_len;
    uint32_t crc = crc32_of(body, crc_offset);
    body[crc_offset + 0] = (uint8_t)(crc);
    body[crc_offset + 1] = (uint8_t)(crc >> 8);
    body[crc_offset + 2] = (uint8_t)(crc >> 16);
    body[crc_offset + 3] = (uint8_t)(crc >> 24);

    send_frame(body, (uint16_t)(crc_offset + CMD_PROTO_CRC_LEN));
}

cmd_protocol_status_t command_protocol_send(uint8_t type, uint16_t session_id, uint32_t seq, const uint8_t *payload,
                                             uint16_t payload_len)
{
    if (!s_ready) {
        return CMD_PROTO_NOT_READY;
    }
    if (payload_len > CMD_PROTO_MAX_PAYLOAD) {
        return CMD_PROTO_INVALID_PARAM;
    }
    if (payload_len > 0U && payload != NULL) {
        memcpy(&body[CMD_PROTO_HEADER_LEN], payload, payload_len);
    }
    finish_and_send(type, session_id, seq, payload_len);
    return CMD_PROTO_OK;
}

uint8_t *command_protocol_tx_scratch(void)
{
    return &body[CMD_PROTO_HEADER_LEN];
}

cmd_protocol_status_t command_protocol_send_staged(uint8_t type, uint16_t session_id, uint32_t seq,
                                                    uint16_t payload_len)
{
    if (!s_ready) {
        return CMD_PROTO_NOT_READY;
    }
    if (payload_len > CMD_PROTO_MAX_PAYLOAD) {
        return CMD_PROTO_INVALID_PARAM;
    }
    finish_and_send(type, session_id, seq, payload_len);
    return CMD_PROTO_OK;
}

/** Feed one raw (pre-unescape) byte into the decoder. Returns true and
 *  fills *out when a complete, CRC-valid packet was just decoded. */
static bool decoder_feed(decoder_t *d, uint8_t byte, cmd_protocol_packet_t *out)
{
    if (byte == CMD_PROTO_FLAG) {
        bool have_frame = false;
        if (d->in_frame && d->len >= (CMD_PROTO_HEADER_LEN + CMD_PROTO_CRC_LEN)) {
            uint16_t payload_len = (uint16_t)(d->buf[8] | ((uint16_t)d->buf[9] << 8));
            uint16_t expected_len = CMD_PROTO_HEADER_LEN + payload_len + CMD_PROTO_CRC_LEN;
            if (d->len == expected_len) {
                uint32_t crc_rx = (uint32_t)d->buf[expected_len - 4] | ((uint32_t)d->buf[expected_len - 3] << 8) |
                                   ((uint32_t)d->buf[expected_len - 2] << 16) |
                                   ((uint32_t)d->buf[expected_len - 1] << 24);
                uint32_t crc_calc = crc32_of(d->buf, CMD_PROTO_HEADER_LEN + payload_len);
                if (crc_rx == crc_calc) {
                    out->type = d->buf[1];
                    out->session_id = (uint16_t)(d->buf[2] | ((uint16_t)d->buf[3] << 8));
                    out->seq = (uint32_t)d->buf[4] | ((uint32_t)d->buf[5] << 8) | ((uint32_t)d->buf[6] << 16) |
                               ((uint32_t)d->buf[7] << 24);
                    out->payload = &d->buf[CMD_PROTO_HEADER_LEN];
                    out->length = payload_len;
                    have_frame = true;
#if EVT2_DIAGNOSTICS
                    /* See s_dbg_recv_cycles' own doc comment -- frame_start_cycles was
                     * stamped at the OPENING flag of this same frame, below, the
                     * previous time decoder_feed() saw a FLAG byte. */
                    s_dbg_recv_cycles += (uint64_t)(platform_get_cycle_count() - d->frame_start_cycles);
                    s_dbg_recv_count++;
                    if (s_dbg_decode_ok_budget > 0U) {
                        s_dbg_decode_ok_budget--;
                        app_log("[cp dbg] decode OK type=");
                        app_log_uint(out->type);
                        app_log(" len=");
                        app_log_uint(out->length);
                        app_log("\r\n");
                    }
#endif
                }
#if EVT2_DIAGNOSTICS
                else if (s_dbg_crc_fail_budget > 0U) {
                    s_dbg_crc_fail_budget--;
                    app_log("[cp dbg] CRC FAIL d->len=");
                    app_log_uint(d->len);
                    app_log(" payload_len=");
                    app_log_uint(payload_len);
                    app_log("\r\n");
                }
#endif
            }
#if EVT2_DIAGNOSTICS
            else if (s_dbg_len_mismatch_budget > 0U) {
                s_dbg_len_mismatch_budget--;
                app_log("[cp dbg] LEN MISMATCH d->len=");
                app_log_uint(d->len);
                app_log(" expected=");
                app_log_uint(expected_len);
                app_log(" payload_len_field=");
                app_log_uint(payload_len);
                app_log("\r\n");
            }
#endif
        }
        /* Whether this frame was valid or not, a FLAG always starts a
         * fresh frame right after it -- classic HDLC resync. */
        d->in_frame = true;
        d->len = 0;
        d->escape_next = false;
#if EVT2_DIAGNOSTICS
        d->frame_start_cycles = platform_get_cycle_count();
#endif
        return have_frame;
    }

    if (!d->in_frame) {
        return false; /* garbage before the first FLAG -- ignore */
    }

    if (byte == CMD_PROTO_ESC) {
        d->escape_next = true;
        return false;
    }

    uint8_t real_byte = byte;
    if (d->escape_next) {
        real_byte = byte ^ CMD_PROTO_ESC_XOR;
        d->escape_next = false;
    }

    if (d->len >= CMD_PROTO_RX_BODY_MAX) {
        /* Oversized frame -- drop it, stop accumulating until next FLAG. */
#if EVT2_DIAGNOSTICS
        if (s_dbg_oversized_budget > 0U) {
            s_dbg_oversized_budget--;
            app_log("[cp dbg] OVERSIZED frame, dropping\r\n");
        }
#endif
        d->in_frame = false;
        return false;
    }

    d->buf[d->len++] = real_byte;
    return false;
}

/* Trace hook (weak, no-op here): the App layer's post-mortem trace (Core_app/App/app_trace.c) overrides it to record
 * which command was being handled when the board hung. Keeps this middleware independent of the App layer. */
__attribute__((weak)) void command_protocol_trace_hook(uint8_t type, uint8_t sub_cmd, bool begin)
{
    (void)type;
    (void)sub_cmd;
    (void)begin;
}

static void handle_packet_inner(const cmd_protocol_packet_t *pkt);

static void handle_packet(const cmd_protocol_packet_t *pkt)
{
    const uint8_t sub = (pkt->length > 0U) ? pkt->payload[0] : 0U;
    command_protocol_trace_hook(pkt->type, sub, true);
    handle_packet_inner(pkt);
    command_protocol_trace_hook(pkt->type, sub, false);
}

static void handle_packet_inner(const cmd_protocol_packet_t *pkt)
{
    if (pkt->type == CMD_TYPE_HELLO) {
        uint8_t ack_payload[1] = { CMD_PROTOCOL_VERSION };
        command_protocol_send(CMD_TYPE_HELLO_ACK, pkt->session_id, pkt->seq, ack_payload, sizeof(ack_payload));
        return;
    }

    if (pkt->type >= CMD_TYPE_MEDIA_FIRST && pkt->type <= CMD_TYPE_MEDIA_LAST) {
        /* Whole packet, not the [sub_cmd][params] shape below -- see
         * cmd_protocol_media_handler_t's doc comment. No reply here even
         * if unregistered: same "silently ignored" rule as an
         * unregistered Security/Biometric/QRNG type below, and matches
         * this file's existing "a CRC-invalid frame gets no NACK either"
         * philosophy (see command_protocol.h's doc comment) -- the media
         * handler itself decides what, if anything, each packet type
         * gets back (e.g. ABORT_STREAM is fire-and-forget). */
        if (s_media_handler != NULL) {
            s_cur_session_id = pkt->session_id;
            s_cur_seq = pkt->seq;
            s_media_handler(pkt);
        }
        return;
    }

    int slot = handler_slot(pkt->type);
    if (slot < 0 || s_handlers[slot] == NULL) {
        return; /* unknown/unregistered type -- silently ignored, no reply */
    }
    if (pkt->length < 1U) {
        return; /* need at least a sub_cmd byte */
    }

    /* Write the handler's response straight into the TX staging buffer (see command_protocol_tx_scratch()'s doc
     * comment) instead of a separate ~CMD_PROTO_MAX_PAYLOAD-sized local -- pkt->payload aliases s_decoder.buf, a
     * completely different array, so there is no input/output overlap even though a handler reads from one and
     * writes to the other in the same call. */
    uint8_t *response = command_protocol_tx_scratch();
    uint16_t response_len = 0;
    s_cur_session_id = pkt->session_id;
    s_cur_seq = pkt->seq;
    bool ok = s_handlers[slot](pkt->payload, pkt->length, response, &response_len, CMD_PROTO_MAX_PAYLOAD);

    if (!ok) {
        uint8_t fail[2] = { pkt->payload[0], (uint8_t)CMD_PROTO_INVALID_PARAM };
        command_protocol_send(CMD_TYPE_RESULT, pkt->session_id, pkt->seq, fail, sizeof(fail));
        return;
    }
    if (response_len > 0U) {
        command_protocol_send_staged(CMD_TYPE_RESULT, pkt->session_id, pkt->seq, response_len);
    }
}

uint16_t command_protocol_current_session_id(void)
{
    return s_cur_session_id;
}

uint32_t command_protocol_current_seq(void)
{
    return s_cur_seq;
}

void command_protocol_poll(void)
{
    if (!s_ready) {
        return;
    }

    /* Drain platform_usb.h's backend RX ring (platform_usb_stm32lib.c's
     * USB_RX_RING_SIZE, currently 32768) completely every call, in fixed
     * -size chunks, rather than needing a local buffer as big as the
     * ring itself: platform_usb_receive() returning fewer bytes than
     * requested means the ring is now empty, so looping until that
     * happens (or until PLATFORM_OK stops coming back) still fully
     * drains an arbitrarily large ring using a small, constant amount of
     * stack/static RAM. Chunk size is arbitrary -- large enough to keep
     * the loop's per-call overhead low, small enough it costs nothing
     * to keep on the stack instead of static. */
    uint8_t rx[512];
    cmd_protocol_packet_t pkt;
    for (;;) {
        size_t n = 0;
        if (platform_usb_receive(rx, sizeof(rx), &n) != PLATFORM_OK) {
            return;
        }
        if (n == 0U) {
            return;
        }
        for (size_t i = 0; i < n; i++) {
            if (decoder_feed(&s_decoder, rx[i], &pkt)) {
                handle_packet(&pkt);
            }
        }
        if (n < sizeof(rx)) {
            return; /* short read -- ring is now empty, no point looping again */
        }
    }
}
