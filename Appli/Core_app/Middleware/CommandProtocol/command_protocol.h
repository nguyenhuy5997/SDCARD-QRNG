/**
 * @file    command_protocol.h
 * @brief   Framed request/response command dispatcher over platform_usb.h.
 *
 * Wire format deliberately mirrors C:\Users\SingPC\usb_encrypt_host's
 * PROTOCOL.md (a separate, already hardware-verified project's protocol,
 * running on D:\Workspace\STM32\STM32H743_DEV -- not shared code, but a
 * proven design reused here rather than invented fresh):
 *
 *   FLAG(1B=0x7E) | escaped( HEADER(10B) + PAYLOAD(0..MAX_PAYLOAD) + CRC32(4B) ) | FLAG(1B=0x7E)
 *
 * HEADER (little-endian, before escaping): VER(1) TYPE(1) SESSION_ID(2) SEQ(4) LENGTH(2)
 * Escaping: any literal 0x7E/0x7D byte inside HEADER+PAYLOAD+CRC becomes
 * 0x7D followed by (byte XOR 0x20) -- so FLAG never appears mid-frame.
 * CRC32 (zlib/CRC-32 poly 0xEDB88320, reflected) covers HEADER+PAYLOAD
 * pre-escape. A CRC mismatch drops the frame silently and resyncs at the
 * next FLAG -- no NACK, since SESSION_ID/SEQ in a corrupted frame can't
 * be trusted enough to address one.
 *
 * PACKET TYPEs 0x01-0x10 are reserved to match PROTOCOL.md's own table
 * (HELLO/HELLO_ACK/START_STREAM/DATA_CHUNK/.../ENCRYPTED_CHUNK/
 * DEBUG_TIMING*) for when a throughput-oriented media channel (video
 * call streaming) is added later -- not implemented yet, reserved so
 * that addition doesn't renumber anything below. Only HELLO/HELLO_ACK
 * (handshake) are implemented so far, plus the EVT2-specific range
 * 0x11+ below for Security/Biometric/QRNG command dispatch (not part of
 * PROTOCOL.md, since that protocol has no equivalent).
 */
#ifndef COMMAND_PROTOCOL_H
#define COMMAND_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    CMD_PROTO_OK = 0,
    CMD_PROTO_ERROR,
    CMD_PROTO_INVALID_PARAM,
    CMD_PROTO_NOT_READY,
} cmd_protocol_status_t;

/* ---- Packet types -- 0x01-0x10 reserved to match PROTOCOL.md, see file doc comment ----
 *
 * 0x03-0x0E copy usb_encrypt_host/PROTOCOL.md's own table verbatim (same
 * values, same payload layouts) -- deliberate, so the wire format this
 * device speaks for video-call media is the already cross-verified one,
 * not a fresh invention. 0x0F/0x10 are new: that reference project is
 * encrypt-only (its own PROTOCOL.md section 8: "only encryption happens
 * on the device... there is no DECRYPT_CHUNK-style packet type in this
 * protocol", decryption is done in software on the Android side instead).
 * EVT2's video-call flow is explicitly two-directional on the SAME
 * device -- encrypt this device's outgoing stream AND decrypt the peer's
 * incoming stream, both using the STM32 HW accelerator -- so this
 * extends the reserved range (0x0F/0x10 were the two unused values left
 * in it) with a DECRYPT_CHUNK/DECRYPTED_CHUNK pair, symmetric to
 * DATA_CHUNK/ENCRYPTED_CHUNK's LIVE_AUDIO shape (stop-and-wait,
 * caller-assigned SEQ echoed back, fresh per-chunk nonce -- here supplied
 * by the caller instead of generated, since the ciphertext to decrypt
 * already carries the sender's own nonce/tag). */
typedef enum {
    CMD_TYPE_HELLO             = 0x01, /* host->device: [proto_ver: 1B] */
    CMD_TYPE_HELLO_ACK         = 0x02, /* device->host: [proto_ver: 1B] */

    /* ---- 0x03-0x10: media/stream channel, dispatched as a whole to the
     * single handler registered via command_protocol_register_media() --
     * see that function's doc comment for why this range doesn't use
     * command_protocol_register()'s per-TYPE sub_cmd-dispatch shape. */
    CMD_TYPE_START_STREAM      = 0x03, /* host->device: [total_len:4B LE][source_name:32B][mode:1B optional] */
    CMD_TYPE_DATA_CHUNK        = 0x04, /* host->device: raw bytes, 0..CMD_PROTO_MAX_PAYLOAD */
    CMD_TYPE_END_STREAM        = 0x05, /* host->device: [total_bytes_sent:4B LE][sha256_of_stream:32B] (BATCH only) */
    CMD_TYPE_MEDIA_ACK         = 0x06, /* either: [acked_seq:4B LE] */
    CMD_TYPE_MEDIA_NACK        = 0x07, /* either: [seq:4B LE][reason:1B] */
    CMD_TYPE_ABORT_STREAM      = 0x08, /* host->device: empty; SESSION_ID identifies which stream */
    CMD_TYPE_MEDIA_PING        = 0x09, /* either: empty */
    CMD_TYPE_MEDIA_PONG        = 0x0A, /* either: empty */
    CMD_TYPE_ENCRYPT_RESULT    = 0x0B, /* device->host: [nonce:12B][tag:16B][ciphertext:rest] (BATCH only) */
    CMD_TYPE_MEDIA_ERROR       = 0x0C, /* either: [error_code:1B][message:UTF-8 optional] */
    CMD_TYPE_MEDIA_RESET       = 0x0D, /* either: empty -- hard-resets media session state */
    CMD_TYPE_ENCRYPTED_CHUNK   = 0x0E, /* device->host: [acked_seq:4B LE][nonce:12B][tag:16B][ciphertext:same len as DATA_CHUNK] */
    /* host->device, no redundant seq field (like DATA_CHUNK, uses the
     * frame header's own SEQ) -- EVT2 extension, see block comment above. */
    CMD_TYPE_DECRYPT_CHUNK     = 0x0F, /* host->device: [nonce:12B][tag:16B][ciphertext:rest] */
    CMD_TYPE_DECRYPTED_CHUNK   = 0x10, /* device->host: [acked_seq:4B LE][status:1B][plaintext:rest, only if status==OK] -- EVT2 extension */

    CMD_TYPE_SECURITY          = 0x11, /* host->device: [sub_cmd: 1B][params...] */
    CMD_TYPE_BIOMETRIC         = 0x12, /* host->device: [sub_cmd: 1B][params...] */
    CMD_TYPE_QRNG              = 0x13, /* host->device: [sub_cmd: 1B][params...] */
    CMD_TYPE_RESULT            = 0x14, /* device->host: [sub_cmd: 1B][status: 1B][data...] */
    CMD_TYPE_CA                = 0x15, /* host->device: [sub_cmd: 1B][params...] -- CA-based key-exchange handshake,
                                         * see Core_app/App/protocol_adapters/ca_protocol.c and
                                         * docs/key_exchange_ca_profile.md section 6. Replies come back as
                                         * CMD_TYPE_RESULT like _SECURITY/_BIOMETRIC/_QRNG. */
    CMD_TYPE_PROVISION         = 0x16, /* host->device: [sub_cmd: 1B][params...] -- factory provisioning of the CA
                                         * identity, FACTORY IMAGE ONLY (EVT2_FACTORY_PROVISION): see
                                         * Core_app/App/protocol_adapters/provision_protocol.c. Unregistered (answered
                                         * like any unknown type) in the product image. Replies as CMD_TYPE_RESULT. */
} cmd_protocol_type_t;

#define CMD_TYPE_MEDIA_FIRST CMD_TYPE_START_STREAM
#define CMD_TYPE_MEDIA_LAST  CMD_TYPE_DECRYPTED_CHUNK

#define CMD_PROTOCOL_VERSION 1U

/** Largest single payload this transport can carry in either direction --
 *  the real numeric value lives here (not just command_protocol.c) because
 *  media_protocol.c's LIVE_AUDIO handlers must know it precisely: a
 *  DATA_CHUNK's usable size is this ceiling MINUS the 32-byte
 *  ACK/nonce/tag overhead its ENCRYPTED_CHUNK reply adds (see
 *  media_protocol.c's MEDIA_MAX_DATA_CHUNK), not the full value -- an
 *  oversized DATA_CHUNK would otherwise make command_protocol_send()
 *  silently fail to send the reply at all (its own `payload_len >
 *  CMD_PROTO_MAX_PAYLOAD` guard) instead of NACKing cleanly up front. See
 *  command_protocol.c's own definition-site comment for the RAM-budget
 *  math behind the original 32768 value.
 *
 *  Raised 32768 -> 49152 (2026-09-19): a real H.264 keyframe measured up
 *  to ~30010B on real hardware during a real call (CLAUDE.md's
 *  2026-09-19 session) -- right at the old ceiling, leaving almost no
 *  margin. 49152 leaves ~1.6x headroom over that worst-case measurement.
 *  NOT raised to the wire format's true limit (this header's LENGTH
 *  field is uint16_t, so 65535 is the hard ceiling) -- see
 *  platform_usb_stm32lib.c's USB_RX_RING_SIZE doc comment for why
 *  65536 there (a required power-of-2 jump) does not mean this value had
 *  to follow it to the same number: this one has no power-of-2
 *  constraint, and picking a value well under the ring's new capacity
 *  leaves room for post-escaping inflation and whatever's mid-drain in
 *  the ring when a new frame starts arriving, same margin reasoning
 *  tools/device_link.py's own MAX_IN_FLIGHT_BYTES already documents.
 *
 *  RAM check done before picking this value: raising this constant grows
 *  every static buffer sized to it (or to CMD_PROTO_TX_FRAME_MAX, which
 *  is derived from it and scales 2x since it holds the worst-case
 *  ESCAPED frame) -- command_protocol.c's decoder buf[]/body[]/tx[]/
 *  response[], and media_protocol.c's s_reply_buf[]. That FIRST attempt
 *  at 49152 also still had media_protocol.c's now-removed
 *  s_live_cipher_buf[]/s_live_plain_buf[] scratch buffers in the count
 *  and came out to ~164KB needed against ~162KB actually free in
 *  RAM_D1 -- would not have linked. Removing those two (see
 *  media_protocol.c's s_reply_buf doc comment: they were pure
 *  redundant copies, encrypt/decrypt now write directly into
 *  s_reply_buf instead) dropped the real cost to ~128KB, comfortably
 *  inside the ~162KB free -- confirmed this was the right fix instead
 *  of relocating buffers to another RAM bank (RAM_D2/DTCM), since
 *  USB_OTG_HS's DMA is explicitly disabled in this project
 *  (USB_DEVICE/Target's `hpcd_USB_OTG_HS.Init.dma_enable = DISABLE`) --
 *  every one of these buffers is CPU-only regardless of which RAM bank
 *  it lives in, so bank placement was never the real lever here, the
 *  redundant buffers were. Re-run this same accounting (`.bss` size
 *  from a fresh Release build's .map file) before raising this
 *  constant again.
 *
 *  Overridable via a build's own compiler flags (e.g. a leaner target's
 *  .cproject, -DCMD_PROTO_MAX_PAYLOAD=32768) instead of editing this
 *  default -- added while sizing a future STM32H7S3 port, whose AXI-SRAM
 *  (456KB total, no RAM_D1/RAM_D2 split) cannot hold this project's
 *  current H753 RAM_D1+RAM_D2 footprint as-is. Do NOT change the
 *  default here for that: this project's own real-hardware history
 *  right above is why it is 49152, and going back to 32768 (or lower)
 *  reintroduces the exact keyframe-drop problem that raise fixed --
 *  CLAUDE.md's later HEVC-tuning sessions measured real keyframes as
 *  large as 94522B even AFTER this raise (handled today by
 *  VideoCallEngine.kt's adaptBitrateDown() on a drop, not by this
 *  ceiling covering every case). A smaller value only belongs in a
 *  build that has independently decided to accept more frequent
 *  keyframe drops/freezes (or does not carry this project's video
 *  path at all) in exchange for RAM -- see docs/ram usage discussion,
 *  CLAUDE.md's H7S3-porting entries. */
#ifndef CMD_PROTO_MAX_PAYLOAD
#define CMD_PROTO_MAX_PAYLOAD 49152u
#endif

/** A decoded, CRC-valid packet. `payload` aliases the decoder's internal
 *  buffer -- valid only until the next command_protocol_poll() call. */
typedef struct {
    uint8_t        type;
    uint16_t       session_id;
    uint32_t       seq;
    const uint8_t *payload;
    uint16_t       length;
} cmd_protocol_packet_t;

/** Registered per-service handler for CMD_TYPE_SECURITY/_BIOMETRIC/_QRNG.
 *  `payload[0]` is the sub-command id, `payload+1`/`payload_len-1` are
 *  its parameters. On return, if `*response_len` > 0, command_protocol
 *  sends it back wrapped in a CMD_TYPE_RESULT packet (same session_id,
 *  same seq) with `response[0]` == the same sub-command id and
 *  `response[1]` == a service-defined status byte -- handlers must
 *  write both themselves (this function does not prepend them), leaving
 *  `response+2` for the service's own result data.
 *  Returns false if `payload` was malformed (unknown sub_cmd, wrong
 *  length) -- command_protocol then sends a minimal CMD_TYPE_RESULT
 *  with just [sub_cmd][CMD_PROTO_INVALID_PARAM] and no data. */
typedef bool (*cmd_protocol_handler_t)(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                        uint16_t *response_len, uint16_t max_response_len);

/** Registered handler for the WHOLE CMD_TYPE_MEDIA_FIRST..CMD_TYPE_MEDIA_LAST
 *  (0x03-0x10) packet range -- unlike cmd_protocol_handler_t above (one
 *  TYPE, many [sub_cmd]-selected operations under it), this range is many
 *  TYPEs (START_STREAM/DATA_CHUNK/.../DECRYPT_CHUNK) belonging to ONE
 *  service (the video-call media session state machine), so it gets the
 *  whole decoded packet -- including session_id/seq, which that state
 *  machine needs directly to track its single active session and
 *  per-chunk sequence numbers -- and is responsible for calling
 *  command_protocol_send() itself for any reply (ACK/NACK/
 *  ENCRYPTED_CHUNK/DECRYPTED_CHUNK/...), since unlike
 *  cmd_protocol_handler_t not every inbound media packet gets exactly one
 *  reply (e.g. ABORT_STREAM is fire-and-forget, PING gets PONG). `pkt`
 *  aliases the decoder's internal buffer, same lifetime rule as every
 *  other use of cmd_protocol_packet_t: valid only for the duration of
 *  this call. */
typedef void (*cmd_protocol_media_handler_t)(const cmd_protocol_packet_t *pkt);

cmd_protocol_status_t command_protocol_init(void);

/** Register `handler` for `type` (one of CMD_TYPE_SECURITY/_BIOMETRIC/_QRNG/_CA/_PROVISION).
 *  Call once per service during App init, before command_protocol_poll()
 *  ever runs. */
cmd_protocol_status_t command_protocol_register(uint8_t type, cmd_protocol_handler_t handler);

/** Register the single handler for the whole media/stream packet range --
 *  see cmd_protocol_media_handler_t's doc comment for why this is a
 *  separate registration from command_protocol_register() above. At most
 *  one handler; a second call overwrites the first. Call once during App
 *  init, before command_protocol_poll() ever runs, same as
 *  command_protocol_register(). */
cmd_protocol_status_t command_protocol_register_media(cmd_protocol_media_handler_t handler);

/** Drain platform_usb.h's RX buffer, decode any complete frames, dispatch
 *  to the registered handler, and send the response. Call once per
 *  App main-loop iteration -- never blocks. */
void command_protocol_poll(void);

/** Send a packet that isn't a reply to an inbound request -- e.g. a
 *  server-push frame for a continuous stream (CMD_TYPE_QRNG's
 *  STREAM_NOISE/STREAM_ENTROPY). `session_id`/`seq` are caller-managed
 *  (typically: the session_id of the request that started the stream,
 *  and a per-stream counter incremented on each push). Safe to call
 *  from a service's own poll function (e.g. qrng_protocol_poll()),
 *  called after command_protocol_poll() in the same main-loop
 *  iteration. */
cmd_protocol_status_t command_protocol_send(uint8_t type, uint16_t session_id, uint32_t seq, const uint8_t *payload,
                                             uint16_t payload_len);

/** Pointer to this file's own TX staging buffer, positioned right where a payload belongs (CMD_PROTO_MAX_PAYLOAD
 *  bytes of room). A caller assembling a large reply (a CMD_TYPE_RESULT response, a media reply, ...) may build
 *  it directly here instead of keeping a same-sized scratch buffer of its own that would just get memcpy'd into
 *  this same storage by command_protocol_send() anyway -- see command_protocol_send_staged(). Same reuse rule as
 *  command_protocol_send()'s own internal staging: valid to fill and hand to command_protocol_send_staged()
 *  synchronously (this is a single-threaded dispatcher, one frame in flight at a time); do not hold the pointer
 *  across an unrelated command_protocol_send()/_staged() call, which reuses the same storage for its own payload. */
uint8_t *command_protocol_tx_scratch(void);

/** Same wire result as command_protocol_send(type, session_id, seq, command_protocol_tx_scratch(), payload_len),
 *  without the memcpy() command_protocol_send() would otherwise do -- use this when the payload was already
 *  written in place via command_protocol_tx_scratch() (the whole point of that function). `payload_len` must not
 *  exceed CMD_PROTO_MAX_PAYLOAD, same limit command_protocol_send() enforces. */
cmd_protocol_status_t command_protocol_send_staged(uint8_t type, uint16_t session_id, uint32_t seq,
                                                    uint16_t payload_len);

/** Valid only while a cmd_protocol_handler_t callback registered via
 *  command_protocol_register() is executing: the session_id/seq of the
 *  request currently being dispatched (handler_t itself is not passed
 *  these, to keep its signature the same across all three services).
 *  Intended for a handler that starts a server-push stream (e.g.
 *  CMD_TYPE_QRNG's continuous-noise/entropy mode) and needs to tag the
 *  stream's later command_protocol_send() pushes to the session that
 *  requested it. Outside a handler callback, returns 0. */
uint16_t command_protocol_current_session_id(void);
uint32_t command_protocol_current_seq(void);

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/** Debug: per-send_frame() cycle-counter breakdown, averaged since the
 *  last read (resets to 0 on every call, same convention as
 *  Core_app/Middleware/QRNG/ADC_Noise/qrng_service_adc_noise.c's
 *  qrng_service_debug_get_timing()). Separates the two things that could
 *  plausibly dominate a send's cost: `wait_us_avg` is time spent inside
 *  platform_usb_wait_tx_ready() (blocked on the *previous* frame's USB
 *  hardware transfer actually finishing), `build_tx_us_avg` is the
 *  HDLC-escape loop plus the platform_usb_transmit()/CDC_Transmit_HS()
 *  call that only arms the *next* transfer (register writes, does not
 *  itself wait for the hardware to finish). If wait_us_avg dominates,
 *  the bottleneck is genuine USB Full-Speed bus transfer time for this
 *  frame's byte count, not this file's own framing/escaping logic. */
void command_protocol_debug_get_send_timing(uint32_t *wait_us_avg, uint32_t *build_tx_us_avg, uint32_t *count);

/** Debug: average wall time (cycle-counter based, resets to 0 on every
 *  read, same convention as command_protocol_debug_get_send_timing())
 *  from the opening FLAG byte of a host->device frame to the moment its
 *  CRC validates as complete -- i.e. real elapsed time for the WHOLE
 *  receive, spanning as many command_protocol_poll() calls (and
 *  therefore actual USB OUT transactions) as it took. NOT split into
 *  "wire time" vs "waiting for the next poll" the way the send side
 *  splits wait/build -- the receive path is interrupt-driven and
 *  asynchronous to this loop, so firmware alone cannot cleanly tell
 *  those apart (see command_protocol.c's own doc comment on this). */
void command_protocol_debug_get_receive_timing(uint32_t *recv_us_avg, uint32_t *count);
#endif /* EVT2_DIAGNOSTICS */

#ifdef __cplusplus
}
#endif

#endif /* COMMAND_PROTOCOL_H */
