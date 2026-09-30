/**
 * @file    qrng_protocol.c
 * @brief   App-layer command_protocol.h adapter for Middleware/QRNG (CMD_TYPE_QRNG).
 *
 * Lives under Core_app/App, not Core_app/Middleware/QRNG -- it depends on
 * both command_protocol.h and qrng_service.h, and App is the only layer
 * in this project allowed to depend on more than one Middleware module
 * at once (every Middleware module otherwise only depends on the
 * Drivers/Platform below it, never a sibling Middleware). Putting this
 * file inside Middleware/QRNG would have made that module depend on
 * Middleware/CommandProtocol, which is exactly the coupling this
 * placement avoids. Registered from Core_app/App/app_main.c via an
 * `extern` (see that file), not declared in any shared header, since
 * only app_main.c needs to know these functions exist.
 *
 * Sub-command set below is this project's own numbering (not a byte-for-
 * byte clone of D:\Workspace\vQRNG1.0's USB command table) that covers
 * the same functionality qrng_service.h exposes, one sub-command per
 * capability.
 *
 * Continuous stream (STREAM_NOISE_START/STREAM_ENTROPY_START/STREAM_STOP)
 * is implemented non-blocking, unlike upstream vQRNG1.0's
 * vQRNG_get_noise_handler()/get_entropy_handler() (a blocking `while`
 * loop that pumps CDC_Transmit() directly): command_protocol.c's
 * command_protocol_poll() must never block (see its own doc comment), so
 * a START command here only arms `s_streaming` and replies with a plain
 * ack; qrng_protocol_poll() (called from Core_app/App/app_main.c's main
 * loop right after command_protocol_poll(), per command_protocol_send()'s
 * doc comment) pushes one CMD_TYPE_RESULT frame per main-loop iteration
 * for as long as streaming stays armed. This matches upstream's own
 * auto-stop-on-health-test-failure behavior, just spread across many
 * non-blocking calls instead of one blocking loop.
 */
#include "command_protocol.h"
#include "qrng_service.h"
#include "platform.h"

#include <string.h>

typedef enum {
    QRNG_CMD_GET_NOISE                 = 0x01, /* -> response: [sub_cmd][status][QRNG_NOISE_BYTES bytes] */
    QRNG_CMD_GET_ENTROPY                = 0x02, /* -> response: [sub_cmd][status][QRNG_ENTROPY_BYTES bytes] */
    QRNG_CMD_IS_HEALTHY                 = 0x03, /* -> response: [sub_cmd][is_healthy: 0/1] */
    QRNG_CMD_SET_HEALTH_TEST            = 0x04, /* payload[1]: 0=disable,1=enable -> response: [sub_cmd][status] */
    QRNG_CMD_STREAM_NOISE_START         = 0x05, /* -> response: [sub_cmd][status] (ack); frames pushed via qrng_protocol_poll() tagged QRNG_CMD_GET_NOISE */
    QRNG_CMD_STREAM_ENTROPY_START       = 0x06, /* -> response: [sub_cmd][status] (ack); frames pushed via qrng_protocol_poll() tagged QRNG_CMD_GET_ENTROPY */
    QRNG_CMD_STREAM_STOP                = 0x07, /* -> response: [sub_cmd][status] -- always succeeds, even if no stream was active */
    QRNG_CMD_GET_STARTUP_HEALTH_RECORD  = 0x08, /* -> response: [sub_cmd][status][QRNG_STARTUP_HEALTH_RECORD_BYTES bytes] */
    QRNG_CMD_SET_AUTO_RESEED            = 0x09, /* payload[1]: 0=disable,1=enable -> response: [sub_cmd][status] */
    QRNG_CMD_REGEN_KEY                  = 0x0A, /* -> response: [sub_cmd][status] */
    QRNG_CMD_SET_EXTRACTOR              = 0x0B, /* payload[1]: qrng_extractor_t value -> response: [sub_cmd][status].
                                                  * SCOPE: governs qrng_service_get_entropy()/this file's own
                                                  * GET_ENTROPY/STREAM_ENTROPY_START -- i.e. every draw a USB client
                                                  * asks for directly. Does NOT affect the AES-256-GCM nonce pool
                                                  * Core_app/App/protocol_adapters/media_protocol.c uses for an
                                                  * active video-call session: that pool always draws via
                                                  * qrng_service_get_entropy_with(QRNG_EXTRACTOR_TOEPLITZ, ...)
                                                  * regardless of this setting, on purpose (Toeplitz is pure math,
                                                  * so it never contends with the SAME physical CRYP peripheral
                                                  * media_protocol.c's own AES-256-GCM encrypt/decrypt calls use --
                                                  * letting a media session's nonces follow this setting caused a
                                                  * real, reproducible HELLO-timeout/CRYP-contention bug on
                                                  * hardware when set to AES). Deliberate design decision, not an
                                                  * oversight -- see qrng_service_get_entropy_with()'s doc comment
                                                  * in qrng_service.h and CLAUDE.md's "2026-09-19 continuation"
                                                  * section for the full reasoning. */
    /* 0x0C..0x10 are diagnostic sub-commands: handled only when built with EVT2_DIAGNOSTICS=1 (see
     * Core/Src/main.c); a product build answers them like any unknown sub-command. */
    QRNG_CMD_BENCH_NOISE                = 0x0C, /* payload[1..2]: duration_ms (u16 LE) -> response: [sub_cmd][status][draws:u32][ok_draws:u32][elapsed_ms:u32][wait_us_avg:u32][process_us_avg:u32][timing_draw_count:u32][health_us_avg:u32][extractor_or_copy_us_avg:u32] -- the last 2 break process_us_avg down into its 2 stages (see qrng_service_debug_get_stage_timing()'s doc comment) */
    QRNG_CMD_BENCH_ENTROPY              = 0x0D, /* same shape as BENCH_NOISE, but draws qrng_service_get_entropy() under whichever extractor is currently selected */
    QRNG_CMD_STREAM_DEBUG_TIMING        = 0x0E, /* -> response: [sub_cmd][status][draw_us_avg:u32][send_us_avg:u32][push_count:u32] -- per-push breakdown of qrng_protocol_poll()'s two stages (see its doc comment); averages reset to 0 after each read, same convention as qrng_service_debug_get_timing() */
    QRNG_CMD_ECHO                       = 0x0F, /* payload[1..]: arbitrary bytes -> response: [sub_cmd][status][payload[1..] echoed back unchanged] -- pure transport-layer loopback, no QRNG involved; exists to test command_protocol.c's large-payload path (CMD_PROTO_MAX_PAYLOAD) end-to-end without any handler's own data-size limits (e.g. the SE05x secure element's one-shot APDU size cap) getting in the way */
    QRNG_CMD_NONCE_POOL_STATUS          = 0x10, /* -> response: [sub_cmd][status][pool_count:u8][pool_capacity:u8][rng_in_pool:u8][last_qrng_draw_ok:u8][qrng_draw_ok:u32][qrng_draw_fail:u32][nonces_from_qrng:u32][nonces_from_rng:u32] -- read-only debug snapshot of media_protocol.c's AES-GCM nonce pool (never any nonce bytes); counters are cumulative since boot, u32 LE */
    QRNG_CMD_RAW_CAPTURE                = 0x13, /* -> response: [sub_cmd][status][count:u16][count x u16 raw ADC samples] (LE) -- 1024 consecutive samples, NO health test; payload[1] (optional) bit 0 = do not power the front end, bit 1 = packed 12-bit stream (MSB first, 2 samples in 3 bytes, 1536 bytes); starts the analog front end + ADC if the service is not running (qrng_service_raw_capture()). Analog bring-up only. */
    QRNG_CMD_ANALOG_CTRL                = 0x15, /* payload[1]: element (qrng_analog_elem_t: 0 PS_FIRST, 1 PS_SECOND, 2 LED_EN, 3 AD5398 at BOARD_QRNG_DRIVE_CURRENT_UA; 0xFF or absent = read only, 0xFE = release: stop the QRNG service (qrng_service_deinit(), front end off) so manual control is allowed -- until the next reset the random-number users fall back to the TRNG; 0xFD = AD5398 current setpoint, payload[2..5] = uA u32 LE, max 30 mA, applied at once if on), payload[2]: 0 off / 1 on -> response: [sub_cmd][status][state bits, bit n = element n on, bit 7 = the QRNG service runs and owns the front end][ad5398_ua:u32 LE, programmed code][setpoint_ua:u32 LE] -- manual analog front-end control for bring-up; QRNG_ERROR while the QRNG service runs. */
    QRNG_CMD_RAW_STOP                   = 0x14, /* -> response: [sub_cmd][status] -- stops what RAW_CAPTURE started */
    QRNG_CMD_ADC_RATE                   = 0x12, /* payload[1..2]: window_ms (u16 LE, 1..1000, default 200) -> response: [sub_cmd][status][boot_sps:u32][live_sps:u32][init diag: qrng_init_diag_t fields in order, 32 B] (LE) -- ADC sample rate of the noise source, measured on the chip from the DMA position (qrng_service_measure_adc_rate()). Built in every image. */
    QRNG_CMD_DEVICE_STATUS              = 0x11, /* -> response: [sub_cmd][status][temp_c:i32][temp_max_c:i32][sleep_permille:u32][wfi_per_s:u32][uptime_ms:u32][boot_count:u32][reset_rsr:u32] (LE; the last 3 added later, readers of the first 18 bytes still work) -- die temperature (DTS, deg C; INT32_MIN = no reading) and main-loop sleep share, refreshed once a second by Core_app/App/app_power.c. Not a QRNG function: it lives here with the other device diagnostics (0x10). Built in every image (read-only counters, no secrets). */
} qrng_cmd_t;

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* Defined in media_protocol.c, deliberately not in a shared header (same
 * convention as media_protocol_get_nonce_stats() there). */
extern void media_protocol_get_nonce_pool_status(uint32_t *count, uint32_t *capacity, uint32_t *rng_in_pool,
                                                 uint32_t *qrng_draw_ok, uint32_t *qrng_draw_fail, bool *last_draw_ok);
extern void media_protocol_get_nonce_stats(uint32_t *from_qrng, uint32_t *from_rng);
#endif /* EVT2_DIAGNOSTICS */

#include "app_power.h"
#include "app_trace.h"

static bool s_streaming;
static bool s_stream_is_entropy;
static uint16_t s_stream_session;
static uint32_t s_stream_seq;

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* qrng_protocol_poll() debug timing -- see QRNG_CMD_STREAM_DEBUG_TIMING's
 * doc comment above. Cycle counts accumulate here and are converted/reset
 * only when read, same pattern as
 * Core_app/Middleware/QRNG/ADC_Noise/qrng_service_adc_noise.c's own
 * qrng_service_debug_get_timing()/get_stage_timing(). */
static uint64_t s_dbg_draw_cycles;
static uint64_t s_dbg_send_cycles;
static uint32_t s_dbg_push_count;
#endif /* EVT2_DIAGNOSTICS */

bool qrng_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response, uint16_t *response_len,
                            uint16_t max_response_len)
{
    uint8_t sub_cmd = payload[0];
    response[0] = sub_cmd;

    switch (sub_cmd) {
        case QRNG_CMD_GET_NOISE: {
            if (max_response_len < 2U + QRNG_NOISE_BYTES) {
                return false;
            }
            qrng_status_t st = qrng_service_get_noise(&response[2], QRNG_NOISE_BYTES);
            response[1] = (uint8_t)st;
            *response_len = (uint16_t)(2U + ((st == QRNG_OK) ? QRNG_NOISE_BYTES : 0U));
            return true;
        }
        case QRNG_CMD_GET_ENTROPY: {
            if (max_response_len < 2U + QRNG_ENTROPY_BYTES) {
                return false;
            }
            qrng_status_t st = qrng_service_get_entropy(&response[2], QRNG_ENTROPY_BYTES);
            response[1] = (uint8_t)st;
            *response_len = (uint16_t)(2U + ((st == QRNG_OK) ? QRNG_ENTROPY_BYTES : 0U));
            return true;
        }
        case QRNG_CMD_IS_HEALTHY: {
            response[1] = qrng_service_is_healthy() ? 1U : 0U;
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_SET_HEALTH_TEST: {
            if (payload_len < 2U) {
                return false;
            }
            qrng_status_t st = qrng_service_set_health_test(payload[1] != 0U);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_STREAM_NOISE_START:
        case QRNG_CMD_STREAM_ENTROPY_START: {
            /* Starting a new stream simply retargets s_streaming -- any
             * previous stream (from this or another session) stops
             * receiving pushes immediately, no explicit hand-off needed
             * since only one host talks to this device at a time. */
            s_stream_is_entropy = (sub_cmd == QRNG_CMD_STREAM_ENTROPY_START);
            s_stream_session = command_protocol_current_session_id();
            s_stream_seq = 0U;
            s_streaming = true;
            response[1] = (uint8_t)QRNG_OK;
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_STREAM_STOP: {
            s_streaming = false;
            response[1] = (uint8_t)QRNG_OK;
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_GET_STARTUP_HEALTH_RECORD: {
            if (max_response_len < 2U + QRNG_STARTUP_HEALTH_RECORD_BYTES) {
                return false;
            }
            qrng_status_t st = qrng_service_get_startup_health_record(&response[2], QRNG_STARTUP_HEALTH_RECORD_BYTES);
            response[1] = (uint8_t)st;
            *response_len = (uint16_t)(2U + ((st == QRNG_OK) ? QRNG_STARTUP_HEALTH_RECORD_BYTES : 0U));
            return true;
        }
        case QRNG_CMD_SET_AUTO_RESEED: {
            if (payload_len < 2U) {
                return false;
            }
            qrng_status_t st = qrng_service_set_auto_reseed(payload[1] != 0U);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_REGEN_KEY: {
            qrng_status_t st = qrng_service_reseed_extractor();
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_SET_EXTRACTOR: {
            if (payload_len < 2U) {
                return false;
            }
            qrng_status_t st = qrng_service_set_extractor((qrng_extractor_t)payload[1]);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_RAW_CAPTURE: {
            const uint16_t n = (uint16_t)QRNG_RAW_CAPTURE_SAMPLES;
            if (max_response_len < 4U + 2U * n) {
                return false;
            }
            static uint16_t s_raw[QRNG_RAW_CAPTURE_SAMPLES];
            /* payload[1] (optional) bit 0 = 1: start the ADC without powering the analog front end (manual control
             * with QRNG_CMD_ANALOG_CTRL). Absent or 0: power it with the normal sequence, as before. */
            const bool power_analog = !(payload_len >= 2U && (payload[1] & 0x01U) != 0U);
            /* payload[1] bit 1 = 1: send the 12-bit samples packed as one MSB-first bit stream (sample A's 12 bits,
             * then B's 12 bits, ...): 2 samples in 3 bytes, the first 16 bits = A[11:0] + B[11:8]. 1536 bytes per
             * block instead of 2048, i.e. 33 % more samples through the USB Full Speed bottleneck. */
            const bool packed12 = (payload_len >= 2U && (payload[1] & 0x02U) != 0U);
            const qrng_status_t st = qrng_service_raw_capture(s_raw, n, power_analog);
            response[1] = (uint8_t)st;
            const uint16_t count = (st == QRNG_OK) ? n : 0U;
            response[2] = (uint8_t)count;
            response[3] = (uint8_t)(count >> 8);
            if (packed12) {
                uint8_t *o = &response[4];
                for (uint32_t i = 0; i + 1U < count; i += 2U) { /* count is even (1024) */
                    const uint16_t a = s_raw[i] & 0x0FFFU;
                    const uint16_t b = s_raw[i + 1U] & 0x0FFFU;
                    *o++ = (uint8_t)(a >> 4);
                    *o++ = (uint8_t)(((a & 0x0FU) << 4) | (b >> 8));
                    *o++ = (uint8_t)b;
                }
                *response_len = (uint16_t)(4U + (3U * count) / 2U);
            }
            else {
                for (uint32_t i = 0; i < count; i++) {
                    response[4U + 2U * i] = (uint8_t)s_raw[i];
                    response[5U + 2U * i] = (uint8_t)(s_raw[i] >> 8);
                }
                *response_len = (uint16_t)(4U + 2U * count);
            }
            return true;
        }
        case QRNG_CMD_RAW_STOP: {
            response[1] = (uint8_t)qrng_service_raw_stop();
            *response_len = 2U;
            return true;
        }
        case QRNG_CMD_ANALOG_CTRL: {
            if (max_response_len < 11U) {
                return false;
            }
            qrng_status_t st = QRNG_OK;
            if (payload_len >= 2U && payload[1] == 0xFEU) {
                st = qrng_service_deinit(); /* release: stop the QRNG service, front end off, manual control allowed */
            }
            else if (payload_len >= 2U && payload[1] == 0xFDU) {
                /* AD5398 current setpoint: payload[2..5] = uA (u32 LE), 0..QRNG_ANALOG_AD5398_MAX_UA (30 mA) */
                if (payload_len >= 6U) {
                    const uint32_t set_ua = (uint32_t)payload[2] | ((uint32_t)payload[3] << 8) |
                                            ((uint32_t)payload[4] << 16) | ((uint32_t)payload[5] << 24);
                    st = qrng_service_analog_set_ad5398_ua(set_ua);
                }
                else {
                    st = QRNG_INVALID_PARAM;
                }
            }
            else if (payload_len >= 3U && payload[1] != 0xFFU) {
                st = (payload[1] < (uint8_t)QRNG_ANALOG_COUNT)
                    ? qrng_service_analog_set((qrng_analog_elem_t)payload[1], payload[2] != 0U)
                    : QRNG_INVALID_PARAM;
            }
            uint32_t ua = 0U;
            response[1] = (uint8_t)st;
            response[2] = (uint8_t)(qrng_service_analog_state(&ua) | (qrng_service_is_ready() ? 0x80U : 0x00U));
            const uint32_t setpoint = qrng_service_analog_get_ad5398_setpoint_ua();
            for (uint32_t i = 0; i < 4U; i++) {
                response[3U + i] = (uint8_t)(ua >> (8U * i));
                response[7U + i] = (uint8_t)(setpoint >> (8U * i));
            }
            *response_len = 11U;
            return true;
        }
        case QRNG_CMD_ADC_RATE: {
            if (max_response_len < 42U) {
                return false;
            }
            uint32_t window_ms = 200U;
            if (payload_len >= 3U) {
                window_ms = (uint32_t)payload[1] | ((uint32_t)payload[2] << 8);
            }
            uint32_t boot_sps = 0U;
            uint32_t live_sps = 0U;
            const qrng_status_t st = qrng_service_measure_adc_rate(window_ms, &boot_sps, &live_sps);
            response[1] = (uint8_t)st;
            for (uint32_t i = 0; i < 4U; i++) {
                response[2U + i] = (uint8_t)(boot_sps >> (8U * i));
                response[6U + i] = (uint8_t)(live_sps >> (8U * i));
            }
            qrng_init_diag_t d;
            qrng_service_get_init_diag(&d);
            uint8_t *r = &response[10];
            r[0] = d.init_status;
            r[1] = d.step;
            r[2] = d.health_status;
            r[3] = d.attempts;
            for (uint32_t i = 0; i < 4U; i++) {
                r[4U + i] = (uint8_t)(d.healthy_samples >> (8U * i));
                r[8U + i] = (uint8_t)(d.ad5398_ua >> (8U * i));
            }
            r[12] = (uint8_t)d.min;
            r[13] = (uint8_t)(d.min >> 8);
            r[14] = (uint8_t)d.max;
            r[15] = (uint8_t)(d.max >> 8);
            for (uint32_t i = 0; i < 8U; i++) {
                r[16U + 2U * i] = (uint8_t)d.samples[i];
                r[17U + 2U * i] = (uint8_t)(d.samples[i] >> 8);
            }
            *response_len = 42U;
            return true;
        }
        case QRNG_CMD_DEVICE_STATUS: {
            if (max_response_len < 30U) {
                return false;
            }
            int32_t temp, temp_max;
            uint32_t permille, count;
            app_power_get_status(&temp, &temp_max, &permille, &count);
#if EVT2_TRACE
            const uint32_t boots = g_app_trace.boot_count;
            const uint32_t rsr = g_app_trace.rsr;
#else
            const uint32_t boots = 0U;
            const uint32_t rsr = 0U;
#endif
            const uint32_t v[7] = { (uint32_t)temp, (uint32_t)temp_max, permille, count,
                                    platform_get_tick_ms(), boots, rsr };
            response[1] = (uint8_t)QRNG_OK;
            for (uint32_t i = 0; i < 7U; i++) {
                response[2U + 4U * i] = (uint8_t)v[i];
                response[3U + 4U * i] = (uint8_t)(v[i] >> 8);
                response[4U + 4U * i] = (uint8_t)(v[i] >> 16);
                response[5U + 4U * i] = (uint8_t)(v[i] >> 24);
            }
            *response_len = 30U;
            return true;
        }
#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
        case QRNG_CMD_BENCH_NOISE:
        case QRNG_CMD_BENCH_ENTROPY: {
            /* Blocking on purpose: draws back-to-back for the whole
             * window with NO per-draw USB send, so the result measures
             * qrng_service_get_noise()/get_entropy()'s own draw rate
             * (ADC/DMA pace, plus the extractor for BENCH_ENTROPY) with
             * zero USB/framing overhead mixed in -- unlike watching a
             * live STREAM_*_START, which also includes this device's own
             * per-frame USB transmit time. command_protocol_poll() is not
             * called again until this returns, so the host's RX just
             * buffers (up to platform_usb's ring size) until the single
             * summary response comes back -- fine, the host isn't meant
             * to send anything else while this runs. */
            if (payload_len < 3U) {
                return false;
            }
            if (max_response_len < 34U) {
                return false;
            }
            uint16_t duration_ms = (uint16_t)(payload[1] | ((uint16_t)payload[2] << 8));
            static uint8_t bench_buf[QRNG_NOISE_BYTES]; /* QRNG_NOISE_BYTES > QRNG_ENTROPY_BYTES, sized for the larger */

            /* Drain both debug timing accumulators first so this bench's
             * own window isn't polluted by draws from anything that ran
             * before it (e.g. a prior BENCH_* call, or
             * app_qrng_protocol_self_test()'s own stream ticks). */
            uint32_t discard_a, discard_b, discard_c;
            qrng_service_debug_get_timing(&discard_a, &discard_b, &discard_c);
            qrng_service_debug_get_stage_timing(&discard_a, &discard_b, &discard_c);

            uint32_t draws = 0U;
            uint32_t ok_draws = 0U;
            uint32_t start = platform_get_tick_ms();
            while ((platform_get_tick_ms() - start) < duration_ms) {
                qrng_status_t st = (sub_cmd == QRNG_CMD_BENCH_NOISE)
                    ? qrng_service_get_noise(bench_buf, QRNG_NOISE_BYTES)
                    : qrng_service_get_entropy(bench_buf, QRNG_ENTROPY_BYTES);
                draws++;
                if (st == QRNG_OK) {
                    ok_draws++;
                }
            }
            uint32_t elapsed_ms = platform_get_tick_ms() - start;

            uint32_t wait_us_avg, process_us_avg, timing_draw_count;
            qrng_service_debug_get_timing(&wait_us_avg, &process_us_avg, &timing_draw_count);
            uint32_t health_us_avg, extractor_or_copy_us_avg, stage_draw_count;
            qrng_service_debug_get_stage_timing(&health_us_avg, &extractor_or_copy_us_avg, &stage_draw_count);

            response[1] = (uint8_t)QRNG_OK;
            memcpy(&response[2], &draws, sizeof(draws));
            memcpy(&response[6], &ok_draws, sizeof(ok_draws));
            memcpy(&response[10], &elapsed_ms, sizeof(elapsed_ms));
            memcpy(&response[14], &wait_us_avg, sizeof(wait_us_avg));
            memcpy(&response[18], &process_us_avg, sizeof(process_us_avg));
            memcpy(&response[22], &timing_draw_count, sizeof(timing_draw_count));
            memcpy(&response[26], &health_us_avg, sizeof(health_us_avg));
            memcpy(&response[30], &extractor_or_copy_us_avg, sizeof(extractor_or_copy_us_avg));
            *response_len = 34U;
            return true;
        }
        case QRNG_CMD_STREAM_DEBUG_TIMING: {
            if (max_response_len < 26U) {
                return false;
            }
            uint32_t count = s_dbg_push_count;
            uint32_t cpu_hz = platform_get_cpu_hz();
            uint32_t draw_us_avg = (count && cpu_hz) ? (uint32_t)((s_dbg_draw_cycles / count) * 1000000ULL / cpu_hz) : 0U;
            uint32_t send_us_avg = (count && cpu_hz) ? (uint32_t)((s_dbg_send_cycles / count) * 1000000ULL / cpu_hz) : 0U;
            s_dbg_draw_cycles = 0U;
            s_dbg_send_cycles = 0U;
            s_dbg_push_count = 0U;

            /* Further breaks send_us_avg down into command_protocol.c's
             * own two sub-stages -- see
             * command_protocol_debug_get_send_timing()'s doc comment. */
            uint32_t wait_us_avg, build_tx_us_avg, send_count;
            command_protocol_debug_get_send_timing(&wait_us_avg, &build_tx_us_avg, &send_count);

            response[1] = (uint8_t)QRNG_OK;
            memcpy(&response[2], &draw_us_avg, sizeof(draw_us_avg));
            memcpy(&response[6], &send_us_avg, sizeof(send_us_avg));
            memcpy(&response[10], &count, sizeof(count));
            memcpy(&response[14], &wait_us_avg, sizeof(wait_us_avg));
            memcpy(&response[18], &build_tx_us_avg, sizeof(build_tx_us_avg));
            memcpy(&response[22], &send_count, sizeof(send_count));
            *response_len = 26U;
            return true;
        }
        case QRNG_CMD_ECHO: {
            uint16_t echo_len = (uint16_t)(payload_len - 1U); /* payload_len >= 1 guaranteed by command_protocol.c's dispatch */
            if (max_response_len < (uint16_t)(2U + echo_len)) {
                return false;
            }
            response[1] = (uint8_t)QRNG_OK;
            if (echo_len > 0U) {
                memcpy(&response[2], &payload[1], echo_len);
            }
            *response_len = (uint16_t)(2U + echo_len);
            return true;
        }
        case QRNG_CMD_NONCE_POOL_STATUS: {
            if (max_response_len < 22U) {
                return false;
            }
            uint32_t count, capacity, rng_in_pool, draw_ok, draw_fail, from_qrng, from_rng;
            bool last_ok;
            media_protocol_get_nonce_pool_status(&count, &capacity, &rng_in_pool, &draw_ok, &draw_fail, &last_ok);
            media_protocol_get_nonce_stats(&from_qrng, &from_rng);
            response[1] = (uint8_t)QRNG_OK;
            response[2] = (uint8_t)count;
            response[3] = (uint8_t)capacity;
            response[4] = (uint8_t)rng_in_pool;
            response[5] = last_ok ? 1U : 0U;
            memcpy(&response[6], &draw_ok, sizeof(draw_ok));
            memcpy(&response[10], &draw_fail, sizeof(draw_fail));
            memcpy(&response[14], &from_qrng, sizeof(from_qrng));
            memcpy(&response[18], &from_rng, sizeof(from_rng));
            *response_len = 22U;
            return true;
        }
#endif /* EVT2_DIAGNOSTICS */
        default:
            return false;
    }
}

/** True while a stream is armed: qrng_protocol_poll() then has a frame to push on every main-loop pass, so the loop
 *  must not sleep (Core_app/App/app_power.c's idle check, extern there -- same convention as the poll below). */
bool qrng_protocol_is_streaming(void)
{
    return s_streaming;
}

/** Called from Core_app/App/app_main.c's main loop, right after
 *  command_protocol_poll() -- see this file's doc comment and
 *  command_protocol_send()'s. No-op unless a STREAM_*_START command
 *  armed `s_streaming`. */
void qrng_protocol_poll(void)
{
    if (!s_streaming) {
        return;
    }

    static uint8_t frame[2U + QRNG_NOISE_BYTES]; /* QRNG_NOISE_BYTES > QRNG_ENTROPY_BYTES, sized for the larger */
    qrng_status_t st;
    uint16_t data_len;

#if EVT2_DIAGNOSTICS
    uint32_t t0 = platform_get_cycle_count();
#endif

    if (s_stream_is_entropy) {
        frame[0] = QRNG_CMD_GET_ENTROPY;
        st = qrng_service_get_entropy(&frame[2], QRNG_ENTROPY_BYTES);
        data_len = (st == QRNG_OK) ? QRNG_ENTROPY_BYTES : 0U;
    }
    else {
        frame[0] = QRNG_CMD_GET_NOISE;
        st = qrng_service_get_noise(&frame[2], QRNG_NOISE_BYTES);
        data_len = (st == QRNG_OK) ? QRNG_NOISE_BYTES : 0U;
    }
    frame[1] = (uint8_t)st;

#if EVT2_DIAGNOSTICS
    uint32_t t1 = platform_get_cycle_count();
#endif

    (void)command_protocol_send(CMD_TYPE_RESULT, s_stream_session, s_stream_seq++, frame, (uint16_t)(2U + data_len));

#if EVT2_DIAGNOSTICS
    uint32_t t2 = platform_get_cycle_count();

    /* Wraparound-safe on a 32-bit cycle counter (unsigned subtraction),
     * only matters across DWT->CYCCNT's own ~26.8s wrap period at 160MHz
     * -- fine for a per-push delta this small. */
    s_dbg_draw_cycles += (uint64_t)(t1 - t0);
    s_dbg_send_cycles += (uint64_t)(t2 - t1);
    s_dbg_push_count++;
#endif

    if (st != QRNG_OK) {
        /* Mirrors upstream vQRNG1.0's auto-stop-on-health-test-failure
         * (qrng_if.c's vQRNG_get_noise_handler()/get_entropy_handler()),
         * widened to any non-OK draw here (not just QRNG_HEALTH_FAIL) so
         * a stuck TIMEOUT/ERROR condition can't turn into an unbounded
         * stream of failure-only frames -- the frame just sent already
         * carries the status byte so the host knows why it stopped. */
        s_streaming = false;
    }
}
