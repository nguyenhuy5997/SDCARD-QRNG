/**
 * @file    app_power.c
 * @brief   Main-loop idle sleep and die-temperature monitoring -- see app_power.h.
 */
#include "app_power.h"

#include <stdbool.h>
#include <stdint.h>

#include "platform.h"
#include "app_trace.h"

/* Defined in Core_app/App/protocol_adapters/qrng_protocol.c (App-layer entry point, no shared header -- same
 * convention as app_main.c's externs). */
extern bool qrng_protocol_is_streaming(void);

#define APP_POWER_REPORT_MS 1000U

static bool s_temp_ok;
static uint32_t s_window_start_ms;
static uint32_t s_sleep_us;
static uint32_t s_sleep_count;
/* last published snapshot (app_power_report()) */
static int32_t s_temp_c = INT32_MIN;
static int32_t s_temp_max_c = INT32_MIN;
static uint32_t s_last_permille;
static uint32_t s_last_count;

/* Runs with interrupts masked (platform_sleep_until_interrupt()): flag and counter reads only.
 * - USB configured: the EVT2 board lost USB enumeration with WFI + D-Cache (platform_time.c), so the loop keeps
 *   spinning until the host has configured the device.
 * - RX ring empty: bytes that arrived since command_protocol_poll() drained it must be handled first. The OUT
 *   endpoint is re-armed in the interrupt (usbd_cdc_if.c), so there is no other deferred USB work.
 * - No QRNG stream: qrng_protocol_poll() pushes a frame on every pass while one is armed. */
static bool app_power_nothing_pending(void)
{
    return platform_usb_is_connected() && platform_usb_bytes_available() == 0U && !qrng_protocol_is_streaming();
}

void app_power_init(void)
{
    s_temp_ok = (platform_temp_init() == PLATFORM_OK);
    s_window_start_ms = platform_get_tick_ms();
}

static void app_power_report(uint32_t window_ms)
{
    uint32_t permille = (window_ms == 0U) ? 0U : (uint32_t)(((uint64_t)s_sleep_us) / window_ms);
    if (permille > 1000U) {
        permille = 1000U;
    }
    int32_t t;
    const bool have_temp = s_temp_ok && platform_temp_read_c(&t) == PLATFORM_OK;
    if (have_temp) {
        s_temp_c = t;
        if (s_temp_max_c == INT32_MIN || t > s_temp_max_c) {
            s_temp_max_c = t;
        }
    }
    s_last_permille = permille;
    s_last_count = s_sleep_count;
#if EVT2_TRACE
    g_app_trace.sleep_permille = permille;
    g_app_trace.sleep_count = s_sleep_count;
    if (have_temp) {
        g_app_trace.temp_c = t;
        if (g_app_trace.temp_max_c == APP_TRACE_TEMP_NONE || t > g_app_trace.temp_max_c) {
            g_app_trace.temp_max_c = t;
        }
    }
#else
    (void)permille;
    (void)have_temp;
    (void)t;
#endif
}

void app_power_get_status(int32_t *temp_c, int32_t *temp_max_c, uint32_t *sleep_permille, uint32_t *sleep_count)
{
    *temp_c = s_temp_c;
    *temp_max_c = s_temp_max_c;
    *sleep_permille = s_last_permille;
    *sleep_count = s_last_count;
}

void app_power_idle(void)
{
    const uint32_t us = platform_sleep_until_interrupt(app_power_nothing_pending);
    if (us != 0U) {
        s_sleep_us += us;
        s_sleep_count++;
    }

    const uint32_t now = platform_get_tick_ms();
    const uint32_t window_ms = now - s_window_start_ms;
    if (window_ms >= APP_POWER_REPORT_MS) {
        app_power_report(window_ms);
        s_window_start_ms = now;
        s_sleep_us = 0U;
        s_sleep_count = 0U;
    }
}
