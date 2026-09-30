/**
 * @file    qrng_service_adc_noise.c
 * @brief   ADC-noise backend of the chip-agnostic qrng_service interface.
 *
 * Wraps Core_app/Drivers/QRNG's entropy/extractor algorithms behind
 * qrng_service.h so App never touches entropy_context_t/extractor_run()
 * or Core_app/Platform's ADC/DAC/RNG/hash primitives directly -- same
 * boundary Core_app/Middleware/Security/SE052F/security_service_se052f.c
 * keeps for the SE05x host library.
 *
 * Core_app/Drivers/QRNG/entropy.c expects something to call
 * entropy_get_samples()/entropy_run_health_checks() and to set
 * `raw_pool`/`buffer_1_ready`/`buffer_2_ready` on its entropy_context_t
 * -- upstream (D:\Workspace\STM32\vQRNG1.0) did that from
 * HAL_ADC_ConvHalfCpltCallback()/ConvCpltCallback() ISRs. This backend
 * has no ISR (Core_app/Platform's ADC module is poll-based, see
 * platform_adc.h): pump_adc_buffer_flags() below polls
 * platform_adc_dma_pos() instead and sets those same fields itself,
 * once per half/full lap of the circular DMA buffer.
 *
 * DEVIATION FROM UPSTREAM: upstream's own vQRNG_get_noise_handler()/
 * get_entropy_handler() (qrng_if.c) call entropy_get_samples() on every
 * draw without ever resetting `is_source_ready` afterwards, and nothing
 * else in that project resets it either -- since entropy_get_samples()
 * only updates `raw_pool` while `is_source_ready` is still 0, this looks
 * like a real bug upstream: after the very first successful draw,
 * `is_source_ready` latches at 1 forever, so every later
 * entropy_get_samples() call becomes a no-op and every subsequent draw
 * (including "continuous stream" mode) would keep re-reading the exact
 * same first buffer forever. wait_for_fresh_buffer() below resets it
 * (via entropy_reset(), which also re-arms the RCT/APT health-check
 * counters -- upstream never reset those between draws either, so its
 * "Continuous Health Test" only ever real-checks the first buffer too)
 * before claiming each new buffer, instead of reproducing that bug.
 */
#include "qrng_service.h"

#include <string.h>

#include "platform.h"
#include "board.h"

#include "qrng_constant.h"
#include "entropy.h"
#include "extractor.h"
#include "toeplitz.h"
#include "ad5398.h"

/* How long to wait for one ADC DMA half-buffer lap before giving up.
 * Not a qrng_constant.h setting -- that file is pure algorithm timing
 * (sample counts, reseed interval), this is a Platform-level bring-up
 * timeout. */
#define QRNG_BUFFER_TIMEOUT_MS 2000U

static entropy_context_t s_entropy;
/* DMA-written, CPU-read via a raw pointer (s_entropy.raw_pool below) --
 * must live in the non-cacheable .dma_noncache region once D-Cache is
 * enabled, see STM32H753ZITX_FLASH.ld's doc comment on that section. */
static uint16_t s_adc_buf[QRNG_ADC_SAMPLES] __attribute__((section(".dma_noncache")));
static uint32_t s_last_dma_pos;

static qrng_extractor_t s_extractor_algo = QRNG_EXTRACTOR_TOEPLITZ;
static bool s_health_test_enabled = true;
static bool s_auto_reseed_enabled;
static uint32_t s_reseed_counter;
static bool s_ready;

static uint8_t s_startup_health_record[QRNG_STARTUP_HEALTH_RECORD_BYTES];
static bool s_startup_record_valid;

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* TEMPORARY diagnostic (2026-09-19, chasing a real qrng_service_init()
 * startup-health-check failure after the SYSCLK retune): captures what
 * actually happened on the LAST run_startup_health_check() attempt, plus
 * a raw ADC throughput measurement taken right after the DMA/timer start
 * -- independent of qrng_service_debug_measure_adc_rate() below, which
 * requires s_ready (not yet true while we're still diagnosing why init
 * itself fails). See qrng_service_debug_get_boot_diag() in qrng_service.h. */
static uint32_t s_dbg_boot_adc_sps;
static uint32_t s_dbg_last_health_status;
static uint32_t s_dbg_last_healthy_samples;
static uint16_t s_dbg_sample_snapshot[8];

/* Per-attempt breakdown across all QRNG_SYSTEM_MAX_RETRIES attempts (not
 * just the last one) -- added to distinguish "the buffer content is
 * genuinely frozen/identical every attempt" (points at a DMA/cache bug:
 * real writes aren't reaching CPU-visible memory) from "each attempt
 * sees different, real-but-still-repetitive data" (points at the analog
 * front-end genuinely not producing noise). Each attempt reads a
 * DIFFERENT physical half of s_adc_buf (buffer_1 vs buffer_2 alternate),
 * so identical values across attempts would be a strong tell. */
static uint32_t s_dbg_attempt_status[QRNG_SYSTEM_MAX_RETRIES];
static uint32_t s_dbg_attempt_healthy[QRNG_SYSTEM_MAX_RETRIES];
static uint16_t s_dbg_attempt_sample0[QRNG_SYSTEM_MAX_RETRIES];
static uint16_t s_dbg_attempt_sample1[QRNG_SYSTEM_MAX_RETRIES];
static int s_dbg_attempt_count;
#endif /* EVT2_DIAGNOSTICS */

/* qrng_extractor_t's values (0/1/2, this Middleware's own numbering) and
 * QRNG_EXTRACTOR_USE_*'s values (1/2/3, Core_app/Drivers/QRNG/
 * qrng_constant.h's numbering) are two independent enumerations -- do
 * not cast one to the other, map explicitly. */
/* Analog noise front end power sequence (board.h, BOARD_QRNG_POWERUP_STEP_MS). The three enables are active high
 * and low after reset (MX_GPIO_Init(); Boot and the loader also drive them low); the AD5398 PD pin is high (sink
 * off) until ad5398_set_current_ua() releases it. */
static void qrng_analog_power_off(void)
{
    (void)ad5398_power_down();                                        /* drive current off first */
    (void)platform_gpio_write(BOARD_LED_EN_GPIO, true);
    (void)platform_gpio_write(BOARD_PS_SECOND_STAGE_EN_GPIO, true);
    (void)platform_gpio_write(BOARD_PS_FIRST_STAGE_EN_GPIO, true);
}

/** PS_FIRST_STAGE -> PS_SECOND_STAGE -> LED_ENABLE -> AD5398 at BOARD_QRNG_DRIVE_CURRENT_UA (register read back
 *  and checked by ad5398_set_current_ua()). Everything is switched off again if any step fails. */
static platform_status_t qrng_analog_power_on(void)
{
    static const platform_gpio_t order[] = {
        BOARD_PS_FIRST_STAGE_EN_GPIO,
        BOARD_PS_SECOND_STAGE_EN_GPIO,
        BOARD_LED_EN_GPIO,
    };
    platform_status_t st = PLATFORM_OK;
    // platform_status_t st = ad5398_init(); /* talks to the chip, keeps the PD pin high: no current yet */
    for (size_t i = 0; st == PLATFORM_OK && i < sizeof(order) / sizeof(order[0]); i++) {
        st = platform_gpio_write(order[i], true);
        platform_delay_ms(BOARD_QRNG_POWERUP_STEP_MS);
    }
    if (st == PLATFORM_OK) {
        st = ad5398_set_current_ua(BOARD_QRNG_DRIVE_CURRENT_UA);
        platform_delay_ms(BOARD_QRNG_POWERUP_STEP_MS);
    }
    st == PLATFORM_OK;
    if (st != PLATFORM_OK) {
        qrng_analog_power_off();
    }
    return st;
}

static uint8_t map_extractor_algorithm(qrng_extractor_t algo)
{
    switch (algo) {
        case QRNG_EXTRACTOR_HMAC_SHA256: return QRNG_EXTRACTOR_USE_HMAC_SHA256;
        case QRNG_EXTRACTOR_AES:         return QRNG_EXTRACTOR_USE_AES;
        case QRNG_EXTRACTOR_TOEPLITZ:
        default:                         return QRNG_EXTRACTOR_USE_TOEPLITZ;
    }
}

static void pump_adc_buffer_flags(void)
{
    uint32_t pos = platform_adc_dma_pos(BOARD_ADC, QRNG_ADC_SAMPLES);
    uint32_t half = QRNG_ADC_SAMPLES / 2;

    /* Detect the same two edges HAL_ADC_ConvHalfCpltCallback()/
     * ConvCpltCallback() would have signaled via interrupt upstream:
     * crossing the half-buffer mark (first half just filled), and
     * wrapping back near 0 (second half just filled, buffer full). */
    if (s_last_dma_pos < half && pos >= half) {
        s_entropy.raw_pool = &s_adc_buf[0];
        s_entropy.buffer_1_ready = 1;
    }
    else if (pos < s_last_dma_pos) {
        s_entropy.raw_pool = &s_adc_buf[half];
        s_entropy.buffer_2_ready = 1;
    }
    s_last_dma_pos = pos;
}

static qrng_status_t wait_for_fresh_buffer(uint32_t timeout_ms)
{
    uint32_t start = platform_get_tick_ms();

    s_entropy.is_source_ready = 0;
    for (;;) {
        pump_adc_buffer_flags();
        if (s_entropy.buffer_1_ready || s_entropy.buffer_2_ready) {
            entropy_get_samples(&s_entropy);
            entropy_reset(&s_entropy); /* re-arm RCT/APT + is_source_ready for this fresh buffer; keeps raw_pool -- see file doc comment */
            return QRNG_OK;
        }
        if (timeout_ms != 0U && (platform_get_tick_ms() - start) > timeout_ms) {
            return QRNG_TIMEOUT;
        }
    }
}

static void record_attempt(uint8_t health, uint32_t healthy, const uint16_t *pool, size_t n);

static qrng_status_t run_startup_health_check(void)
{
#if EVT2_DIAGNOSTICS
    s_dbg_attempt_count = 0;
#endif
    for (int attempt = 0; attempt < QRNG_SYSTEM_MAX_RETRIES; attempt++) {
        qrng_status_t wait_status = wait_for_fresh_buffer(QRNG_BUFFER_TIMEOUT_MS);
        if (wait_status != QRNG_OK) {
            /* health_status stays ENTROPY_HEALTH_OK (0) from entropy_reset() --
             * used as the "timed out waiting for a buffer at all" marker,
             * distinct from a real RCT/APT trip on live data. */
#if EVT2_DIAGNOSTICS
            s_dbg_last_health_status = 0xFFFFFFFFU;
            s_dbg_last_healthy_samples = 0U;
            s_dbg_attempt_status[attempt] = 0xFFFFFFFFU;
            s_dbg_attempt_healthy[attempt] = 0U;
            s_dbg_attempt_sample0[attempt] = 0xFFFFU;
            s_dbg_attempt_sample1[attempt] = 0xFFFFU;
            s_dbg_attempt_count++;
#endif
            record_attempt(0xFFU, 0U, NULL, 0U);
            continue;
        }
        /* NIST 800-90B 4.3(4): startup tests run the continuous health
         * tests over at least 1024 consecutive samples -- one half
         * buffer (QRNG_ADC_SAMPLES/2) already covers that. */
        entropy_run_health_checks(&s_entropy, true);
        record_attempt((uint8_t)s_entropy.health_status, s_entropy.healthy_samples, s_entropy.raw_pool,
                       QRNG_ADC_SAMPLES / 2U);
#if EVT2_DIAGNOSTICS
        s_dbg_last_health_status = (uint32_t)s_entropy.health_status;
        s_dbg_last_healthy_samples = s_entropy.healthy_samples;
        memcpy(s_dbg_sample_snapshot, s_entropy.raw_pool, sizeof(s_dbg_sample_snapshot));
        s_dbg_attempt_status[attempt] = (uint32_t)s_entropy.health_status;
        s_dbg_attempt_healthy[attempt] = s_entropy.healthy_samples;
        s_dbg_attempt_sample0[attempt] = s_entropy.raw_pool[0];
        s_dbg_attempt_sample1[attempt] = s_entropy.raw_pool[1];
        s_dbg_attempt_count++;
#endif
        if (!entropy_health_check_error(&s_entropy)) {
            memcpy(s_startup_health_record, s_entropy.raw_pool, QRNG_STARTUP_HEALTH_RECORD_BYTES);
            s_startup_record_valid = true;
            return QRNG_OK;
        }
    }
    return QRNG_HEALTH_FAIL;
}

/* TEMPORARY diagnostic -- see s_dbg_boot_adc_sps's doc comment above.
 * Polls platform_adc_dma_pos() for window_ms with no health-check work
 * in between, same technique as qrng_service_debug_measure_adc_rate()
 * but callable before s_ready is set (ADC/timer just need to already be
 * started, which the caller below guarantees). */
static uint32_t measure_adc_rate_raw(uint32_t window_ms)
{
    uint32_t start_pos = platform_adc_dma_pos(BOARD_ADC, QRNG_ADC_SAMPLES);
    uint32_t last_pos = start_pos;
    uint32_t laps = 0U;
    uint32_t start_tick = platform_get_tick_ms();

    while ((platform_get_tick_ms() - start_tick) < window_ms) {
        uint32_t pos = platform_adc_dma_pos(BOARD_ADC, QRNG_ADC_SAMPLES);
        if (pos < last_pos) {
            laps++;
        }
        last_pos = pos;
    }

    int64_t total_samples = (int64_t)laps * QRNG_ADC_SAMPLES + (int64_t)last_pos - (int64_t)start_pos;
    uint32_t elapsed_ms = platform_get_tick_ms() - start_tick;
    return elapsed_ms ? (uint32_t)(total_samples * 1000 / elapsed_ms) : 0U;
}

/* ADC samples/s measured right after the ADC started in qrng_service_init() (0 until then), kept even when the
 * startup health check fails afterwards -- see qrng_service_measure_adc_rate(). */
static uint32_t s_boot_adc_sps;

static qrng_init_diag_t s_init_diag = { .init_status = 0xFFU };

static void record_attempt(uint8_t health, uint32_t healthy, const uint16_t *pool, size_t n)
{
    s_init_diag.health_status = health;
    s_init_diag.healthy_samples = healthy;
    s_init_diag.attempts++;
    if (pool == NULL) {
        return;
    }
    uint16_t mn = 0xFFFFU;
    uint16_t mx = 0U;
    for (size_t i = 0; i < n; i++) {
        mn = (pool[i] < mn) ? pool[i] : mn;
        mx = (pool[i] > mx) ? pool[i] : mx;
    }
    s_init_diag.min = mn;
    s_init_diag.max = mx;
    memcpy(s_init_diag.samples, pool, sizeof(s_init_diag.samples));
}

void qrng_service_get_init_diag(qrng_init_diag_t *out)
{
    if (out != NULL) {
        *out = s_init_diag;
    }
}

/* qrng_service_init() failed after the analog front end was powered: stop sampling and switch it off again. */
static void qrng_init_fail_cleanup(void)
{
    (void)platform_adc_stop_dma(BOARD_ADC);
    (void)platform_timer_stop(BOARD_ADC_TRIGGER_TIMER);
    qrng_analog_power_off();
}

static qrng_status_t qrng_service_init_impl(void)
{
    s_init_diag.step = 1U;

    /* STM32H7RSxx port: the MCU has no DAC (Platform/STM32H7RSxx/
     * platform_dac.c returns PLATFORM_NOT_SUPPORTED for everything). That
     * one code means "no programmable noise drive on this board, the
     * circuit runs at its fixed bias" -- carry on; the startup health check
     * below still decides whether the noise is usable. Any OTHER failure is
     * a real DAC fault on a board that does have one, and stays fatal. */
    platform_status_t dac_status = platform_dac_init(BOARD_QRNG_DAC);
    if (dac_status == PLATFORM_OK) {
        /* DAC must be driving the noise circuit before the ADC starts
         * sampling it, same order as upstream's vQRNG_init_board(). */
        if (platform_dac_set_value(BOARD_QRNG_DAC, QRNG_DAC_DEFAULT_VALUE) != PLATFORM_OK ||
            platform_dac_start(BOARD_QRNG_DAC) != PLATFORM_OK) {
            return QRNG_ERROR;
        }
    }
    else if (dac_status != PLATFORM_NOT_SUPPORTED) {
        return QRNG_ERROR;
    }
    /* H7S3 board: the AD5398 current-sink DAC sets the noise-source drive current instead of the MCU DAC, as the
     * last step of the power-up sequence (qrng_analog_power_on()); a missing/unresponsive AD5398 or a failed
     * readback is fatal (the noise would be taken at the wrong operating point) and powers everything off. */
    s_init_diag.step = 2U;
    if (qrng_analog_power_on() != PLATFORM_OK) {
        return QRNG_ERROR;
    }
    {
        uint32_t ua = 0U;
        bool on = false;
        (void)ad5398_get_current_ua(&ua, &on);
        s_init_diag.ad5398_ua = on ? ua : 0U;
    }
    s_init_diag.step = 3U;
    /* Let the analog noise circuit (DAC-driven avalanche/opto noise
     * source) settle into its proper noisy operating point before the
     * ADC samples it -- immediately after power-up the signal can be
     * near-constant, which trips the RCT/APT startup health checks
     * below (run_startup_health_check() sees the same ADC sample
     * repeat several times in a row) well before QRNG_SYSTEM_MAX_RETRIES
     * is exhausted. Confirmed on real hardware: with
     * app_self_test()/app_biometric_self_test() called first (Src/main.c),
     * their own ~20+s of runtime incidentally provided this settle time
     * and qrng_service_init() passed; called on its own right after
     * boot, it failed every time until this delay was added. Upstream
     * (D:\Workspace\STM32\vQRNG1.0's vQRNG_init_board()) has the same
     * gap with no explicit delay either -- this is a difference in this
     * port's specific analog front-end/timing, not a known upstream
     * requirement, so it is a value tuned against this board rather
     * than a spec'd constant.
     *
     * 2026-09-19 SYSCLK 80->480MHz retune note: qrng_service_init() started
     * failing again after the retune. First suspect was this delay
     * (bumped 3000->20000ms), but that test was CONFOUNDED: at the time,
     * hadc1.Init.ClockPrescaler (Src/main.c) had also been regenerated to
     * ADC_CLOCK_ASYNC_DIV1 -- ADC kernel clock is 75MHz from PLL2P
     * (independent of this retune), and DIV1 feeds the ADC that full
     * 75MHz, well above its actual clock spec. Fixed that back to DIV2
     * (37.5MHz, in-spec) and reverted this delay to 3000ms, but it still
     * failed. Per-attempt diagnostics (qrng_service_debug_get_attempt(),
     * temporary, see qrng_service.h) then showed WHY: with the ADC clock
     * now correct (adc_sps measured ~1,333,313, matching the 1.333MHz
     * TIM1 trigger exactly), most of the 5 startup-health-check retries
     * still read near-zero/flat samples, but the LAST retry -- occurring
     * latest in real time, even though all 5 span only a few ms -- read
     * genuine clustered analog noise (~40800/65535, real sample-to-sample
     * jitter, not memory corruption or a frozen value). That is
     * consistent with the noise circuit still being mid-settle at
     * 3000ms: re-trying the earlier 20000ms delay now that the ADC clock
     * confound is gone, to see if it actually fixes it this time. */
    platform_delay_ms(3000);

    if (platform_rng_init() != PLATFORM_OK || platform_hash_init() != PLATFORM_OK ||
        platform_crypto_init() != PLATFORM_OK) {
        qrng_init_fail_cleanup();
        return QRNG_ERROR;
    }

    s_init_diag.step = 4U;
    if (platform_timer_init(BOARD_ADC_TRIGGER_TIMER) != PLATFORM_OK ||
        platform_adc_init(BOARD_ADC) != PLATFORM_OK) {
        qrng_init_fail_cleanup();
        return QRNG_ERROR;
    }

    entropy_init(&s_entropy);
    s_last_dma_pos = 0;

    s_init_diag.step = 5U;
    if (platform_adc_start_dma(BOARD_ADC, s_adc_buf, QRNG_ADC_SAMPLES) != PLATFORM_OK ||
        platform_timer_start(BOARD_ADC_TRIGGER_TIMER) != PLATFORM_OK) {
        qrng_init_fail_cleanup();
        return QRNG_ERROR;
    }

    s_boot_adc_sps = measure_adc_rate_raw(100U); /* 100 ms of the ADC/DMA chain alone, before any health work */
#if EVT2_DIAGNOSTICS
    /* See s_dbg_boot_adc_sps's doc comment. */
    s_dbg_boot_adc_sps = s_boot_adc_sps;
#endif

    s_init_diag.step = 6U;
    s_init_diag.attempts = 0U;
    if (run_startup_health_check() != QRNG_OK) {
        qrng_init_fail_cleanup();
        return QRNG_HEALTH_FAIL;
    }

    extractor_init();
    s_reseed_counter = 0;

    s_init_diag.step = 7U;
    s_ready = true;
    return QRNG_OK;
}

qrng_status_t qrng_service_init(void)
{
    if (s_ready) {
        return QRNG_OK;
    }
    const qrng_status_t st = qrng_service_init_impl();
    s_init_diag.init_status = (uint8_t)st;
    return st;
}

/* ---- raw capture (analog front-end bring-up) ---- */
static bool s_raw_running;

qrng_status_t qrng_service_raw_capture(uint16_t *out, size_t n, bool power_analog)
{
    if (out == NULL || n != QRNG_RAW_CAPTURE_SAMPLES || n != (QRNG_ADC_SAMPLES / 2U)) {
        return QRNG_INVALID_PARAM;
    }
    if (!s_ready && !s_raw_running) {
        if (power_analog) {
            if (qrng_analog_power_on() != PLATFORM_OK) {
                return QRNG_ERROR;
            }
            platform_delay_ms(3000); /* same settle time as qrng_service_init() */
        }
        if (platform_timer_init(BOARD_ADC_TRIGGER_TIMER) != PLATFORM_OK || platform_adc_init(BOARD_ADC) != PLATFORM_OK) {
            qrng_init_fail_cleanup();
            return QRNG_ERROR;
        }
        entropy_init(&s_entropy);
        s_last_dma_pos = 0;
        if (platform_adc_start_dma(BOARD_ADC, s_adc_buf, QRNG_ADC_SAMPLES) != PLATFORM_OK ||
            platform_timer_start(BOARD_ADC_TRIGGER_TIMER) != PLATFORM_OK) {
            qrng_init_fail_cleanup();
            return QRNG_ERROR;
        }
        s_raw_running = true;
    }
    const qrng_status_t st = wait_for_fresh_buffer(QRNG_BUFFER_TIMEOUT_MS);
    if (st != QRNG_OK) {
        return st;
    }
    memcpy(out, s_entropy.raw_pool, n * sizeof(uint16_t));
    return QRNG_OK;
}

qrng_status_t qrng_service_raw_stop(void)
{
    if (!s_ready) {
        /* ADC + timer stop, analog power-off sequence. Also when only qrng_service_analog_set() switched parts on:
         * the stop command must always leave the front end off. */
        qrng_init_fail_cleanup();
    }
    s_raw_running = false;
    return QRNG_OK;
}

/* ---- manual analog front-end control (bring-up) ---- */
static const platform_gpio_t s_analog_gpio[] = {
    [QRNG_ANALOG_PS_FIRST] = BOARD_PS_FIRST_STAGE_EN_GPIO,
    [QRNG_ANALOG_PS_SECOND] = BOARD_PS_SECOND_STAGE_EN_GPIO,
    [QRNG_ANALOG_LED] = BOARD_LED_EN_GPIO,
};

/* Current the AD5398 gets when it is switched on manually (qrng_service_analog_set()); 8 mA was the user's choice
 * (2026-09-29), qrng_service_analog_set_ad5398_ua() changes it. Never above QRNG_ANALOG_AD5398_MAX_UA. */
static uint32_t s_manual_ad5398_ua = 8000U;

qrng_status_t qrng_service_analog_set_ad5398_ua(uint32_t ua)
{
    if (s_ready) {
        return QRNG_ERROR; /* the running QRNG service owns the front end */
    }
    if (ua > QRNG_ANALOG_AD5398_MAX_UA) {
        return QRNG_INVALID_PARAM;
    }
    s_manual_ad5398_ua = ua;
    uint32_t cur = 0U;
    bool enabled = false;
    if (ad5398_get_current_ua(&cur, &enabled) == PLATFORM_OK && enabled &&
        !platform_gpio_read(BOARD_AD5398_PD_GPIO)) {
        /* switched on right now: apply the new value at once (register read back by the driver) */
        return (ad5398_set_current_ua(ua) == PLATFORM_OK) ? QRNG_OK : QRNG_ERROR;
    }
    return QRNG_OK; /* switched off: used at the next switch-on */
}

uint32_t qrng_service_analog_get_ad5398_setpoint_ua(void)
{
    return s_manual_ad5398_ua;
}

qrng_status_t qrng_service_analog_set(qrng_analog_elem_t elem, bool on)
{
    if (s_ready) {
        return QRNG_ERROR; /* the running QRNG service owns the front end */
    }
    platform_status_t st;
    switch (elem) {
        case QRNG_ANALOG_PS_FIRST:
        case QRNG_ANALOG_PS_SECOND:
        case QRNG_ANALOG_LED:
            st = platform_gpio_write(s_analog_gpio[elem], on);
            break;
        case QRNG_ANALOG_AD5398:
            if (on) {
                st = ad5398_init();
                if (st == PLATFORM_OK) {
                    st = ad5398_set_current_ua(s_manual_ad5398_ua); /* releases PD, reads back */
                }
                if (st != PLATFORM_OK) {
                    (void)ad5398_power_down();
                }
            }
            else {
                st = ad5398_power_down();
            }
            break;
        default:
            return QRNG_INVALID_PARAM;
    }
    return (st == PLATFORM_OK) ? QRNG_OK : QRNG_ERROR;
}

uint8_t qrng_service_analog_state(uint32_t *ad5398_ua)
{
    uint8_t bits = 0U;
    for (uint32_t i = 0; i < sizeof(s_analog_gpio) / sizeof(s_analog_gpio[0]); i++) {
        if (platform_gpio_read(s_analog_gpio[i])) {
            bits |= (uint8_t)(1U << i);
        }
    }
    uint32_t ua = 0U;
    bool enabled = false;
    if (ad5398_get_current_ua(&ua, &enabled) != PLATFORM_OK) { /* fails before ad5398_init(): chip never used */
        ua = 0U;
        enabled = false;
    }
    if (enabled && !platform_gpio_read(BOARD_AD5398_PD_GPIO)) {
        bits |= (uint8_t)(1U << QRNG_ANALOG_AD5398);
    }
    if (ad5398_ua != NULL) {
        *ad5398_ua = ua;
    }
    return bits;
}

qrng_status_t qrng_service_measure_adc_rate(uint32_t window_ms, uint32_t *boot_sps, uint32_t *live_sps)
{
    if (boot_sps == NULL || live_sps == NULL || window_ms == 0U || window_ms > 1000U) {
        return QRNG_INVALID_PARAM;
    }
    *boot_sps = s_boot_adc_sps;
    *live_sps = (s_ready || s_raw_running) ? measure_adc_rate_raw(window_ms) : 0U;
    return QRNG_OK;
}

qrng_status_t qrng_service_deinit(void)
{
    if (!s_ready) {
        return QRNG_OK;
    }

    (void)platform_adc_stop_dma(BOARD_ADC);
    (void)platform_timer_stop(BOARD_ADC_TRIGGER_TIMER);
    (void)platform_dac_stop(BOARD_QRNG_DAC);
    qrng_analog_power_off();

    s_ready = false;
    s_startup_record_valid = false;
    return QRNG_OK;
}

bool qrng_service_is_ready(void)
{
    return s_ready;
}

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
void qrng_service_debug_get_boot_diag(uint32_t *adc_sps, uint32_t *last_health_status,
                                       uint32_t *last_healthy_samples,
                                       uint16_t *sample_snapshot, size_t snapshot_len)
{
    if (adc_sps != NULL) {
        *adc_sps = s_dbg_boot_adc_sps;
    }
    if (last_health_status != NULL) {
        *last_health_status = s_dbg_last_health_status;
    }
    if (last_healthy_samples != NULL) {
        *last_healthy_samples = s_dbg_last_healthy_samples;
    }
    if (sample_snapshot != NULL) {
        size_t n = snapshot_len < (sizeof(s_dbg_sample_snapshot) / sizeof(s_dbg_sample_snapshot[0]))
                       ? snapshot_len
                       : (sizeof(s_dbg_sample_snapshot) / sizeof(s_dbg_sample_snapshot[0]));
        memcpy(sample_snapshot, s_dbg_sample_snapshot, n * sizeof(uint16_t));
    }
}

int qrng_service_debug_get_attempt_count(void)
{
    return s_dbg_attempt_count;
}

void qrng_service_debug_get_attempt(int index, uint32_t *status, uint32_t *healthy_samples,
                                     uint16_t *sample0, uint16_t *sample1)
{
    if (index < 0 || index >= QRNG_SYSTEM_MAX_RETRIES) {
        return;
    }
    if (status != NULL) { *status = s_dbg_attempt_status[index]; }
    if (healthy_samples != NULL) { *healthy_samples = s_dbg_attempt_healthy[index]; }
    if (sample0 != NULL) { *sample0 = s_dbg_attempt_sample0[index]; }
    if (sample1 != NULL) { *sample1 = s_dbg_attempt_sample1[index]; }
}
#endif /* EVT2_DIAGNOSTICS */

#if EVT2_DIAGNOSTICS /* dev/QA only, see Core/Src/main.c */
/* TEMPORARY diagnostic timing -- see qrng_service_debug_get_timing()'s
 * doc comment in qrng_service.h. Cheap (2 cycle-counter reads + a
 * subtract per draw). Compiled in only with EVT2_DIAGNOSTICS: the counters
 * are cheap enough that the timing they report still reflects the real path. */
static uint64_t s_dbg_wait_cycles;
static uint64_t s_dbg_process_cycles;
static uint32_t s_dbg_draw_count;

/* Finer breakdown of s_dbg_process_cycles -- see
 * qrng_service_debug_get_stage_timing()'s doc comment in qrng_service.h.
 * s_dbg_copy_cycles is memcpy() time for get_noise() draws, extractor_run()
 * time for get_entropy() draws -- whichever ran, tracked under one name
 * since a single measurement window (one QRNG_CMD_BENCH_NOISE/_ENTROPY
 * run) only ever calls one of the two functions, never both. */
static uint64_t s_dbg_health_cycles;
static uint64_t s_dbg_copy_cycles;
/* Independent from s_dbg_draw_count on purpose: qrng_service_debug_get_timing()
 * and qrng_service_debug_get_stage_timing() each reset their own counter
 * on read, so calling one does not disturb an in-progress measurement
 * window for the other regardless of call order. */
static uint32_t s_dbg_stage_count;
#endif /* EVT2_DIAGNOSTICS */

qrng_status_t qrng_service_get_noise(uint8_t *buf, size_t len)
{
    if (!s_ready) {
        return QRNG_NOT_READY;
    }
    if (buf == NULL || len != QRNG_NOISE_BYTES) {
        return QRNG_INVALID_PARAM;
    }

#if EVT2_DIAGNOSTICS
    uint32_t t0 = platform_get_cycle_count();
#endif
    qrng_status_t status = wait_for_fresh_buffer(QRNG_BUFFER_TIMEOUT_MS);
#if EVT2_DIAGNOSTICS
    uint32_t t1 = platform_get_cycle_count();
    s_dbg_wait_cycles += (uint32_t)(t1 - t0);
    if (status != QRNG_OK) {
        s_dbg_draw_count++;
    }
#endif
    if (status != QRNG_OK) {
        return status;
    }

    entropy_run_health_checks(&s_entropy, s_health_test_enabled);
#if EVT2_DIAGNOSTICS
    uint32_t t2 = platform_get_cycle_count();
    s_dbg_health_cycles += (uint32_t)(t2 - t1);
#endif
    if (entropy_health_check_error(&s_entropy)) {
#if EVT2_DIAGNOSTICS
        s_dbg_process_cycles += (uint32_t)(platform_get_cycle_count() - t1);
        s_dbg_draw_count++;
#endif
        return QRNG_HEALTH_FAIL;
    }

    memcpy(buf, s_entropy.raw_pool, QRNG_NOISE_BYTES);
#if EVT2_DIAGNOSTICS
    s_dbg_copy_cycles += (uint32_t)(platform_get_cycle_count() - t2);
    s_dbg_process_cycles += (uint32_t)(platform_get_cycle_count() - t1);
    s_dbg_draw_count++;
    s_dbg_stage_count++; /* only on full success -- see s_dbg_stage_count's doc comment */
#endif
    return QRNG_OK;
}

/** Shared body of qrng_service_get_entropy()/qrng_service_get_entropy_with()
 *  -- `algorithm` is an explicit parameter here specifically so the
 *  "_with" variant never has to touch s_extractor_algo (the global,
 *  USB-settable default) at all. See qrng_service_get_entropy_with()'s
 *  doc comment in qrng_service.h for why that separation exists: a
 *  caller (Core_app/App/protocol_adapters/media_protocol.c's QRNG nonce
 *  pool) that needs to GUARANTEE one specific algorithm regardless of
 *  what a USB client's QRNG_CMD_SET_EXTRACTOR has configured must not
 *  do so by overwriting that global -- an earlier version of this file
 *  did exactly that (media_protocol_init() forcing Toeplitz into
 *  s_extractor_algo), which silently fought/reverted a user's own
 *  SET_EXTRACTOR choice for their own direct GET_ENTROPY/STREAM_ENTROPY
 *  calls every time the nonce pool refilled. */
static qrng_status_t get_entropy_using(qrng_extractor_t algorithm, uint8_t *buf, size_t len)
{
    if (!s_ready) {
        return QRNG_NOT_READY;
    }
    if (buf == NULL || len != QRNG_ENTROPY_BYTES) {
        return QRNG_INVALID_PARAM;
    }

#if EVT2_DIAGNOSTICS
    uint32_t t0 = platform_get_cycle_count();
#endif
    qrng_status_t status = wait_for_fresh_buffer(QRNG_BUFFER_TIMEOUT_MS);
#if EVT2_DIAGNOSTICS
    uint32_t t1 = platform_get_cycle_count();
    s_dbg_wait_cycles += (uint32_t)(t1 - t0);
    if (status != QRNG_OK) {
        s_dbg_draw_count++;
    }
#endif
    if (status != QRNG_OK) {
        return status;
    }

    entropy_run_health_checks(&s_entropy, s_health_test_enabled);
#if EVT2_DIAGNOSTICS
    uint32_t t2 = platform_get_cycle_count();
    s_dbg_health_cycles += (uint32_t)(t2 - t1);
#endif
    if (entropy_health_check_error(&s_entropy)) {
#if EVT2_DIAGNOSTICS
        s_dbg_process_cycles += (uint32_t)(platform_get_cycle_count() - t1);
        s_dbg_draw_count++;
#endif
        return QRNG_HEALTH_FAIL;
    }

    bool extractor_ok = extractor_run(map_extractor_algorithm(algorithm), (const uint32_t *)s_entropy.raw_pool,
                                       (uint32_t *)buf);
#if EVT2_DIAGNOSTICS
    s_dbg_copy_cycles += (uint32_t)(platform_get_cycle_count() - t2);
#endif
    if (!extractor_ok) {
        /* HMAC-SHA256/AES hardware call failed partway through -- buf may
         * be partially filled with real output and partially untouched;
         * neither this function nor its caller can tell which bytes are
         * which, so treat the whole draw as unusable rather than return
         * QRNG_OK with data that might be stale/uninitialized. */
#if EVT2_DIAGNOSTICS
        s_dbg_process_cycles += (uint32_t)(platform_get_cycle_count() - t1);
        s_dbg_draw_count++;
#endif
        return QRNG_ERROR;
    }

    if (s_auto_reseed_enabled) {
        s_reseed_counter++;
        if (s_reseed_counter >= QRNG_EXTRACTOR_RESEED_INTERVAL) {
            /* Best-effort: a failed reseed just leaves the current
             * key/matrix in place for the next draw, it does not affect
             * the entropy already produced above -- not worth failing
             * this whole call over. qrng_service_reseed_extractor() is
             * the direct, caller-visible way to reseed and get a real
             * answer if that matters. */
            (void)extractor_reseed(map_extractor_algorithm(algorithm), (const uint32_t *)s_entropy.raw_pool);
            s_reseed_counter = 0;
        }
    }

#if EVT2_DIAGNOSTICS
    s_dbg_process_cycles += (uint32_t)(platform_get_cycle_count() - t1);
    s_dbg_draw_count++;
    s_dbg_stage_count++; /* only on full success -- see s_dbg_stage_count's doc comment */
#endif
    return QRNG_OK;
}

qrng_status_t qrng_service_get_entropy(uint8_t *buf, size_t len)
{
    return get_entropy_using(s_extractor_algo, buf, len);
}

qrng_status_t qrng_service_get_entropy_with(qrng_extractor_t algorithm, uint8_t *buf, size_t len)
{
    return get_entropy_using(algorithm, buf, len);
}

/* Chunk counters of qrng_service_random_bytes() per source -- diagnostics only (read over SWD on a board without UART). */
volatile uint32_t g_random_chunks_qrng;
volatile uint32_t g_random_chunks_rng;

qrng_status_t qrng_service_random_bytes(uint8_t *buf, size_t len, bool *from_qrng)
{
    static uint8_t scratch[QRNG_ENTROPY_BYTES];
    bool all_qrng = true;
    size_t done = 0;

    if (from_qrng != NULL) {
        *from_qrng = false;
    }
    if (buf == NULL && len != 0U) {
        return QRNG_INVALID_PARAM;
    }
    while (done < len) {
        size_t chunk = (len - done < QRNG_ENTROPY_BYTES) ? (len - done) : QRNG_ENTROPY_BYTES;
        if (get_entropy_using(QRNG_EXTRACTOR_TOEPLITZ, scratch, sizeof(scratch)) == QRNG_OK) {
            memcpy(&buf[done], scratch, chunk);
            g_random_chunks_qrng++;
        }
        else if (platform_rng_get_bytes(&buf[done], chunk) == PLATFORM_OK) {
            all_qrng = false;
            g_random_chunks_rng++;
        }
        else {
            memset(scratch, 0, sizeof(scratch));
            memset(buf, 0, len);
            return QRNG_ERROR;
        }
        done += chunk;
    }
    memset(scratch, 0, sizeof(scratch)); /* the unused rest of the last draw is never kept for a later caller */
    if (from_qrng != NULL) {
        *from_qrng = all_qrng && len != 0U;
    }
    return QRNG_OK;
}

qrng_status_t qrng_service_set_health_test(bool enable)
{
    s_health_test_enabled = enable;
    return QRNG_OK;
}

bool qrng_service_is_healthy(void)
{
    return !entropy_health_check_error(&s_entropy);
}

qrng_status_t qrng_service_set_extractor(qrng_extractor_t algorithm)
{
    if (algorithm != QRNG_EXTRACTOR_TOEPLITZ && algorithm != QRNG_EXTRACTOR_HMAC_SHA256 &&
        algorithm != QRNG_EXTRACTOR_AES) {
        return QRNG_INVALID_PARAM;
    }

    s_extractor_algo = algorithm;
    return QRNG_OK;
}

qrng_status_t qrng_service_set_extractor_key(qrng_extractor_t algorithm, const uint8_t *key, size_t len)
{
    if (!s_ready) {
        return QRNG_NOT_READY;
    }
    if (key == NULL) {
        return QRNG_INVALID_PARAM;
    }

    uint8_t result = extractor_set_key(map_extractor_algorithm(algorithm), key, (uint32_t)len);
    return (result == EXTRACTOR_SET_KEY_SUCCESS) ? QRNG_OK : QRNG_INVALID_PARAM;
}

qrng_status_t qrng_service_reseed_extractor(void)
{
    if (!s_ready) {
        return QRNG_NOT_READY;
    }

    bool ok = extractor_reseed(map_extractor_algorithm(s_extractor_algo), (const uint32_t *)s_entropy.raw_pool);
    s_reseed_counter = 0;
    return ok ? QRNG_OK : QRNG_ERROR;
}

qrng_status_t qrng_service_set_auto_reseed(bool enable)
{
    s_auto_reseed_enabled = enable;
    s_reseed_counter = 0;
    return QRNG_OK;
}

qrng_status_t qrng_service_get_startup_health_record(uint8_t *buf, size_t len)
{
    if (!s_startup_record_valid) {
        return QRNG_NOT_READY;
    }
    if (buf == NULL || len != QRNG_STARTUP_HEALTH_RECORD_BYTES) {
        return QRNG_INVALID_PARAM;
    }

    memcpy(buf, s_startup_health_record, QRNG_STARTUP_HEALTH_RECORD_BYTES);
    return QRNG_OK;
}

#if EVT2_DIAGNOSTICS /* self-tests, benchmarks and diagnostics -- dev/QA only, see Core/Src/main.c */

qrng_status_t qrng_service_self_test_toeplitz(uint8_t buf[QRNG_TOEPLITZ_KAT_BYTES])
{
    if (buf == NULL) {
        return QRNG_INVALID_PARAM;
    }

    /* Fixed xorshift32(seed=0x12345678) stream -- deterministic and
     * reproducible, NOT the hardware TRNG. Must match byte-for-byte the
     * generator used by the reference KAT harness run against the
     * unmodified vQRNG1.0 sources for this comparison to be valid. */
    static uint32_t matrix[QRNG_TOEPLITZ_WORDS];
    static uint32_t input[QRNG_ADC_SAMPLES / 4];
    static uint32_t output[(QRNG_ADC_SAMPLES / 4) / QRNG_EXTRACTOR_RATIO];

    uint32_t x = 0x12345678U;
    for (size_t i = 0; i < QRNG_TOEPLITZ_WORDS; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        matrix[i] = x;
    }
    for (size_t i = 0; i < QRNG_ADC_SAMPLES / 4; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        input[i] = x;
    }

    toeplitz_build_lookup(matrix);
    /* Identical loop shape to extractor_run()'s Toeplitz branch
     * (Core_app/Drivers/QRNG/extractor.c) -- same stride and in_len
     * expression, so this KAT exercises exactly the code path
     * qrng_service_get_entropy() uses. */
    for (uint32_t i = 0; i < QRNG_ADC_SAMPLES / 4; i += QRNG_TOEPLITZ_INPUT_EXTRACTOR_SIZE / 4) {
        toeplitz_extractor_ultra_fast(input + i, QRNG_EXTRACTOR_RATIO * QRNG_OUTPUT_WORDS,
                                       output + i / QRNG_EXTRACTOR_RATIO, QRNG_OUTPUT_WORDS);
    }

    memcpy(buf, output, QRNG_TOEPLITZ_KAT_BYTES);
    return QRNG_OK;
}

qrng_status_t qrng_service_self_test_hmac(bool *matches_rfc4231)
{
    if (matches_rfc4231 == NULL) {
        return QRNG_INVALID_PARAM;
    }

    /* RFC 4231 SHA-256 Test Case 2. */
    static const uint8_t key[] = { 'J', 'e', 'f', 'e' };
    static const uint8_t data[] = "what do ya want for nothing?";
    static const uint8_t expected[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };
    uint8_t actual[32];

    if (platform_hash_init() != PLATFORM_OK ||
        platform_hmac_sha256(key, sizeof(key), data, sizeof(data) - 1U, actual) != PLATFORM_OK) {
        return QRNG_ERROR;
    }

    *matches_rfc4231 = (memcmp(actual, expected, sizeof(expected)) == 0);
    return QRNG_OK;
}

qrng_status_t qrng_service_self_test_aes(bool *matches_fips197)
{
    if (matches_fips197 == NULL) {
        return QRNG_INVALID_PARAM;
    }

    /* FIPS-197 Appendix B AES-128 example. A single-block message under
     * AES-128-CBC-MAC with a zero IV is just AES-128-ECB-encrypt of that
     * block (P0 XOR 0 == P0), so this published vector directly checks
     * platform_aes128_cbc_mac()'s single-block case. */
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const uint8_t expected[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };
    uint8_t actual[16];

    if (platform_crypto_init() != PLATFORM_OK ||
        platform_aes128_cbc_mac(key, plaintext, sizeof(plaintext), actual) != PLATFORM_OK) {
        return QRNG_ERROR;
    }

    *matches_fips197 = (memcmp(actual, expected, sizeof(expected)) == 0);
    return QRNG_OK;
}

qrng_status_t qrng_service_self_test_aes_batch(bool *matches)
{
    if (matches == NULL) {
        return QRNG_INVALID_PARAM;
    }

    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    /* Block 0 is the FIPS-197 Appendix B vector qrng_service_self_test_aes()
     * already checks; block 1 is an arbitrary second block -- its
     * "expected" value here comes from this same test's own single-call
     * reference path, not a published vector, so this function only
     * proves the batch path agrees with the already-verified single-call
     * path, not that either is independently correct (that is
     * qrng_service_self_test_aes()'s job). */
    static const uint8_t plaintext[2][16] = {
        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 }
    };

    if (platform_crypto_init() != PLATFORM_OK) {
        return QRNG_ERROR;
    }

    uint8_t reference[2][16];
    if (platform_aes128_cbc_mac(key, plaintext[0], sizeof(plaintext[0]), reference[0]) != PLATFORM_OK ||
        platform_aes128_cbc_mac(key, plaintext[1], sizeof(plaintext[1]), reference[1]) != PLATFORM_OK) {
        return QRNG_ERROR;
    }

    uint8_t batch_out[2][16];
    if (platform_aes128_cbc_mac_batch(key, (const uint8_t *)plaintext, sizeof(plaintext[0]), 2U,
                                       (uint8_t *)batch_out) != PLATFORM_OK) {
        return QRNG_ERROR;
    }

    *matches = (memcmp(reference, batch_out, sizeof(reference)) == 0);
    return QRNG_OK;
}

void qrng_service_debug_get_timing(uint32_t *wait_us_avg, uint32_t *process_us_avg, uint32_t *draw_count)
{
    uint32_t count = s_dbg_draw_count;
    uint32_t cpu_hz = platform_get_cpu_hz();
    *draw_count = count;
    *wait_us_avg = count ? (uint32_t)((s_dbg_wait_cycles / count) * 1000000ULL / cpu_hz) : 0U;
    *process_us_avg = count ? (uint32_t)((s_dbg_process_cycles / count) * 1000000ULL / cpu_hz) : 0U;
    s_dbg_wait_cycles = 0U;
    s_dbg_process_cycles = 0U;
    s_dbg_draw_count = 0U;
}

void qrng_service_debug_get_stage_timing(uint32_t *health_check_us_avg, uint32_t *extractor_or_copy_us_avg,
                                          uint32_t *stage_draw_count)
{
    uint32_t count = s_dbg_stage_count;
    uint32_t cpu_hz = platform_get_cpu_hz();
    *stage_draw_count = count;
    *health_check_us_avg = count ? (uint32_t)((s_dbg_health_cycles / count) * 1000000ULL / cpu_hz) : 0U;
    *extractor_or_copy_us_avg = count ? (uint32_t)((s_dbg_copy_cycles / count) * 1000000ULL / cpu_hz) : 0U;
    s_dbg_health_cycles = 0U;
    s_dbg_copy_cycles = 0U;
    s_dbg_stage_count = 0U;
}

uint32_t qrng_service_debug_measure_adc_rate(uint32_t window_ms)
{
    if (!s_ready) {
        return 0U;
    }

    uint32_t start_pos = platform_adc_dma_pos(BOARD_ADC, QRNG_ADC_SAMPLES);
    uint32_t last_pos = start_pos;
    uint32_t laps = 0U;
    uint32_t start_tick = platform_get_tick_ms();

    while ((platform_get_tick_ms() - start_tick) < window_ms) {
        uint32_t pos = platform_adc_dma_pos(BOARD_ADC, QRNG_ADC_SAMPLES);
        if (pos < last_pos) {
            laps++;
        }
        last_pos = pos;
    }

    int64_t total_samples = (int64_t)laps * QRNG_ADC_SAMPLES + (int64_t)last_pos - (int64_t)start_pos;
    uint32_t elapsed_ms = platform_get_tick_ms() - start_tick;
    return elapsed_ms ? (uint32_t)(total_samples * 1000 / elapsed_ms) : 0U;
}

#endif /* EVT2_DIAGNOSTICS */
