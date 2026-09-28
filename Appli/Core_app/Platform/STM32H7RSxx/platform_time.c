/**
 * @file    platform_time.c
 * @brief   STM32H7xx implementation of the Platform time/delay interface.
 *
 * platform_get_tick_ms()/platform_delay_ms() ride on SysTick, which the
 * vendor HAL already configures as part of HAL_Init() (called from
 * main() before any application code runs). platform_delay_us() uses
 * the Cortex-M7 DWT cycle counter, lazily enabled on first use -- it is
 * off by default out of reset and HAL_Init() does not turn it on.
 */
#include "platform.h"
#include "bsp_hal.h"

static bool s_dwt_enabled;

static void ensure_dwt_enabled(void)
{
    if (!s_dwt_enabled) {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
        DWT->CYCCNT = 0U;
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
        s_dwt_enabled = true;
    }
}

uint32_t platform_get_tick_ms(void)
{
    return HAL_GetTick();
}

void platform_delay_ms(uint32_t ms)
{
    HAL_Delay(ms);
}

void platform_delay_us(uint32_t us)
{
    ensure_dwt_enabled();

    uint32_t start = DWT->CYCCNT;
    uint32_t cycles = (SystemCoreClock / 1000000U) * us;

    while ((DWT->CYCCNT - start) < cycles) {
        /* busy-wait */
    }
}

void platform_wait_for_interrupt(void)
{
    /* No WFI here on purpose -- this used to be a plain __WFI() (a power
     * optimization only: Core_app/Drivers/FPC5234/fpc_hal.c's
     * fpc_hal_wfi() calls this from enroll()/identify()'s tight
     * data-available poll loop purely to sleep between checks). With
     * D-Cache enabled (Src/main.c's SCB_EnableDCache(), needed for the
     * QRNG extractor throughput this board targets -- see
     * Core_app/Drivers/QRNG's benchmarks), that WFI reproducibly made
     * Windows fail USB CDC enumeration ("device descriptor request
     * failed", never recovering without a physically unplugging and
     * replugging the USB cable) whenever enroll()/identify() ran
     * concurrently with USB_DEVICE bring-up at boot.
     *
     * Root-caused by isolating each variable on real hardware, in order:
     *  - Not interrupt priority: lowering DMA1_Stream1/2_IRQn,
     *    USART1_IRQn and FPC2530_IRQ_EXTI_IRQn below OTG_FS_IRQn's
     *    priority did not fix it.
     *  - Not blocking duration alone: biometric_service_init() alone
     *    (which blocks on Core_app/Middleware/Biometric/FPC5234/
     *    biometric_service_fpc5234.c's pump_until() instead of this
     *    function -- no WFI in that loop) never reproduced the failure.
     *  - Is D-Cache + WFI specifically: disabling D-Cache alone (this
     *    function unchanged, still calling WFI) made enumeration succeed
     *    instantly every time; separately, keeping D-Cache enabled but
     *    removing just this WFI call (D-Cache otherwise untouched) also
     *    made it succeed instantly every time.
     *  - Not a simple missing-barrier race: adding the standard
     *    ARM-recommended __DSB(); __WFI(); __ISB(); idiom around the WFI
     *    did NOT fix it either -- whatever the exact mechanism is (most
     *    likely cache-miss latency stacking across the loop's very
     *    frequent sleep/wake cycles, eventually delaying OTG_FS_IRQn
     *    past the host's enumeration timing budget), it is deeper than a
     *    textbook unbarriered-WFI race.
     * Net effect of removing it: this now busy-polls instead of
     * sleeping between checks -- slightly more power draw during
     * enroll()/identify()/navigation()/secure_com() (see
     * Core_app/Drivers/FPC5234/tests/, the other fpc_hal_wfi() callers),
     * traded for USB staying reliable. If a future board revision or
     * silicon stepping needs the power saving back, re-verify on real
     * hardware with USB_DEVICE active at boot before restoring WFI here
     * -- do not assume DSB/ISB alone fixes it, that was already tried. */
}

uint32_t platform_sleep_until_interrupt(bool (*still_idle)(void))
{
    /* PRIMASK set: a pending interrupt still ends the WFI, but its handler only runs after __enable_irq(), so the
     * idle check and the sleep are atomic with respect to every interrupt. Unlike platform_wait_for_interrupt()
     * above (FPC polling loop, left without WFI), the caller of this one (app_power.c) only sleeps once USB is
     * configured -- the EVT2 D-Cache + WFI problem described above hit during USB enumeration. */
    /* DBGMCU DBG_SLEEP keeps the core clock running in WFI so that SWD can reach the chip while it sleeps. Off by
     * default (2026-09-28): it costs heat. Its value survives a system reset (debug domain), so it is written
     * explicitly either way. With it off, SWD -- even "connect under reset", the V8Y board has no NRST line -- only
     * reaches the chip right after power-up, before this loop first sleeps: flash with flash.bat retried in a loop
     * and power-cycle the board. Build with EVT2_DEBUG_IN_SLEEP=1 for SWD access to a running board. */
#ifndef EVT2_DEBUG_IN_SLEEP
#define EVT2_DEBUG_IN_SLEEP 0
#endif
    static bool s_dbg_sleep_set;
    if (!s_dbg_sleep_set) {
#if EVT2_DEBUG_IN_SLEEP
        HAL_DBGMCU_EnableDBGSleepMode();
#else
        HAL_DBGMCU_DisableDBGSleepMode();
#endif
        s_dbg_sleep_set = true;
    }

    __disable_irq();
    if (still_idle == NULL || !still_idle()) {
        __enable_irq();
        return 0U;
    }

    /* Sleep time from SysTick (it keeps counting in Sleep mode, unlike the DWT cycle counter, which stops with the
     * core clock). It counts down from LOAD; with interrupts masked, at most one wrap can happen during the sleep,
     * because the wrap itself pends the SysTick interrupt, which ends the WFI. */
    const uint32_t period = SysTick->LOAD + 1U;
    const bool wrapped_before = (SCB->ICSR & SCB_ICSR_PENDSTSET_Msk) != 0U;
    const uint32_t v0 = SysTick->VAL;
    __DSB();
    __WFI();
    const uint32_t v1 = SysTick->VAL;
    const bool wrapped_after = (SCB->ICSR & SCB_ICSR_PENDSTSET_Msk) != 0U;
    __enable_irq();
    __ISB();

    uint32_t cycles;
    if (wrapped_after && !wrapped_before) {
        cycles = v0 + (period - v1);
    }
    else {
        cycles = (v0 >= v1) ? (v0 - v1) : 0U;
    }
    return (uint32_t)(((uint64_t)cycles * 1000U) / period); /* period cycles = 1 ms */
}

uint32_t platform_get_cycle_count(void)
{
    ensure_dwt_enabled();
    return DWT->CYCCNT;
}

uint32_t platform_get_cpu_hz(void)
{
    return SystemCoreClock;
}
