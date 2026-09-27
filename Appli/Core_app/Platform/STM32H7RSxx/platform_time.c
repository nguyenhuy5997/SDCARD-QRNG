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

uint32_t platform_get_cycle_count(void)
{
    ensure_dwt_enabled();
    return DWT->CYCCNT;
}

uint32_t platform_get_cpu_hz(void)
{
    return SystemCoreClock;
}
