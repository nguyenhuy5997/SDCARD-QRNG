/**
 * @file    platform_time.h
 * @brief   MCU-agnostic delay/tick interface of the Platform HAL.
 *
 * Unlike the peripheral modules (GPIO/UART/I2C/ADC/Timer), this one has
 * no "generated init" to attach to -- SysTick and the cycle counter are
 * core Cortex-M facilities the vendor HAL already brings up as part of
 * HAL_Init(), so these calls work immediately, no platform_time_init().
 */
#ifndef PLATFORM_TIME_H
#define PLATFORM_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/** Milliseconds elapsed since boot (wraps at UINT32_MAX like HAL_GetTick()). */
uint32_t platform_get_tick_ms(void);

/** Blocking delay, whole milliseconds. */
void platform_delay_ms(uint32_t ms);

/** Blocking delay, whole microseconds (busy-wait; not for long delays). */
void platform_delay_us(uint32_t us);

/** Free-running CPU cycle counter (Cortex-M7 DWT->CYCCNT), lazily enabled
 *  on first use like platform_delay_us(). Wraps at UINT32_MAX cycles
 *  (~53s at 80MHz) -- fine for timing short intervals via
 *  `platform_get_cycle_count() - start`, which is correct across a
 *  single wrap thanks to unsigned overflow, but don't use it to measure
 *  anything longer than that. For profiling short hot-path sections
 *  (microsecond-to-low-millisecond scale) where platform_get_tick_ms()'s
 *  1ms resolution is too coarse. */
uint32_t platform_get_cycle_count(void);

/** CPU clock frequency in Hz (SystemCoreClock) -- pairs with
 *  platform_get_cycle_count() to convert a cycle delta into real time
 *  without a caller outside Platform needing to know the MCU's actual
 *  clock configuration. */
uint32_t platform_get_cpu_hz(void);

/** Put the CPU to sleep until the next interrupt (any enabled interrupt,
 *  not a specific one -- callers that need to wait for one particular
 *  event must check for it themselves after this returns). */
void platform_wait_for_interrupt(void);

/** Idle sleep for the main loop: with interrupts masked, asks `still_idle()`; if it returns true, sleeps (WFI) until
 *  any interrupt is pending, then unmasks so that interrupt runs. Masking closes the race where an interrupt that
 *  brings new work arrives between the check and the WFI -- it then wakes the WFI at once instead of being slept
 *  through. `still_idle` runs with interrupts masked: keep it to a few flag/counter reads.
 *  Returns the time spent asleep in microseconds (0 when it did not sleep). The system tick interrupt (1 ms) always
 *  ends a sleep, so a caller's periodic work still runs at least once per millisecond. */
uint32_t platform_sleep_until_interrupt(bool (*still_idle)(void));

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_TIME_H */
