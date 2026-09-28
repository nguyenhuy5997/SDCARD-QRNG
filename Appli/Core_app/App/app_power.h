/**
 * @file    app_power.h
 * @brief   Main-loop idle sleep and die-temperature monitoring (2026-09-28, the chip was running hot).
 *
 * Before this the main loop spun at full speed forever. Now, when nothing is pending, the core sleeps (WFI) until the
 * next interrupt: a USB transfer, the 1 ms system tick, a DMA. Every poll in the loop (command protocol, QRNG stream,
 * media nonce pool and session timeout, IWDG refresh) therefore still runs at least once per millisecond, and at once
 * when USB data arrives.
 *
 * The DTS temperature and the share of time spent asleep are refreshed once a second into the post-mortem trace
 * record (g_app_trace, fixed address 0x24071800, non-cacheable): read them over SWD while the phone owns the USB port
 * -- see app_trace.c for the offsets.
 */
#ifndef APP_POWER_H
#define APP_POWER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** Start the temperature sensor. Call once, after the generated MX_*_Init() calls. */
void app_power_init(void);

/** Main loop, once per pass, after the protocol polls: sleeps until the next interrupt if nothing is pending, and
 *  once a second reads the temperature and publishes the statistics. */
void app_power_idle(void);

/** Latest once-a-second snapshot. *temp_c / *temp_max_c = INT32_MIN when there is no reading (yet). temp_max_c is the
 *  maximum of this run. */
void app_power_get_status(int32_t *temp_c, int32_t *temp_max_c, uint32_t *sleep_permille, uint32_t *sleep_count);

#ifdef __cplusplus
}
#endif

#endif /* APP_POWER_H */
