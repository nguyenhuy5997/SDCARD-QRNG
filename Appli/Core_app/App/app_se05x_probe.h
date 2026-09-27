/**
 * @file    app_se05x_probe.h
 * @brief   TEMPORARY (2026-09-26): which security_service functions work on the SE050F2 (applet 3.6.0, FIPS mode) of
 *          the STM32H7S3V8Y6TR board. See app_se05x_probe.c. Set EVT2_SE05X_PROBE to 0 (or delete both files) after.
 */
#ifndef APP_SE05X_PROBE_H
#define APP_SE05X_PROBE_H

#define EVT2_SE05X_PROBE 0 /* 1 = full probe, 2 = HKDF-only probe */

/* Hang tests (2026-09-27): run the probe this many times per boot, pausing this long before every step (test "3a"). */
#define EVT2_SE05X_PROBE_LOOPS    5
#define EVT2_SE05X_PROBE_PAUSE_MS 0

#if EVT2_SE05X_PROBE
void app_se05x_probe(void);
#endif

#endif /* APP_SE05X_PROBE_H */
