/**
 * @file    app_main.h
 * @brief   App-layer entry points -- bring-up and USB/command-protocol wiring (what a product build needs).
 *
 * Self-test entry points (dev/QA builds only) moved to app_self_test.h on 2026-09-24 -- see that header's own doc
 * comment for why. A product build includes only this header/its .c; a dev/QA build additionally includes
 * app_self_test.h and links app_self_test.c.
 */
#ifndef APP_MAIN_H
#define APP_MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/** Bring up the App-layer peripherals this module needs (currently just
 *  the debug UART) on top of what generated init code already brought
 *  up. Call once, after main()'s MX_*_Init() calls. */
void app_init(void);

/** Bring up platform_usb.h (USB CDC) and Middleware/CommandProtocol,
 *  registering the Security/Biometric/QRNG/CA/Media command adapters.
 *  Call once, after app_init() (and, on a dev/QA build that also runs
 *  app_self_test.h's self-tests, after those -- they exercise Security/
 *  Biometric/QRNG directly; this exposes the same services to a host
 *  over USB instead). Returns false if platform_usb_init() or
 *  command_protocol_init() fails. */
bool app_command_protocol_init(void);

/** Drain and dispatch any pending USB command-protocol traffic. Call
 *  every iteration of main()'s while(1) loop -- never blocks. */
void app_command_protocol_poll(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_MAIN_H */
