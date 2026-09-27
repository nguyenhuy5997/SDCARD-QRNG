#ifndef SCP03_KEYS_CFG_H
#define SCP03_KEYS_CFG_H

/* Which Platform SCP03 static key set security_service_init() authenticates with.
 *   1 = the PUBLIC test key 0x40..0x4F (ENC = MAC): this dev board's SE052F was moved off the NXP defaults onto it.
 *   0 = the NXP factory defaults for the SE052 "B501" OEF.
 * Must match what is actually on the chip, otherwise security_service_init() fails.
 * How the chip got there, and how to go back: docs/SE052F_SCP03_key_rotation.md. */
#define EVT2_SCP03_USE_TEST_KEYS 0

/* 1 = NXP factory keys of the SE050F2 with OEF 0x0001A92A (Plug&Trust ex_sss_tp_scp03_keys.h,
 * SSS_PFSCP_ENABLE_SE050F2_0001A92A). The STM32H7S3V8Y6TR board carries an SE050F2HQ1/Z018HZ: its GET DATA IDENTIFY
 * returned configuration ID 00 01 A9 2A.., FIPS mode 1, applet 3.6.0 (2026-09-26). Takes precedence over the flag above. */
#define EVT2_SCP03_SE050F2_A92A 1

/* TEMPORARY: 1 = security_service_init() only reads the SE05x IDENTIFY data (no SCP03 attempt). Set back to 0. */
#define EVT2_SE05X_IDENTIFY 0
/* TEMPORARY: 1 = after SCP03 auth, GetFreeMemory/GetVersion/ReadIDList + one tiny write test. */
#define EVT2_SE05X_STATE_DIAG 0
/* TEMPORARY: security_service_debug_write_persistent_hmac_key() for the HKDF probe. */
#define EVT2_SE05X_HKDF_PERSIST_TEST 0
/* TEMPORARY: security_service_debug_hkdf_cases() (8 HKDF cases, results in RAM), called from main.c after init. */
#define EVT2_SE05X_HKDF_CASES 0

#endif
