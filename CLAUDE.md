# exercise1 -- STM32H7S3V8Y6TR CUSTOM BOARD variant (copy of D:\Workspace\SDQRNG, 2026-09-26)

This folder is the custom-board version of the NUCLEO-H7S3L8 project in `D:\Workspace\SDQRNG` (that one stays the
Nucleo build; this one is NOT in git either). Everything below this section describes the shared history.

What changed for the board (schematic from the user, 2026-09-26):
- MCU STM32H7S3V8Y6TR (WLCSP101; first converted for V8T6/LQFP100 by mistake, then retargeted -- same pins,
  only the pin order in the generated code changed). The .ioc was converted by a script (CubeMX "Import Project" refuses multi-context
  projects). The `.cproject` MCU was set to STM32H7S3V8Yx by hand: the first generation's CubeIDE update service
  failed and dropped `Drivers`/`Middlewares` from the source paths, so if that happens again restore the
  `.cproject` from a good copy.
- External flash: GD25Q128E, 16 MB quad SPI, 3.3 V, on XSPIM **port 1** (PO0 NCS1, PO4 CLK, PP0-3 IO0-3). This package has
  no port N / XSPI2. ExtMem Manager `EXTMEM_LINK_CONFIG_4LINES`, XSPI1 Micron (standard) mode, 128 Mbit. HSLV is OFF
  (`SBS.XSPIM1/2=Disable` in the .ioc = the HSLV setting): never enable it at 3.3 V, and the XSPI1_HSLV option byte
  must stay off too. The XSPI1 compensation cell is enabled in Boot's and the loader's `HAL_MspInit` USER CODE
  (CubeMX only generates it together with HSLV). The SFDP driver raises the clock only for octal DTR, so the quad
  flash runs at its 50 MHz default: XIP is slower than on the Nucleo; raising it needs the ExtMem MaxFreq setting
  and a hardware test. Appli linker `__FLASH_SIZE` = 16 MB.
- External loader: ST's Nucleo loader does not fit. Build `ExtMemLoader` (name `EVT2_V8Y_GD25Q128E`, 4096 x 4 KB
  sectors) and copy `ExtMemLoader/Release/exercise1_ExtMemLoader.elf` to CubeProgrammer's `ExternalLoader` folder as
  `EVT2_V8Y_GD25Q128E.stldr` (postbuild.sh does it when STM32_PRG_PATH is set). Not tested on hardware.
- HSE: ECS-1612MV-240 24 MHz oscillator on PH0 only -> `HSE-External-Clock-Source` (RCC_HSE_BYPASS, analog bypass:
  the mode the user's test project ran with on this board; digital bypass was used first, untested).
  Its enable OSC_ENABLE (PC15) is driven high in Boot's and the loader's USER CODE Init, before SystemClock_Config();
  the Appli's GPIO default for it is HIGH. HSE only feeds the USB PHY; SYSCLK comes from HSI/PLL as before.
- USB: 3.3 V straight to VDD33USB (the generated code already only enables the voltage detector + HS PHY regulator).
- ADC: noise input PA5 = **ADC2**_INP18 (PA5 does not reach ADC1). hadc2, `PLATFORM_ADC_2`, GPDMA1 request ADC2.
  platform_adc.c refers to hadc1/hadc2 weakly. Check that channel 18 keeps up with the continuous sampling rate.
- I2C1 moved to PB6/PB7 (SE05x + AD5398). SE05x enable = PC14 (SE05x_ENABLE).
- QRNG analog enables (active high, low after reset): PS_FIRST_STAGE_ENABLE PA8, PS_SECOND_STAGE_ENABLE PB14,
  LED_ENABLE PM11 replace OPTO_EN; LED_SINK PO2 = the old AD5398_PD. `qrng_analog_front_end()` in
  qrng_service_adc_noise.c turns them on in that order: **placeholder, the user will give the real power-up
  sequence and delays.**
- Removed (not on the board): debug UART USART3 (app_log() is a no-op; the HAL UART module is gone, platform_uart.c
  returns PLATFORM_NOT_SUPPORTED), user button, ST33_RST, PD13, fingerprint sensor (EVT2_ENABLE_BIOMETRIC=1 is a
  #error in board.h). platform_gpio gained ports M..P.
- ExtMem Manager middleware = the user's patched copy from D:\STM32H7S3_SDCARD (2)\STM32H7S3_SDCARD (1S1S4S/6Bh quad
  read, QE for QER 001b/110b, SAL_XSPI_EnableMapMode() line modes; verified there: Boot -> XIP jump). CubeMX Generate
  overwrites Middlewares\ with ST's originals: run `Patchespply_extmem_patch.bat` after EVERY generate (the fixed files
  are kept in `Patches\STM32_ExtMem_Manager`). Longer term: move to an EXTMEM_USER driver (decision pending).
- SAFETY LOCK (board hardware problem): `BOARD_QRNG_ANALOG_ENABLE 0` in board.h. qrng_service_init() keeps
  PS_FIRST/PS_SECOND/LED_ENABLE low, powers the AD5398 down (register PD bit + LED_SINK = PD pin high, active high per
  the driver) and returns QRNG_ERROR; nonces fall back to the TRNG. Boot and the loader also drive the three enables
  low in USER CODE Init. Do not set it to 1 until the hardware is fixed and the power-up sequence is known.
- Hardware bring-up 2026-09-26 (real board, SWD + USB): Boot -> XIP from GD25 -> Appli runs; HSE ready; USB CDC
  enumerates (COM18); HELLO OK.
- Secure element is an **SE050F2HQ1/Z018HZ**, not the SE052F of the dev board. GET DATA IDENTIFY (temporary
  `EVT2_SE05X_IDENTIFY` diagnostic, kept in security_service_se052f.c, off) returned OEF ID 0x0001A92A, FIPS mode 1,
  applet 3.6.0. Hence: `SSS_HAVE_SE05X_VER_03_XX 1` (fsl_sss_ftr.h) and the NXP factory keys for SE050F2 A92A
  (`EVT2_SCP03_SE050F2_A92A 1` in scp03_keys_cfg.h). With these SCP03 authenticates; SHA-256 and get-random work.
  Failed SCP03 attempts made while finding this: ~3 with the SE052 test key, 1 with the SE052 B501 default.
  SE_RESET_LOGIC is really 1 (active high, right for SE050): the "active-low for SE052F" comments are stale.
- OPEN: applet 3.x has no ECDH-into-object, so `security_service_ecdh_to_secret()` returns SEC_ERROR and the CA
  handshake cannot complete on this board. Also untested on this chip: HKDF, transient HMAC keys, ECDSA/RSA sign
  (FIPS mode may restrict some), and the CA identity/keys are not provisioned on the new SE050.
- SE050F2 "6985 on everything" was a PORT BUG, not the chip (found 2026-09-27): `se05x_platform_scp03.c` hard-wired
  the Platform SCP03 counter model to kSSS_AuthType_AESKey (applet >= 4.3, SE052F: every command advances the
  counter). NXP's fsl_sss_se05x_apis.c picks it by applet version; SE050 applets (3.x) need kSSS_AuthType_SCP03
  (commands without a data field do not advance it, their response ICV uses counter - 1). With AESKey, the first
  no-data command (GetVersion, ReadECCurveList, ...) desynchronised the channel and every later command failed
  with 6982/6985. Now chosen from SSS_HAVE_SE05X_VER_GTE_07_02. Proven with a sequence test (write OK before a
  no-data command, 6982/6985 after it; all 9000 with the fix). Docs read on the way, all in
  C:/Users/Huyvoker/Downloads/SE05x: AN12413 (SE050 APDU spec, applet 3.x), AN12436 (configurations and default
  keys), AN12514 (user guidelines A-D), AN12543 (applet 7.x), AN14028 (moving from SE050F to SE052F).
- Capability probe with the fix (`Core_app/App/app_se05x_probe.c`, EVT2_SE05X_PROBE 0 = off): OK = random, SHA-256,
  EC gen/sign/verify/read-pub on all 7 curves, EC public-key import, secret store/load, plaintext EC key-pair import,
  transient EC key, transient HMAC key + HMAC, RSA 2048/3072 gen + v1.5/PSS sign/verify + public-key read/import.
  NOT working: ECDH to host (6985 -- FIPS forbids it, AN12413 3.10), ECDH into an object (not in applet 3.x), HKDF
  (6A80: security_service uses Se05x_API_HKDF_Extended; check the 3.x HKDF form). RSA-4096 key generation is
  disabled on SE050F (AN12436 2.1, not tested). So the CA handshake (ECDH + HKDF on the SE) cannot run on this
  chip as designed.
- AN12436/AN12514: SE050F makes Platform SCP03 mandatory and says the default Platform SCP keys MUST be updated
  (the chip does not enforce it: it works with the defaults).
- Diagnostics left in the code, all off: EVT2_SE05X_IDENTIFY, EVT2_SE05X_STATE_DIAG (scp03_keys_cfg.h),
  EVT2_SE05X_PROBE (app_se05x_probe.h).
- HARD HANG (2026-09-27), found and fixed: the board froze (SWD could not reach the core, only a power cycle helped)
  while the SE050F2 did long work. Tools added for a board with no UART and no NRST:
  - IWDG in the .ioc (Appli, prescaler 256, reload 4095 = ~32.8 s), refreshed in the main loop; frozen while SWD
    halts the core. Script: scratchpad ioc_add_iwdg.py (to_v8t.py notes it).
  - Post-mortem trace `Core_app/App/app_trace.c/.h` (EVT2_TRACE): fixed-address record at 0x24071800 (NOLOAD,
    non-cacheable, survives IWDG/fault resets) with last breadcrumbs (command begin/end via a weak hook in
    command_protocol.c, every I2C transfer via a weak hook in platform_i2c.c, USB IRQ, poll stages, main loop),
    fault frame from HardFault/MemManage/BusFault/UsageFault/NMI (then reset), and the last 8 runs with RCC_RSR.
  Findings: every hang ended in an I2C read of the SE050 (0x48) during RSA key generation; with SWD alive the CPU
  sat in HAL_Delay between polls while the SE050 NACKed for 30+ s. Not the XSPI link (25 MHz + sample shift: no
  change). Cause: the T1oI2C back-off polls a busy SE05x every 1-2 ms. Fix: EVT2_SE05X_POLL_MIN_MS 10 in
  phNxpEsePal_i2c.c (minimum 10 ms between polls) -> 5/5 probe loops (190 s continuous SE050 work, 10 RSA key
  generations) with no reset. EVT2_XSPI_AB_SLOW (Boot extmem_manager.c) and EVT2_SE05X_PROBE_LOOPS/PAUSE_MS are
  test switches, left off.
- Flashing while the Appli runs XIP: use mode=UR; a HOTPLUG connect fails with "failed to erase memory".
- HKDF on the SE050F2 is NOT available (settled 2026-09-27). With the applet 3.x HKDF form (Se05x_API_HKDF,
  AN12413 4.14.1; security_service_hkdf_export() now uses it when SSS_HAVE_SE05X_VER_GTE_07_02 is 0) the chip answers
  6985 for every variant (no salt / 32-byte salt / L = 64, transient AND persistent HMAC key) while HMAC with the same
  key works. The applet feature bitmap is 0x61D2 (CONFIG_FIPS_MODE_DISABLED = 0 -> FIPS mode; no PBKDF/TLS/RSA_PLAIN),
  and NXP's own middleware skips its HKDF and ECDH examples when built for FIPS (Plug&Trust v02.12 release notes;
  ex_sss_hkdf.c expects HKDF to fail under SSS_HAVE_FIPS). The old 6A80 came from HKDF_Extended (applet 7.x form).
  So on this chip both ECDH and HKDF must run on the MCU; the SE050F2 can still sign (ECDSA identity), verify and HMAC.
  Re-checked after the user pointed at AN14028 table 1 (it lists an HKDF difference for applet 3.6, so the command
  exists): security_service_debug_hkdf_cases() (EVT2_SE05X_HKDF_CASES, off) tried 8 cases -- transient/persistent key,
  no policy / explicit policy with ALLOW_KDF, 16/32/64-byte key, SHA-256/384/512, salt + 32-byte info + L 64: every
  key write 9000, every HKDF 6985 (raw SW from Se05x_API_HKDF). Free transient memory 607 B (RSA keygen works with
  it). Still unexplained by the docs on this PC; the SE050F user guidelines (AN13482) or the SE050 FIPS 140-2
  Security Policy (approved services list) should settle whether HKDF is disabled in FIPS approved mode.
- Tools/ (2026-09-27): ca_provision.py + its dependencies ca_tool.py, evt2_cli.py (copies of D:/EVT2/tools -- keep
  them in sync by hand) and the CA: Tools/ca/root (root cert + PRIVATE key), Tools/ca/issuing (intermediate CA +
  issued.json), Tools/ca/provisioned/<UID>/. Same test PKI as D:/EVT2/tools/dev_ca (same root and issuing CA), so the
  EVT2 PC peers (ca_peer_sim.py / pc_call_peer.py, identity device_2) and this board trust each other. See Tools/README.md.
- RANDOM NUMBERS (2026-09-27): every host-side consumer takes QRNG first, MCU TRNG fallback, through ONE function,
  qrng_service_random_bytes() (Middleware/QRNG; counters g_random_chunks_qrng / g_random_chunks_rng for SWD):
  CA BEGIN nonce (ca_protocol.c), ML-DSA seed (security_protocol.c -- had no fallback, so ML-DSA keys could not be
  made on this board before), PQClean randombytes() (pqc_randombytes.c). The Security service must not depend on the
  QRNG service, so the App registers it: security_service_set_random_source() in app_init() (before
  security_service_init()); the backend's host_random() then feeds the software ECDH key, the RSA-PSS salt,
  security_service_get_random() (SEC_CMD_GET_RANDOM -- no longer the SE's DRBG) and, through the weak hook
  se05x_port_host_random() in the SE05x port (fsl_sss_user_impl.c), the SCP03 host challenge. media_protocol.c's
  nonce pool already did QRNG -> TRNG itself (unchanged). Not changed on purpose: qrng_protocol.c GET/STREAM_ENTROPY
  (must be real QRNG output or an error), the QRNG extractor's own seeds (extractor.c, toeplitz_util.c: TRNG, they seed
  the QRNG itself), and randomness generated INSIDE the SE050 (on-chip key generation, ECDSA nonce).
  Verified on the board (QRNG locked, so every draw fell back to the TRNG, counted): SCP03 opens at boot (1 chunk),
  GET_RANDOM, hybrid + classical CA handshakes (3 chunks per BEGIN), ML-DSA-44 key creation now works (this created
  the persistent seed object for ML-DSA-44 in the chip).
- CA identity PROVISIONED into the SE050F2 (2026-09-27) with Tools/ca_provision.py (this project; GUI, or --cli
  provision|info|refresh-token|erase). Identity key generated INSIDE the chip, CN = the chip's real UNIQUE_ID
  04005001B5747A2B4055AD04493112482590, signed by Tools/ca (EVT2 DEV Issuing CA), 10-year cert + status token,
  no object policy. Record: Tools/ca/provisioned/<UID>/.
  - Factory image only: build with EVT2_FACTORY_PROVISION=1 (Appli Release C define; toggle with
    `python Patches/factory_flag.py on|off`, then rebuild). Adds CMD_TYPE_PROVISION 0x16 =
    App/protocol_adapters/provision_protocol.c (GET_INFO, GEN_IDENTITY, SIGN_POP, WRITE_BLOB, READ_BLOB, FINALIZE,
    ERASE) over Middleware/CA/ca_provision.c. The product image has none of it (checked: 0 provision symbols, the
    tool gets no answer). ALWAYS flash the product image again after provisioning -- the board now runs it.
  - Object ids/sizes moved to Middleware/CA/ca_store.h (shared by ca_service.c and ca_provision.c).
    New security_service_read_unique_id() (works in FIPS mode). ca_service_init() now also checks that the stored
    certificate's public key equals the chip key and its CN equals the device id (CA_ERR_KEY_MISMATCH), as its
    header already promised. New CA_ERR_EXISTS.
  - Verified on the board: provision 13/13, re-provision refused, refresh-token, erase + re-provision; then with the
    product image, real handshakes board <-> tools/ca_peer_sim.py --software device_2 over tools/relay_server.py:
    hybrid ML-KEM-768 (board initiator) and classical (board responder, software ECDH + MCU HKDF) both
    "HANDSHAKE COMPLETE -- mutual confirmation verified". Audio/video call with the phone not run yet.
- AD5398 PD safety gap closed (2026-09-27): PO2 (PD, active HIGH) was LOW by default (.ioc PinState RESET), so the
  AD5398 sink was ON from reset until qrng_service_init() powered it down (after SE050 init, seconds later), and
  ad5398_init() itself drove PD low during the lock path. Now: .ioc PO2.PinState=GPIO_PIN_SET (+ matching
  MX_GPIO_Init), Boot main.c and ExtMemLoader extmemloader_init.c safety blocks also drive PO2 high, and
  ad5398_init() keeps PD high (only ad5398_set_current_ua() releases it). Checked over SWD after reflash:
  PA8/PB14/PM11 outputs low, PO2 output high. Keep BOARD_QRNG_ANALOG_ENABLE 0 until the analog block is repaired.
- CA key derivation in MCU software (2026-09-27) -- the SE050F2 only breaks CA_CMD_DERIVE_KEYS (ECDH + HKDF);
  identity signing, chain/transcript verify and the confirm HMAC stay in the chip. Wire format unchanged.
  - p256-m (Mbed TLS author, Apache-2.0, constant time) vendored byte-identical in
    Core_app/Middleware/Security/p256-m/ (README_EVT2.txt has the commit). Only the Security backend uses it.
  - security_service_se052f.c "Software ECDH" section (only when SSS_HAVE_SE05X_VER_GTE_07_02 == 0):
    generate_ephemeral_ec_keypair() keeps a P-256 key in MCU RAM (2 slots), read_ec_public_key()/ecdh_to_host()/
    delete_key()/key_exists() serve those ids; randomness = SE050 GetRandom XOR MCU TRNG; RFC 5903 8.1 KAT at
    security_service_init() (s_soft_ecdh_ok, fail closed). New security_service_derives_in_chip() (false here).
  - ca_protocol.c DERIVE_KEYS: the classical suite takes the host-side branch when !derives_in_chip():
    IKM = Z_ecdh (hybrid: Z_ecdh || Z_kem), software HKDF-SHA256 with the same salt/info (RFC 5869 = what the
    SE052F computes), confirm key written back as a transient HMAC key. BEGIN's nonce falls back to the MCU TRNG
    when the QRNG is unavailable (it is locked off on this board).
  - app_init() now calls platform_rng_init()/platform_hash_init()/platform_crypto_init(). Before, only
    qrng_service_init() did, and the QRNG safety lock returns before that -- so on this board TRNG, HASH and
    CRYP were never attached (media AES-GCM, HKDF/HMAC and the nonce fallback would all have failed).
  - Verified on the board: build 0 errors/0 warnings; KAT passes on chip (s_soft_ecdh_ok = 1 over SWD); HELLO OK;
    CA GET_IDENTITY/BEGIN answer CA_NOT_READY because the SE050F2 has NO CA identity yet. A real handshake
    (tools/ca_peer_sim.py --device COM18 vs --software device_2) needs the identity key + 6 blobs provisioned first
    -- done later the same day, see "CA identity PROVISIONED" above.
- Status: Boot, Appli (Debug/Release) and ExtMemLoader build with 0 errors; a second CubeMX generation keeps all
  USER CODE. NOTHING has run on the custom board yet. First bring-up: SWD connect, boot, flash through the new
  loader, USB CDC enumeration, then QRNG once the analog sequence is known.

# exercise1 -- EVT2 firmware port to STM32H7S3 (NUCLEO-H7S3L8)

This project is NOT in git. The full handoff (what was ported, verified results, open issues, next steps) is in
`D:\EVT2\CLAUDE.md`, section "2026-09-25: PORT sang STM32H7S3". Short version:

- All port code lives in `Appli/` (XIP app at 0x90000000): `Appli/Core_app/` (EVT2 Core_app, platform layer rewritten
  as `Platform/STM32H7RSxx`), `Appli/Core_app/BSP/bsp_h7s3.c` (the few things CubeMX does not generate),
  `Appli/USB_DEVICE/` (USB_OTG_HS CDC), linker `Appli/STM32H7S3L8HX_ROMxspi1.ld` (DTCM / AXI / 8KB non-cacheable DMA
  window / AHB SRAM).
- Rule from the user: port changes go here, never into D:\EVT2.
- CURRENT STATE: the firmware flashed last (build 06:45) contains an experimental USB RX flow control in
  `USB_DEVICE/App/usbd_cdc_if.c` + `platform_usb_rx_free()` that made things WORSE -- remove or debug it first.
  Without it, and with the ST FIFO sizes (RX 0x200 / TX0 0x40 / TX1 0x80), echo 1..49150 B worked and 4 KB echoes ran
  at ~21 Mbps per direction.
- Flash with ST's loader `MX25UW25645G_NUCLEO-H7S3L8-XSPIM1.stldr`; the custom `exercise1_ExtMemLoader` is flaky.
- Regenerating code from exercise1.ioc may drop the hand-added HAL modules/links -- see the EVT2 CLAUDE.md section.
- AES-256-GCM (2026-09-26): `platform_crypto.c` builds GCM from single-block hardware AES + software GHASH, because
  the H7RS CRYP/SAES HAL computes the wrong result for lengths that aren't a multiple of 16. `ghash_mul` is branch-free
  (H is secret), and decrypt zeroes `plain_out` on failure. `stm32h7rsxx_hal_cryp.c` is back to the ST V1.3.0 original:
  the NPBLB-for-decrypt patch did not fix the bug, so do not re-apply it. Checked on the board over USB (CA handshake,
  then board vs Python `cryptography` AESGCM, lengths 1..20001, both directions, tampered tags rejected): all pass.
- `Core_app/Drivers/AD5398/AD5398.c` includes `bsp_hal.h` (was the H753 `stm32h7xx_hal.h`, which broke the build).
- Release build (2026-09-26): `-O3 -g0`, no `DEBUG` define, the same settings as EVT2 Release; otherwise identical to Debug.
  Launch config: `Appli/exercise1_Appli Release.launch` (`Release/exercise1_Appli.elf`). Verified on the board: boot OK,
  and the GCM interop test passes. `-O3` adds 3 `-Wmaybe-uninitialized` warnings in ST's `stm32h7rsxx_hal_dma_ex.c`
  (vendor code, false positives).
- AD5398 (2026-09-26): `Core_app/Drivers/AD5398/ad5398.[ch]` was rewritten to follow the project layering (only
  `platform_i2c`/`platform_gpio` plus `board.h`: `BOARD_AD5398_I2C` = I2C1, shared with the SE052F; `BOARD_AD5398_PD_GPIO`
  = PE11, active high). `qrng_service_init()` sets `BOARD_QRNG_DRIVE_CURRENT_UA` (20 mA, code 171 = 20.04 mA) before
  OPTO_EN and the settle delay, and fails if the chip does not ACK or the readback differs. `qrng_service_deinit()`
  powers it down. On the board: QRNG init OK and the CA handshake over the shared bus still works. Raw ADC noise stats
  did NOT change versus the build without the driver (mean ~1267, std ~625-630), so check the actual sink current
  with a meter.
- EVT2_DIAGNOSTICS (2026-09-26): ONE compiler define now gates every self-test, benchmark and diagnostic; it replaces
  `EVT2_RUN_SELF_TESTS`. With it at 0 or undefined, none of the following is compiled:
  - `app_self_test.[ch]` and `bsp_port_self_test.c`, including the GCM edge-size test (now 2 buffers, and it
    returns false when a length fails);
  - the qrng_service `self_test_*`/`debug_*` functions, the boot ADC-rate diagnostic, and per-draw timing;
  - QRNG wire sub-commands 0x0C-0x10 (BENCH_NOISE/ENTROPY, STREAM_DEBUG_TIMING, ECHO, NONCE_POOL_STATUS);
  - the MEDIA_PING debug-timing PONG (a plain PING still works);
  - the `[media dbg]`/`[cp dbg]` logs, the command_protocol send/receive timing, and the nonce statistics;
  - `ca_protocol_test_set_peer_id()`;
  - FPC `fpc_sample_logf` + the user-button test hook, and the vendor example/test files
    (`Drivers/SE05x/tests`, `Drivers/FPC5234/tests`).
  Set it only as a compiler define. The Debug config lists `EVT2_DIAGNOSTICS=0`; change it to 1 there. The global
  `DEBUG` symbol was removed because it silently enabled SE05x `aes_cmac.c` printf of CMAC subkeys.
  Security flags (`EVT2_MEDIA_ALLOW_UNAUTHENTICATED`, `EVT2_SCP03_USE_TEST_KEYS`, `EVT2_CA_ALLOW_TEST_IDENTITY`)
  stay separate on purpose. Also fixed: `qrng_service_get_noise()` had its not-ready `return` commented out.
  Release without diagnostics: code 176.8 KB (was 187.7), AXI free 91.5 KB (was 54.3). With EVT2_DIAGNOSTICS=1 it
  builds; AXI free is 20.7 KB. Host tools and the Android Debug tab that use 0x0C-0x10 or the PING timing need a
  diagnostics build.
- EVT2_ENABLE_BIOMETRIC (2026-09-26): compiler define (0/undefined = current hardware, no fingerprint sensor; the
  Debug config lists `EVT2_ENABLE_BIOMETRIC=0`). It gates the whole FPC2530/FPC5234 stack:
  - `Drivers/FPC5234/*.c`; the vendor tests need both flags;
  - `Middleware/Biometric/FPC5234`, `biometric_protocol.c`, and the CMD_TYPE_BIOMETRIC registration in `app_main.c`
    (unregistered = answered like an unknown type);
  - `app_biometric_self_test()`;
  - in `bsp_h7s3.c`: the FPC pins (PC0/PA3/PF11/PF15), EXTI11, USART1 + GPDMA1 ch1/ch2, and their IRQ handlers.
    OPTO_EN was split out of the shared PC0|PC3 init, so it is still configured.
  Platform stays generic: the `huart1` object remains but is never initialised, so `platform_uart_init(PLATFORM_UART_1)`
  returns ERROR. The 512 B TX bounce buffer in `platform_uart.c` stays.
  All four EVT2_DIAGNOSTICS x EVT2_ENABLE_BIOMETRIC combinations build (0 errors). The Release build without
  biometric has 165.5 KB of code (was 176.8 KB). Not yet flashed: the board was not connected.
- CubeMX now owns the Appli init (2026-09-26). `exercise1.ioc` describes everything the running code uses; generated
  code builds identically, checked symbol by symbol against the previous ELF. Backup of the tree before this:
  `D:\Workspace\SDQRNG_backup_2026-09-26`.
  - Configured in the .ioc:
    - GPIO: OPTO_EN PC3, SE052_EN PF3, ST33_RST PE9, AD5398_PD PE11, USER_BUTTON PC13 EXTI13.
    - ADC1: PC4/INP4, sync PCLK/4, continuous, TIM1 TRGO, DMA circular, 47.5 cycles.
    - TIM1 (TRGO update, period 1790), I2C1 PB8/PB9 (Timing 0x30929BBB), USART3 PD8/PD9 921600.
    - CRYP (GCM placeholder), HASH (SHA256, byte swap), RNG, CRC.
    - USB_OTG_HS device + USB_DEVICE CDC_HS: VID/PID 0x0483/0x5740 and the EVT2 strings; APP_TX 512, because HS
      needs a multiple of 512.
    - MPU regions 0/1/2 (region 2 = .dma_noncache, fixed at 0x24070000); NVIC.
    - Heap/stack 0x4000/0x7000: CubeMX writes these into the linker script.
  - Boot's SystemClock_Config() now turns on HSE (USB PHY) and HSI48 (RNG), so the Appli no longer does it at run
    time. **Reflash Boot as well as Appli.**
  - I2C1 needs the FLASH IP active: on H7RS, I2C1/I3C1 are one block selected by option byte I2C_NI3C, and
    `MX_FLASH_Init()` only programs it if it is not already I2C.
  - Still hand-written, not expressible in the .ioc:
    - `bsp_h7s3.c` holds only: bsp_early_init() (AHB SRAM zero-fill + D-Cache clean before MPU_Config(), and a check
      that the linker window equals the MPU region 2 address), and the FPC2530/USART1 stack under
      EVT2_ENABLE_BIOMETRIC.
    - EVT2 logic in USER CODE blocks: ADC calibration (MX_ADC1_Init), the CDC RX push into the Platform ring and
      line coding (usbd_cdc_if.c), and the hUsbDeviceHS extern (usb_device.h).
  - CubeMX re-adds `DEBUG` to the Debug config on every generate, so SE05x `aes_cmac.c` now uses its own
    `AES_CMAC_DEBUG` guard instead (before this, DEBUG made it print CMAC subkeys).
  - Pitfalls found while building the .ioc (CubeMX -q hangs on a hidden error dialog):
    - an invalid value, e.g. APP_TX_DATA_SIZE not a multiple of 512;
    - `MANUFACTURER_STRING` has no `-CDC_HS` suffix.
  - Status: builds (Appli Debug/Release, BIO/DIAG on and off, Boot). NOT yet flashed or tested on the board.
  - ADC1's DMA is in the .ioc as well (2026-09-26): GPDMA1 ch0, request ADC1, circular (linked list), halfword to
    halfword, memory increment, single burst, LOW_PRIORITY_HIGH_WEIGHT, NVIC priority 0. CubeMX generates
    MX_GPDMA1_Init() (before MX_ADC1_Init), the list in HAL_ADC_MspInit and GPDMA1_Channel0_IRQHandler in
    stm32h7rsxx_it.c. The node `Node_GPDMA1_Channel0` has section "noncacheable_buffer", which the linker script
    keeps in .dma_noncache (checked: 0x24071000, inside MPU region 2). The same settings as the old hand-written
    bsp_adc1_dma_init(), which was removed. The symbol table matches the old build apart from the renamed DMA objects.
    Not flashed yet.
