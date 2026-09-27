# Plug and Trust STM32H753 port (SE052F, I2C)

Porting package extracted from `simw-top` Plug and Trust Middleware
v04.08.01, for an STM32H753 (STM32CubeIDE, bare metal / HAL, no RTOS)
talking to an **SE052F** over I2C using **T=1 over I2C** (UM11225).

Unlike the rest of this package, `platform/stm32h7/src/i2c_stm32h7.c` and
`ax_reset_stm32h7.c` are **not** self-contained: they call into
`Core_app/Platform` (`platform_i2c.h`/`platform_gpio.h`) and reference
`BOARD_SE052_I2C`/`BOARD_SE052_EN_GPIO` from `Core_app/BSP/board.h` -- the
one file for the whole project that maps every board pin/bus to a name,
so changing a pin only means editing that one file instead of hunting
through every driver. Porting this SE05x folder to a project that does
not have `Core_app/Platform`/`Core_app/BSP` means either bringing both
along or replacing those two references with your own HAL calls.

Scope: SE05x transport + APDU layer only (`HOSTCRYPTO_NONE`, `SCP_NONE`,
session-less auth by default). No SSS runtime. An opt-in Platform SCP03
transport-encryption add-on is included -- see "Enabling Platform SCP03"
below -- but is off unless you turn it on. See "What is intentionally not
included" before assuming any other capability is present.

## Layout

- `config/fsl_sss_ftr.h` -- feature-selection header for this build (applet,
  reset polarity, host-crypto/SCP selection). Read this file's comments
  before changing anything; the "exactly one of these must be 1" checks
  are enforced by `#error`.
- `middleware/hostlib/inc` -- SE05x/APDU constant and type headers.
- `middleware/hostlib/platform/inc` -- the porting contracts this package
  implements (`i2c_a7.h`, `ax_reset.h`, `se05x_reset_apis.h`,
  `sm_timer.h`, `sm_printf.h`).
- `middleware/hostlib/libCommon/infra` -- `SM_Connect`/`SM_Close`/`GP_Select`
  (`sm_connect.c`, `global_platf.c`) and APDU/error/print helpers.
- `middleware/hostlib/libCommon/log` -- the generic (`AX_EMBEDDED`) logger.
- `middleware/hostlib/libCommon/smCom` -- generic transport dispatch plus
  the T=1oI2C (ISO7816-3/UM11225) protocol state machine under `T1oI2C/`.
- `middleware/hostlib/se05x/src` -- TLV/APDU engine (`se05x_tlv.c`), ECC
  curve tables (`se05x_ECC_curves.c`), and `se05x_session_none.c` (see
  below -- this file is **not** from upstream NXP source, it is new glue
  code required by this reduced port).
- `middleware/hostlib/se05x_03_xx_xx` -- the generated SE05x APDU command
  layer (`Se05x_API_*`) and personalization APDUs.
- `middleware/sss/inc`, `middleware/sss/port/default` -- the small type
  headers (`tlvHeader_t`, `fsl_sss_types.h`) that the APDU/session layer
  needs by value; no SSS session/runtime implementation is included.
- `platform/stm32h7` -- the adapters written for this port: I2C
  (`i2c_stm32h7.c`), SE052F enable/reset GPIO (`ax_reset_stm32h7.c`) and
  timing (`sm_timer_stm32h7.c`) all go through `Core_app/Platform`
  (`platform_i2c.h`/`platform_gpio.h`/`platform_time.h`) instead of
  calling STM32 HAL directly, so this port's own code has no
  `hi2c1`/`SE052_EN_Pin`/`HAL_Delay`/DWT references. Platform itself is
  a thin business-logic wrapper, not an alternative to CubeMX init --
  the CubeMX-generated `hi2c1`/GPIO config in `Src/main.c` still has to
  run first (see "Required integration work").
- `Core_app/BSP/board.h` (outside this folder) -- defines `BOARD_SE052_I2C`
  and `BOARD_SE052_EN_GPIO`, referenced directly by `i2c_stm32h7.c` /
  `ax_reset_stm32h7.c`. This is the project's single board pin/bus map,
  shared by every driver, not something private to the SE05x port -- see
  "Required integration work".
- `tests/se052_transport_test.c` -- smoke test: reset the SE052F, open
  T=1oI2C, `SM_Connect` (selects the SE05x applet), call
  `Se05x_API_GetVersion`, `SM_Close`.
- `middleware/sss/src/user`, `middleware/sss/src/se05x`,
  `middleware/hostlib/libCommon/nxScp`, `se05x_platform_scp03.*`,
  `tests/se052_scp03_example.c` -- the opt-in Platform SCP03 (transport
  encryption) add-on; not part of the base build. See "Enabling Platform
  SCP03" below.
- `tests/se052_sign_example.c` -- digital-signature example: ensure a
  NIST P-256 key pair on the SE052F, hash a message with the SE's own
  SHA-256, `Se05x_API_ECDSASign`, `Se05x_API_ECDSAVerify`. Entirely on
  the secure element -- no host crypto needed, matching this port's
  `HOSTCRYPTO_NONE` scope.

## Why `se05x_session_none.c` exists

`Se05xSession_t::fp_TXn` / `fp_RawTXn` (declared in `se05x_tlv.h`) are the
function pointers every generated `Se05x_API_*` call goes through to
reach the wire. Upstream, they are only ever assigned inside the full SSS
layer (`sss/src/se05x/fsl_sss_se05x_apis.c`, not part of this reduced
port). Without an assignment, any `Se05x_API_*` call dereferences a NULL
pointer. `se05x_session_none.c` provides `Se05x_SessionInit()`, a ~30-line
equivalent of the upstream `sss_se05x_TXn`/`sss_se05x_channel_txnRaw` pair
trimmed to the session-less (`kSSS_AuthType_None`, no transform/decrypt)
case, wiring straight to `smCom_TransceiveRaw()`. Call it once after
`SM_Connect()` succeeds, before issuing any `Se05x_API_*` call.

## Required integration work

This port talks to the MCU through `Core_app/Platform`
(`platform_i2c.h` / `platform_gpio.h`) instead of calling STM32 HAL
directly, so its own code has no `hi2c1`/`SE052_EN_Pin` references. It
still requires the CubeMX-generated peripherals to already be initialized,
the same as before -- `Core_app/Platform`'s STM32H7xx backend is a thin
business-logic wrapper around the `hi2c1`/GPIO port CubeMX's
`MX_I2C1_Init()`/`MX_GPIO_Init()` (in `Src/main.c`) set up; it does not
configure clocks/pins/peripherals itself.

1. Edit `Core_app/BSP/board.h` -- **not** a file inside this SE05x folder --
   to define `BOARD_SE052_I2C` and `BOARD_SE052_EN_GPIO` for your board:

   ```c
   #define BOARD_SE052_I2C     PLATFORM_I2C_1
   #define BOARD_SE052_EN_GPIO ((platform_gpio_t){ PLATFORM_GPIO_PORT_E, 14U })
   ```

   `board.h` is the project's single board pin/bus map (every driver reads
   its pins from there, not just this one), so if you are integrating
   this port into a project that does not already have
   `Core_app/Platform`/`Core_app/BSP`, either bring both folders along or
   replace the `BOARD_SE052_I2C`/`BOARD_SE052_EN_GPIO` references in
   `i2c_stm32h7.c`/`ax_reset_stm32h7.c` with your own equivalents.

   Add `Core_app/Platform` and `Core_app/BSP` to your include paths (see
   "STM32CubeIDE build steps" below) so `platform.h` and `board.h` are
   visible.

2. The CubeMX-generated GPIO and I2C initialization (`MX_GPIO_Init()`,
   `MX_I2C1_Init()`, both called from `main()`) must run, and
   `sm_initSleep()` must be called, before opening any Plug and Trust
   session -- `axI2CInit()`/`axReset_HostConfigure()` only attach to
   those already-initialized peripherals through Platform
   (`platform_i2c_init()`/pin read-write calls); they do not bring the
   peripherals up themselves. `platform_i2c_init()` is safe to call more
   than once (e.g. if another driver already attached to the same bus).

3. Retarget `printf()` to your UART in the application if you want to see
   the log/test output (`sm_printf.h` maps `PRINTF` to plain `printf` on
   this target -- see `PLUG_AND_TRUST_STM32` below).

   STM32CubeIDE generates `Core/Src/syscalls.c` with a `_write()` stub
   that newlib's `printf`/`putchar` funnel through. Edit that existing
   function (do not add a second `_write()` elsewhere -- it is not
   `weak`, so a duplicate definition is a link error):

   ```c
   /* Core/Src/syscalls.c */
   #include "usart.h" /* or main.h, wherever CubeMX declares huartX */

   int _write(int file, char *ptr, int len)
   {
       HAL_UART_Transmit(&huart1, (uint8_t *)ptr, (uint16_t)len, HAL_MAX_DELAY);
       return len;
   }
   ```

   Replace `huart1` with whichever UART CubeMX generated for your board's
   debug/VCP port. Newlib buffers `stdout` by default, so early output can
   appear to "stick" until the buffer fills or the program exits; add this
   once near the top of `main()` if you want each `printf()` to flush
   immediately:

   ```c
   setvbuf(stdout, NULL, _IONBF, 0);
   ```

## SE052F reset polarity (read this before wiring the EN/RESET pin)

`se05x_reset_apis.h` documents: *"Select 1 (Active High) for SE050 and
51. Select 0 (Active low) for SE052."* This port's
`config/fsl_sss_ftr.h` sets `SSS_HAVE_SE_RESET_LOGIC_1=0` /
`SSS_HAVE_SE_RESET_LOGIC_0=1`, which is what `SE_RESET_LOGIC` resolves to
-- i.e. the polarity is already correct for the SE052F by construction,
not by an extra override in the platform files. If you ever swap in an
SE050/SE051, flip those two defines in `config/fsl_sss_ftr.h` (and nothing
else needs to change).

## STM32CubeIDE build steps

1. Copy this whole folder into the CubeIDE project, e.g. as
   `Middlewares/plug_and_trust_stm32`.

2. **Project > Properties > C/C++ Build > Settings > MCU GCC Compiler >
   Include paths** -- add all of:
   - `Core_app/Platform` (the `platform.h` HAL this port is built on --
     see "Required integration work" above)
   - `Core_app/BSP` (`board.h`, the project's board pin/bus map --
     see "Required integration work" above)
   - `middleware/hostlib/inc`
   - `middleware/hostlib/platform/inc`
   - `middleware/hostlib/libCommon/infra`
   - `middleware/hostlib/libCommon/log`
   - `middleware/hostlib/libCommon/smCom`
   - `middleware/hostlib/libCommon/smCom/T1oI2C`
   - `middleware/hostlib/se05x/src`
   - `middleware/hostlib/se05x_03_xx_xx`
   - `middleware/sss/inc`
   - `middleware/sss/port/default`
   - `config`
   - `platform/stm32h7/inc`
   - `tests` (only if the application calls into the smoke test)

3. **MCU GCC Compiler > Preprocessor** -- add these symbols:
   - `T1oI2C`
   - `T1oI2C_UM11225`
   - `SSS_USE_FTR_FILE` (makes every hostlib file pick up
     `config/fsl_sss_ftr.h` instead of `fsl_sss_ftr_default.h`, which is
     deliberately **not** copied into this port)
   - `AX_EMBEDDED=1`
   - `PLUG_AND_TRUST_STM32` (selects the plain-`printf` branch in
     `sm_printf.h` instead of `fsl_debug_console.h`, which does not exist
     outside the MCUXpresso SDK)

4. Add these C files to the project:
   - `middleware/hostlib/libCommon/infra/global_platf.c`
   - `middleware/hostlib/libCommon/infra/sm_apdu.c`
   - `middleware/hostlib/libCommon/infra/sm_connect.c`
   - `middleware/hostlib/libCommon/infra/sm_errors.c`
   - `middleware/hostlib/libCommon/infra/sm_printf.c`
   - `middleware/hostlib/libCommon/log/nxLog.c`
   - `middleware/hostlib/libCommon/smCom/smCom.c`
   - `middleware/hostlib/libCommon/smCom/smComT1oI2C.c`
   - `middleware/hostlib/libCommon/smCom/T1oI2C/phNxpEse_Api.c`
   - `middleware/hostlib/libCommon/smCom/T1oI2C/phNxpEseProto7816_3.c`
   - `middleware/hostlib/libCommon/smCom/T1oI2C/phNxpEsePal_i2c.c`
   - `middleware/hostlib/se05x/src/se05x_ECC_curves.c`
   - `middleware/hostlib/se05x/src/se05x_tlv.c`
   - `middleware/hostlib/se05x/src/se05x_session_none.c`
   - `middleware/hostlib/se05x_03_xx_xx/se05x_APDU.c`
   - `middleware/hostlib/se05x_03_xx_xx/se05x_perso_api.c`
   - `platform/stm32h7/src/i2c_stm32h7.c`
   - `platform/stm32h7/src/ax_reset_stm32h7.c`
   - `platform/stm32h7/src/sm_timer_stm32h7.c`
   - `tests/se052_transport_test.c` (smoke test, optional)
   - `tests/se052_sign_example.c` (signing example, optional)

   Do not add any Linux/i.MX/KSDK/Android files, `sci2c*`/`smComSocket*`/
   `smComPCSC*`/other-transport sources, `sm_app_boot.c` (board-bringup
   example code, not part of this port), or `se05x_mw.c` (its one
   function needs `sss/ex/inc/ex_sss_objid.h` and is not used by anything
   else here).

5. Make sure `Core_app/Platform/STM32H7xx/platform_i2c.c` and
   `platform_gpio.c` are also added to the project -- this port calls
   into them, they are not optional. Point
   `BOARD_SE052_I2C`/`BOARD_SE052_EN_GPIO` in `Core_app/BSP/board.h` at
   whichever Platform bus/pin your board actually wires the SE052F to.

6. Call, in this order, before opening a Plug and Trust session:
   `HAL_Init()` -> `SystemClock_Config()` -> `MX_GPIO_Init()` ->
   `MX_I2C1_Init()` -> `sm_initSleep()`. `axI2CInit()` /
   `axReset_HostConfigure()` only attach to those already-initialized
   peripherals through Platform; they do not initialize them.

## SE052F smoke test

```c
#include "se052_transport_test.h"

if (se052_transport_test_run() != 0) {
    Error_Handler();
}
```

`se052_transport_test_run()` powers the SE052F (`axReset_HostConfigure()` +
`axReset_ResetPulseDUT(SE_RESET_LOGIC)`), opens a T=1oI2C session and
selects the SE05x applet (`SM_Connect`), reads back the applet version
(`Se05x_API_GetVersion`), then closes the session (`SM_Close`). It is a
real (if minimal) exercise of the ported middleware, not a hand-rolled
raw-APDU stand-in.

## SE052F digital signature example

```c
#include "se052_sign_example.h"

if (se052_sign_example_run() != 0) {
    Error_Handler();
}
```

`se052_sign_example_run()` opens its own session (same reset + `SM_Connect`
sequence as the smoke test above), then:

1. `Se05x_API_CheckObjectExists()` / `Se05x_API_WriteECKey()` -- ensures a
   NIST P-256 key pair exists at object ID `0x7DCC0001` (change the
   `SE052_SIGN_EXAMPLE_KEY_ID` define if that collides with something you
   already provisioned). The private key is generated on-chip and never
   leaves the SE052F.
2. `Se05x_API_DigestOneShot()` -- hashes a fixed demo message with
   SHA-256 computed *inside* the SE052F. This is what makes signing
   possible without any host crypto library: the digest never needs a
   host-side SHA implementation.
3. `Se05x_API_ECDSASign()` -- signs the digest, returns an ASN.1 DER
   signature.
4. `Se05x_API_ECDSAVerify()` -- verifies the signature against the same
   key's public part, as a sanity check.

To sign your own data instead of the fixed demo message, replace the
`message` buffer in `se052_sign_example.c`; for data too large for one
APDU, use `Se05x_API_DigestInit()` / `Se05x_API_DigestUpdate()` /
`Se05x_API_DigestFinal()` (declared in `se05x_APDU_apis.h`) instead of
`Se05x_API_DigestOneShot()` to hash it in chunks.

## Enabling Platform SCP03 (transport encryption)

By default this port talks to the SE052F in the clear (`HOSTCRYPTO_NONE`,
`SCP_NONE`, session-less). It also includes an opt-in **Platform SCP03**
add-on -- a GlobalPlatform secure channel that AES-128-CBC encrypts and
CMACs every APDU -- built on a small, dependency-free (no mbedTLS/OpenSSL)
software AES/CMAC implementation, so it stays as portable as the rest of
this port. It is off by default; the base smoke test and signing example
above are unaffected either way.

All of the SCP03 add-on's `.c` files are safe to leave permanently in the
CubeIDE project, added or not: every one of them compiles to an empty
translation unit (or, for `se05x_platform_scp03.c`, a stub
`Se05x_Scp03_Authenticate()` that just returns failure) when
`PLUG_AND_TRUST_STM32_ENABLE_SCP03` is undefined, instead of erroring.
Toggling that single preprocessor symbol (plus a Clean build) is enough
to turn the whole add-on on or off -- you never need to add/remove files
from the project to match.

### What's added

- `middleware/sss/src/user/crypto/{aes,aes_cmac,aes_cmac_multistep}.{c,h}` --
  a small (~600 line), MIT-licensed, dependency-free software AES-128 /
  CMAC implementation (from `sss/src/user/crypto`; see its `LICENSE`
  file). This is what actually does the encryption/MAC math.
- `middleware/sss/src/user/fsl_sss_user_impl.c` + `middleware/sss/inc/fsl_sss_user_apis.h`
  + `fsl_sss_user_types.h` -- the "host crypto" backend (`SSS_HAVE_HOSTCRYPTO_USER`)
  that wraps the AES/CMAC primitives above in the generic `sss_host_*`
  session/keystore/symmetric/mac API that `nxScp03_Com.c` and
  `fsl_sss_se05x_scp03.c` are written against. **Edited from upstream**:
  the RNG functions (`sss_user_impl_rng_*`) originally seed libc `rand()`
  from `time(NULL)` -- a weak, and on bare metal without an RTC,
  *identical-every-boot* source of "randomness" for the SCP03 host
  challenge. This port's copy uses the STM32H7's own hardware TRNG
  (`HAL_RNG_GenerateRandomNumber()`) instead.
- `middleware/sss/src/se05x/fsl_sss_se05x_scp03.c` + `middleware/sss/inc/fsl_sss_se05x_scp03.h` --
  `nxScp03_AuthenticateChannel()`: the actual GP INITIALIZE UPDATE / session-key
  derivation / GP EXTERNAL AUTHENTICATE handshake. Unmodified upstream.
- `middleware/hostlib/libCommon/nxScp/nxScp03_Com.c` -- per-APDU
  encrypt/MAC (`nxSCP03_Encrypt_CommandAPDU`, `nxpSCP03_CalculateMac_CommandAPDU`)
  and response decrypt/verify (`nxpSCP03_Decrypt_ResponseAPDU`). Wired to
  `se05x_Transform_scp`/`se05x_DeCrypt` that were already compiled into
  `se05x_tlv.c` in the base port (they are
  `#if SSS_HAVE_SCP_SCP03_SSS`-guarded there and simply inert until now).
  **One small edit from upstream**: this file's own guard is only
  `#if !defined(USE_THREADX_RTOS)` -- upstream relies on its build system
  to add the file only when SCP03 is actually enabled, so it otherwise
  hits `#error "No hostcrypto"` unconditionally. This port instead adds
  an `#if SSS_HAVE_HOSTCRYPTO_ANY` guard around the body so the file is
  a harmless no-op with `PLUG_AND_TRUST_STM32_ENABLE_SCP03` undefined,
  and can stay in the project either way.
- `middleware/hostlib/se05x/src/se05x_platform_scp03.{c,h}` (new glue,
  not from upstream) -- `Se05x_Scp03_Authenticate()`: sets up the
  host-crypto session/keystore, the 2 static + 3 session key objects,
  runs the handshake, and rewires the `Se05xSession_t` (from
  `Se05x_SessionInit()`) to route every following `Se05x_API_*` call
  through SCP03. This is the piece with no ready-made non-SSS source
  anywhere in the tree; it mirrors (does not copy) the equivalent
  `kSSS_AuthType_SCP03` branch in `sss/src/se05x/fsl_sss_se05x_apis.c`.
  With `PLUG_AND_TRUST_STM32_ENABLE_SCP03` undefined,
  `Se05x_Scp03_Authenticate()` compiles to a stub that just returns
  `kStatus_SSS_Fail` -- so `tests/se052_scp03_example.c` can also stay in
  the project unconditionally.
- `config/fsl_sss_ftr.h` -- a single file for both build modes:
  `SSS_HAVE_HOSTCRYPTO_USER` / `SSS_HAVE_SCP_SCP03_SSS` switch to `1`
  (from the base `HOSTCRYPTO_NONE=1` / `SCP_NONE=1`) automatically when
  `PLUG_AND_TRUST_STM32_ENABLE_SCP03` is defined -- no separate config
  directory or include-path swap needed.
- `tests/se052_scp03_example.c` -- authenticates the channel and calls
  `Se05x_API_GetVersion` over it.

### How to enable it

1. Add two more include paths:
   `middleware/sss/src/user` and `middleware/sss/src/user/crypto`.

2. Add these C files to the project (on top of the base file list):
   - `middleware/sss/src/user/crypto/aes.c`
   - `middleware/sss/src/user/crypto/aes_cmac.c`
   - `middleware/sss/src/user/crypto/aes_cmac_multistep.c`
   - `middleware/sss/src/user/fsl_sss_user_impl.c`
   - `middleware/sss/src/se05x/fsl_sss_se05x_scp03.c`
   - `middleware/hostlib/libCommon/nxScp/nxScp03_Com.c`
   - `middleware/hostlib/se05x/src/se05x_platform_scp03.c`
   - `tests/se052_scp03_example.c` (example, optional)

3. Enable **RNG** in CubeMX (`MX_RNG_Init()`) and add the preprocessor
   symbol `PLUG_AND_TRUST_STM32_ENABLE_SCP03`. That single symbol both
   switches `config/fsl_sss_ftr.h` to the SCP03 selection above and makes
   `platform/stm32h7/inc/plug_and_trust_stm32_config.h` declare
   `extern RNG_HandleTypeDef hrng;` -- if your project's RNG handle has a
   different name, edit `PLUG_AND_TRUST_STM32_RNG_HANDLE` there. Call
   `MX_RNG_Init()` in the same bring-up sequence as `MX_I2C1_Init()`.
   **Clean the project after adding this define** so every file that
   reads `fsl_sss_ftr.h` recompiles under the new selection.

4. **Check which Platform SCP03 keys apply.** `tests/se052_scp03_example.c`
   ships with the NXP **factory-default** ENC/MAC keys for the
   `SSS_PFSCP_ENABLE_SE052_B501` OEF variant, copied verbatim from
   `simw-top/sss/ex/inc/ex_sss_tp_scp03_keys.h` (a generated, "DO NOT
   MODIFY" table sourced from AN12436 -- not a placeholder). This only
   authenticates if your SE052F (a) is genuinely the B501 OEF variant and
   (b) has never had its Platform SCP03 keys rotated/provisioned to
   something else. If `Se05x_Scp03_Authenticate()` fails against a unit
   that has been re-keyed, replace `s_scp03EncKey`/`s_scp03MacKey` with
   the actual provisioned keys (get those from whoever did the
   provisioning -- there is no way to recover them from the chip).
   `SE052_SCP03_KEY_VERSION_NO` (0x0B) matches NXP's own example default
   (`EX_SSS_AUTH_SE05X_KEY_VERSION_NO`); change it if yours differs.

   **Why SCP03 may be required at all**: on some SE052F units,
   session-less (plaintext) access works for pure identification commands
   (`Se05x_API_GetVersion`) but Secure-Object-management commands
   (`Se05x_API_CheckObjectExists`, `Se05x_API_WriteECKey`, key
   read/write/delete, etc.) come back `SW=0x6985`
   (`SM_ERR_CONDITIONS_NOT_SATISFIED`) until the channel is Platform-SCP03
   authenticated -- `se052_sign_example.c` (which touches objects) needs
   this; `se052_transport_test.c` (`GetVersion` only) does not.

### Using it

```c
#include "se052_scp03_example.h"

if (se052_scp03_example_run() != 0) {
    Error_Handler();
}
```

To add SCP03 to your own code instead: call `Se05x_SessionInit()` as
usual, then `Se05x_Scp03_Authenticate(&session, &staticKeys, &dynCtx)`
before any `Se05x_API_*` call -- `dynCtx` (a `NXSCP03_DynCtx_t`) must stay
allocated for as long as the session is open, since every subsequent APDU
reads it through `session.pdynScp03Ctx`.

## What is intentionally not included

- **No SSS runtime** (`sss/src/se05x/fsl_sss_se05x_apis.c` and the rest
  of the SSS key-store/session abstraction): `Se05x_API_*` calls work
  because `se05x_session_none.c` (and, with SCP03 enabled,
  `se05x_platform_scp03.c`) wire the transport/channel directly instead.
  ECKey/UserID authentication and the mbedTLS/PSA ALT glue are not
  available as-is.
- **No `sm_app_boot.c`**: that file is NXP's example board-bringup code
  (RTOS init, per-board clock/debug-console setup, LED handling) for
  MCUXpresso-SDK boards, not a porting contract. This port's test files
  show the STM32-equivalent bring-up directly instead.
