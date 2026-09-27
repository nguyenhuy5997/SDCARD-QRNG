p256-m -- P-256 ECDH/ECDSA in portable, constant-time C (Manuel Pegourie-Gonnard, Apache-2.0, see LICENSE).
Vendored VERBATIM (byte-identical, checked with cmp) from https://github.com/mpg/p256-m,
commit 44af59e0cff5d3b1d653bc333814077ef830e1bd (2022-06-15). Do not edit these files; update by re-copying.

Used ONLY by Middleware/Security/SE052F/security_service_se052f.c, and only when the secure element's applet cannot
do ECDH (SSS_HAVE_SE05X_VER_GTE_07_02 == 0, e.g. the SE050F2 in FIPS mode on the V8Y board: ECDH answers 6985).
The backend keeps the ephemeral ECDH key in MCU RAM and computes the shared secret here -- see the
"Software ECDH" section of that file. p256_generate_random() (required by p256-m) is defined there too.
On Cortex-M7 p256-m uses its UMAAL inline-asm multiplier (__ARM_FEATURE_DSP).
