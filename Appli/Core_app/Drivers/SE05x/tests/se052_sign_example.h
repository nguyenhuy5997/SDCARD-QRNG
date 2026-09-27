#ifndef SE052_SIGN_EXAMPLE_H
#define SE052_SIGN_EXAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Demonstrates ECDSA signing entirely on the SE052F, with no host-side
 * crypto (fits this port's HOSTCRYPTO_NONE / SCP_NONE scope):
 *
 *   1. Ensure a NIST P-256 key pair exists at a demo object ID (generated
 *      on-chip via Se05x_API_WriteECKey if not already present).
 *   2. Hash a fixed message with the SE's own SHA-256
 *      (Se05x_API_DigestOneShot) -- no host SHA implementation needed.
 *   3. Sign the digest with that key (Se05x_API_ECDSASign).
 *   4. Verify the signature back with the same key's public part
 *      (Se05x_API_ECDSAVerify).
 *
 * Opens and closes its own T=1 over I2C session. Call after HAL_Init(),
 * SystemClock_Config(), MX_GPIO_Init(), MX_I2C1_Init() and
 * sm_initSleep(). Returns 0 on success, non-zero otherwise. */
int se052_sign_example_run(void);

#ifdef __cplusplus
}
#endif

#endif /* SE052_SIGN_EXAMPLE_H */
