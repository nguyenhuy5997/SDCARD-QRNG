#ifndef SE052_SCP03_EXAMPLE_H
#define SE052_SCP03_EXAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Opens a T=1 over I2C session, authenticates a Platform SCP03 secure
 * channel (AES-128 encrypted + CMAC'd transport, no plaintext APDUs after
 * this point), then issues Se05x_API_GetVersion over that channel to
 * prove it end to end.
 *
 * Requires building against config/scp03/fsl_sss_ftr.h (not the base
 * config/fsl_sss_ftr.h), PLUG_AND_TRUST_STM32_ENABLE_SCP03 defined, and
 * RNG enabled in CubeMX -- see README.md "Enabling Platform SCP03".
 * Returns 0 on success, non-zero otherwise. */
int se052_scp03_example_run(void);

#ifdef __cplusplus
}
#endif

#endif /* SE052_SCP03_EXAMPLE_H */
