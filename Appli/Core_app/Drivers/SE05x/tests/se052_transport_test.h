#ifndef SE052_TRANSPORT_TEST_H
#define SE052_TRANSPORT_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

/* Powers up the SE052F, opens a T=1 over I2C session, selects the SE05x
 * applet, and reads back the applet version via Se05x_API_GetVersion().
 *
 * Call after HAL_Init(), SystemClock_Config(), MX_GPIO_Init(),
 * MX_I2C1_Init() and sm_initSleep(). Returns 0 on success, non-zero
 * otherwise. */
int se052_transport_test_run(void);

#ifdef __cplusplus
}
#endif

#endif /* SE052_TRANSPORT_TEST_H */
