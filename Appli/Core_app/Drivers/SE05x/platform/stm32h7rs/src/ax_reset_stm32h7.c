#include "plug_and_trust_stm32_config.h"
#include "ax_reset.h"
#include "se05x_reset_apis.h"
#include "sm_timer.h"

/* SE_RESET_LOGIC (from se05x_reset_apis.h) resolves to
 * SSS_HAVE_SE_RESET_LOGIC_1 in config/fsl_sss_ftr.h, which this port sets
 * to 0 for the SE052F (active-low enable/reset pin). */

void axReset_PowerUp(int reset_logic)
{
    platform_gpio_write(BOARD_SE052_EN_GPIO, reset_logic != 0);
}

void axReset_PowerDown(int reset_logic)
{
    platform_gpio_write(BOARD_SE052_EN_GPIO, reset_logic == 0);
}

void axReset_ResetPulseDUT(int reset_logic)
{
    axReset_PowerDown(reset_logic);
    sm_usleep(2000U);
    axReset_PowerUp(reset_logic);
}

void axReset_HostConfigure(void)
{
    /* The SE052F enable/reset pin is configured as a push-pull output by
     * the CubeMX-generated MX_GPIO_Init() in main.c (called from main()
     * before any application code runs) -- nothing to configure here. */
    axReset_PowerDown(SE_RESET_LOGIC);
}

void axReset_HostUnconfigure(void)
{
}
