#include "plug_and_trust_stm32_config.h"
#include "sm_timer.h"

/* Core_app/Platform's platform_time module (platform_delay_ms/_us) owns
 * SysTick/DWT lazy-init internally -- see
 * Core_app/Platform/STM32H7xx/platform_time.c. Nothing to do here. */
uint32_t sm_initSleep(void)
{
    return 0U;
}

void sm_sleep(uint32_t msec)
{
    platform_delay_ms(msec);
}

void sm_usleep(uint32_t microsec)
{
    platform_delay_us(microsec);
}
