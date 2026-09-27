/**
 * @file    platform_dac.c
 * @brief   STM32H7RSxx implementation of the Platform DAC interface: none.
 *
 * STM32H7S3 has no DAC peripheral (no DAC1 in stm32h7s3xx.h, no
 * stm32h7rsxx_hal_dac.c in STM32Cube_FW_H7RS). On EVT2 (STM32H753) DAC1 ch1
 * (PA4) set the drive current of the QRNG's analog noise circuit
 * (Core_app/Middleware/QRNG/ADC_Noise). Every call here therefore reports
 * PLATFORM_NOT_SUPPORTED, and qrng_service_adc_noise.c treats that one code
 * as "this board has no programmable noise drive -- the circuit runs at its
 * fixed bias" instead of failing QRNG init.
 *
 * When the H7S3 board's noise front-end is designed, the drive needs a
 * replacement: an external I2C/SPI DAC (implement it here), or a filtered
 * TIM PWM output, or a fixed bias resistor (keep this file as is).
 */
#include "platform.h"

platform_status_t platform_dac_init(platform_dac_id_t id)
{
    (void)id;
    return PLATFORM_NOT_SUPPORTED;
}

platform_status_t platform_dac_start(platform_dac_id_t id)
{
    (void)id;
    return PLATFORM_NOT_SUPPORTED;
}

platform_status_t platform_dac_stop(platform_dac_id_t id)
{
    (void)id;
    return PLATFORM_NOT_SUPPORTED;
}

platform_status_t platform_dac_set_value(platform_dac_id_t id, uint16_t value)
{
    (void)id;
    (void)value;
    return PLATFORM_NOT_SUPPORTED;
}
