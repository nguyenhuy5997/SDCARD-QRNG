/**
 * @file    platform_temp.c
 * @brief   STM32H7RSxx implementation of the Platform temperature interface: the DTS.
 *
 * MX_DTS_Init() (Core/Src/main.c, from exercise1.ioc -- same settings as ST's NUCLEO-H7S3L8 DTS_GetTemperature
 * example: PCLK reference, no hardware trigger, 15 sampling cycles, factory calibration) configures the sensor;
 * HAL_DTS_Start() here starts continuous measurement, and HAL_DTS_GetTemperature() only converts the latest result
 * register, so a read does not wait for a conversion.
 */
#include "platform.h"
#include "bsp_hal.h"

static bool s_started;

platform_status_t platform_temp_init(void)
{
    if (s_started) {
        return PLATFORM_OK;
    }
    if (hdts.State != HAL_DTS_STATE_READY) {
        return PLATFORM_ERROR; /* MX_DTS_Init() did not run or failed */
    }
    if (HAL_DTS_Start(&hdts) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    s_started = true;
    return PLATFORM_OK;
}

platform_status_t platform_temp_read_c(int32_t *celsius)
{
    if (celsius == NULL) {
        return PLATFORM_INVALID_PARAM;
    }
    if (!s_started) {
        return PLATFORM_ERROR;
    }
    int32_t t;
    if (HAL_DTS_GetTemperature(&hdts, &t) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    *celsius = t;
    return PLATFORM_OK;
}
