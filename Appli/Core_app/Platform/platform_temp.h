/**
 * @file    platform_temp.h
 * @brief   MCU-agnostic on-die temperature sensor interface of the Platform HAL.
 *
 * STM32H7RSxx: the DTS (digital temperature sensor). Its peripheral setup is CubeMX's (exercise1.ioc -> MX_DTS_Init());
 * platform_temp_init() only starts the continuous measurement, after which a read is a few register accesses.
 */
#ifndef PLATFORM_TEMP_H
#define PLATFORM_TEMP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** Start continuous measurement (the sensor must already be configured by the generated init). Blocks ~5 ms. */
platform_status_t platform_temp_init(void);

/** Latest junction temperature, whole degrees Celsius. PLATFORM_ERROR before platform_temp_init() succeeded or when
 *  the sensor has no measurement yet. */
platform_status_t platform_temp_read_c(int32_t *celsius);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_TEMP_H */
