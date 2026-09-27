/**
 * @file    platform_timer.c
 * @brief   STM32H7xx implementation of the Platform timer interface.
 *
 * Clock, period/prescaler, clock-source and trigger-output (TRGO)
 * configuration are done by the CubeMX-generated MX_TIM1_Init() in
 * Src/main.c, called from main() before any application code runs.
 * This file only implements the runtime business operations
 * (start/stop/read) on the `htim1` handle that generated code already
 * initialized -- it never calls HAL_TIM_Base_Init()/DeInit() or
 * reconfigures the period/trigger itself.
 *
 * On this board htim1 is generated with MasterOutputTrigger =
 * TIM_TRGO_UPDATE (Prescaler 0, Period 59), and hadc1's
 * ExternalTrigConv is ADC_EXTERNALTRIG_T1_TRGO -- i.e. TIM1's only job
 * is pacing ADC1 conversions. platform_timer_start(PLATFORM_TIMER_1)
 * must be called for platform_adc_read()/platform_adc_start_dma() to
 * actually produce conversions.
 */
#include "platform.h"
#include "bsp_hal.h"

extern TIM_HandleTypeDef htim1;

static TIM_HandleTypeDef *const s_timer_handle[PLATFORM_TIMER_COUNT] = {
    [PLATFORM_TIMER_1] = &htim1,
};

static bool s_timer_ready[PLATFORM_TIMER_COUNT];

static bool timer_id_valid(platform_timer_id_t id)
{
    return id < PLATFORM_TIMER_COUNT && s_timer_ready[id];
}

platform_status_t platform_timer_init(platform_timer_id_t id)
{
    if (id >= PLATFORM_TIMER_COUNT) {
        return PLATFORM_INVALID_PARAM;
    }
    if (s_timer_ready[id]) {
        return PLATFORM_OK;
    }
    if (HAL_TIM_Base_GetState(s_timer_handle[id]) == HAL_TIM_STATE_RESET) {
        /* MX_TIM1_Init() has not run yet -- a call-order bug in the
         * caller, not something Platform can fix by initializing the
         * peripheral itself. */
        return PLATFORM_ERROR;
    }

    s_timer_ready[id] = true;
    return PLATFORM_OK;
}

platform_status_t platform_timer_deinit(platform_timer_id_t id)
{
    if (!timer_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }

    s_timer_ready[id] = false;
    return PLATFORM_OK;
}

platform_status_t platform_timer_start(platform_timer_id_t id)
{
    if (!timer_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }

    return (HAL_TIM_Base_Start(s_timer_handle[id]) == HAL_OK) ? PLATFORM_OK : PLATFORM_ERROR;
}

platform_status_t platform_timer_stop(platform_timer_id_t id)
{
    if (!timer_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }

    return (HAL_TIM_Base_Stop(s_timer_handle[id]) == HAL_OK) ? PLATFORM_OK : PLATFORM_ERROR;
}

uint32_t platform_timer_get_count(platform_timer_id_t id)
{
    if (!timer_id_valid(id)) {
        return 0;
    }

    return __HAL_TIM_GET_COUNTER(s_timer_handle[id]);
}
