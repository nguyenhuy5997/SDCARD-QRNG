/**
 * @file    platform_timer.h
 * @brief   MCU-agnostic hardware timer interface of the Platform HAL.
 *
 * Period/prescaler/trigger-output configuration is the code generator's
 * job (e.g. STM32CubeMX's MX_TIMx_Init() in main.c) and is not part of
 * this API. platform_timer_init() only attaches to a timer that code
 * already brought up; start/stop just runs or halts its counter (and,
 * if the instance is wired that way by generated code, whatever it
 * drives -- e.g. this board's TIM1 paces ADC1 conversions through its
 * TRGO output, so platform_adc_read()/start_dma() need
 * platform_timer_start(BOARD_ADC_TRIGGER_TIMER) to actually produce
 * conversions).
 */
#ifndef PLATFORM_TIMER_H
#define PLATFORM_TIMER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "platform.h"

/** Logical timer instances exposed by the board. */
typedef enum {
    PLATFORM_TIMER_1 = 0,
    PLATFORM_TIMER_COUNT,
} platform_timer_id_t;

/** Attach to a timer already brought up by generated init code. Returns
 *  PLATFORM_ERROR if that init has not run yet. Safe to call more than
 *  once. */
platform_status_t platform_timer_init(platform_timer_id_t id);

/** Detach from the timer. Does not touch clocks/HAL peripheral state --
 *  those stay owned by generated init code. */
platform_status_t platform_timer_deinit(platform_timer_id_t id);

/** Start/stop the timer's counter (and whatever it drives, e.g. a TRGO
 *  output wired to another peripheral). */
platform_status_t platform_timer_start(platform_timer_id_t id);
platform_status_t platform_timer_stop(platform_timer_id_t id);

/** Current counter value (0..period, per the generated configuration). */
uint32_t platform_timer_get_count(platform_timer_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_TIMER_H */
