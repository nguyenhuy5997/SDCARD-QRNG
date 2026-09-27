/**
 * @file    platform_adc.c
 * @brief   STM32H7RSxx implementation of the Platform ADC interface.
 *
 * Clock, GPIO (PC4 = ADC1_INP4 on this port, corrected 2026-09-25 -- see bsp_h7s3.c's top-of-file doc comment;
 * EVT2 used PB1 = INP5),
 * resolution/channel/trigger-source and HAL_ADC_Init() are done by
 * bsp_h7s3.c's MX_ADC1_Init(), called from main() before any
 * application code runs. H7RS differences vs EVT2's H753: the ADC is
 * 12-bit (not 16-bit) and its circular DMA is a GPDMA1 linked-list channel
 * (see platform_adc_dma_pos() for the unit change that implies). This
 * file only implements the runtime business operations (start/stop/read)
 * on the `hadc1`/`hadc2` handle that generated code already initialized -- it
 * never calls HAL_ADC_Init()/HAL_ADC_DeInit() or reconfigures the
 * channel/trigger itself.
 *
 * Note: on this board hadc1 is generated with ExternalTrigConv =
 * ADC_EXTERNALTRIG_T1_TRGO (TIM1 TRGO) and ConversionDataManagement =
 * ADC_CONVERSIONDATA_DMA_CIRCULAR, i.e. it is meant to be driven by
 * platform_adc_start_dma()/stop_dma() paced by TIM1. platform_adc_read()
 * still works (HAL_ADC_Start() + HAL_ADC_PollForConversion()) but will
 * only complete once TIM1 actually fires a trigger -- it times out
 * otherwise, which is expected given the generated trigger source.
 */
#include "platform.h"
#include "bsp_hal.h"

/* Weak: CubeMX only defines the handle of an ADC that is enabled in the .ioc (the NUCLEO board uses ADC1, the
 * STM32H7S3V8Y6TR board ADC2). An ADC that is not there resolves to NULL and platform_adc_init() rejects it. */
extern ADC_HandleTypeDef hadc1 __attribute__((weak));
extern ADC_HandleTypeDef hadc2 __attribute__((weak));

static ADC_HandleTypeDef *const s_adc_handle[PLATFORM_ADC_COUNT] = {
    [PLATFORM_ADC_1] = &hadc1,
    [PLATFORM_ADC_2] = &hadc2,
};

static bool s_adc_ready[PLATFORM_ADC_COUNT];

static bool adc_id_valid(platform_adc_id_t id)
{
    return id < PLATFORM_ADC_COUNT && s_adc_ready[id];
}

platform_status_t platform_adc_init(platform_adc_id_t id)
{
    if (id >= PLATFORM_ADC_COUNT) {
        return PLATFORM_INVALID_PARAM;
    }
    if (s_adc_ready[id]) {
        return PLATFORM_OK;
    }
    if (s_adc_handle[id] == NULL) {
        return PLATFORM_NOT_SUPPORTED; /* not enabled in the .ioc */
    }
    if (HAL_ADC_GetState(s_adc_handle[id]) == HAL_ADC_STATE_RESET) {
        /* MX_ADC1_Init() has not run yet -- a call-order bug in the
         * caller, not something Platform can fix by initializing the
         * peripheral itself. */
        return PLATFORM_ERROR;
    }

    s_adc_ready[id] = true;
    return PLATFORM_OK;
}

platform_status_t platform_adc_deinit(platform_adc_id_t id)
{
    if (!adc_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }

    s_adc_ready[id] = false;
    return PLATFORM_OK;
}

platform_status_t platform_adc_read(platform_adc_id_t id, uint32_t *value, uint32_t timeout_ms)
{
    if (!adc_id_valid(id) || value == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    ADC_HandleTypeDef *hadc = s_adc_handle[id];

    if (HAL_ADC_Start(hadc) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    if (HAL_ADC_PollForConversion(hadc, timeout_ms) != HAL_OK) {
        HAL_ADC_Stop(hadc);
        return PLATFORM_TIMEOUT;
    }

    *value = HAL_ADC_GetValue(hadc);
    HAL_ADC_Stop(hadc);
    return PLATFORM_OK;
}

platform_status_t platform_adc_start_dma(platform_adc_id_t id, uint16_t *buffer, uint32_t length)
{
    if (!adc_id_valid(id) || buffer == NULL || length == 0) {
        return PLATFORM_INVALID_PARAM;
    }

    if (HAL_ADC_Start_DMA(s_adc_handle[id], (uint32_t *)buffer, length) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    return PLATFORM_OK;
}

platform_status_t platform_adc_stop_dma(platform_adc_id_t id)
{
    if (!adc_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }

    if (HAL_ADC_Stop_DMA(s_adc_handle[id]) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    return PLATFORM_OK;
}

uint32_t platform_adc_dma_pos(platform_adc_id_t id, uint32_t length)
{
    if (!adc_id_valid(id) || length == 0) {
        return 0;
    }

    DMA_HandleTypeDef *hdma = s_adc_handle[id]->DMA_Handle;
    if (hdma == NULL) {
        return 0;
    }

    /* H7RS GPDMA: __HAL_DMA_GET_COUNTER() reads CBR1.BNDT, the number of
     * BYTES still to transfer in the current block -- not data items like
     * the H7 DMA's NDTR that EVT2's version of this function relied on.
     * The ADC channel is configured with a half-word (uint16_t) source and
     * destination (bsp_h7s3.c), and `length` counts uint16_t samples, so
     * convert before comparing. Without this the reported position would be
     * off by 2x and qrng_service_adc_noise.c would read half-written
     * buffers. */
    uint32_t remaining = __HAL_DMA_GET_COUNTER(hdma) / (uint32_t)sizeof(uint16_t);
    if (remaining > length) {
        return 0;
    }
    return length - remaining;
}
