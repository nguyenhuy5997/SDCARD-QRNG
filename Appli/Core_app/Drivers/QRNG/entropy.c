/**
 * @file    entropy.c
 * @brief   Entropy source context and NIST 800-90B online health tests.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Src\entropy.c, unchanged
 * except QRNG_-prefixed constants and dropping the `extern uint16_t
 * adc_buff[]` global -- entropy_get_samples() below only reacts to
 * `es->raw_pool`/`buffer_1_ready`/`buffer_2_ready`, which the caller
 * (the QRNG backend) sets directly; this file has no idea where the
 * samples physically come from.
 */
#include <string.h>
#include "entropy.h"

static sample_t rctA = 0;
static uint32_t rctB = 1;

static sample_t aptA = 0;
static uint32_t aptB = 1;
static uint32_t aptSampleN = 1;

static bool is1stSample = true;

static int entropy_run_apt(sample_t sample); /* Adaptive Proportion Test */
static int entropy_run_rct(sample_t sample); /* Repetitive Count Test */

void entropy_init(entropy_context_t *es)
{
    memset(es, 0, sizeof(entropy_context_t));
}

void entropy_get_samples(entropy_context_t *es)
{
    while (!es->is_source_ready) {
        if (es->buffer_1_ready) {
            es->buffer_1_ready = 0;
            es->is_source_ready = 1;
        }
        else if (es->buffer_2_ready) {
            es->buffer_2_ready = 0;
            es->is_source_ready = 1;
        }
    }
}

void entropy_reset(entropy_context_t *es)
{
    uint16_t *raw_pool = es->raw_pool;
    memset(es, 0, sizeof(entropy_context_t));
    es->raw_pool = raw_pool;

    is1stSample = true;
    rctB = 1;
    aptB = 1;
    aptSampleN = 1;
}

void entropy_run_health_checks(entropy_context_t *es, bool enable)
{
    if (!enable) {
        return;
    }

    if (is1stSample) {
        is1stSample = false;
        rctA = es->raw_pool[0];
        aptA = es->raw_pool[0];
        es->healthy_samples++;
    }

    while (es->healthy_samples < QRNG_ADC_SAMPLES / 2) {
        if (entropy_run_rct(es->raw_pool[es->healthy_samples]) != 0) {
            es->health_status = ENTROPY_HEALTH_RCT_ERROR;
            return;
        }

        if (entropy_run_apt(es->raw_pool[es->healthy_samples]) != 0) {
            es->health_status = ENTROPY_HEALTH_APT_ERROR;
            return;
        }

        es->healthy_samples++;
    }
}

/**************** Private functions ****************/

static int entropy_run_rct(sample_t sample)
{
    if (rctA == sample) {
        rctB++;
        if (rctB >= QRNG_ENTROPY_RCT_CUTOFF_VALUE) {
            return 1;
        }
    }
    else {
        rctA = sample;
        rctB = 1;
    }

    return 0;
}

static int entropy_run_apt(sample_t sample)
{
    if (aptSampleN < QRNG_ENTROPY_APT_WINDOW_SIZE) {
        aptSampleN++;
        if (aptA == sample) {
            aptB++;
            if (aptB >= QRNG_ENTROPY_APT_CUTOFF_VALUE) {
                return 1;
            }
        }
    }
    else {
        aptSampleN = 1;
        aptB = 1;
        aptA = sample;
    }

    return 0;
}
