#include <stdio.h>
#include "qrng_service_adc_noise.c"
static uint32_t mock_pos;
platform_status_t platform_gpio_write(platform_gpio_t p,bool v){(void)p;(void)v;return PLATFORM_OK;}
platform_status_t ad5398_init(void){return PLATFORM_OK;}
platform_status_t ad5398_power_down(void){return PLATFORM_OK;}
uint32_t platform_adc_dma_pos(platform_adc_id_t id,uint32_t length){(void)id;(void)length;return mock_pos;}
int main(void){
 printf("before_init_ready=%d healthy=%d\n",qrng_service_is_ready(),qrng_service_is_healthy());
 int r=qrng_service_init();printf("safety_locked_init_result=%d ready=%d healthy=%d\n",r,qrng_service_is_ready(),qrng_service_is_healthy());
 s_last_dma_pos=1900;mock_pos=1800;pump_adc_buffer_flags();
 printf("missed_lap_claims_half=%d dma_current_half=%d ready=%d\n",(int)(s_entropy.raw_pool-s_adc_buf)/1024,(int)mock_pos/1024,s_entropy.buffer_2_ready);
 return 0;
}
uint32_t platform_get_tick_ms(void){static uint32_t t;return ++t;}
platform_status_t platform_adc_stop_dma(platform_adc_id_t id){(void)id;return PLATFORM_OK;}
platform_status_t platform_timer_stop(platform_timer_id_t id){(void)id;return PLATFORM_OK;}
platform_status_t platform_dac_stop(platform_dac_id_t id){(void)id;return PLATFORM_OK;}
bool extractor_run(uint8_t a,const uint32_t *i,uint32_t *o){(void)a;(void)i;(void)o;return false;}
bool extractor_reseed(uint8_t a,const uint32_t *i){(void)a;(void)i;return false;}
uint8_t extractor_set_key(uint8_t a,const uint8_t *i,uint32_t n){(void)a;(void)i;(void)n;return 0;}

