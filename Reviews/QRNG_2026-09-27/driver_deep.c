#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include "extractor.h"
#include "entropy.h"
#include "toeplitz.h"
static int fail_words, zero_hmac=-1,zero_aes=-1; static uint32_t rng=0x918ab631;
platform_status_t platform_rng_get_bytes(uint8_t *p,size_t n){(void)p;(void)n;return PLATFORM_ERROR;}
platform_status_t platform_rng_get_word(uint32_t *p){if(fail_words)return PLATFORM_ERROR; rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;*p=rng;return PLATFORM_OK;}
static int allzero(const uint8_t *p,size_t n){for(size_t i=0;i<n;i++)if(p[i])return 0;return 1;}
platform_status_t platform_hmac_sha256(const uint8_t *k,size_t kn,const uint8_t *p,size_t n,uint8_t *o){(void)p;(void)n;zero_hmac=allzero(k,kn);memset(o,0xA7,32);return PLATFORM_OK;}
platform_status_t platform_aes128_cbc_mac(const uint8_t *k,const uint8_t *p,size_t n,uint8_t *o){(void)p;(void)n;zero_aes=allzero(k,16);memset(o,0xB8,16);return PLATFORM_OK;}
platform_status_t platform_aes128_cbc_mac_batch(const uint8_t *k,const uint8_t *p,size_t n,size_t c,uint8_t *o){(void)p;(void)n;zero_aes=allzero(k,16);memset(o,0xB8,16*c);return PLATFORM_OK;}
int main(int argc,char **argv){
 uint32_t input[512]={0},out[256]={0};
 if(argc>1 && strcmp(argv[1],"coldfail")==0){fail_words=1;extractor_init();puts("UNEXPECTED cold init returned");return 0;}
 extractor_init();
 extractor_run(QRNG_EXTRACTOR_USE_HMAC_SHA256,input,out); extractor_run(QRNG_EXTRACTOR_USE_AES,input,out);
 printf("init_rng_bytes_failed_but_hmac_zero_key=%d aes_zero_key=%d\n",zero_hmac,zero_aes);
 fail_words=1; printf("toeplitz_reseed_reports_success_when_rng_fails=%d\n",extractor_reseed(QRNG_EXTRACTOR_USE_TOEPLITZ,input));
 uint32_t seed[96]; for(int i=0;i<96;i++)seed[i]=0x55555555u;
 toeplitz_build_lookup(seed);
 uint32_t other[512]={0},out2[256]={0}; uint16_t *a=(uint16_t*)input,*b=(uint16_t*)other;
 for(int i=0;i<1024;i++){a[i]=(uint16_t)i;b[i]=a[i];if(i%128>=64)b[i]=(uint16_t)(i+2048);}
 entropy_context_t e; entropy_init(&e); e.raw_pool=a;entropy_reset(&e);entropy_run_health_checks(&e,1);int ha=e.health_status;
 e.raw_pool=b;entropy_reset(&e);entropy_run_health_checks(&e,1);int hb=e.health_status;
 memset(out,0,sizeof out);extractor_run(1,input,out);extractor_run(1,other,out2);
 printf("different_healthy_sources_same_output=%d health_a=%d health_b=%d\n",memcmp(out,out2,sizeof out)==0,ha,hb);
 memset(out2,0,sizeof out2);for(int i=4;i<96;i++)seed[i]^=0xffffffffu;toeplitz_build_lookup(seed);extractor_run(1,input,out2);
 printf("seed_words4_to95_irrelevant=%d\n",memcmp(out,out2,sizeof out)==0);
 memset(out2,0,sizeof out2);memcpy(other,input,sizeof input);for(int i=3;i<512;i++)other[i]^=0x12345678u;extractor_run(1,other,out2);
 printf("first_nonce_12_bytes_ignore_input_after_first_12_bytes=%d\n",memcmp(out,out2,12)==0);
 return 0;
}

