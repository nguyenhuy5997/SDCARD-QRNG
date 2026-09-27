#include <stdio.h>
#include <string.h>
#include "platform.h"
#include "qrng_service.h"
#include "api.h"

#include "randombytes.h"
static int errors;
platform_status_t platform_rng_get_bytes(uint8_t *p,size_t n){(void)p;(void)n;errors++;return PLATFORM_ERROR;}
qrng_status_t qrng_service_get_entropy_with(qrng_extractor_t a,uint8_t *p,size_t n){(void)a;(void)p;(void)n;return QRNG_NOT_READY;}
int main(void){
 unsigned char pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES],sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
 unsigned char ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES],ss[32],out[64];
 memset(out,0xA5,sizeof out); int r=randombytes(out,sizeof out);
 printf("randombytes_failure=%d output_unchanged=%d\n",r,out[0]==0xA5 && out[63]==0xA5);
 r=PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk,sk);
 printf("MLKEM_keypair_return_with_all_rng_failed=%d\n",r);
 r=PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct,ss,pk);
 printf("MLKEM_encaps_return_with_all_rng_failed=%d rng_error_calls=%d\n",r,errors);
 return 0;
}

