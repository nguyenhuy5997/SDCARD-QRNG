#ifndef MOCK_PLATFORM_H
#define MOCK_PLATFORM_H
#include <stdint.h>
#include <stddef.h>
typedef enum {PLATFORM_OK, PLATFORM_ERROR, PLATFORM_INVALID_PARAM} platform_status_t;
platform_status_t platform_rng_get_bytes(uint8_t *,size_t);
platform_status_t platform_rng_get_word(uint32_t *);
platform_status_t platform_hmac_sha256(const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *);
platform_status_t platform_aes128_cbc_mac(const uint8_t *,const uint8_t *,size_t,uint8_t *);
platform_status_t platform_aes128_cbc_mac_batch(const uint8_t *,const uint8_t *,size_t,size_t,uint8_t *);
#endif
