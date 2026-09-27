/**
 * @file    pqc_kem.c
 * @brief   ML-KEM-768 wrapper -- see pqc_kem.h.
 *
 * H7S3 port (RAM reduction "C"): every PQClean call runs on the dedicated
 * alternate stack (pqc_stack_call.h) instead of the main stack. Measured
 * with -fstack-usage on EVT2: PQCLEAN_MLKEM768_CLEAN_indcpa_enc alone takes
 * ~12.3KB, keypair ~9.3KB, so the main stack used to need ~16KB+ of headroom
 * just for a CA handshake. This port keeps the main stack in DTCM (64KB,
 * shared with the 32KB Toeplitz table), so that headroom moves to the
 * alternate stack, which is idle whenever no ML-DSA call is running and is
 * sized for >= ML-DSA-44 (~50KB), far above ML-KEM's need.
 */
#include "pqc_kem.h"
#include "pqc_stack_call.h"

#include "api.h" /* Core_app/Middleware/PQC/pqclean/ml-kem-768-clean/api.h -- PQCLEAN_MLKEM768_CLEAN_* declarations */

typedef struct {
    uint8_t *pk;
    uint8_t *sk;
    bool ok;
} kem_keygen_ctx_t;

static void kem_keygen_trampoline(void *arg)
{
    kem_keygen_ctx_t *ctx = (kem_keygen_ctx_t *)arg;
    ctx->ok = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(ctx->pk, ctx->sk) == 0;
}

bool pqc_kem_keygen(uint8_t pk[PQC_KEM_PUBLICKEY_BYTES], uint8_t sk[PQC_KEM_SECRETKEY_BYTES])
{
    kem_keygen_ctx_t ctx = {pk, sk, false};
    pqc_call_on_alt_stack(kem_keygen_trampoline, &ctx);
    return ctx.ok;
}

typedef struct {
    const uint8_t *pk;
    uint8_t *ct;
    uint8_t *ss;
    bool ok;
} kem_enc_ctx_t;

static void kem_enc_trampoline(void *arg)
{
    kem_enc_ctx_t *ctx = (kem_enc_ctx_t *)arg;
    ctx->ok = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ctx->ct, ctx->ss, ctx->pk) == 0;
}

bool pqc_kem_encapsulate(const uint8_t pk[PQC_KEM_PUBLICKEY_BYTES], uint8_t ct[PQC_KEM_CIPHERTEXT_BYTES],
                          uint8_t ss[PQC_KEM_SHARED_SECRET_BYTES])
{
    kem_enc_ctx_t ctx = {pk, ct, ss, false};
    pqc_call_on_alt_stack(kem_enc_trampoline, &ctx);
    return ctx.ok;
}

typedef struct {
    const uint8_t *sk;
    const uint8_t *ct;
    uint8_t *ss;
    bool ok;
} kem_dec_ctx_t;

static void kem_dec_trampoline(void *arg)
{
    kem_dec_ctx_t *ctx = (kem_dec_ctx_t *)arg;
    ctx->ok = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ctx->ss, ctx->ct, ctx->sk) == 0;
}

bool pqc_kem_decapsulate(const uint8_t sk[PQC_KEM_SECRETKEY_BYTES], const uint8_t ct[PQC_KEM_CIPHERTEXT_BYTES],
                          uint8_t ss[PQC_KEM_SHARED_SECRET_BYTES])
{
    kem_dec_ctx_t ctx = {sk, ct, ss, false};
    pqc_call_on_alt_stack(kem_dec_trampoline, &ctx);
    return ctx.ok;
}
