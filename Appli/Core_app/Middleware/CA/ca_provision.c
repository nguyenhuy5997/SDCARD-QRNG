/**
 * @file    ca_provision.c
 * @brief   Factory provisioning of the CA identity -- see ca_provision.h. FACTORY IMAGE ONLY (EVT2_FACTORY_PROVISION).
 *
 * Depends only on security_service.h, like the rest of Middleware/CA.
 */
#if defined(EVT2_FACTORY_PROVISION) && EVT2_FACTORY_PROVISION

#include "ca_provision.h"
#include "ca_store.h"
#include "security_service.h"

#include <string.h>

static const uint32_t s_blob_id[CA_PROV_BLOB_COUNT] = {
    CA_STORE_ROOT_PUBKEY_ID, CA_STORE_ROOT_SUBJECT_ID, CA_STORE_ISSUING_CERT_ID,
    CA_STORE_DEVICE_ID_ID,   CA_STORE_DEVICE_CERT_ID,  CA_STORE_STATUS_TOKEN_ID,
};

/* Largest value ca_service.c can cache for each blob (ca_store.h); the root public key must be exactly one point. */
static const size_t s_blob_max[CA_PROV_BLOB_COUNT] = {
    CA_POINT_LEN, CA_NAME_MAX, CA_CERT_MAX, CA_ID_MAX, CA_CERT_MAX, CA_TOKEN_MAX,
};

uint8_t ca_provision_presence(void)
{
    uint8_t mask = security_service_key_exists(EVT2_CA_IDENTITY_KEY_ID) ? 0x01U : 0x00U;
    for (size_t i = 0; i < CA_PROV_BLOB_COUNT; i++) {
        if (security_service_key_exists(s_blob_id[i])) {
            mask |= (uint8_t)(1U << (i + 1U));
        }
    }
    return mask;
}

ca_status_t ca_provision_read_identity_pubkey(uint8_t pub[65])
{
    if (!security_service_is_ready()) {
        return CA_NOT_READY;
    }
    if (!security_service_key_exists(EVT2_CA_IDENTITY_KEY_ID)) {
        return CA_ERR_NOT_PROVISIONED;
    }
    size_t len = CA_POINT_LEN;
    if (security_service_read_ec_public_key(EVT2_CA_IDENTITY_KEY_ID, pub, &len) != SEC_OK || len != CA_POINT_LEN) {
        return CA_ERR_READBACK;
    }
    return CA_OK;
}

ca_status_t ca_provision_generate_identity(uint8_t pub[65])
{
    if (!security_service_is_ready()) {
        return CA_NOT_READY;
    }
    if (security_service_key_exists(EVT2_CA_IDENTITY_KEY_ID)) {
        return CA_ERR_EXISTS;
    }
    /* ensure_ec_keypair_ex() generates the pair inside the chip (persistent object, default policy) when it is absent. */
    if (security_service_ensure_ec_keypair_ex(EVT2_CA_IDENTITY_KEY_ID, SEC_EC_CURVE_P256) != SEC_OK) {
        return CA_ERR_PROVISION;
    }
    return ca_provision_read_identity_pubkey(pub);
}

ca_status_t ca_provision_sign_pop(const uint8_t nonce[32], uint8_t *sig, size_t *sig_len)
{
    if (nonce == NULL || sig == NULL || sig_len == NULL) {
        return CA_INVALID_PARAM;
    }
    uint8_t q[CA_POINT_LEN];
    ca_status_t st = ca_provision_read_identity_pubkey(q);
    if (st != CA_OK) {
        return st;
    }
    uint8_t uid[SEC_UNIQUE_ID_LEN];
    if (security_service_read_unique_id(uid) != SEC_OK) {
        return CA_ERR_READBACK;
    }
    static const uint8_t ctx[] = CA_PROV_POP_CONTEXT;
    uint8_t msg[sizeof(ctx) - 1U + 32U + CA_POINT_LEN + SEC_UNIQUE_ID_LEN];
    size_t o = 0;
    memcpy(&msg[o], ctx, sizeof(ctx) - 1U);
    o += sizeof(ctx) - 1U;
    memcpy(&msg[o], nonce, 32U);
    o += 32U;
    memcpy(&msg[o], q, CA_POINT_LEN);
    o += CA_POINT_LEN;
    memcpy(&msg[o], uid, SEC_UNIQUE_ID_LEN);
    o += SEC_UNIQUE_ID_LEN;
    uint8_t digest[32];
    if (security_service_sha256(msg, o, digest) != SEC_OK) {
        return CA_ERR_SIGN_TEST;
    }
    return security_service_ecdsa_sign(EVT2_CA_IDENTITY_KEY_ID, digest, sig, sig_len) == SEC_OK ? CA_OK : CA_ERR_SIGN_TEST;
}

ca_status_t ca_provision_write_blob(ca_prov_blob_t which, const uint8_t *data, size_t len)
{
    if (!security_service_is_ready()) {
        return CA_NOT_READY;
    }
    if ((unsigned)which >= CA_PROV_BLOB_COUNT || data == NULL || len == 0U || len > s_blob_max[which] ||
        (which == CA_PROV_ROOT_PUBKEY && len != CA_POINT_LEN)) {
        return CA_INVALID_PARAM;
    }
    uint32_t id = s_blob_id[which];
    /* A BinaryFile keeps the size it was created with: delete first so a value of a different length can be stored. */
    if (security_service_key_exists(id) && security_service_delete_key(id) != SEC_OK) {
        return CA_ERR_PROVISION;
    }
    return security_service_store_secret(id, data, len) == SEC_OK ? CA_OK : CA_ERR_PROVISION;
}

ca_status_t ca_provision_read_blob(ca_prov_blob_t which, uint8_t *data, size_t *len)
{
    if (!security_service_is_ready()) {
        return CA_NOT_READY;
    }
    if ((unsigned)which >= CA_PROV_BLOB_COUNT || data == NULL || len == NULL) {
        return CA_INVALID_PARAM;
    }
    if (!security_service_key_exists(s_blob_id[which])) {
        return CA_ERR_NOT_PROVISIONED;
    }
    return security_service_load_secret(s_blob_id[which], data, len) == SEC_OK ? CA_OK : CA_ERR_READBACK;
}

ca_status_t ca_provision_erase(void)
{
    if (!security_service_is_ready()) {
        return CA_NOT_READY;
    }
    ca_status_t result = CA_OK;
    if (security_service_key_exists(EVT2_CA_IDENTITY_KEY_ID) &&
        security_service_delete_key(EVT2_CA_IDENTITY_KEY_ID) != SEC_OK) {
        result = CA_ERR_PROVISION;
    }
    for (size_t i = 0; i < CA_PROV_BLOB_COUNT; i++) {
        if (security_service_key_exists(s_blob_id[i]) && security_service_delete_key(s_blob_id[i]) != SEC_OK) {
            result = CA_ERR_PROVISION; /* keep going: delete as much as possible */
        }
    }
    return result;
}

#endif /* EVT2_FACTORY_PROVISION */
