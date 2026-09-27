/**
 * @file    ca_service.c
 * @brief   CA service: reads device identity from SE052F objects a one-time factory provisioning step put there. See ca_service.h.
 *
 * Where each value lives in the chip and its size limit: ca_store.h (shared with ca_provision.c).
 *
 * Nothing here ever writes the chip: this file only reads. Writing the identity (generating the key pair in the chip and
 * storing the six values) is the factory step in ca_provision.c, compiled only into the factory image
 * (EVT2_FACTORY_PROVISION), driven from the PC by tools/ca_provision.py.
 */
#include "ca_service.h"
#include "security_service.h"

#include "ca_store.h"
#include "ca_x509.h"

#include <string.h>

static uint8_t s_root_pubkey[CA_POINT_LEN];
static uint8_t s_root_subject[CA_NAME_MAX];
static size_t s_root_subject_len;
static uint8_t s_issuing_cert[CA_CERT_MAX];
static size_t s_issuing_cert_len;
static uint8_t s_device_id[CA_ID_MAX];
static size_t s_device_id_len;
static uint8_t s_device_cert[CA_CERT_MAX];
static size_t s_device_cert_len;
static uint8_t s_device_pubkey[CA_POINT_LEN];
static uint8_t s_status_token[CA_TOKEN_MAX];
static size_t s_status_token_len;

static bool s_ready;

static ca_blob_t blob(const uint8_t *data, size_t len)
{
    ca_blob_t b = {data, len};
    return b;
}

/* Load the whole object at `id` into `buf` (capacity `cap`), record its length in `*out_len`. Distinguishes "object
 * missing" (CA_ERR_NOT_PROVISIONED -- expected on a board that never went through the factory step) from "present but
 * unreadable/oversized" (CA_ERR_READBACK -- a real problem: either the chip misbehaved or CA_*_MAX above is stale). */
static ca_status_t load_blob(uint32_t id, uint8_t *buf, size_t cap, size_t *out_len)
{
    if (!security_service_key_exists(id)) {
        return CA_ERR_NOT_PROVISIONED;
    }
    size_t len = cap;
    if (security_service_load_secret(id, buf, &len) != SEC_OK || len == 0U) {
        return CA_ERR_READBACK;
    }
    *out_len = len;
    return CA_OK;
}

/* True if `cn` is exactly the upper-case hex text of `id` (the CN convention of tools/ca_tool.py's device certificates). */
static bool cn_is_hex_of(ca_span_t cn, const uint8_t *id, size_t id_len)
{
    static const char digits[] = "0123456789ABCDEF";
    if (cn.len != 2U * id_len) {
        return false;
    }
    for (size_t i = 0; i < id_len; i++) {
        if (cn.p[2U * i] != (uint8_t)digits[id[i] >> 4] || cn.p[2U * i + 1U] != (uint8_t)digits[id[i] & 0x0FU]) {
            return false;
        }
    }
    return true;
}

ca_status_t ca_service_init(void)
{
    s_ready = false;
    if (!security_service_is_ready()) {
        return CA_NOT_READY;
    }

    if (!security_service_key_exists(EVT2_CA_IDENTITY_KEY_ID)) {
        return CA_ERR_NOT_PROVISIONED;
    }
    size_t pub_len = sizeof(s_device_pubkey);
    if (security_service_read_ec_public_key(EVT2_CA_IDENTITY_KEY_ID, s_device_pubkey, &pub_len) != SEC_OK ||
        pub_len != CA_POINT_LEN) {
        return CA_ERR_READBACK;
    }

    ca_status_t st;
    size_t root_pubkey_len = sizeof(s_root_pubkey);
    if ((st = load_blob(CA_STORE_ROOT_PUBKEY_ID, s_root_pubkey, sizeof(s_root_pubkey), &root_pubkey_len)) != CA_OK) {
        return st;
    }
    if (root_pubkey_len != CA_POINT_LEN) { /* the root's point has a fixed known length; a truncated store is a real problem */
        return CA_ERR_READBACK;
    }
    if ((st = load_blob(CA_STORE_ROOT_SUBJECT_ID, s_root_subject, sizeof(s_root_subject), &s_root_subject_len)) != CA_OK) {
        return st;
    }
    if ((st = load_blob(CA_STORE_ISSUING_CERT_ID, s_issuing_cert, sizeof(s_issuing_cert), &s_issuing_cert_len)) != CA_OK) {
        return st;
    }
    if ((st = load_blob(CA_STORE_DEVICE_ID_ID, s_device_id, sizeof(s_device_id), &s_device_id_len)) != CA_OK) {
        return st;
    }
    if ((st = load_blob(CA_STORE_DEVICE_CERT_ID, s_device_cert, sizeof(s_device_cert), &s_device_cert_len)) != CA_OK) {
        return st;
    }
    if ((st = load_blob(CA_STORE_STATUS_TOKEN_ID, s_status_token, sizeof(s_status_token), &s_status_token_len)) != CA_OK) {
        return st;
    }

    /* The stored certificate must describe THIS chip's key and id: its public key equal to the identity key's public half
     * (read from the key object above), its CN equal to the stored device id in upper-case hex. Catches a certificate
     * written for another board or for an older identity key. */
    ca_x509_cert_t cert;
    if (ca_x509_parse_cert(s_device_cert, s_device_cert_len, &cert) != CA_X509_OK || cert.role != CA_ROLE_DEVICE) {
        return CA_ERR_READBACK;
    }
    if (memcmp(cert.point, s_device_pubkey, CA_POINT_LEN) != 0 || !cn_is_hex_of(cert.subject_cn, s_device_id, s_device_id_len)) {
        return CA_ERR_KEY_MISMATCH;
    }

    /* Prove the private half really is the one behind that public key: sign a fixed digest with the pair, then verify
     * it against the pair's own stored public half (just read above). A private scalar that does not belong to that
     * public key produces a signature that fails here. */
    static const uint8_t digest[32] = {0x45, 0x56, 0x54, 0x32, 0x2D, 0x43, 0x41, 0x2D, 0x73, 0x65, 0x6C, 0x66, 0x74, 0x65, 0x73, 0x74,
                                       0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t sig[72];
    size_t sig_len = sizeof(sig);
    bool valid = false;
    if (security_service_ecdsa_sign(EVT2_CA_IDENTITY_KEY_ID, digest, sig, &sig_len) != SEC_OK ||
        security_service_ecdsa_verify(EVT2_CA_IDENTITY_KEY_ID, digest, sig, sig_len, &valid) != SEC_OK || !valid) {
        return CA_ERR_SIGN_TEST;
    }

    s_ready = true;
    return CA_OK;
}

bool ca_service_is_ready(void)
{
    return s_ready;
}

uint32_t ca_service_identity_key_id(void)
{
    return EVT2_CA_IDENTITY_KEY_ID;
}

ca_status_t ca_service_sign_identity(const uint8_t digest[32], uint8_t *sig, size_t *sig_len)
{
    if (!s_ready) {
        return CA_NOT_READY;
    }
    if (digest == NULL || sig == NULL || sig_len == NULL) {
        return CA_INVALID_PARAM;
    }
    return security_service_ecdsa_sign(EVT2_CA_IDENTITY_KEY_ID, digest, sig, sig_len) == SEC_OK ? CA_OK : CA_ERR_SIGN_TEST;
}

ca_blob_t ca_service_get_root_pubkey(void)
{
    return blob(s_root_pubkey, CA_POINT_LEN);
}

ca_blob_t ca_service_get_root_subject_der(void)
{
    return blob(s_root_subject, s_root_subject_len);
}

ca_blob_t ca_service_get_issuing_cert(void)
{
    return blob(s_issuing_cert, s_issuing_cert_len);
}

ca_blob_t ca_service_get_device_id(void)
{
    return blob(s_device_id, s_device_id_len);
}

ca_blob_t ca_service_get_device_cert(void)
{
    return blob(s_device_cert, s_device_cert_len);
}

ca_blob_t ca_service_get_device_pubkey(void)
{
    return blob(s_device_pubkey, CA_POINT_LEN);
}

ca_blob_t ca_service_get_status_token(void)
{
    return blob(s_status_token, s_status_token_len);
}
