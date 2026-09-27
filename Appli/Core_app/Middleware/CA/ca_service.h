/**
 * @file    ca_service.h
 * @brief   Device identity for CA-based authenticated key exchange: the values a board carries and the identity key it signs with.
 *
 * Spec of the whole scheme: docs/key_exchange_ca_profile.md. This service owns "what this board is and who it trusts":
 *   - trust anchor        root CA public key + root CA subject name (what every peer certificate chain must end in)
 *   - CA chain             the issuing (intermediate) CA certificate that signed the device certificate
 *   - device identity      device id, device certificate, identity public key, latest status token (revocation + trusted time)
 *   - identity private key lives ON THE SE052F (via security_service.h); this service only ever reads/signs with it.
 *
 * WHERE THE VALUES COME FROM: everything this service returns lives in SE052F objects, put there by a ONE-TIME factory
 * provisioning step (was Core_app/Middleware/CA/ca_provision_once.c, run once per board then deleted -- see CLAUDE.md
 * for when). This file only READS: it never writes a private key or a certificate anywhere. If ca_service_init() fails
 * with CA_ERR_NOT_PROVISIONED, the board's SE052F has not been through that step (or was erased) -- re-run a
 * provisioning step against it (regenerate one from ca_identity_cfg.h's shape and tools/gen_ca_dev_cfg.py's dev PKI
 * during development, or the real enrolment flow once it exists), it is not something this service can fix itself.
 *
 * Layering: depends only on security_service.h (Middleware/Security). It does not know about USB or command_protocol; a
 * protocol adapter under Core_app/App exposes it, the same way security_protocol.c exposes security_service.h.
 */
#ifndef CA_SERVICE_H
#define CA_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    CA_OK = 0,
    CA_NOT_READY,           /* ca_service_init() not called or failed, or security_service is not ready */
    CA_INVALID_PARAM,
    CA_ERR_NOT_PROVISIONED, /* the identity key or a required blob is missing from the SE052F -- run provisioning */
    CA_ERR_PROVISION,       /* an operation that writes/derives something in the SE052F failed at RUN TIME (not a
                             * provisioning-step concern) -- e.g. ca_protocol.c's ephemeral key/ECDH/HKDF calls during
                             * a handshake. Named for historical reasons (this used to be ca_service_init()'s "could not
                             * import the identity key pair" error, before provisioning moved out of this service). */
    CA_ERR_READBACK,        /* a value exists but could not be read back, or didn't fit the cache buffer */
    CA_ERR_KEY_MISMATCH,    /* the identity key's public half does not match the stored device certificate's */
    CA_ERR_SIGN_TEST,       /* sign-then-verify self-check with the identity key failed */
    CA_ERR_EXISTS,          /* ca_provision.c: the identity key already exists -- erase it first to re-provision */
} ca_status_t;

/** A read-only byte string owned by this service (points into a static cache filled by ca_service_init(); never free
 *  or modify). Empty (data may be NULL, len 0) before ca_service_init() has succeeded. */
typedef struct {
    const uint8_t *data;
    size_t len;
} ca_blob_t;

/** Load every CA value (trust anchor, issuing CA cert, this device's id/cert/status token) from the SE052F into RAM,
 *  and self-check the identity key: read its public half back and compare against the stored device certificate's
 *  public key, then sign a fixed digest and verify it against that same key. Requires security_service_init() to have
 *  already succeeded. Safe to call more than once (re-reads and re-checks every time; the SE052F is never written by
 *  this call). */
ca_status_t ca_service_init(void);

bool ca_service_is_ready(void);

/** SE052F object id of the identity key pair (pass to security_service_ecdsa_sign*() only if you must; prefer
 *  ca_service_sign_identity()). */
uint32_t ca_service_identity_key_id(void);

/** Sign a pre-computed SHA-256 `digest` (32 bytes) with the device identity key. Same in/out convention as
 *  security_service_ecdsa_sign(): `sig` needs 72 bytes, `*sig_len` is the capacity on call and the DER length after. */
ca_status_t ca_service_sign_identity(const uint8_t digest[32], uint8_t *sig, size_t *sig_len);

/* ---- what this board is and trusts (only valid once ca_service_init() has returned CA_OK) ---- */
ca_blob_t ca_service_get_root_pubkey(void);        /* 65 B uncompressed P-256 point */
ca_blob_t ca_service_get_root_subject_der(void);   /* root CA subject Name, DER */
ca_blob_t ca_service_get_issuing_cert(void);       /* issuing CA certificate, DER */
ca_blob_t ca_service_get_device_id(void);          /* 18 B (SE052F UNIQUE_ID length) */
ca_blob_t ca_service_get_device_cert(void);        /* device certificate, DER */
ca_blob_t ca_service_get_device_pubkey(void);      /* 65 B uncompressed P-256 point */
ca_blob_t ca_service_get_status_token(void);       /* latest status token (docs/key_exchange_ca_profile.md section 3) */

#ifdef __cplusplus
}
#endif

#endif /* CA_SERVICE_H */
