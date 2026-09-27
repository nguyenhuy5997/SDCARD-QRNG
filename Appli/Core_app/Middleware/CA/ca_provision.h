/**
 * @file    ca_provision.h
 * @brief   Factory provisioning of the CA identity into the secure element -- FACTORY IMAGE ONLY.
 *
 * Compiled only when EVT2_FACTORY_PROVISION is 1 (compiler define). The product image does not contain any of this, so in
 * the field nothing can write, replace or erase the identity. Flow, driven from the PC by tools/ca_provision.py through
 * App/protocol_adapters/provision_protocol.c:
 *   1. ca_provision_generate_identity(): the P-256 identity key pair is generated INSIDE the chip; only the public key
 *      comes out.
 *   2. ca_provision_sign_pop(): proof of possession for the CA -- the chip signs
 *      SHA-256("EVT2-POP-v1" || N || Q || id) with the identity key (N = 32-byte CA nonce, Q = the identity public key,
 *      id = the chip's UNIQUE_ID). Only this fixed layout is ever signed, never host-chosen bytes.
 *   3. ca_provision_write_blob() x6: trust anchor, issuing CA certificate, device id, device certificate, status token.
 *   4. ca_service_init() re-reads and self-checks everything (the caller does this, see provision_protocol.c).
 * Object ids and size limits: ca_store.h. No object policy (NULL), by decision for the development boards.
 */
#ifndef CA_PROVISION_H
#define CA_PROVISION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#include "ca_service.h"

/* The six stored values, in wire order (provision_protocol.c uses these numbers on the wire). */
typedef enum {
    CA_PROV_ROOT_PUBKEY = 0,
    CA_PROV_ROOT_SUBJECT,
    CA_PROV_ISSUING_CERT,
    CA_PROV_DEVICE_ID,
    CA_PROV_DEVICE_CERT,
    CA_PROV_STATUS_TOKEN,
    CA_PROV_BLOB_COUNT,
} ca_prov_blob_t;

#define CA_PROV_POP_CONTEXT "EVT2-POP-v1" /* 11 ASCII bytes, no terminator */

/** Bit mask of what is present in the chip: bit 0 = identity key, bit 1 + n = blob n (ca_prov_blob_t). */
uint8_t ca_provision_presence(void);

/** Generate the identity key pair inside the chip and return its public key (65 bytes, 0x04||X||Y).
 *  CA_ERR_EXISTS if it already exists (never replaced silently -- ca_provision_erase() first). */
ca_status_t ca_provision_generate_identity(uint8_t pub[65]);

/** Read the identity public key (65 bytes). CA_ERR_NOT_PROVISIONED if there is none. */
ca_status_t ca_provision_read_identity_pubkey(uint8_t pub[65]);

/** Proof of possession, see the file comment. `sig` gets a DER ECDSA signature (*sig_len in: capacity, out: length). */
ca_status_t ca_provision_sign_pop(const uint8_t nonce[32], uint8_t *sig, size_t *sig_len);

/** Store one value, replacing a previous one. Refuses sizes that would not fit ca_service.c's cache (ca_store.h). */
ca_status_t ca_provision_write_blob(ca_prov_blob_t which, const uint8_t *data, size_t len);

/** Read one stored value back (*len in: capacity, out: length). */
ca_status_t ca_provision_read_blob(ca_prov_blob_t which, uint8_t *data, size_t *len);

/** Delete the identity key and all six values (objects that are not there are skipped). For re-provisioning dev boards. */
ca_status_t ca_provision_erase(void);

#ifdef __cplusplus
}
#endif

#endif /* CA_PROVISION_H */
