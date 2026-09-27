/**
 * @file    ca_store.h
 * @brief   PRIVATE to Middleware/CA: where the CA identity lives in the secure element, and the size limits of each value.
 *
 * Shared by ca_service.c (reads them at boot, every build) and ca_provision.c (writes them, factory build only --
 * EVT2_FACTORY_PROVISION). Not included from anywhere outside Middleware/CA: the rest of the firmware sees these values only
 * through ca_service.h's getters.
 *
 * Object ids, all under the 0x0068xxxx "CA" range -- must not collide with app_self_test.c (0x00223344), the signing feature
 * (0x0066xxxx/0x0067xxxx, security_protocol.c) or the per-call CA handshake objects (0x0069xxxx, ca_protocol.c):
 *   0x00680001  identity EC key pair (generated INSIDE the chip at provisioning; the private half never leaves it)
 *   0x00680002  root CA public key             \
 *   0x00680003  root CA subject Name (DER)      |
 *   0x00680004  issuing CA certificate (DER)     > BinaryFile objects (security_service_store/load_secret)
 *   0x00680005  this device's id                |   (= the chip's 18-byte UNIQUE_ID, which is also the certificate CN)
 *   0x00680006  this device's certificate       |
 *   0x00680007  this device's status token      /
 * No object policy is set (NULL -> the chip's default policy), by decision for the development boards.
 */
#ifndef CA_STORE_H
#define CA_STORE_H

#define EVT2_CA_IDENTITY_KEY_ID  0x00680001U
#define CA_STORE_ROOT_PUBKEY_ID  0x00680002U
#define CA_STORE_ROOT_SUBJECT_ID 0x00680003U
#define CA_STORE_ISSUING_CERT_ID 0x00680004U
#define CA_STORE_DEVICE_ID_ID    0x00680005U
#define CA_STORE_DEVICE_CERT_ID  0x00680006U
#define CA_STORE_STATUS_TOKEN_ID 0x00680007U

/* Cache buffer sizes: generous headroom over what the dev PKI actually produces (root pubkey 65 B, root subject 44 B,
 * issuing cert 383 B, device id 18 B, device cert ~415 B, status token ~103 B -- see docs/key_exchange_ca_profile.md
 * for the profile these come from). CA_CERT_MAX/CA_NAME_MAX leave headroom for a longer CN/O within the strict
 * profile's own hard limits (names capped at 64 bytes each, serials at 20, exactly two extensions on top of the
 * mandatory two -- ca_x509.c's parser rejects anything past that, so this cannot grow unboundedly). ca_provision.c
 * refuses to store anything larger, so a provisioned value always fits ca_service.c's cache. */
#define CA_NAME_MAX  128U
#define CA_CERT_MAX  512U
#define CA_TOKEN_MAX 128U
#define CA_ID_MAX    32U
#define CA_POINT_LEN 65U

#endif /* CA_STORE_H */
