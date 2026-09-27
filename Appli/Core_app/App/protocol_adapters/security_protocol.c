/**
 * @file    security_protocol.c
 * @brief   App-layer command_protocol.h adapter for Middleware/Security (CMD_TYPE_SECURITY).
 *
 * Lives under Core_app/App, not Core_app/Middleware/Security -- see
 * qrng_protocol.c's doc comment for why (this file depends on both
 * command_protocol.h and security_service.h; App is the only layer
 * allowed to depend on more than one Middleware module at once).
 *
 * Exposes get_random, sha256 (both key-less) and the multi-curve/multi-hash EX/RSA signing family (0x0C-0x15,
 * key_id computed internally from curve/bits, never taken off the wire -- see that block's own doc comment).
 *
 * The raw, arbitrary-key_id keystore primitives (ensure_ec_keypair, delete_key, key_exists, store_secret,
 * load_secret -- formerly 0x03-0x07) are NOT exposed here any more (removed 2026-09-23, same class of finding as
 * the SEC_CMD_ECDSA_SIGN/_VERIFY/VERIFY_MESSAGE/SIGN_MESSAGE removal below on 2026-09-22): any USB host could name ANY SE052F
 * object id, including Middleware/CA's identity key (0x00680001) and trust-anchor blobs (0x00680002..0x00680007,
 * ca_service.c) -- DELETE_KEY could erase the device's CA identity outright, STORE_SECRET could overwrite the
 * root/issuing CA data the CA handshake blindly trusts on read, with no policy or range check stopping either
 * (see CLAUDE.md's object-policy TODO). Not used by the real product (android/'s call and CA-handshake code paths
 * never touch CMD_TYPE_SECURITY with these sub_cmds; only the signing feature's 0x0C+ family, which was already
 * scoped). tools/evt2_cli.py's own generic keystore self-test used them against two fixed scratch ids
 * (0x00223344/0x00223345, matching app_main.c's own APP_SELF_TEST_KEY_ID/_SECRET_ID) -- removed there too; that
 * exact roundtrip is already covered by app_self_test()'s own C-level (not wire) exercise of the same functions
 * at every boot. The underlying security_service_ensure_ec_keypair()/delete_key()/key_exists()/store_secret()/
 * load_secret() are UNCHANGED and still called directly in C by app_main.c's app_self_test() and by
 * Core_app/App/protocol_adapters/ca_protocol.c / Core_app/Middleware/CA/ca_service.c -- only this file's wire
 * exposure of them (with a host-chosen key_id) was removed.
 */
#include "command_protocol.h"
#include "security_service.h"
#include "pqc_sign.h"
#include "qrng_service.h"

#include <string.h>

typedef enum {
    SEC_CMD_GET_RANDOM        = 0x01, /* payload: [num_bytes: 1B, 1..32] -> response: [sub_cmd][status][num_bytes bytes] */
    /* 0x02, 0x09, 0x0A, 0x0B (SIGN_MESSAGE/ECDSA_SIGN/ECDSA_VERIFY/VERIFY_MESSAGE) REMOVED 2026-09-22 -- see the doc
     * comment at their old handler location (search this file for "REMOVED 2026-09-22"). Numeric values retired, not
     * reused -- an old client sending one now gets CMD_PROTO_INVALID_PARAM (unregistered sub_cmd), not a
     * misinterpreted different command.
     *
     * 0x03-0x07 (ENSURE_EC_KEYPAIR/DELETE_KEY/KEY_EXISTS/STORE_SECRET/LOAD_SECRET) REMOVED 2026-09-23, same reason
     * and same "retire, don't reuse" rule -- see this file's own top doc comment. This was a raw, arbitrary-key_id
     * keystore oracle: any USB host could delete or overwrite ANY SE052F object by id, including the CA identity
     * key and trust-anchor blobs (Core_app/Middleware/CA -- see the top doc comment for exactly which ones). Not
     * used by the real product; the underlying security_service.h functions are unchanged and still called
     * directly in C where genuinely needed. */
    SEC_CMD_SHA256            = 0x08, /* payload: data bytes -> response: [sub_cmd][status][32-byte digest] */

    /* Multi-curve/multi-hash ECDSA and RSA signing -- the SIGNING FEATURE's own keys, one per
     * (curve | key_bits). `key_id` is computed INSIDE the firmware from `curve`/`key_bits` (see
     * app_ec_key_id()/app_rsa_key_id() below), never taken from the host. An earlier revision
     * took a raw key_id straight off the wire: every host tool then had to duplicate the
     * KEY_ID_BASE offset formula (real risk of drift between firmware/Kotlin/Python, the same
     * class of bug this project has hit more than once elsewhere), AND nothing stopped a host
     * from naming a key_id that had nothing to do with this feature -- e.g. the CA identity key
     * at 0x00680001 (ca_identity_cfg.h), which exists to authenticate this device in the CA
     * handshake, not to rubber-stamp arbitrary caller-supplied documents. The host now only
     * ever says WHICH key it wants (by curve/bits), never WHERE it lives on the chip -- it is
     * structurally unable to name a key_id outside this feature's own reserved range.
     *
     * `hash` is a sec_hash_t value (0=SHA224,1=SHA256,2=SHA384,3=SHA512). Callers hash
     * arbitrarily large files themselves (chunked, on the host) and only ever send the
     * fixed-size digest here -- see security_service.h's doc comments on the *_ex/rsa_*_digest
     * functions for why that's sufficient for files of any size. RSA sig_len fields are 2 bytes
     * (LE) since a 4096-bit signature is 512 bytes, past what a 1-byte length can express;
     * ECDSA's is 1 byte (P-521 worst case is 141 bytes).
     *
     * VERIFY/IMPORT below take neither key_id nor curve/bits: there is only ever one "peer's
     * key" being checked at a time, so they always target the one fixed scratch slot
     * (SEC_APP_VERIFY_SLOT_EC/_RSA) -- its curve/size is simply whatever was imported into it
     * most recently. */
    SEC_CMD_ENSURE_EC_KEYPAIR_EX = 0x0C, /* payload: [curve:1B] -> response: [sub_cmd][status] */
    SEC_CMD_ECDSA_SIGN_EX       = 0x0D, /* payload: [curve:1B][hash:1B][digest_len:1B][digest bytes] -> response: [sub_cmd][status][sig_len:1B][sig bytes] */
    SEC_CMD_ECDSA_VERIFY_EX     = 0x0E, /* payload: [hash:1B][digest_len:1B][digest bytes][sig_len:1B][sig bytes] -> response: [sub_cmd][status][valid: 0/1] */
    SEC_CMD_ENSURE_RSA_KEYPAIR  = 0x0F, /* payload: [key_bits:1B] -> response: [sub_cmd][status] */
    /* `padding` is a sec_rsa_padding_t value (0=PKCS1_V15, 1=PSS). PSS
     * draws a fresh random salt from the chip's TRNG each call, so
     * signing the same digest twice yields two different (both valid)
     * signatures -- see security_service_rsa_sign_digest()'s doc comment. */
    SEC_CMD_RSA_SIGN_DIGEST     = 0x10, /* payload: [key_bits:1B][padding:1B][hash:1B][digest_len:1B][digest bytes] -> response: [sub_cmd][status][sig_len:2B LE][sig bytes] */
    SEC_CMD_RSA_VERIFY_DIGEST   = 0x11, /* payload: [padding:1B][hash:1B][digest_len:1B][digest bytes][sig_len:2B LE][sig bytes] -> response: [sub_cmd][status][valid: 0/1] */
    SEC_CMD_READ_RSA_PUBLIC_KEY = 0x12, /* payload: [key_bits:1B] -> response: [sub_cmd][status][mod_len:2B LE][modulus bytes][exp_len:1B][exponent bytes] */
    SEC_CMD_READ_EC_PUBLIC_KEY  = 0x13, /* payload: [curve:1B] -> response: [sub_cmd][status][len:1B][uncompressed point 0x04||X||Y] */

    /* Peer public-key import, so this device can verify signatures made by
     * ANOTHER device's private key. Always targets the one fixed scratch
     * slot (SEC_APP_VERIFY_SLOT_EC/_RSA); refuses to touch a private
     * key/key pair either way -- see
     * security_service_import_ec_public_key()'s doc comment. */
    SEC_CMD_IMPORT_EC_PUBLIC_KEY  = 0x14, /* payload: [curve:1B][point_len:1B][point bytes] -> response: [sub_cmd][status] */
    SEC_CMD_IMPORT_RSA_PUBLIC_KEY = 0x15, /* payload: [mod_len:2B LE][exp_len:1B][modulus bytes][exponent bytes] -> response: [sub_cmd][status] */

    /* ML-DSA (FIPS 204, Giai đoạn 4 -- see CLAUDE.md 2026-09-24), the "Ký số" feature's post-quantum signing
     * option, ADDITIONAL to (not a replacement for) 0x0C-0x15's EC/RSA -- a caller picks whichever algorithm it
     * wants per signature, independently each time; ML-DSA is deliberately NOT hybrid with ECDSA here (unlike the
     * CA handshake's ML-KEM hybrid): signing has no "harvest now, decrypt later" exposure the way a key exchange
     * does, so there is no urgency forcing both algorithms into one signature.
     *
     * `level` is a pqc_sign_level_t value (0=ML-DSA-44, 1=ML-DSA-65, 2=ML-DSA-87) -- same crypto-agility shape as
     * `curve`/`key_bits` above, own sub-command family (mirroring how RSA got 0x0F-0x12/0x15 instead of being
     * shoehorned into sec_ec_curve_t) since ML-DSA has neither a curve nor RSA padding concept. `hash`/`digest_len`
     * /`digest` follow EXACTLY the EC/RSA convention (host hashes an arbitrarily large file itself, only the
     * fixed-size digest crosses the wire) even though the underlying pqc_sign_sign()/_verify() have no chip-side
     * APDU size limit forcing that -- kept for wire uniformity across all three algorithm choices, and because the
     * file being signed may be far larger than one USB frame regardless of which algorithm computes over it;
     * `hash` itself is a sanity check only (digest_len must match its output size), same as
     * security_service_ecdsa_sign_ex()'s own `hash` parameter -- ML-DSA does not care which hash produced the
     * bytes it signs.
     *
     * KEY STORAGE: unlike EC/RSA, there is no SE052F object holding an ML-DSA key pair -- the SE052F cannot run
     * ML-DSA at all (see pqc_sign.h's own doc comment for why). Only a 32-byte SEED is ever stored (via
     * security_service_store_secret(), well within its size limit), at a per-level key_id (app_mldsa_key_id());
     * the real (pk, sk) pair is re-derived in MCU RAM every time SIGN or READ_PUBLIC_KEY needs it and wiped
     * immediately after (pqc_sign_keygen_from_seed(), pqc_sign.h). VERIFY needs no stored key at all -- unlike
     * EC/RSA's IMPORT+fixed-scratch-slot dance, it takes the signer's public key directly in its own payload
     * (a real ML-DSA public key is just data, nothing SE052F-object-shaped about it) -- so there is no
     * SEC_CMD_IMPORT_MLDSA_PUBLIC_KEY at all. */
    SEC_CMD_ENSURE_MLDSA_KEYPAIR = 0x16, /* payload: [level:1B] -> response: [sub_cmd][status] */
    SEC_CMD_MLDSA_SIGN          = 0x17, /* payload: [level:1B][hash:1B][digest_len:1B][digest bytes]
                                          * -> response: [sub_cmd][status][sig_len:2B LE][sig bytes] */
    SEC_CMD_MLDSA_VERIFY        = 0x18, /* payload: [level:1B][hash:1B][digest_len:1B][digest bytes]
                                          *          [pk_len:2B LE][pk bytes][sig_len:2B LE][sig bytes]
                                          * -> response: [sub_cmd][status][valid: 0/1] */
    SEC_CMD_READ_MLDSA_PUBLIC_KEY = 0x19, /* payload: [level:1B] -> response: [sub_cmd][status][pk_len:2B LE][pk bytes] */
} security_cmd_t;

/* SIGNING-FEATURE key_id layout -- SE052F object ids SEC_CMD_*_EX/RSA_* (0x0C-0x15) compute
 * internally, never taken from the host (see that block's own doc comment above). This used to
 * be duplicated in tools/sign_app.py and the phone app's DeviceCrypto.kt; now it exists in
 * exactly one place. Must not collide with the ids other users of the chip pick (app_main.c
 * self-test 0x00223344, the CA identity key 0x00680001 -- see ca_identity_cfg.h). */
#define SEC_APP_KEY_ID_BASE     0x00660000UL
#define SEC_APP_VERIFY_SLOT_EC  0x00670001UL
#define SEC_APP_VERIFY_SLOT_RSA 0x00670002UL

static uint32_t app_ec_key_id(sec_ec_curve_t curve)
{
    return SEC_APP_KEY_ID_BASE + 0x10UL + (uint32_t)curve;
}

static uint32_t app_rsa_key_id(sec_rsa_key_bits_t key_bits)
{
    return SEC_APP_KEY_ID_BASE + 0x20UL + (uint32_t)key_bits;
}

/* ML-DSA's "key id" (0x30 sub-range, distinct from EC's 0x10 and RSA's 0x20 above) names the SE052F secret object
 * holding that level's 32-byte SEED -- not a key pair object, see SEC_CMD_ENSURE_MLDSA_KEYPAIR's own doc comment
 * for why there is no ML-DSA equivalent of an SE052F-resident key pair at all. */
static uint32_t app_mldsa_key_id(pqc_sign_level_t level)
{
    return SEC_APP_KEY_ID_BASE + 0x30UL + (uint32_t)level;
}

/* Shared scratch for SEC_CMD_MLDSA_SIGN/READ_MLDSA_PUBLIC_KEY -- the two sub-commands that need a re-derived
 * (pk, sk) pair (never both at once, this is a single-threaded request/response handler) -- rather than each
 * case having its own ~7.5KB pair of static buffers. RAM_D1 headroom is scarce in this project (see
 * CLAUDE.md's Giai đoạn 4 stack-overflow finding) -- worth the small shared-state discipline to not duplicate it. */
static uint8_t s_mldsa_seed[PQC_SIGN_SEED_BYTES];
static uint8_t s_mldsa_pk[PQC_SIGN_MAX_PUBLICKEY_BYTES];
static uint8_t s_mldsa_sk[PQC_SIGN_MAX_SECRETKEY_BYTES];

/* Loads app_mldsa_key_id(level)'s stored seed and re-derives (s_mldsa_pk, s_mldsa_sk) from it -- shared by
 * SEC_CMD_MLDSA_SIGN and SEC_CMD_READ_MLDSA_PUBLIC_KEY. Always wipes s_mldsa_seed before returning (the seed
 * itself is never needed past this call); the CALLER is responsible for wiping s_mldsa_sk once it is done with
 * it (SIGN needs it a moment longer than this function's own scope). Returns SEC_ERROR uniformly for "no such
 * key" (SEC_CMD_ENSURE_MLDSA_KEYPAIR never ran), "corrupt seed" (wrong length), or an invalid `level`. */
static sec_status_t mldsa_load_keypair(pqc_sign_level_t level)
{
    size_t seed_len = sizeof(s_mldsa_seed);
    sec_status_t st = security_service_load_secret(app_mldsa_key_id(level), s_mldsa_seed, &seed_len);
    if (st == SEC_OK && seed_len != sizeof(s_mldsa_seed)) {
        st = SEC_ERROR;
    }
    if (st == SEC_OK && !pqc_sign_keygen_from_seed(level, s_mldsa_seed, s_mldsa_pk, s_mldsa_sk)) {
        st = SEC_ERROR;
    }
    memset(s_mldsa_seed, 0, sizeof(s_mldsa_seed));
    return st;
}

static uint16_t read_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

bool security_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                uint16_t *response_len, uint16_t max_response_len)
{
    uint8_t sub_cmd = payload[0];
    response[0] = sub_cmd;

    switch (sub_cmd) {
        case SEC_CMD_GET_RANDOM: {
            if (payload_len < 2U || max_response_len < 2U) {
                return false;
            }
            uint8_t num_bytes = payload[1];
            if (num_bytes == 0U || num_bytes > 32U || max_response_len < (uint16_t)(2U + num_bytes)) {
                return false;
            }
            sec_status_t st = security_service_get_random(&response[2], num_bytes);
            response[1] = (uint8_t)st;
            *response_len = (uint16_t)(2U + ((st == SEC_OK) ? num_bytes : 0U));
            return true;
        }
        /* SEC_CMD_SIGN_MESSAGE (0x02) removed 2026-09-22 alongside ECDSA_SIGN/_VERIFY/VERIFY_MESSAGE -- see the doc
         * comment further down (search this file for "REMOVED 2026-09-22"). security_service_sign_message() itself
         * is unchanged and still used directly (in C) by app_main.c's app_self_test(). */
        /* SEC_CMD_ENSURE_EC_KEYPAIR/DELETE_KEY/KEY_EXISTS/STORE_SECRET/LOAD_SECRET (0x03-0x07) REMOVED 2026-09-23 --
         * see this file's top doc comment and the enum's own "REMOVED 2026-09-23" comment. This was a raw,
         * arbitrary-key_id keystore oracle over USB: any host could delete/overwrite/read any SE052F object by
         * id, no range or policy check, including Middleware/CA's identity key and trust-anchor blobs. Confirmed
         * unused by the real product (android/ never sends these sub_cmds) before removal; the underlying
         * security_service_ensure_ec_keypair()/delete_key()/key_exists()/store_secret()/load_secret() are
         * unchanged and still called directly in C by app_main.c's app_self_test() and by
         * Core_app/App/protocol_adapters/ca_protocol.c / Core_app/Middleware/CA/ca_service.c. */
        case SEC_CMD_SHA256: {
            if (max_response_len < 34U) {
                return false;
            }
            const uint8_t *data = &payload[1];
            size_t data_len = (size_t)(payload_len - 1U);
            sec_status_t st = security_service_sha256(data, data_len, &response[2]);
            response[1] = (uint8_t)st;
            *response_len = (uint16_t)(2U + ((st == SEC_OK) ? 32U : 0U));
            return true;
        }
        /* SEC_CMD_ECDSA_SIGN/_VERIFY/VERIFY_MESSAGE/SIGN_MESSAGE (0x02, 0x09, 0x0A, 0x0B) REMOVED 2026-09-22: they took an
         * arbitrary key_id AND an arbitrary caller-supplied digest/message straight off the wire -- a generic signing
         * oracle for whatever key_id a host named, including the CA identity key at 0x00680001 (ca_identity_cfg.h),
         * which exists to authenticate this device inside the structured CA_CMD_SIGN_TRANSCRIPT format
         * (Core_app/App/protocol_adapters/ca_protocol.c), not to rubber-stamp arbitrary caller-supplied bytes. This was
         * the exact class of bug SEC_CMD_ENSURE_EC_KEYPAIR_EX's doc comment above already fixed for the 0x0C+ family;
         * these four were the original, now-unused (the signing feature moved to 0x0C+ entirely -- see
         * android/.../sign/spec/DeviceCrypto.kt, tools/sign_app.py) ECDSA-only commands from before that family
         * existed, and closing them removes the oracle instead of merely narrowing it. security_service_ecdsa_sign()/
         * _verify()/sign_message()/verify_message() themselves are unchanged -- app_main.c's app_self_test() still
         * calls them directly in C, not through this wire handler. */
        case SEC_CMD_ENSURE_EC_KEYPAIR_EX: {
            if (payload_len < 2U || max_response_len < 2U) {
                return false;
            }
            sec_ec_curve_t curve = (sec_ec_curve_t)payload[1];
            sec_status_t st = security_service_ensure_ec_keypair_ex(app_ec_key_id(curve), curve);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case SEC_CMD_ECDSA_SIGN_EX: {
            if (payload_len < 4U || max_response_len < 3U) {
                return false;
            }
            sec_ec_curve_t curve = (sec_ec_curve_t)payload[1];
            sec_hash_t hash = (sec_hash_t)payload[2];
            uint8_t digest_len = payload[3];
            if (payload_len < (uint16_t)(4U + digest_len)) {
                return false;
            }
            const uint8_t *digest = &payload[4];

            uint8_t sig[141]; /* ASN.1 DER, P-521 worst case */
            size_t sig_len = sizeof(sig);
            sec_status_t st = security_service_ecdsa_sign_ex(app_ec_key_id(curve), hash, digest, digest_len, sig, &sig_len);

            response[1] = (uint8_t)st;
            if (st != SEC_OK || max_response_len < (uint16_t)(3U + sig_len)) {
                response[2] = 0U;
                *response_len = 3U;
                return true;
            }
            response[2] = (uint8_t)sig_len;
            memcpy(&response[3], sig, sig_len);
            *response_len = (uint16_t)(3U + sig_len);
            return true;
        }
        case SEC_CMD_ECDSA_VERIFY_EX: {
            if (payload_len < 3U || max_response_len < 3U) {
                return false;
            }
            sec_hash_t hash = (sec_hash_t)payload[1];
            uint8_t digest_len = payload[2];
            if (payload_len < (uint16_t)(3U + digest_len + 1U)) {
                return false;
            }
            const uint8_t *digest = &payload[3];
            uint8_t sig_len = payload[3U + digest_len];
            if (payload_len < (uint16_t)(4U + digest_len + sig_len)) {
                return false;
            }
            const uint8_t *sig = &payload[4U + digest_len];

            bool valid = false;
            sec_status_t st = security_service_ecdsa_verify_ex(SEC_APP_VERIFY_SLOT_EC, hash, digest, digest_len, sig, sig_len, &valid);
            response[1] = (uint8_t)st;
            response[2] = (st == SEC_OK && valid) ? 1U : 0U;
            *response_len = 3U;
            return true;
        }
        case SEC_CMD_ENSURE_RSA_KEYPAIR: {
            if (payload_len < 2U || max_response_len < 2U) {
                return false;
            }
            sec_rsa_key_bits_t key_bits = (sec_rsa_key_bits_t)payload[1];
            sec_status_t st = security_service_ensure_rsa_keypair(app_rsa_key_id(key_bits), key_bits);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case SEC_CMD_RSA_SIGN_DIGEST: {
            if (payload_len < 5U || max_response_len < 4U) {
                return false;
            }
            sec_rsa_key_bits_t key_bits = (sec_rsa_key_bits_t)payload[1];
            sec_rsa_padding_t padding = (sec_rsa_padding_t)payload[2];
            sec_hash_t hash = (sec_hash_t)payload[3];
            uint8_t digest_len = payload[4];
            if (payload_len < (uint16_t)(5U + digest_len)) {
                return false;
            }
            const uint8_t *digest = &payload[5];

            uint8_t sig[512]; /* SEC_RSA_4096 worst case */
            size_t sig_len = sizeof(sig);
            sec_status_t st =
                security_service_rsa_sign_digest(app_rsa_key_id(key_bits), padding, hash, digest, digest_len, sig, &sig_len);

            response[1] = (uint8_t)st;
            if (st != SEC_OK || max_response_len < (uint16_t)(4U + sig_len)) {
                response[2] = 0U;
                response[3] = 0U;
                *response_len = 4U;
                return true;
            }
            response[2] = (uint8_t)(sig_len & 0xFFU);
            response[3] = (uint8_t)((sig_len >> 8) & 0xFFU);
            memcpy(&response[4], sig, sig_len);
            *response_len = (uint16_t)(4U + sig_len);
            return true;
        }
        case SEC_CMD_RSA_VERIFY_DIGEST: {
            if (payload_len < 6U || max_response_len < 3U) {
                return false;
            }
            sec_rsa_padding_t padding = (sec_rsa_padding_t)payload[1];
            sec_hash_t hash = (sec_hash_t)payload[2];
            uint8_t digest_len = payload[3];
            if (payload_len < (uint16_t)(4U + digest_len + 2U)) {
                return false;
            }
            const uint8_t *digest = &payload[4];
            uint16_t sig_len = read_u16le(&payload[4U + digest_len]);
            /* sig_len is attacker-controlled and can be up to 65535 --
             * compare in 32-bit to avoid the uint16_t sum wrapping around
             * and passing this check when it shouldn't (would otherwise
             * read past the end of the actual payload buffer). */
            if ((uint32_t)payload_len < (uint32_t)6U + digest_len + sig_len) {
                return false;
            }
            const uint8_t *sig = &payload[6U + digest_len];

            bool valid = false;
            sec_status_t st =
                security_service_rsa_verify_digest(SEC_APP_VERIFY_SLOT_RSA, padding, hash, digest, digest_len, sig, sig_len, &valid);
            response[1] = (uint8_t)st;
            response[2] = (st == SEC_OK && valid) ? 1U : 0U;
            *response_len = 3U;
            return true;
        }
        case SEC_CMD_READ_EC_PUBLIC_KEY: {
            if (payload_len < 2U || max_response_len < 3U) {
                return false;
            }
            sec_ec_curve_t curve = (sec_ec_curve_t)payload[1];

            uint8_t point[136]; /* P-521 uncompressed point (133 B) worst case */
            size_t point_len = sizeof(point);
            sec_status_t st = security_service_read_ec_public_key(app_ec_key_id(curve), point, &point_len);

            response[1] = (uint8_t)st;
            if (st != SEC_OK || max_response_len < (uint16_t)(3U + point_len)) {
                response[2] = 0U;
                *response_len = 3U;
                return true;
            }
            response[2] = (uint8_t)point_len;
            memcpy(&response[3], point, point_len);
            *response_len = (uint16_t)(3U + point_len);
            return true;
        }
        case SEC_CMD_IMPORT_EC_PUBLIC_KEY: {
            if (payload_len < 3U || max_response_len < 2U) {
                return false;
            }
            sec_ec_curve_t curve = (sec_ec_curve_t)payload[1];
            uint8_t point_len = payload[2];
            if ((uint32_t)payload_len < 3U + (uint32_t)point_len) {
                return false;
            }
            sec_status_t st = security_service_import_ec_public_key(SEC_APP_VERIFY_SLOT_EC, curve, &payload[3], point_len);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case SEC_CMD_IMPORT_RSA_PUBLIC_KEY: {
            if (payload_len < 4U || max_response_len < 2U) {
                return false;
            }
            uint16_t mod_len = read_u16le(&payload[1]);
            uint8_t exp_len = payload[3];
            /* mod_len comes straight off the wire (up to 65535): compare in
             * 32-bit so the sum cannot wrap and pass a bounds check it
             * should fail, same reason as SEC_CMD_RSA_VERIFY_DIGEST. */
            if ((uint32_t)payload_len < 4U + (uint32_t)mod_len + (uint32_t)exp_len) {
                return false;
            }
            sec_status_t st = security_service_import_rsa_public_key(
                SEC_APP_VERIFY_SLOT_RSA, &payload[4], mod_len, &payload[4U + mod_len], exp_len);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case SEC_CMD_READ_RSA_PUBLIC_KEY: {
            if (payload_len < 2U || max_response_len < 5U) {
                return false;
            }
            sec_rsa_key_bits_t key_bits = (sec_rsa_key_bits_t)payload[1];

            uint8_t modulus[512]; /* SEC_RSA_4096 worst case */
            size_t mod_len = sizeof(modulus);
            uint8_t exponent[16];
            size_t exp_len = sizeof(exponent);
            sec_status_t st = security_service_read_rsa_public_key(app_rsa_key_id(key_bits), modulus, &mod_len, exponent, &exp_len);

            response[1] = (uint8_t)st;
            if (st != SEC_OK || max_response_len < (uint16_t)(5U + mod_len + exp_len)) {
                response[2] = 0U;
                response[3] = 0U;
                response[4] = 0U;
                *response_len = 5U;
                return true;
            }
            response[2] = (uint8_t)(mod_len & 0xFFU);
            response[3] = (uint8_t)((mod_len >> 8) & 0xFFU);
            memcpy(&response[4], modulus, mod_len);
            response[4U + mod_len] = (uint8_t)exp_len;
            memcpy(&response[5U + mod_len], exponent, exp_len);
            *response_len = (uint16_t)(5U + mod_len + exp_len);
            return true;
        }
        case SEC_CMD_ENSURE_MLDSA_KEYPAIR: {
            if (payload_len < 2U || max_response_len < 2U) {
                return false;
            }
            pqc_sign_level_t level = (pqc_sign_level_t)payload[1];
            uint32_t key_id = app_mldsa_key_id(level);
            sec_status_t st;
            if (security_service_key_exists(key_id)) {
                st = SEC_OK; /* idempotent -- same "create only if missing" contract as ENSURE_EC_KEYPAIR_EX/
                              * ENSURE_RSA_KEYPAIR, see this sub-command's own doc comment */
            } else {
                uint8_t seed[PQC_SIGN_SEED_BYTES];
                /* The project's random source: QRNG first, MCU TRNG fallback -- see qrng_service_random_bytes(). */
                qrng_status_t qs = qrng_service_random_bytes(seed, sizeof(seed), NULL);
                st = (qs == QRNG_OK) ? security_service_store_secret(key_id, seed, sizeof(seed)) : SEC_ERROR;
                memset(seed, 0, sizeof(seed));
            }
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case SEC_CMD_MLDSA_SIGN: {
            if (payload_len < 4U || max_response_len < 4U) {
                return false;
            }
            pqc_sign_level_t level = (pqc_sign_level_t)payload[1];
            /* payload[2] (hash) is a sanity check only -- see this sub-command's own doc comment -- and is not
             * needed by pqc_sign_sign() itself, so it is deliberately not read into a named variable here. */
            uint8_t digest_len = payload[3];
            if (payload_len < (uint16_t)(4U + digest_len)) {
                return false;
            }
            const uint8_t *digest = &payload[4];

            sec_status_t st = mldsa_load_keypair(level);
            /* Sign straight into the caller's response buffer instead of keeping a separate ~4.6KB static
             * `sig[PQC_SIGN_MAX_BYTES]` scratch -- response[] is already sized for the whole command-protocol
             * frame (tens of KB), so this needs no RAM of its own; saves that duplicate on top of the shared
             * s_mldsa_pk/sk scratch above (RAM_D1 headroom is scarce, see CLAUDE.md's Giai đoạn 4 note). Must
             * know the signature fits BEFORE calling pqc_sign_sign() -- it requires a
             * pqc_sign_max_signature_bytes()-sized destination, not just room for the eventual (smaller) actual
             * length. */
            size_t sig_cap = pqc_sign_max_signature_bytes(level);
            bool fits = max_response_len >= (uint16_t)(4U + sig_cap);
            size_t sig_len = sig_cap;
            if (st == SEC_OK && fits && !pqc_sign_sign(level, s_mldsa_sk, digest, digest_len, &response[4], &sig_len)) {
                st = SEC_ERROR;
            }
            memset(s_mldsa_sk, 0, sizeof(s_mldsa_sk)); /* done with the secret key the moment the signature exists (or failed to) */

            response[1] = (uint8_t)st;
            if (st != SEC_OK || !fits) {
                response[2] = 0U;
                response[3] = 0U;
                *response_len = 4U;
                return true;
            }
            response[2] = (uint8_t)(sig_len & 0xFFU);
            response[3] = (uint8_t)((sig_len >> 8) & 0xFFU);
            *response_len = (uint16_t)(4U + sig_len);
            return true;
        }
        case SEC_CMD_MLDSA_VERIFY: {
            if (payload_len < 4U || max_response_len < 3U) {
                return false;
            }
            pqc_sign_level_t level = (pqc_sign_level_t)payload[1];
            uint8_t digest_len = payload[3];
            if ((uint32_t)payload_len < 4U + (uint32_t)digest_len + 2U) {
                return false;
            }
            const uint8_t *digest = &payload[4];
            size_t o = (size_t)4U + digest_len;
            uint16_t pk_len = read_u16le(&payload[o]);
            o += 2U;
            if ((uint32_t)payload_len < (uint32_t)o + pk_len + 2U) {
                return false;
            }
            const uint8_t *pk = &payload[o];
            o += pk_len;
            uint16_t sig_len = read_u16le(&payload[o]);
            o += 2U;
            if ((uint32_t)payload_len != (uint32_t)o + sig_len) {
                return false;
            }
            const uint8_t *sig = &payload[o];

            bool valid = pqc_sign_verify(level, pk, digest, digest_len, sig, sig_len);
            response[1] = (uint8_t)SEC_OK; /* no chip/transport round trip here to fail independently of `valid` --
                                             * unlike EC/RSA verify, this is pure MCU software (see pqc_sign.h) */
            response[2] = valid ? 1U : 0U;
            *response_len = 3U;
            return true;
        }
        case SEC_CMD_READ_MLDSA_PUBLIC_KEY: {
            if (payload_len < 2U || max_response_len < 4U) {
                return false;
            }
            pqc_sign_level_t level = (pqc_sign_level_t)payload[1];

            sec_status_t st = mldsa_load_keypair(level);
            memset(s_mldsa_sk, 0, sizeof(s_mldsa_sk)); /* only s_mldsa_pk is actually wanted here */
            size_t pk_len = pqc_sign_publickey_bytes(level);

            response[1] = (uint8_t)st;
            if (st != SEC_OK || max_response_len < (uint16_t)(4U + pk_len)) {
                response[2] = 0U;
                response[3] = 0U;
                *response_len = 4U;
                return true;
            }
            response[2] = (uint8_t)(pk_len & 0xFFU);
            response[3] = (uint8_t)((pk_len >> 8) & 0xFFU);
            memcpy(&response[4], s_mldsa_pk, pk_len);
            *response_len = (uint16_t)(4U + pk_len);
            return true;
        }
        default:
            return false;
    }
}
