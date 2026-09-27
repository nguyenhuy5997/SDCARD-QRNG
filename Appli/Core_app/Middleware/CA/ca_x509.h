/**
 * @file    ca_x509.h
 * @brief   Strict reader for the EVT2 certificate profile (X.509 DER) and status tokens, plus the chain rules.
 *
 * Pure C, no dependencies beyond <stdint.h>, no heap, no globals: it never allocates and never modifies its input. Every
 * pointer in the result structs points INTO the caller's input buffers, which must stay alive and unchanged while the
 * results are used.
 *
 * The profile (docs/key_exchange_ca_profile.md) is deliberately tiny: P-256 keys, ecdsa-with-SHA256, names of exactly
 * O + CN, two UTCTimes, a fixed extension set per role. The reader accepts exactly that and rejects everything else; it is
 * NOT a general X.509 library. tools/ca_tool.py is the reference: tools/ca_x509_diff_test.py feeds both the same inputs
 * (named cases plus thousands of mutations) and requires the same accept/reject decision and the same parsed fields.
 *
 * Signature MATH is not done here: chain verification calls a caller-supplied `ca_verify_fn` (on the board: the SE052F).
 * Time is not read here either: the caller passes `now` (on the board: derived from the status tokens, see ca_service.h).
 */
#ifndef CA_X509_H
#define CA_X509_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    CA_X509_OK = 0,
    CA_X509_ERR_PARAM,        /* NULL/empty argument */
    CA_X509_ERR_DER,          /* not strict DER: truncated, non-minimal or indefinite length, multi-byte tag, overrun */
    CA_X509_ERR_PROFILE,      /* well-formed DER, but outside the profile */
    CA_X509_ERR_POINT,        /* public key is not a valid uncompressed P-256 point */
    CA_X509_ERR_ROLE,         /* certificate has the wrong role for its place in the chain */
    CA_X509_ERR_NAME,         /* issuer name does not match the parent's subject, byte for byte */
    CA_X509_ERR_SIGNATURE,    /* a signature did not verify */
    CA_X509_ERR_TOKEN,        /* status token malformed */
    CA_X509_ERR_TOKEN_SERIAL, /* status token is for another certificate */
    CA_X509_ERR_REVOKED,      /* status token says the certificate is revoked */
    CA_X509_ERR_TOKEN_TIME,   /* status token not valid at `now` */
    CA_X509_ERR_CERT_TIME,    /* a certificate is not valid at `now` */
} ca_x509_status_t;

const char *ca_x509_status_name(ca_x509_status_t s);

typedef struct {
    const uint8_t *p;
    size_t len;
} ca_span_t;

typedef enum {
    CA_ROLE_NONE = 0,
    CA_ROLE_ROOT,
    CA_ROLE_ISSUING,
    CA_ROLE_DEVICE,
} ca_role_t;

#define CA_X509_POINT_LEN 65U

typedef struct {
    ca_span_t tbs;         /* the exact bytes that are signed (whole tbsCertificate TLV) */
    ca_span_t sig;         /* ECDSA signature, ASN.1 DER SEQUENCE{r,s} */
    ca_span_t serial;      /* INTEGER content */
    ca_span_t issuer;      /* whole issuer Name TLV: compare byte for byte with the parent's `subject` */
    ca_span_t subject;     /* whole subject Name TLV */
    ca_span_t subject_cn;  /* the CN text of the subject (for a device: its id as upper-case hex) */
    int64_t not_before;    /* unix seconds; UTCTime years 1950..2049, so it can be negative */
    int64_t not_after;
    const uint8_t *point;  /* subject public key, 65 bytes 0x04||X||Y, verified to be on the curve */
    ca_role_t role;
} ca_x509_cert_t;

/** Parse and strictly validate one certificate. */
ca_x509_status_t ca_x509_parse_cert(const uint8_t *der, size_t len, ca_x509_cert_t *out);

typedef struct {
    ca_span_t serial;
    ca_span_t body;         /* signed part (everything before the signature length byte); the signed message is
                             * "EVT2-STATUS-v1\0" || body */
    ca_span_t sig;          /* ECDSA signature, DER */
    uint32_t this_update;   /* unix seconds */
    uint32_t next_update;
    bool revoked;
} ca_token_t;

/** Parse and strictly validate one status token (format: docs/key_exchange_ca_profile.md section 3). */
ca_x509_status_t ca_token_parse(const uint8_t *data, size_t len, ca_token_t *out);

/** Verify an ECDSA-SHA256 signature: `sig` (DER) over the message `msg` (hashed with SHA-256 by the callee) under the
 *  uncompressed P-256 public key `point` (65 bytes). Return true ONLY for a valid signature. */
typedef bool (*ca_verify_fn)(void *ctx, const uint8_t point[CA_X509_POINT_LEN], const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len);

typedef struct {
    const uint8_t *root_point;    /* 65 bytes */
    ca_span_t root_subject;       /* root subject Name TLV (DER) */
} ca_trust_anchor_t;

typedef struct {
    ca_x509_cert_t issuing;
    ca_x509_cert_t leaf;
    bool have_token;
    ca_token_t token;
} ca_chain_t;

/** The chain rules of docs/key_exchange_ca_profile.md section 4 (points 1-5): parse both certificates, roles (issuing CA,
 *  device), issuer names against the trust anchor and the issuing CA, both signatures, the status token if one is given
 *  (`token.p != NULL && token.len != 0`; format, signature, serial, not revoked, valid at `now`), and both certificates
 *  valid at `now`. `now` is unix seconds, chosen by the caller. On CA_X509_OK `out` holds the parsed material. */
ca_x509_status_t ca_chain_verify(const ca_trust_anchor_t *anchor, ca_span_t issuing_der, ca_span_t leaf_der, ca_span_t token,
                                 int64_t now, ca_verify_fn verify, void *ctx, ca_chain_t *out);

/** Standalone check: is `point` (65 bytes, 0x04||X||Y) a valid uncompressed point on the P-256 curve (both
 *  coordinates < p, and y^2 == x^3 - 3x + b mod p)? Same math ca_x509_parse_cert() already applies to a
 *  certificate's embedded public key, exposed here for a caller that receives a bare point some other way and must
 *  validate it before feeding it to hardware ECDH -- e.g. Core_app/App/protocol_adapters/ca_protocol.c's
 *  CA_CMD_DERIVE_KEYS, whose peer ephemeral key comes straight off the wire with no certificate around it. */
bool ca_x509_point_on_curve(const uint8_t point[CA_X509_POINT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* CA_X509_H */
