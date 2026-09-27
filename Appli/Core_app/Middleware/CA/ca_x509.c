/**
 * @file    ca_x509.c
 * @brief   Strict reader for the EVT2 certificate profile and status tokens. See ca_x509.h.
 *
 * Structure mirrors tools/ca_tool.py (read_tlv / parse_name / parse_utctime / parse_cert / parse_token / verify_chain) on
 * purpose: same checks, same order where it matters. Bounds: every read is checked against the END OF THE ENCLOSING
 * STRUCTURE before it is made, offsets are size_t and every "remaining bytes" test is written as a subtraction on values
 * already known to be ordered, so no addition can wrap.
 */
#include "ca_x509.h"

#include <string.h>

/* ---------------------------------------------------------------------------------------------------- profile constants */
static const uint8_t ALG_ECDSA_SHA256[12] = {0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
static const uint8_t SPKI_P256_PREFIX[26] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                             0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
static const uint8_t VERSION_V3[5] = {0xA0, 0x03, 0x02, 0x01, 0x02};
static const uint8_t OID_O[3] = {0x55, 0x04, 0x0A};
static const uint8_t OID_CN[3] = {0x55, 0x04, 0x03};
static const uint8_t OID_BC[3] = {0x55, 0x1D, 0x13};
static const uint8_t OID_KU[3] = {0x55, 0x1D, 0x0F};
static const uint8_t OID_EKU[3] = {0x55, 0x1D, 0x25};
static const uint8_t BC_LEAF[2] = {0x30, 0x00};
static const uint8_t BC_ISSUING[8] = {0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00}; /* CA:TRUE, pathLen 0 */
static const uint8_t BC_ROOT[8] = {0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x01};    /* CA:TRUE, pathLen 1 */
static const uint8_t KU_CA[4] = {0x03, 0x02, 0x02, 0x04};   /* keyCertSign */
static const uint8_t KU_LEAF[4] = {0x03, 0x02, 0x07, 0x80}; /* digitalSignature */
static const uint8_t EKU_VALUE[8] = {0x30, 0x06, 0x06, 0x04, 0x88, 0x37, 0x01, 0x01}; /* SEQUENCE { OID 2.999.1.1 } */
static const uint8_t TOKEN_MAGIC[4] = {'E', 'V', 'S', 'T'};
static const uint8_t TOKEN_CONTEXT[15] = {'E', 'V', 'T', '2', '-', 'S', 'T', 'A', 'T', 'U', 'S', '-', 'v', '1', 0x00};

#define TAG_INTEGER 0x02U
#define TAG_BITSTRING 0x03U
#define TAG_OCTETSTRING 0x04U
#define TAG_OID 0x06U
#define TAG_UTF8STRING 0x0CU
#define TAG_UTCTIME 0x17U
#define TAG_SEQUENCE 0x30U
#define TAG_SET 0x31U
#define TAG_BOOLEAN 0x01U
#define TAG_EXTENSIONS 0xA3U

/* ------------------------------------------------------------------------------------------------------- strict DER reader */
typedef struct {
    uint8_t tag;
    size_t vs;   /* value start */
    size_t ve;   /* value end == start of the next TLV */
} tlv_t;

/* One definite-length TLV with minimal length encoding, entirely inside buf[off..end). */
static bool tlv_read(const uint8_t *buf, size_t off, size_t end, tlv_t *t)
{
    if (off > end || end - off < 2U) {
        return false;
    }
    uint8_t tag = buf[off];
    if ((tag & 0x1FU) == 0x1FU) {
        return false; /* multi-byte tag */
    }
    uint8_t b = buf[off + 1U];
    size_t pos = off + 2U;
    size_t length;
    if (b < 0x80U) {
        length = b;
    }
    else if (b == 0x80U) {
        return false; /* indefinite length */
    }
    else {
        size_t n = (size_t)(b & 0x7FU);
        if (n > 2U || end - pos < n) {
            return false;
        }
        length = 0;
        for (size_t i = 0; i < n; i++) {
            length = (length << 8) | buf[pos + i];
        }
        if (buf[pos] == 0U || length < 0x80U || (n == 2U && length < 0x100U)) {
            return false; /* non-minimal */
        }
        pos += n;
    }
    if (end - pos < length) {
        return false;
    }
    t->tag = tag;
    t->vs = pos;
    t->ve = pos + length;
    return true;
}

/* tlv_read + tag check. DER failures and tag mismatches are reported separately. */
static ca_x509_status_t tlv_expect(const uint8_t *buf, size_t off, size_t end, uint8_t tag, tlv_t *t)
{
    if (!tlv_read(buf, off, end, t)) {
        return CA_X509_ERR_DER;
    }
    return t->tag == tag ? CA_X509_OK : CA_X509_ERR_PROFILE;
}

#define TRY(expr)                        \
    do {                                 \
        ca_x509_status_t s_ = (expr);    \
        if (s_ != CA_X509_OK) {          \
            return s_;                   \
        }                                \
    } while (0)

/* buf[p .. p+n) equals `pat`, where the slice must lie inside buf[0..total). */
static bool bytes_at(const uint8_t *buf, size_t total, size_t p, const uint8_t *pat, size_t n)
{
    return p <= total && total - p >= n && memcmp(buf + p, pat, n) == 0;
}

static bool span_is(const uint8_t *buf, size_t vs, size_t ve, const uint8_t *pat, size_t n)
{
    return ve - vs == n && memcmp(buf + vs, pat, n) == 0;
}

/* ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }, both minimal positive, at most 33 bytes (leading 00 + 32). */
static ca_x509_status_t ecdsa_sig_der_ok(const uint8_t *sig, size_t len)
{
    tlv_t seq;
    TRY(tlv_expect(sig, 0, len, TAG_SEQUENCE, &seq));
    if (seq.ve != len) {
        return CA_X509_ERR_PROFILE;
    }
    size_t o = seq.vs;
    for (int i = 0; i < 2; i++) {
        tlv_t in;
        TRY(tlv_expect(sig, o, seq.ve, TAG_INTEGER, &in));
        size_t n = in.ve - in.vs;
        if (n == 0U || (sig[in.vs] & 0x80U) != 0U || (n > 1U && sig[in.vs] == 0U && (sig[in.vs + 1U] & 0x80U) == 0U) || n > 33U) {
            return CA_X509_ERR_PROFILE;
        }
        o = in.ve;
    }
    return o == seq.ve ? CA_X509_OK : CA_X509_ERR_PROFILE;
}

/* Name must be exactly SEQUENCE { SET{SEQ{O, UTF8}} SET{SEQ{CN, UTF8}} }, values 1..64 printable ASCII bytes. On success
 * *whole is the entire Name TLV, *cn the CN text. */
static ca_x509_status_t parse_name(const uint8_t *buf, size_t off, size_t end, ca_span_t *whole, ca_span_t *cn)
{
    tlv_t name;
    TRY(tlv_expect(buf, off, end, TAG_SEQUENCE, &name));
    size_t o = name.vs;
    for (int i = 0; i < 2; i++) {
        const uint8_t *oid = (i == 0) ? OID_O : OID_CN;
        tlv_t set, ava, oidt, val;
        TRY(tlv_expect(buf, o, name.ve, TAG_SET, &set));
        o = set.ve;
        TRY(tlv_expect(buf, set.vs, set.ve, TAG_SEQUENCE, &ava));
        if (ava.ve != set.ve) {
            return CA_X509_ERR_PROFILE; /* multi-valued RDN */
        }
        TRY(tlv_expect(buf, ava.vs, ava.ve, TAG_OID, &oidt));
        if (!span_is(buf, oidt.vs, oidt.ve, oid, 3U)) {
            return CA_X509_ERR_PROFILE;
        }
        TRY(tlv_expect(buf, oidt.ve, ava.ve, TAG_UTF8STRING, &val));
        if (val.ve != ava.ve) {
            return CA_X509_ERR_PROFILE;
        }
        size_t n = val.ve - val.vs;
        if (n < 1U || n > 64U) {
            return CA_X509_ERR_PROFILE;
        }
        for (size_t k = val.vs; k < val.ve; k++) {
            if (buf[k] < 0x20U || buf[k] > 0x7EU) {
                return CA_X509_ERR_PROFILE;
            }
        }
        if (i == 1) {
            cn->p = buf + val.vs;
            cn->len = n;
        }
    }
    if (o != name.ve) {
        return CA_X509_ERR_PROFILE; /* only O and CN */
    }
    whole->p = buf + off;
    whole->len = name.ve - off;
    return CA_X509_OK;
}

/* days since 1970-01-01 of the civil date y-m-d (proleptic Gregorian); day may overflow the month like calendar.timegm. */
static int64_t days_from_civil(int64_t y, int64_t m, int64_t d)
{
    y -= (m <= 2) ? 1 : 0;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* UTCTime YYMMDDHHMMSSZ, years 1950..2049. Like the reference, day-of-month is only range-checked 1..31. */
static ca_x509_status_t parse_utctime(const uint8_t *buf, size_t off, size_t end, int64_t *out)
{
    tlv_t t;
    TRY(tlv_expect(buf, off, end, TAG_UTCTIME, &t));
    if (t.ve - t.vs != 13U || buf[t.ve - 1U] != (uint8_t)'Z') {
        return CA_X509_ERR_PROFILE;
    }
    int v[6];
    for (int i = 0; i < 6; i++) {
        uint8_t a = buf[t.vs + (size_t)(2 * i)];
        uint8_t b = buf[t.vs + (size_t)(2 * i) + 1U];
        if (a < '0' || a > '9' || b < '0' || b > '9') {
            return CA_X509_ERR_PROFILE;
        }
        v[i] = (a - '0') * 10 + (b - '0');
    }
    int64_t year = (v[0] < 50) ? 2000 + v[0] : 1900 + v[0];
    if (!(v[1] >= 1 && v[1] <= 12 && v[2] >= 1 && v[2] <= 31 && v[3] < 24 && v[4] < 60 && v[5] < 60)) {
        return CA_X509_ERR_PROFILE;
    }
    int64_t days = days_from_civil(year, v[1], v[2]);
    *out = ((days * 24 + v[3]) * 60 + v[4]) * 60 + v[5];
    return CA_X509_OK;
}

/* ------------------------------------------------------------------------------------------ P-256 point-on-curve check */
/* Public data only (no secrets), so plain double-and-add modular multiplication is fine and keeps this file dependency-free.
 * u256 = 8 little-endian 32-bit limbs. */
typedef uint32_t u256[8];

static const u256 P256_P = {0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU};
static const u256 P256_B = {0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U, 0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U};

static void u256_from_be(u256 r, const uint8_t *b)
{
    for (size_t i = 0; i < 8U; i++) {
        const uint8_t *q = b + (7U - i) * 4U;
        r[i] = ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16) | ((uint32_t)q[2] << 8) | (uint32_t)q[3];
    }
}

static int u256_cmp(const u256 a, const u256 b)
{
    for (int i = 7; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] > b[i] ? 1 : -1;
        }
    }
    return 0;
}

static uint32_t u256_add(u256 r, const u256 a, const u256 b)
{
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        c += (uint64_t)a[i] + b[i];
        r[i] = (uint32_t)c;
        c >>= 32;
    }
    return (uint32_t)c;
}

static uint32_t u256_sub(u256 r, const u256 a, const u256 b)
{
    int64_t br = 0;
    for (int i = 0; i < 8; i++) {
        int64_t d = (int64_t)a[i] - (int64_t)b[i] - br;
        br = d < 0 ? 1 : 0;
        r[i] = (uint32_t)d;
    }
    return (uint32_t)br;
}

static void addmod(u256 r, const u256 a, const u256 b)
{
    u256 t;
    uint32_t c = u256_add(t, a, b);
    if (c != 0U || u256_cmp(t, P256_P) >= 0) {
        (void)u256_sub(t, t, P256_P);
    }
    memcpy(r, t, sizeof(u256));
}

static void submod(u256 r, const u256 a, const u256 b)
{
    u256 t;
    if (u256_sub(t, a, b) != 0U) {
        (void)u256_add(t, t, P256_P);
    }
    memcpy(r, t, sizeof(u256));
}

static void mulmod(u256 r, const u256 a, const u256 b)
{
    u256 acc = {0};
    for (int i = 255; i >= 0; i--) {
        addmod(acc, acc, acc);
        if (((b[i / 32] >> (i % 32)) & 1U) != 0U) {
            addmod(acc, acc, a);
        }
    }
    memcpy(r, acc, sizeof(u256));
}

/* 65-byte uncompressed point: tag 04, x and y both < p, and y^2 == x^3 - 3x + b (mod p). */
static bool p256_point_ok(const uint8_t *pt)
{
    if (pt[0] != 0x04U) {
        return false;
    }
    u256 x, y, x2, x3, rhs, y2;
    u256_from_be(x, pt + 1);
    u256_from_be(y, pt + 33);
    if (u256_cmp(x, P256_P) >= 0 || u256_cmp(y, P256_P) >= 0) {
        return false;
    }
    mulmod(x2, x, x);
    mulmod(x3, x2, x);
    submod(rhs, x3, x);
    submod(rhs, rhs, x);
    submod(rhs, rhs, x);
    addmod(rhs, rhs, P256_B);
    mulmod(y2, y, y);
    return u256_cmp(y2, rhs) == 0;
}

bool ca_x509_point_on_curve(const uint8_t point[CA_X509_POINT_LEN])
{
    return p256_point_ok(point);
}

/* ------------------------------------------------------------------------------------------------------- certificate */
typedef struct {
    size_t oid_vs, oid_ve;
    bool critical;
    size_t val_vs, val_ve;
} ext_t;

/* One extension: SEQUENCE { OID, [BOOLEAN TRUE], OCTET STRING }. */
static ca_x509_status_t parse_extension(const uint8_t *der, size_t off, size_t end, ext_t *e, size_t *next)
{
    tlv_t ext, oid, val;
    TRY(tlv_expect(der, off, end, TAG_SEQUENCE, &ext));
    TRY(tlv_expect(der, ext.vs, ext.ve, TAG_OID, &oid));
    size_t q = oid.ve;
    e->critical = false;
    if (q < ext.ve && der[q] == TAG_BOOLEAN) {
        tlv_t bo;
        TRY(tlv_expect(der, q, ext.ve, TAG_BOOLEAN, &bo));
        if (!span_is(der, bo.vs, bo.ve, (const uint8_t[]){0xFF}, 1U)) {
            return CA_X509_ERR_PROFILE; /* DER: TRUE is 0xFF */
        }
        e->critical = true;
        q = bo.ve;
    }
    TRY(tlv_expect(der, q, ext.ve, TAG_OCTETSTRING, &val));
    if (val.ve != ext.ve) {
        return CA_X509_ERR_PROFILE;
    }
    e->oid_vs = oid.vs;
    e->oid_ve = oid.ve;
    e->val_vs = val.vs;
    e->val_ve = val.ve;
    *next = ext.ve;
    return CA_X509_OK;
}

ca_x509_status_t ca_x509_parse_cert(const uint8_t *der, size_t len, ca_x509_cert_t *out)
{
    if (der == NULL || len == 0U || out == NULL) {
        return CA_X509_ERR_PARAM;
    }
    memset(out, 0, sizeof(*out));

    tlv_t cert, tbs, sigbits;
    TRY(tlv_expect(der, 0, len, TAG_SEQUENCE, &cert));
    if (cert.ve != len) {
        return CA_X509_ERR_PROFILE; /* trailing bytes */
    }
    TRY(tlv_expect(der, cert.vs, cert.ve, TAG_SEQUENCE, &tbs));
    size_t o = tbs.ve;
    if (!bytes_at(der, len, o, ALG_ECDSA_SHA256, sizeof(ALG_ECDSA_SHA256))) {
        return CA_X509_ERR_PROFILE;
    }
    o += sizeof(ALG_ECDSA_SHA256);
    TRY(tlv_expect(der, o, cert.ve, TAG_BITSTRING, &sigbits));
    if (sigbits.ve != cert.ve) {
        return CA_X509_ERR_PROFILE;
    }
    if (sigbits.ve - sigbits.vs < 9U || der[sigbits.vs] != 0U) {
        return CA_X509_ERR_PROFILE;
    }
    const uint8_t *sig = der + sigbits.vs + 1U;
    size_t sig_len = sigbits.ve - sigbits.vs - 1U;
    TRY(ecdsa_sig_der_ok(sig, sig_len));

    /* ---- tbsCertificate ---- */
    size_t p = tbs.vs;
    if (!bytes_at(der, len, p, VERSION_V3, sizeof(VERSION_V3))) {
        return CA_X509_ERR_PROFILE;
    }
    p += sizeof(VERSION_V3);

    tlv_t ser;
    TRY(tlv_expect(der, p, tbs.ve, TAG_INTEGER, &ser));
    size_t sn = ser.ve - ser.vs;
    if (sn < 1U || sn > 20U || (der[ser.vs] & 0x80U) != 0U || (sn > 1U && der[ser.vs] == 0U && (der[ser.vs + 1U] & 0x80U) == 0U) ||
        (sn == 1U && der[ser.vs] == 0U)) {
        return CA_X509_ERR_PROFILE;
    }
    p = ser.ve;

    if (!bytes_at(der, len, p, ALG_ECDSA_SHA256, sizeof(ALG_ECDSA_SHA256))) {
        return CA_X509_ERR_PROFILE;
    }
    p += sizeof(ALG_ECDSA_SHA256);

    ca_span_t issuer_cn;
    TRY(parse_name(der, p, tbs.ve, &out->issuer, &issuer_cn));
    p += out->issuer.len;

    tlv_t validity;
    TRY(tlv_expect(der, p, tbs.ve, TAG_SEQUENCE, &validity));
    p = validity.ve;
    size_t q = validity.vs;
    TRY(parse_utctime(der, q, validity.ve, &out->not_before));
    q += 15U;
    TRY(parse_utctime(der, q, validity.ve, &out->not_after));
    q += 15U;
    if (q != validity.ve || validity.ve - validity.vs != 30U) {
        return CA_X509_ERR_PROFILE;
    }
    if (out->not_after < out->not_before) {
        return CA_X509_ERR_PROFILE;
    }

    TRY(parse_name(der, p, tbs.ve, &out->subject, &out->subject_cn));
    p += out->subject.len;

    if (!bytes_at(der, len, p, SPKI_P256_PREFIX, sizeof(SPKI_P256_PREFIX))) {
        return CA_X509_ERR_PROFILE;
    }
    p += sizeof(SPKI_P256_PREFIX);
    if (len - p < CA_X509_POINT_LEN) {
        return CA_X509_ERR_POINT;
    }
    if (!p256_point_ok(der + p)) {
        return CA_X509_ERR_POINT;
    }
    const uint8_t *point = der + p;
    p += CA_X509_POINT_LEN;

    tlv_t exts_wrap, exts;
    TRY(tlv_expect(der, p, tbs.ve, TAG_EXTENSIONS, &exts_wrap));
    if (exts_wrap.ve != tbs.ve) {
        return CA_X509_ERR_PROFILE;
    }
    TRY(tlv_expect(der, exts_wrap.vs, exts_wrap.ve, TAG_SEQUENCE, &exts));
    if (exts.ve != exts_wrap.ve) {
        return CA_X509_ERR_PROFILE;
    }
    ext_t e[3];
    size_t count = 0;
    size_t eo = exts.vs;
    while (eo < exts.ve) {
        if (count == 3U) {
            return CA_X509_ERR_PROFILE; /* no role has more than three extensions */
        }
        TRY(parse_extension(der, eo, exts.ve, &e[count], &eo));
        count++;
    }
    if (count < 2U || !span_is(der, e[0].oid_vs, e[0].oid_ve, OID_BC, 3U) || !span_is(der, e[1].oid_vs, e[1].oid_ve, OID_KU, 3U) ||
        !e[0].critical || !e[1].critical) {
        return CA_X509_ERR_PROFILE;
    }
    bool bc_root = span_is(der, e[0].val_vs, e[0].val_ve, BC_ROOT, sizeof(BC_ROOT));
    bool bc_iss = span_is(der, e[0].val_vs, e[0].val_ve, BC_ISSUING, sizeof(BC_ISSUING));
    bool bc_leaf = span_is(der, e[0].val_vs, e[0].val_ve, BC_LEAF, sizeof(BC_LEAF));
    bool ku_ca = span_is(der, e[1].val_vs, e[1].val_ve, KU_CA, sizeof(KU_CA));
    bool ku_leaf = span_is(der, e[1].val_vs, e[1].val_ve, KU_LEAF, sizeof(KU_LEAF));
    if (bc_root && ku_ca && count == 2U) {
        out->role = CA_ROLE_ROOT;
    }
    else if (bc_iss && ku_ca && count == 2U) {
        out->role = CA_ROLE_ISSUING;
    }
    else if (bc_leaf && ku_leaf && count == 3U && span_is(der, e[2].oid_vs, e[2].oid_ve, OID_EKU, 3U) && !e[2].critical &&
             span_is(der, e[2].val_vs, e[2].val_ve, EKU_VALUE, sizeof(EKU_VALUE))) {
        out->role = CA_ROLE_DEVICE;
    }
    else {
        return CA_X509_ERR_PROFILE;
    }

    out->tbs.p = der + cert.vs;
    out->tbs.len = tbs.ve - cert.vs;
    out->sig.p = sig;
    out->sig.len = sig_len;
    out->serial.p = der + ser.vs;
    out->serial.len = sn;
    out->point = point;
    return CA_X509_OK;
}

/* ----------------------------------------------------------------------------------------------------------------- token */
ca_x509_status_t ca_token_parse(const uint8_t *data, size_t len, ca_token_t *out)
{
    if (data == NULL || len == 0U || out == NULL) {
        return CA_X509_ERR_PARAM;
    }
    memset(out, 0, sizeof(*out));
    if (len < 4U + 3U + 1U + 8U + 1U || memcmp(data, TOKEN_MAGIC, sizeof(TOKEN_MAGIC)) != 0) {
        return CA_X509_ERR_TOKEN;
    }
    if (data[4] != 1U || data[5] > 1U) {
        return CA_X509_ERR_TOKEN;
    }
    size_t n = data[6];
    if (n < 1U || n > 20U) {
        return CA_X509_ERR_TOKEN;
    }
    size_t o = 7U;
    out->serial.p = data + o;
    out->serial.len = n;
    o += n;
    if (o > len || len - o < 9U) { /* o = 7 + serial length can already be past the end: never subtract before comparing */
        return CA_X509_ERR_TOKEN;
    }
    out->this_update = ((uint32_t)data[o] << 24) | ((uint32_t)data[o + 1U] << 16) | ((uint32_t)data[o + 2U] << 8) | data[o + 3U];
    out->next_update = ((uint32_t)data[o + 4U] << 24) | ((uint32_t)data[o + 5U] << 16) | ((uint32_t)data[o + 6U] << 8) | data[o + 7U];
    o += 8U;
    size_t sl = data[o];
    o += 1U;
    if (sl < 8U || sl > 72U || len - o != sl) {
        return CA_X509_ERR_TOKEN;
    }
    out->body.p = data;
    out->body.len = o - 1U;
    out->sig.p = data + o;
    out->sig.len = sl;
    if (ecdsa_sig_der_ok(out->sig.p, out->sig.len) != CA_X509_OK) {
        return CA_X509_ERR_TOKEN;
    }
    out->revoked = data[5] == 1U;
    if (out->next_update < out->this_update) {
        return CA_X509_ERR_TOKEN;
    }
    return CA_X509_OK;
}

/* ----------------------------------------------------------------------------------------------------------------- chain */
static bool span_eq(ca_span_t a, ca_span_t b)
{
    return a.len == b.len && (a.len == 0U || memcmp(a.p, b.p, a.len) == 0);
}

ca_x509_status_t ca_chain_verify(const ca_trust_anchor_t *anchor, ca_span_t issuing_der, ca_span_t leaf_der, ca_span_t token,
                                 int64_t now, ca_verify_fn verify, void *ctx, ca_chain_t *out)
{
    if (anchor == NULL || anchor->root_point == NULL || verify == NULL || out == NULL) {
        return CA_X509_ERR_PARAM;
    }
    memset(out, 0, sizeof(*out));
    TRY(ca_x509_parse_cert(issuing_der.p, issuing_der.len, &out->issuing));
    TRY(ca_x509_parse_cert(leaf_der.p, leaf_der.len, &out->leaf));
    if (out->issuing.role != CA_ROLE_ISSUING || out->leaf.role != CA_ROLE_DEVICE) {
        return CA_X509_ERR_ROLE;
    }
    if (!span_eq(out->issuing.issuer, anchor->root_subject) || !span_eq(out->leaf.issuer, out->issuing.subject)) {
        return CA_X509_ERR_NAME;
    }
    if (!verify(ctx, anchor->root_point, out->issuing.tbs.p, out->issuing.tbs.len, out->issuing.sig.p, out->issuing.sig.len)) {
        return CA_X509_ERR_SIGNATURE;
    }
    if (!verify(ctx, out->issuing.point, out->leaf.tbs.p, out->leaf.tbs.len, out->leaf.sig.p, out->leaf.sig.len)) {
        return CA_X509_ERR_SIGNATURE;
    }

    if (token.p != NULL && token.len != 0U) {
        TRY(ca_token_parse(token.p, token.len, &out->token));
        out->have_token = true;
        uint8_t msg[sizeof(TOKEN_CONTEXT) + 64U];
        if (out->token.body.len > sizeof(msg) - sizeof(TOKEN_CONTEXT)) {
            return CA_X509_ERR_TOKEN;
        }
        memcpy(msg, TOKEN_CONTEXT, sizeof(TOKEN_CONTEXT));
        memcpy(msg + sizeof(TOKEN_CONTEXT), out->token.body.p, out->token.body.len);
        if (!verify(ctx, out->issuing.point, msg, sizeof(TOKEN_CONTEXT) + out->token.body.len, out->token.sig.p, out->token.sig.len)) {
            return CA_X509_ERR_SIGNATURE;
        }
        if (!span_eq(out->token.serial, out->leaf.serial)) {
            return CA_X509_ERR_TOKEN_SERIAL;
        }
        if (out->token.revoked) {
            return CA_X509_ERR_REVOKED;
        }
        if (!((int64_t)out->token.this_update <= now && now <= (int64_t)out->token.next_update)) {
            return CA_X509_ERR_TOKEN_TIME;
        }
    }
    if (!(out->issuing.not_before <= now && now <= out->issuing.not_after) || !(out->leaf.not_before <= now && now <= out->leaf.not_after)) {
        return CA_X509_ERR_CERT_TIME;
    }
    return CA_X509_OK;
}

const char *ca_x509_status_name(ca_x509_status_t s)
{
    switch (s) {
        case CA_X509_OK: return "OK";
        case CA_X509_ERR_PARAM: return "PARAM";
        case CA_X509_ERR_DER: return "DER";
        case CA_X509_ERR_PROFILE: return "PROFILE";
        case CA_X509_ERR_POINT: return "POINT";
        case CA_X509_ERR_ROLE: return "ROLE";
        case CA_X509_ERR_NAME: return "NAME";
        case CA_X509_ERR_SIGNATURE: return "SIGNATURE";
        case CA_X509_ERR_TOKEN: return "TOKEN";
        case CA_X509_ERR_TOKEN_SERIAL: return "TOKEN_SERIAL";
        case CA_X509_ERR_REVOKED: return "REVOKED";
        case CA_X509_ERR_TOKEN_TIME: return "TOKEN_TIME";
        case CA_X509_ERR_CERT_TIME: return "CERT_TIME";
        default: return "?";
    }
}
