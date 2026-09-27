#!/usr/bin/env python3
"""
ca_tool.py -- the CA side of EVT2's authenticated key exchange, for DEVELOPMENT and TESTING.

WHAT THIS TOOL IS FOR
  1. It plays the "CA server" until a real one exists: creates a test root CA and an issuing (intermediate) CA, issues X.509
     device certificates, issues short signed "status tokens" (the revocation / time mechanism) and revokes devices.
  2. It is the REFERENCE VERIFIER for the strict certificate profile (docs/key_exchange_ca_profile.md). The firmware will
     accept exactly what this verifier accepts and reject everything else; `selftest --write-vectors` writes test vectors
     (good and deliberately broken certificates/tokens) that the C parser must reproduce.
  3. It documents the rules by running them: `selftest` builds a whole PKI in a temp folder and runs positive and negative cases.

WHAT IT IS NOT
  * Not part of the firmware, not a production CA. Keys are written unencrypted (test use only). The real root key must live
    offline / in an HSM and the real issuing CA on a server; this tool only shows what they have to produce.
  * Not a general X.509 tool: it refuses to read anything outside the profile (P-256, ECDSA-SHA256, fixed fields).

THE PROFILE IN ONE PARAGRAPH (full text: docs/key_exchange_ca_profile.md)
  X.509 v3, ECDSA P-256 keys, ecdsa-with-SHA256, names are exactly O=<text>, CN=<text> (UTF8String, printable ASCII), UTCTime dates,
  extensions in a fixed order with fixed contents: root (CA, pathLen 1), issuing CA (CA, pathLen 0), device (not a CA,
  digitalSignature, EKU = 2.999.1.1). Chain = root (trust anchor, known to the device) -> issuing CA -> device.
  Status token: 4-byte magic, fixed layout, signed by the issuing CA key (see below).

Commands
  init-root     --dir D                      create the (test) root CA
  init-issuing  --root-dir R --dir D         create the issuing CA, signed by the root
  issue-device  --dir D --device-id HEX --pubkey FILE|HEX --out cert.pem     issue a device certificate
  revoke        --dir D --serial HEX         mark a certificate revoked (the next status token says so)
  status        --dir D --serial HEX --out token.bin [--hours 24]            issue a status token
  verify        --root-cert R --issuing I --leaf L [--token T] [--now UNIX]  strict chain + token check
  inspect       FILE                         print a certificate / token as the strict parser sees it
  make-test-pki --out DIR                    build the committed development PKI (tools/test_ca)
  selftest      [--write-vectors FILE]       run every positive and negative case

Requires: pip install cryptography
"""
import argparse
import calendar
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

# ----------------------------------------------------------------------------- profile constants
OID_EVT2_DEVICE_EKU = ObjectIdentifier("2.999.1.1")  # 2.999 = the "example" arc; replace with an own PEN before any real deployment
ORG_DEFAULT = "EVT2"
ALG_ECDSA_SHA256 = bytes.fromhex("300a06082a8648ce3d040302")           # AlgorithmIdentifier, no parameters
SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")  # + 04||X||Y
OID_O, OID_CN = bytes.fromhex("55040a"), bytes.fromhex("550403")
OID_BC, OID_KU, OID_EKU = bytes.fromhex("551d13"), bytes.fromhex("551d0f"), bytes.fromhex("551d25")
BC_LEAF = bytes.fromhex("3000")
BC_ISSUING = bytes.fromhex("3006010" + "1ff020100")  # CA:TRUE, pathLen 0
BC_ROOT = bytes.fromhex("3006010" + "1ff020101")     # CA:TRUE, pathLen 1
KU_CA = bytes.fromhex("03020204")                    # keyCertSign
KU_LEAF = bytes.fromhex("03020780")                  # digitalSignature
EKU_VALUE = bytes.fromhex("300606048837" + "0101")   # SEQUENCE { 2.999.1.1 }
TOKEN_MAGIC = b"EVST"
TOKEN_CONTEXT = b"EVT2-STATUS-v1\x00"
ROLE_ROOT, ROLE_ISSUING, ROLE_DEVICE = "root", "issuing", "device"


class ProfileError(Exception):
    """The input is outside the strict profile (or a signature/validity check failed)."""


# ----------------------------------------------------------------------------- strict DER reader
def read_tlv(buf: bytes, off: int, end: int):
    """One definite-length TLV with minimal length encoding. Returns (tag, value_start, value_end, next_off)."""
    if off + 2 > end:
        raise ProfileError("truncated TLV header")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise ProfileError("multi-byte tags are not allowed")
    b = buf[off + 1]
    pos = off + 2
    if b < 0x80:
        length = b
    elif b == 0x80:
        raise ProfileError("indefinite length is not allowed")
    else:
        n = b & 0x7F
        if n > 2 or pos + n > end:
            raise ProfileError("length field too long or truncated")
        length = int.from_bytes(buf[pos:pos + n], "big")
        if buf[pos] == 0 or length < 0x80 or (n == 2 and length < 0x100):
            raise ProfileError("non-minimal length encoding")
        pos += n
    if pos + length > end:
        raise ProfileError("length runs past the end of the enclosing structure")
    return tag, pos, pos + length, pos + length


def expect(buf, off, end, tag, what):
    t, vs, ve, nxt = read_tlv(buf, off, end)
    if t != tag:
        raise ProfileError(f"{what}: expected tag 0x{tag:02X}, got 0x{t:02X}")
    return vs, ve, nxt


def ecdsa_sig_der_ok(sig: bytes) -> None:
    vs, ve, nxt = expect(sig, 0, len(sig), 0x30, "ECDSA signature")
    if nxt != len(sig):
        raise ProfileError("ECDSA signature: trailing bytes")
    o = vs
    for name in ("r", "s"):
        ivs, ive, o = expect(sig, o, ve, 0x02, f"ECDSA {name}")
        v = sig[ivs:ive]
        if not v or v[0] & 0x80 or (len(v) > 1 and v[0] == 0 and not v[1] & 0x80) or len(v) > 33:
            raise ProfileError(f"ECDSA {name}: not a minimal positive INTEGER")
    if o != ve:
        raise ProfileError("ECDSA signature: extra content")


def parse_name(buf, off, end, what):
    """Name must be exactly  SEQUENCE { SET{SEQ{O, UTF8}} SET{SEQ{CN, UTF8}} }, printable ASCII, 1..64 bytes each."""
    vs, ve, nxt = expect(buf, off, end, 0x30, what)
    o, out = vs, []
    for oid, label in ((OID_O, "O"), (OID_CN, "CN")):
        svs, sve, o = expect(buf, o, ve, 0x31, f"{what} RDN")
        avs, ave, after = expect(buf, svs, sve, 0x30, f"{what} AVA")
        if after != sve:
            raise ProfileError(f"{what}: multi-valued RDN")
        ovs, ove, p = expect(buf, avs, ave, 0x06, f"{what} attribute type")
        if buf[ovs:ove] != oid:
            raise ProfileError(f"{what}: expected attribute {label}")
        tvs, tve, p = expect(buf, p, ave, 0x0C, f"{what} {label} must be UTF8String")
        if p != ave:
            raise ProfileError(f"{what}: trailing data in attribute")
        val = buf[tvs:tve]
        if not 1 <= len(val) <= 64 or any(c < 0x20 or c > 0x7E for c in val):
            raise ProfileError(f"{what} {label}: 1..64 printable ASCII bytes required")
        out.append(val.decode("ascii"))
    if o != ve:
        raise ProfileError(f"{what}: only O and CN are allowed")
    return out[0], out[1], buf[off:nxt]


def parse_utctime(buf, off, end, what) -> int:
    vs, ve, nxt = expect(buf, off, end, 0x17, f"{what} must be UTCTime")
    s = buf[vs:ve]
    if len(s) != 13 or s[12:] != b"Z" or not s[:12].isdigit():
        raise ProfileError(f"{what}: UTCTime must be YYMMDDHHMMSSZ")
    yy, mo, dd, hh, mi, ss = (int(s[i:i + 2]) for i in range(0, 12, 2))
    year = 2000 + yy if yy < 50 else 1900 + yy
    if not (1 <= mo <= 12 and 1 <= dd <= 31 and hh < 24 and mi < 60 and ss < 60):
        raise ProfileError(f"{what}: impossible date")
    try:
        return calendar.timegm((year, mo, dd, hh, mi, ss, 0, 0, 0))
    except (ValueError, OverflowError):
        raise ProfileError(f"{what}: impossible date")


class Cert:
    """A certificate accepted by the strict parser."""
    def __init__(self):
        self.der = b""
        self.tbs = b""
        self.sig = b""
        self.serial = b""
        self.issuer = ("", "", b"")
        self.subject = ("", "", b"")
        self.not_before = 0
        self.not_after = 0
        self.point = b""
        self.role = ""


def parse_cert(der: bytes) -> Cert:
    c = Cert()
    c.der = bytes(der)
    vs, ve, nxt = expect(der, 0, len(der), 0x30, "Certificate")
    if nxt != len(der):
        raise ProfileError("trailing bytes after the certificate")
    tbs_start = vs
    tvs, tve, o = expect(der, vs, ve, 0x30, "tbsCertificate")
    c.tbs = der[tbs_start:o]
    if der[o:o + len(ALG_ECDSA_SHA256)] != ALG_ECDSA_SHA256:
        raise ProfileError("signatureAlgorithm must be ecdsa-with-SHA256 without parameters")
    o += len(ALG_ECDSA_SHA256)
    svs, sve, o = expect(der, o, ve, 0x03, "signatureValue")
    if o != ve:
        raise ProfileError("extra data after signatureValue")
    if sve - svs < 9 or der[svs] != 0:
        raise ProfileError("signature BIT STRING must have 0 unused bits and hold a signature")
    c.sig = der[svs + 1:sve]
    ecdsa_sig_der_ok(c.sig)

    p = tvs
    if der[p:p + 5] != bytes.fromhex("a003020102"):
        raise ProfileError("version must be v3")
    p += 5
    ivs, ive, p = expect(der, p, tve, 0x02, "serialNumber")
    s = der[ivs:ive]
    if not 1 <= len(s) <= 20 or s[0] & 0x80 or (len(s) > 1 and s[0] == 0 and not s[1] & 0x80) or s == b"\x00":
        raise ProfileError("serialNumber must be a minimal positive INTEGER of 1..20 bytes")
    c.serial = s
    if der[p:p + len(ALG_ECDSA_SHA256)] != ALG_ECDSA_SHA256:
        raise ProfileError("tbs signature algorithm must be ecdsa-with-SHA256 without parameters")
    p += len(ALG_ECDSA_SHA256)
    o_, cn_, raw = None, None, None
    c.issuer = None
    vo, vc, vraw = parse_name(der, p, tve, "issuer")
    c.issuer = (vo, vc, vraw)
    p += len(vraw)
    vvs, vve, p = expect(der, p, tve, 0x30, "validity")
    q = vvs
    c.not_before = parse_utctime(der, q, vve, "notBefore")
    q += 15
    c.not_after = parse_utctime(der, q, vve, "notAfter")
    q += 15
    if q != vve or vve - vvs != 30:
        raise ProfileError("validity must hold exactly two UTCTimes")
    if c.not_after < c.not_before:
        raise ProfileError("notAfter before notBefore")
    so, sc, sraw = parse_name(der, p, tve, "subject")
    c.subject = (so, sc, sraw)
    p += len(sraw)
    if der[p:p + len(SPKI_P256_PREFIX)] != SPKI_P256_PREFIX:
        raise ProfileError("subjectPublicKeyInfo must be an uncompressed P-256 key")
    p += len(SPKI_P256_PREFIX)
    c.point = der[p:p + 65]
    if len(c.point) != 65 or c.point[0] != 4:
        raise ProfileError("bad P-256 point")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), c.point)
    except ValueError:
        raise ProfileError("the public key is not on the P-256 curve")
    p += 65
    evs, eve, p = expect(der, p, tve, 0xA3, "extensions [3]")
    if p != tve:
        raise ProfileError("unexpected fields after the extensions")
    xvs, xve, after = expect(der, evs, eve, 0x30, "extensions")
    if after != eve:
        raise ProfileError("extra data in extensions [3]")
    exts, o = [], xvs
    while o < xve:
        e_vs, e_ve, o = expect(der, o, xve, 0x30, "extension")
        q = e_vs
        ovs, ove, q = expect(der, q, e_ve, 0x06, "extension id")
        oid = der[ovs:ove]
        crit = False
        if q < e_ve and der[q] == 0x01:
            bvs, bve, q = expect(der, q, e_ve, 0x01, "critical")
            if der[bvs:bve] != b"\xff":
                raise ProfileError("critical flag must be TRUE when present (DER)")
            crit = True
        mvs, mve, q = expect(der, q, e_ve, 0x04, "extension value")
        if q != e_ve:
            raise ProfileError("trailing data in an extension")
        exts.append((oid, crit, der[mvs:mve]))
    if len(exts) < 2 or exts[0][0] != OID_BC or exts[1][0] != OID_KU or not exts[0][1] or not exts[1][1]:
        raise ProfileError("extensions must start with critical basicConstraints then critical keyUsage")
    bc, ku = exts[0][2], exts[1][2]
    if bc == BC_ROOT and ku == KU_CA and len(exts) == 2:
        c.role = ROLE_ROOT
    elif bc == BC_ISSUING and ku == KU_CA and len(exts) == 2:
        c.role = ROLE_ISSUING
    elif bc == BC_LEAF and ku == KU_LEAF and len(exts) == 3 and exts[2] == (OID_EKU, False, EKU_VALUE):
        c.role = ROLE_DEVICE
    else:
        raise ProfileError("extensions do not match any profile role (root / issuing CA / device)")
    return c


def verify_sig(point: bytes, tbs: bytes, sig: bytes) -> bool:
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    try:
        key.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ----------------------------------------------------------------------------- status token
def build_token(ca_key, serial: bytes, revoked: bool, this_update: int, next_update: int) -> bytes:
    if not 1 <= len(serial) <= 20:
        raise ProfileError("serial must be 1..20 bytes")
    body = (TOKEN_MAGIC + bytes([1, 1 if revoked else 0, len(serial)]) + serial +
            this_update.to_bytes(4, "big") + next_update.to_bytes(4, "big"))
    sig = ca_key.sign(TOKEN_CONTEXT + body, ec.ECDSA(hashes.SHA256()))
    return body + bytes([len(sig)]) + sig


class Token:
    pass


def parse_token(data: bytes) -> Token:
    t = Token()
    if len(data) < 4 + 3 + 1 + 8 + 1 or data[:4] != TOKEN_MAGIC:
        raise ProfileError("token: bad magic or too short")
    if data[4] != 1:
        raise ProfileError("token: unknown version")
    if data[5] not in (0, 1):
        raise ProfileError("token: status must be 0 (good) or 1 (revoked)")
    n = data[6]
    if not 1 <= n <= 20:
        raise ProfileError("token: bad serial length")
    o = 7
    t.serial = data[o:o + n]
    o += n
    if o + 9 > len(data):
        raise ProfileError("token: truncated")
    t.this_update = int.from_bytes(data[o:o + 4], "big")
    t.next_update = int.from_bytes(data[o + 4:o + 8], "big")
    o += 8
    sl = data[o]
    o += 1
    if sl < 8 or sl > 72 or o + sl != len(data):
        raise ProfileError("token: bad signature length or trailing bytes")
    t.body = data[:o - 1]
    t.sig = data[o:]
    ecdsa_sig_der_ok(t.sig)
    t.revoked = data[5] == 1
    if t.next_update < t.this_update:
        raise ProfileError("token: nextUpdate before thisUpdate")
    return t


# ----------------------------------------------------------------------------- chain verification (the rules the firmware must follow)
def verify_chain(root_point: bytes, root_subject_raw: bytes, issuing_der: bytes, leaf_der: bytes,
                 token: bytes = None, now: int = None):
    """Returns the leaf Cert or raises ProfileError. With a token, `now` defaults to the token's thisUpdate (the device has no
    trusted clock -- the token IS its clock); without one `now` defaults to the host clock."""
    iss = parse_cert(issuing_der)
    leaf = parse_cert(leaf_der)
    if iss.role != ROLE_ISSUING:
        raise ProfileError("the second certificate is not an issuing CA certificate")
    if leaf.role != ROLE_DEVICE:
        raise ProfileError("the leaf is not a device certificate")
    if iss.issuer[2] != root_subject_raw:
        raise ProfileError("issuing CA was not issued by the trusted root (issuer name differs)")
    if leaf.issuer[2] != iss.subject[2]:
        raise ProfileError("device certificate was not issued by this issuing CA (issuer name differs)")
    if not verify_sig(root_point, iss.tbs, iss.sig):
        raise ProfileError("issuing CA signature does not verify under the trusted root key")
    if not verify_sig(iss.point, leaf.tbs, leaf.sig):
        raise ProfileError("device certificate signature does not verify under the issuing CA key")
    tok = None
    if token is not None:
        tok = parse_token(token)
        if not verify_sig(iss.point, TOKEN_CONTEXT + tok.body, tok.sig):
            raise ProfileError("status token signature does not verify under the issuing CA key")
        if tok.serial != leaf.serial:
            raise ProfileError("status token is for a different certificate serial")
        if tok.revoked:
            raise ProfileError("REVOKED: the status token says this certificate is revoked")
        if now is None:
            now = tok.this_update
        if not tok.this_update <= now <= tok.next_update:
            raise ProfileError("status token is not valid at this time (expired or from the future)")
    elif now is None:
        now = int(time.time())
    for name, cert in (("issuing CA", iss), ("device", leaf)):
        if not cert.not_before <= now <= cert.not_after:
            raise ProfileError(f"{name} certificate is not valid at this time")
    leaf.issuing = iss
    leaf.token = tok
    return leaf


# ----------------------------------------------------------------------------- issuing side (uses the `cryptography` builder)
def _name(cn: str, org: str = ORG_DEFAULT) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def build_cert(subject_pub, subject_cn, issuer_key, issuer_name, role, not_before, not_after, serial=None,
               hash_alg=None, extra_ext=None, drop_eku=False, eku_oid=None, ca_flag_override=None):
    """Issue a certificate. The keyword overrides exist only so selftest can make deliberately non-conforming certificates."""
    serial = serial if serial is not None else int.from_bytes(secrets.token_bytes(16), "big") >> 1 | 1 << 120
    b = (x509.CertificateBuilder().subject_name(_name(subject_cn)).issuer_name(issuer_name)
         .public_key(subject_pub).serial_number(serial).not_valid_before(not_before).not_valid_after(not_after))
    is_ca = role in (ROLE_ROOT, ROLE_ISSUING) if ca_flag_override is None else ca_flag_override
    pathlen = {ROLE_ROOT: 1, ROLE_ISSUING: 0}.get(role) if is_ca else None
    b = b.add_extension(x509.BasicConstraints(ca=is_ca, path_length=pathlen), critical=True)
    if role == ROLE_DEVICE:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        if not drop_eku:
            b = b.add_extension(x509.ExtendedKeyUsage([eku_oid or OID_EVT2_DEVICE_EKU]), critical=False)
    else:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, False, False, False), critical=True)
    if extra_ext:
        b = b.add_extension(extra_ext, critical=False)
    return b.sign(issuer_key, hash_alg or hashes.SHA256())


def cert_der(c) -> bytes:
    return c.public_bytes(serialization.Encoding.DER)


def pem_to_der(path) -> bytes:
    data = Path(path).read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data).public_bytes(serialization.Encoding.DER)
    return data


def write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def point_of(key_or_pub) -> bytes:
    pub = key_or_pub.public_key() if hasattr(key_or_pub, "public_key") else key_or_pub
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def utc(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def hexs(b: bytes) -> str:
    return b.hex().upper()


# ----------------------------------------------------------------------------- commands
def cmd_init_root(a) -> int:
    d = Path(a.dir)
    if (d / "key.pem").exists():
        raise ProfileError(f"{d} already holds a root CA -- refusing to overwrite")
    d.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time())
    name = _name(a.cn)
    cert = build_cert(key.public_key(), a.cn, key, name, ROLE_ROOT, utc(now - 60), utc(now + a.years * 365 * 86400))
    write_key(d / "key.pem", key)
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    parse_cert(cert_der(cert))  # the profile must accept what we make
    print(f"root CA written to {d}  (key.pem = TEST ONLY, unencrypted)")
    return 0


def cmd_init_issuing(a) -> int:
    r, d = Path(a.root_dir), Path(a.dir)
    if (d / "key.pem").exists():
        raise ProfileError(f"{d} already holds an issuing CA -- refusing to overwrite")
    d.mkdir(parents=True, exist_ok=True)
    rkey = load_key(r / "key.pem")
    rcert = x509.load_pem_x509_certificate((r / "cert.pem").read_bytes())
    key = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time())
    cert = build_cert(key.public_key(), a.cn, rkey, rcert.subject, ROLE_ISSUING, utc(now - 60), utc(now + a.years * 365 * 86400))
    parse_cert(cert_der(cert))
    write_key(d / "key.pem", key)
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "root_cert.pem").write_bytes(rcert.public_bytes(serialization.Encoding.PEM))
    (d / "issued.json").write_text("[]")
    print(f"issuing CA written to {d}")
    return 0


def _db(d: Path):
    return json.loads((d / "issued.json").read_text())


def _db_save(d: Path, db) -> None:
    (d / "issued.json").write_text(json.dumps(db, indent=2))


def load_pubkey_arg(s: str):
    p = Path(s)
    if p.exists():
        data = p.read_bytes()
        if b"BEGIN CERTIFICATE" in data:
            return x509.load_pem_x509_certificate(data).public_key()
        if b"BEGIN PUBLIC KEY" in data:
            return serialization.load_pem_public_key(data)
        if b"PRIVATE KEY" in data:
            return serialization.load_pem_private_key(data, password=None).public_key()
        s = data.decode().strip()
    raw = bytes.fromhex(s.replace(":", "").replace(" ", ""))
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def cmd_issue_device(a) -> int:
    d = Path(a.dir)
    key = load_key(d / "key.pem")
    icert = x509.load_pem_x509_certificate((d / "cert.pem").read_bytes())
    pub = load_pubkey_arg(a.pubkey)
    dev = bytes.fromhex(a.device_id)
    if not 1 <= len(dev) <= 32:
        raise ProfileError("device id must be 1..32 bytes of hex (the SE052F unique id is 18 bytes)")
    cn = hexs(dev)
    now = int(time.time())
    cert = build_cert(pub, cn, key, icert.subject, ROLE_DEVICE, utc(now - 60), utc(now + a.days * 86400))
    c = parse_cert(cert_der(cert))
    Path(a.out).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    db = _db(d)
    db.append({"serial": hexs(c.serial), "device_id": cn, "not_before": c.not_before, "not_after": c.not_after, "status": "good"})
    _db_save(d, db)
    print(f"issued device certificate serial {hexs(c.serial)} for {cn} -> {a.out}")
    return 0


def cmd_revoke(a) -> int:
    d = Path(a.dir)
    db = _db(d)
    hit = [e for e in db if e["serial"] == a.serial.upper()]
    if not hit:
        raise ProfileError("no such serial in this CA's database")
    for e in hit:
        e["status"] = "revoked"
        e["revoked_at"] = int(time.time())
    _db_save(d, db)
    print(f"serial {a.serial.upper()} marked revoked; the next status token will say so")
    return 0


def cmd_status(a) -> int:
    d = Path(a.dir)
    key = load_key(d / "key.pem")
    serial = bytes.fromhex(a.serial)
    hit = [e for e in _db(d) if e["serial"] == a.serial.upper()]
    if not hit:
        raise ProfileError("no such serial in this CA's database (not issued here)")
    now = int(time.time()) if a.now is None else a.now
    tok = build_token(key, serial, hit[0]["status"] == "revoked", now, now + int(a.hours * 3600))
    Path(a.out).write_bytes(tok)
    print(f"status token ({'REVOKED' if hit[0]['status'] == 'revoked' else 'good'}), {len(tok)} bytes, valid {a.hours} h -> {a.out}")
    return 0


def cmd_verify(a) -> int:
    root = parse_cert(pem_to_der(a.root_cert))
    if root.role != ROLE_ROOT:
        raise ProfileError("--root-cert is not a root CA certificate")
    if not verify_sig(root.point, root.tbs, root.sig):
        raise ProfileError("the root certificate is not correctly self-signed")
    tok = Path(a.token).read_bytes() if a.token else None
    leaf = verify_chain(root.point, root.subject[2], pem_to_der(a.issuing), pem_to_der(a.leaf), tok, a.now)
    print(f"VALID: device {leaf.subject[1]}, serial {hexs(leaf.serial)}, chain root -> issuing -> device"
          f"{', status token good' if tok else ' (no status token given: revocation NOT checked)'}")
    return 0


def cmd_inspect(a) -> int:
    data = Path(a.file).read_bytes()
    if data[:4] == TOKEN_MAGIC:
        t = parse_token(data)
        print(f"status token: serial {hexs(t.serial)}  {'REVOKED' if t.revoked else 'good'}  "
              f"thisUpdate {utc(t.this_update)}  nextUpdate {utc(t.next_update)}  ({len(data)} bytes)")
        return 0
    c = parse_cert(pem_to_der(a.file))
    print(f"role      : {c.role}\nserial    : {hexs(c.serial)}\nissuer    : O={c.issuer[0]} CN={c.issuer[1]}\n"
          f"subject   : O={c.subject[0]} CN={c.subject[1]}\nvalid     : {utc(c.not_before)} .. {utc(c.not_after)} UTC\n"
          f"public key: {hexs(c.point)}\nDER size  : {len(c.der)} bytes")
    return 0


def make_pki(out: Path, long_lived=False):
    """The development PKI: root, issuing CA, two device keypairs + certificates, a good and a revoked status token."""
    out.mkdir(parents=True, exist_ok=True)
    ns = argparse.Namespace
    cmd_init_root(ns(dir=str(out / "root"), cn="EVT2 TEST Root CA", years=20))
    cmd_init_issuing(ns(root_dir=str(out / "root"), dir=str(out / "issuing"), cn="EVT2 TEST Issuing CA", years=5))
    for i, dev in enumerate(("A", "B")):
        k = ec.generate_private_key(ec.SECP256R1())
        write_key(out / f"device_{dev}_key.pem", k)
        did = ("0" + str(i + 1)) * 18  # 18 bytes, like an SE052F unique id
        cmd_issue_device(ns(dir=str(out / "issuing"), device_id=did, pubkey=hexs(point_of(k)), days=3650 if long_lived else 365,
                            out=str(out / f"device_{dev}_cert.pem")))
    serials = {e["device_id"]: e["serial"] for e in _db(out / "issuing")}
    a_serial = serials[("01") * 18]
    b_serial = serials[("02") * 18]
    cmd_status(ns(dir=str(out / "issuing"), serial=a_serial, hours=24, out=str(out / "device_A_status_good.bin"), now=None) if not long_lived else ns(dir=str(out / "issuing"), serial=a_serial, hours=87600, out=str(out / "device_A_status_good.bin"), now=None))
    cmd_revoke(ns(dir=str(out / "issuing"), serial=b_serial))
    cmd_status(ns(dir=str(out / "issuing"), serial=b_serial, hours=24, out=str(out / "device_B_status_revoked.bin"), now=None) if not long_lived else ns(dir=str(out / "issuing"), serial=b_serial, hours=87600, out=str(out / "device_B_status_revoked.bin"), now=None))
    return 0


# ----------------------------------------------------------------------------- selftest
def selftest(a) -> int:
    fails = []
    vectors = []

    def case(name, fn, expect_ok, why="", vec=None):
        try:
            fn()
            ok, msg = True, ""
        except ProfileError as e:
            ok, msg = False, str(e)
        good = ok == expect_ok
        print(("PASS  " if good else "FAIL  ") + name + ("" if ok else f"   [rejected: {msg}]"))
        if not good:
            fails.append(name)
        if vec is not None:
            vectors.append({"name": name, "expect": "accept" if expect_ok else "reject", **vec})

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        make_pki(tmp / "pki")
        pki = tmp / "pki"
        rc = parse_cert(pem_to_der(pki / "root" / "cert.pem"))
        iss_der = pem_to_der(pki / "issuing" / "cert.pem")
        dev_a = pem_to_der(pki / "device_A_cert.pem")
        dev_b = pem_to_der(pki / "device_B_cert.pem")
        tok_a = (pki / "device_A_status_good.bin").read_bytes()
        tok_b = (pki / "device_B_status_revoked.bin").read_bytes()
        rp, rn = rc.point, rc.subject[2]
        ikey = load_key(pki / "issuing" / "key.pem")
        rkey = load_key(pki / "root" / "key.pem")
        iname = x509.load_pem_x509_certificate((pki / "issuing" / "cert.pem").read_bytes()).subject
        now = int(time.time())
        V = lambda **kw: verify_chain(rp, rn, kw.get("iss", iss_der), kw.get("leaf", dev_a), kw.get("tok", tok_a), kw.get("now"))
        hx = lambda b: hexs(b)

        # ---- positive
        case("valid chain + good status token", lambda: V(), True, vec={"leaf": hx(dev_a), "issuing": hx(iss_der), "token": hx(tok_a)})
        case("valid chain without a token (revocation not checked)", lambda: V(tok=None), True)
        # ---- revocation / token
        case("revoked status token", lambda: V(leaf=dev_b, tok=tok_b), False, vec={"leaf": hx(dev_b), "issuing": hx(iss_der), "token": hx(tok_b)})
        sa = parse_cert(dev_a).serial
        case("token for a different serial", lambda: V(tok=build_token(ikey, b"\x01\x02", False, now, now + 3600)), False)
        case("expired token", lambda: V(tok=build_token(ikey, sa, False, now - 7200, now - 3600), now=now), False)
        case("token from the future", lambda: V(tok=build_token(ikey, sa, False, now + 3600, now + 7200), now=now), False)
        case("token signed by the wrong key", lambda: V(tok=build_token(ec.generate_private_key(ec.SECP256R1()), sa, False, now, now + 3600)), False)
        bad = bytearray(tok_a)
        bad[8] ^= 1
        case("token with a flipped byte", lambda: V(tok=bytes(bad)), False, vec={"leaf": hx(dev_a), "issuing": hx(iss_der), "token": hx(bytes(bad))})
        case("token with trailing garbage", lambda: V(tok=tok_a + b"\x00"), False)
        case("token truncated", lambda: V(tok=tok_a[:-3]), False)
        case("token with an unknown version", lambda: V(tok=tok_a[:4] + b"\x02" + tok_a[5:]), False)
        # ---- chain
        other_root = ec.generate_private_key(ec.SECP256R1())
        case("issuing CA signed by an unknown root", lambda: verify_chain(point_of(other_root), rn, iss_der, dev_a, tok_a), False)
        case("wrong root subject name", lambda: verify_chain(rp, b"\x30\x00", iss_der, dev_a, tok_a), False)
        stranger = ec.generate_private_key(ec.SECP256R1())
        c_str = cert_der(build_cert(stranger.public_key(), "STRANGER", stranger, _name("STRANGER"), ROLE_DEVICE, utc(now - 60), utc(now + 86400)))
        case("device cert signed by a key that is not the issuing CA", lambda: V(leaf=c_str, tok=None), False)
        wrong_sig = cert_der(build_cert(ec.generate_private_key(ec.SECP256R1()).public_key(), "AB" * 18, stranger, iname, ROLE_DEVICE, utc(now - 60), utc(now + 86400)))
        case("right issuer name but signed by a different key", lambda: V(leaf=wrong_sig, tok=None), False)
        case("swapped order (device where the issuing CA belongs)", lambda: V(iss=dev_a, leaf=iss_der, tok=None), False)
        # ---- validity
        dk = ec.generate_private_key(ec.SECP256R1())
        expired = cert_der(build_cert(dk.public_key(), "AB" * 18, ikey, iname, ROLE_DEVICE, utc(now - 200000), utc(now - 100000)))
        case("expired device certificate", lambda: V(leaf=expired, tok=None), False, vec={"leaf": hx(expired), "issuing": hx(iss_der)})
        early = cert_der(build_cert(dk.public_key(), "AB" * 18, ikey, iname, ROLE_DEVICE, utc(now + 100000), utc(now + 200000)))
        case("device certificate not yet valid", lambda: V(leaf=early, tok=None), False)
        # ---- profile violations (built with the normal builder, then deliberately non-conforming)
        def leaf_with(**kw):
            return cert_der(build_cert(dk.public_key(), "CD" * 18, ikey, iname, ROLE_DEVICE, utc(now - 60), utc(now + 86400), **kw))
        p384 = ec.generate_private_key(ec.SECP384R1())
        case("P-384 subject key", lambda: parse_cert(cert_der(build_cert(p384.public_key(), "CD" * 18, ikey, iname, ROLE_DEVICE, utc(now - 60), utc(now + 86400)))), False)
        case("ecdsa-with-SHA384 signature", lambda: parse_cert(leaf_with(hash_alg=hashes.SHA384())), False)
        case("extra extension (subjectKeyIdentifier)", lambda: parse_cert(leaf_with(extra_ext=x509.SubjectKeyIdentifier.from_public_key(dk.public_key()))), False)
        case("device certificate flagged as CA", lambda: parse_cert(leaf_with(ca_flag_override=True)), False)
        case("device certificate without the EVT2 EKU", lambda: parse_cert(leaf_with(drop_eku=True)), False)
        case("device certificate with a different EKU", lambda: parse_cert(leaf_with(eku_oid=ObjectIdentifier("2.999.9.9"))), False)
        far = cert_der(build_cert(dk.public_key(), "EF" * 18, ikey, iname, ROLE_DEVICE, utc(now), datetime(2055, 1, 1)))
        case("GeneralizedTime (year >= 2050)", lambda: parse_cert(far), False)
        pn = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EVT2"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "GH" * 18, _type=x509.name._ASN1Type.PrintableString)])
        b = (x509.CertificateBuilder().subject_name(pn).issuer_name(iname).public_key(dk.public_key()).serial_number(12345)
             .not_valid_before(utc(now - 60)).not_valid_after(utc(now + 86400))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([OID_EVT2_DEVICE_EKU]), critical=False))
        case("PrintableString instead of UTF8String in a name", lambda: parse_cert(cert_der(b.sign(ikey, hashes.SHA256()))), False)
        three = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EVT2"),
                           x509.NameAttribute(NameOID.COMMON_NAME, "IJ" * 18)])
        b3 = (x509.CertificateBuilder().subject_name(three).issuer_name(iname).public_key(dk.public_key()).serial_number(12346)
              .not_valid_before(utc(now - 60)).not_valid_after(utc(now + 86400))
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
              .add_extension(x509.ExtendedKeyUsage([OID_EVT2_DEVICE_EKU]), critical=False))
        case("three-attribute subject name", lambda: parse_cert(cert_der(b3.sign(ikey, hashes.SHA256()))), False)
        case("root certificate offered as the issuing CA", lambda: V(iss=cert_der(x509.load_pem_x509_certificate((pki / "root" / "cert.pem").read_bytes())), tok=None), False)
        # an issuing CA with pathLen 1 (would allow a further CA level) must not pass as an issuing CA
        ca2 = cert_der(build_cert(ikey.public_key(), "EVT2 TEST Issuing CA", rkey, x509.load_pem_x509_certificate((pki / "root" / "cert.pem").read_bytes()).subject, ROLE_ROOT, utc(now - 60), utc(now + 86400)))
        case("issuing CA with pathLen 1 (parses as a root, not an issuing CA)", lambda: V(iss=ca2, tok=None), False)
        # ---- byte-level attacks on the DER
        case("trailing byte after the certificate", lambda: parse_cert(dev_a + b"\x00"), False, vec={"leaf": hx(dev_a + b"\x00")})
        case("truncated certificate", lambda: parse_cert(dev_a[:-1]), False)
        tail = dev_a[4:]  # 30 82 LL LL <body>
        case("non-minimal length (30 83 00 ..)", lambda: parse_cert(b"\x30\x83\x00" + dev_a[2:4] + tail), False)
        case("indefinite length (30 80 .. 00 00)", lambda: parse_cert(b"\x30\x80" + tail + b"\x00\x00"), False)
        case("empty input", lambda: parse_cert(b""), False)
        tam = bytearray(dev_a)
        tam[60] ^= 1  # inside the signed part
        case("one flipped byte inside the certificate", lambda: V(leaf=bytes(tam), tok=None), False, vec={"leaf": hx(bytes(tam)), "issuing": hx(iss_der)})
        cnflip = bytearray(dev_a)
        cnflip[cnflip.index(b"01010101") + 2] ^= 1  # a character inside the subject CN: still valid DER, only the signature can notice
        parse_cert(bytes(cnflip))  # must still PARSE, otherwise this case would not test the signature
        case("one flipped character inside the subject CN (structure valid, signature must catch it)", lambda: V(leaf=bytes(cnflip), tok=None), False, vec={"leaf": hx(bytes(cnflip)), "issuing": hx(iss_der)})
        sigflip = bytearray(dev_a)
        sigflip[-5] ^= 1
        case("one flipped byte inside the signature", lambda: V(leaf=bytes(sigflip), tok=None), False)
        # the parser must also accept what the builder makes for every role
        case("root certificate parses as a root", lambda: parse_cert(pem_to_der(pki / "root" / "cert.pem")), True)
        case("issuing certificate parses as an issuing CA", lambda: (parse_cert(iss_der).role == ROLE_ISSUING) or (_ for _ in ()).throw(ProfileError("wrong role")), True)
        # fuzz: no crash other than ProfileError, on many mutated inputs
        rng = secrets.SystemRandom()
        crashes = 0
        for _ in range(3000):
            m = bytearray(dev_a)
            for _ in range(rng.choice((1, 1, 2, 3))):
                m[rng.randrange(len(m))] = rng.randrange(256)
            if rng.random() < 0.15:
                m = m[:rng.randrange(1, len(m))]
            try:
                V(leaf=bytes(m), tok=None)
            except ProfileError:
                pass
            except Exception:  # anything else means the strict parser let something odd through
                crashes += 1
        print(("PASS  " if crashes == 0 else "FAIL  ") + f"fuzz: 3000 mutated certificates, unexpected exceptions: {crashes}")
        if crashes:
            fails.append("fuzz")
        # nothing mutated should ever verify
        accepted = 0
        for _ in range(3000):
            m = bytearray(dev_a)
            m[rng.randrange(len(m))] ^= 1 << rng.randrange(8)
            try:
                V(leaf=bytes(m), tok=None)
                accepted += 1
            except ProfileError:
                pass
        print(("PASS  " if accepted == 0 else "FAIL  ") + f"fuzz: 3000 single-bit flips, mutated certificates accepted: {accepted}")
        if accepted:
            fails.append("bitflip")
        if a.write_vectors:
            meta = {"note": "test vectors for the strict profile; hex DER. 'now' is implied by the token (thisUpdate) unless a case says otherwise.",
                    "root_point": hx(rp), "root_subject_der": hx(rn), "cases": vectors}
            Path(a.write_vectors).write_text(json.dumps(meta, indent=1))
            print(f"vectors written to {a.write_vectors} ({len(vectors)} cases)")
    print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED: {fails}")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init-root")
    p.add_argument("--dir", required=True)
    p.add_argument("--cn", default="EVT2 TEST Root CA")
    p.add_argument("--years", type=int, default=20)
    p.set_defaults(fn=cmd_init_root)
    p = sub.add_parser("init-issuing")
    p.add_argument("--root-dir", required=True)
    p.add_argument("--dir", required=True)
    p.add_argument("--cn", default="EVT2 TEST Issuing CA")
    p.add_argument("--years", type=int, default=5)
    p.set_defaults(fn=cmd_init_issuing)
    p = sub.add_parser("issue-device")
    p.add_argument("--dir", required=True)
    p.add_argument("--device-id", required=True, help="hex, 1..32 bytes (SE052F unique id = 18 bytes)")
    p.add_argument("--pubkey", required=True, help="PEM file, or hex of the 65-byte uncompressed point (what the board's READ_EC_PUBLIC_KEY returns)")
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_issue_device)
    p = sub.add_parser("revoke")
    p.add_argument("--dir", required=True)
    p.add_argument("--serial", required=True)
    p.set_defaults(fn=cmd_revoke)
    p = sub.add_parser("status")
    p.add_argument("--dir", required=True)
    p.add_argument("--serial", required=True)
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--now", type=int, default=None)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_status)
    p = sub.add_parser("verify")
    p.add_argument("--root-cert", required=True)
    p.add_argument("--issuing", required=True)
    p.add_argument("--leaf", required=True)
    p.add_argument("--token")
    p.add_argument("--now", type=int, default=None)
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("inspect")
    p.add_argument("file")
    p.set_defaults(fn=cmd_inspect)
    p = sub.add_parser("make-test-pki")
    p.add_argument("--out", required=True)
    p.add_argument("--long-lived", action="store_true", help="10-year device certificates and status tokens, for committed fixtures only")
    p.set_defaults(fn=lambda a: make_pki(Path(a.out), a.long_lived))
    p = sub.add_parser("selftest")
    p.add_argument("--write-vectors")
    p.set_defaults(fn=selftest)
    a = ap.parse_args()
    try:
        return a.fn(a)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
