#!/usr/bin/env python3
"""
evt2_cli.py -- general-purpose CLI test tool for EVT2's USB CDC
command_protocol.h wire protocol: every command exposed by
Core_app/App/protocol_adapters/{security,biometric,qrng}_protocol.c,
selectable and parameterized from the command line.

Wire format (Core_app/Middleware/CommandProtocol/command_protocol.h):
    FLAG(1B=0x7E) | escaped( HEADER(10B) + PAYLOAD + CRC32(4B) ) | FLAG(1B=0x7E)
HEADER (little-endian): VER(1) TYPE(1) SESSION_ID(2) SEQ(4) LENGTH(2)
Escaping: any literal 0x7E/0x7D inside HEADER+PAYLOAD+CRC becomes
0x7D followed by (byte XOR 0x20). CRC32: zlib/CRC-32 (poly 0xEDB88320,
reflected) over HEADER+PAYLOAD, pre-escape.

The framing/decoder classes below (Device/FrameDecoder) are carried over
verbatim from tools/qrng_usb_test.py -- that file's comments document a
real hardware-confirmed bug fix (queued-frame draining, see
Device.read_frame()'s doc comment) that this script would otherwise be at
risk of reintroducing if rewritten from scratch.

Requires: pip install pyserial

Examples:
    python evt2_cli.py --port COM13 hello

    --- security (Core_app/Middleware/Security/security_service.h) ---
    python evt2_cli.py --port COM13 security get-random --num-bytes 16
    python evt2_cli.py --port COM13 security sign --key-id 0x223344 --message "hello world"
    python evt2_cli.py --port COM13 security verify-message --key-id 0x223344 --message "hello world" --sig-hex 3045...
    python evt2_cli.py --port COM13 security sign-verify --key-id 0x223344 --message "hello world"   # sign then verify in one shot
    python evt2_cli.py --port COM13 security sha256 --message "hello world"
    python evt2_cli.py --port COM13 security ecdsa-sign --key-id 0x223344 --digest-hex 9c8d3694...
    python evt2_cli.py --port COM13 security ecdsa-verify --key-id 0x223344 --digest-hex 9c8d3694... --sig-hex 3045...

    --- security: multi-curve ECDSA / RSA signing (security_service.h's *_ex + rsa_*_digest) ---
    python evt2_cli.py --port COM13 security ensure-ec-keypair-ex --key-id 0x550001 --curve p384
    python evt2_cli.py --port COM13 security ecdsa-sign-ex --key-id 0x550001 --hash sha384 --digest-hex 9c8d3694...
    python evt2_cli.py --port COM13 security ecdsa-verify-ex --key-id 0x550001 --hash sha384 --digest-hex 9c8d3694... --sig-hex 3045...
    python evt2_cli.py --port COM13 security ensure-rsa-keypair --key-id 0x550010 --bits 2048   # can take ~20s+ at 4096 bits
    python evt2_cli.py --port COM13 security rsa-sign-digest --key-id 0x550010 --padding pkcs1v15 --hash sha256 --digest-hex 9c8d3694...
    python evt2_cli.py --port COM13 security rsa-sign-digest --key-id 0x550010 --padding pss --hash sha256 --digest-hex 9c8d3694...      # RSASSA-PSS, random salt each call
    python evt2_cli.py --port COM13 security rsa-verify-digest --key-id 0x550010 --padding pss --hash sha256 --digest-hex 9c8d3694... --sig-hex 622b26b7...
    python evt2_cli.py --port COM13 security sign-file --key-id 0x550010 --algo rsa --padding pss --hash sha256 --file big_video.mp4      # hashed on the host in 1MB chunks -- works for files of any size
    python evt2_cli.py --port COM13 security sign-file --key-id 0x550001 --algo ecdsa --hash sha256 --file big_video.mp4
    python evt2_cli.py --port COM13 security verify-file --key-id 0x550010 --algo rsa --padding pss --hash sha256 --file big_video.mp4 --sig-hex 622b26b7...
    # All --curve values (p256/p384/p521/brainpool256/384/512/secp256k1) generate keys on this project's SE052F.
    # Verifying ANOTHER device's signature: import-ec-pubkey / import-rsa-pubkey first, then the normal *-verify* command.

    --- biometric (Core_app/Middleware/Biometric/biometric_service.h) ---
    python evt2_cli.py --port COM13 biometric is-ready
    python evt2_cli.py --port COM13 biometric list-templates
    python evt2_cli.py --port COM13 biometric template-exists --template-id 1
    python evt2_cli.py --port COM13 biometric enroll --timeout-ms 15000     # blocks, touch the sensor
    python evt2_cli.py --port COM13 biometric identify --timeout-ms 10000  # blocks, touch the sensor
    python evt2_cli.py --port COM13 biometric delete-template --template-id 1
    python evt2_cli.py --port COM13 biometric delete-template --all
    python evt2_cli.py --port COM13 biometric reset             # required before nav-start if enroll/identify/delete already ran this session
    python evt2_cli.py --port COM13 biometric nav-start --orientation 0
    python evt2_cli.py --port COM13 biometric nav-poll           # one non-blocking check
    python evt2_cli.py --port COM13 biometric nav-poll-loop --seconds 5   # blocks, move a finger over the sensor
    python evt2_cli.py --port COM13 biometric nav-stop

    --- qrng (Core_app/Middleware/QRNG/qrng_service.h) ---
    python evt2_cli.py --port COM13 qrng get-noise
    python evt2_cli.py --port COM13 qrng get-entropy
    python evt2_cli.py --port COM13 qrng is-healthy
    python evt2_cli.py --port COM13 qrng set-health-test --enable
    python evt2_cli.py --port COM13 qrng set-health-test --disable
    python evt2_cli.py --port COM13 qrng stream-noise --seconds 3
    python evt2_cli.py --port COM13 qrng stream-noise --seconds 3 --verbose   # print each frame as it arrives
    python evt2_cli.py --port COM13 qrng stream-entropy --seconds 3
    python evt2_cli.py --port COM13 qrng stream-stop     # recover a stream left running by a killed stream-* run
    python evt2_cli.py --port COM13 qrng get-startup-health-record
    python evt2_cli.py --port COM13 qrng set-auto-reseed --enable
    python evt2_cli.py --port COM13 qrng regen-key
    python evt2_cli.py --port COM13 qrng set-extractor --algo hmac
    python evt2_cli.py --port COM13 qrng echo --message "hello"
    python evt2_cli.py --port COM13 qrng echo --size 32760   # near CMD_PROTO_MAX_PAYLOAD's ceiling
    python evt2_cli.py --port COM13 qrng bench-noise --duration-ms 4000
    python evt2_cli.py --port COM13 qrng bench-entropy --duration-ms 4000 --algo aes

    --- full sweep ---
    python evt2_cli.py --port COM13 all
    python evt2_cli.py --port COM13 all --skip-streams                     # faster, no stream tests
    python evt2_cli.py --port COM13 all --skip-touch                       # faster, no enroll/identify/nav (need a physical touch)
    python evt2_cli.py --port COM13 all --touch-timeout-ms 15000 --nav-seconds 10   # actually going to touch the sensor
"""
import argparse
import hashlib
import struct
import sys
import time
import zlib

import serial

FLAG = 0x7E
ESC = 0x7D
ESC_XOR = 0x20

CMD_TYPE_HELLO = 0x01
CMD_TYPE_HELLO_ACK = 0x02
CMD_TYPE_SECURITY = 0x11
CMD_TYPE_BIOMETRIC = 0x12
CMD_TYPE_QRNG = 0x13
CMD_TYPE_RESULT = 0x14
CMD_TYPE_CA = 0x15  # host->device: [sub_cmd: 1B][params...] -- see Core_app/App/protocol_adapters/ca_protocol.c

# ---- Sub-command ids, mirroring the *_protocol.c enums exactly ----
SEC_CMD_GET_RANDOM = 0x01
# 0x02, 0x09, 0x0A, 0x0B (SIGN_MESSAGE/ECDSA_SIGN/ECDSA_VERIFY/VERIFY_MESSAGE) removed 2026-09-22 -- see
# security_protocol.c's own doc comment at their old handler location.
# 0x03-0x07 (ENSURE_EC_KEYPAIR/DELETE_KEY/KEY_EXISTS/STORE_SECRET/LOAD_SECRET) removed from the firmware 2026-09-23
# (security_protocol.c) -- arbitrary-key_id keystore oracle, not used by the real product. See that file's doc
# comment. Do not reintroduce a CLI wrapper for them without a firmware-side range/policy fix first.
SEC_CMD_SHA256 = 0x08
SEC_CMD_ENSURE_EC_KEYPAIR_EX = 0x0C
SEC_CMD_ECDSA_SIGN_EX = 0x0D
SEC_CMD_ECDSA_VERIFY_EX = 0x0E
SEC_CMD_ENSURE_RSA_KEYPAIR = 0x0F
SEC_CMD_RSA_SIGN_DIGEST = 0x10
SEC_CMD_RSA_VERIFY_DIGEST = 0x11
SEC_CMD_READ_RSA_PUBLIC_KEY = 0x12
SEC_CMD_READ_EC_PUBLIC_KEY = 0x13
SEC_CMD_IMPORT_EC_PUBLIC_KEY = 0x14
SEC_CMD_IMPORT_RSA_PUBLIC_KEY = 0x15
# ML-DSA (FIPS 204, Giai đoạn 4, "Ký số" post-quantum option -- see CLAUDE.md 2026-09-24). No
# SEC_CMD_IMPORT_MLDSA_PUBLIC_KEY: unlike EC/RSA, MLDSA_VERIFY takes the signer's public key directly
# in its own payload (ML-DSA runs in MCU software, no SE052F object/scratch-slot involved at all).
SEC_CMD_ENSURE_MLDSA_KEYPAIR = 0x16
SEC_CMD_MLDSA_SIGN = 0x17
SEC_CMD_MLDSA_VERIFY = 0x18
SEC_CMD_READ_MLDSA_PUBLIC_KEY = 0x19

# sec_hash_t/sec_ec_curve_t/sec_rsa_key_bits_t ordinals, mirroring
# security_service.h exactly (plain C enums, first member = 0).
SEC_HASH_NAMES = {"sha224": 0, "sha256": 1, "sha384": 2, "sha512": 3}
SEC_HASH_DIGEST_LEN = {0: 28, 1: 32, 2: 48, 3: 64}
SEC_HASH_HASHLIB = {"sha224": hashlib.sha224, "sha256": hashlib.sha256,
                     "sha384": hashlib.sha384, "sha512": hashlib.sha512}
SEC_EC_CURVE_NAMES = {
    "p256": 0, "p384": 1, "p521": 2,
    "brainpool256": 3, "brainpool384": 4, "brainpool512": 5,
    "secp256k1": 6,
}
SEC_RSA_BITS_NAMES = {"2048": 0, "3072": 1, "4096": 2}
# sec_rsa_padding_t ordinals (security_service.h). PSS draws a fresh
# random salt from the chip's TRNG each call -- signing the same digest
# twice yields two different (both valid) signatures, unlike PKCS1_V15.
SEC_RSA_PADDING_NAMES = {"pkcs1v15": 0, "pss": 1}
# pqc_sign_level_t ordinals (Core_app/Middleware/PQC/pqc_sign.h) -- same crypto-agility shape as
# SEC_EC_CURVE_NAMES/SEC_RSA_BITS_NAMES above, own family since ML-DSA has neither a curve nor RSA padding.
SEC_MLDSA_LEVEL_NAMES = {"44": 0, "65": 1, "87": 2}

BIO_CMD_IS_READY = 0x01
BIO_CMD_LIST_TEMPLATES = 0x02
BIO_CMD_TEMPLATE_EXISTS = 0x03
BIO_CMD_ENROLL = 0x04
BIO_CMD_IDENTIFY = 0x05
BIO_CMD_DELETE_TEMPLATE = 0x06
BIO_CMD_RESET = 0x07
BIO_CMD_NAV_START = 0x08
BIO_CMD_NAV_POLL = 0x09
BIO_CMD_NAV_STOP = 0x0A
BIO_TEMPLATE_ID_ALL = 0xFFFF

BIO_NAV_GESTURE_NAMES = {0: "NONE", 1: "UP", 2: "DOWN", 3: "RIGHT", 4: "LEFT", 5: "PRESS", 6: "LONG_PRESS"}
BIO_NAV_ORIENTATION_IDS = {"0": 0, "90": 1, "180": 2, "270": 3}

QRNG_CMD_GET_NOISE = 0x01
QRNG_CMD_GET_ENTROPY = 0x02
QRNG_CMD_IS_HEALTHY = 0x03
QRNG_CMD_SET_HEALTH_TEST = 0x04
QRNG_CMD_STREAM_NOISE_START = 0x05
QRNG_CMD_STREAM_ENTROPY_START = 0x06
QRNG_CMD_STREAM_STOP = 0x07
QRNG_CMD_GET_STARTUP_HEALTH_RECORD = 0x08
QRNG_CMD_SET_AUTO_RESEED = 0x09
QRNG_CMD_REGEN_KEY = 0x0A
QRNG_CMD_SET_EXTRACTOR = 0x0B
QRNG_CMD_BENCH_NOISE = 0x0C
QRNG_CMD_BENCH_ENTROPY = 0x0D
QRNG_CMD_STREAM_DEBUG_TIMING = 0x0E
QRNG_CMD_ECHO = 0x0F

QRNG_NOISE_BYTES = 2048
QRNG_ENTROPY_BYTES = 1024
QRNG_STARTUP_HEALTH_RECORD_BYTES = QRNG_NOISE_BYTES

QRNG_STATUS_NAMES = {
    0: "QRNG_OK", 1: "QRNG_ERROR", 2: "QRNG_NOT_READY",
    3: "QRNG_INVALID_PARAM", 4: "QRNG_HEALTH_FAIL", 5: "QRNG_TIMEOUT",
}
SEC_STATUS_NAMES = {
    0: "SEC_OK", 1: "SEC_ERROR", 2: "SEC_NOT_READY", 3: "SEC_INVALID_PARAM",
}
BIO_STATUS_NAMES = {
    0: "BIO_OK", 1: "BIO_ERROR", 2: "BIO_NOT_READY", 3: "BIO_INVALID_PARAM",
    4: "BIO_TIMEOUT", 5: "BIO_NO_MATCH", 6: "BIO_WRONG_STATE",
}
EXTRACTOR_NAMES = {0: "TOEPLITZ", 1: "HMAC_SHA256", 2: "AES"}
EXTRACTOR_IDS = {"toeplitz": 0, "hmac": 1, "aes": 2}


def crc32_of(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def build_frame(pkt_type: int, session_id: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack("<BBHIH", 1, pkt_type, session_id, seq, len(payload))
    body = header + payload
    body += struct.pack("<I", crc32_of(body))

    escaped = bytearray()
    for b in body:
        if b in (FLAG, ESC):
            escaped.append(ESC)
            escaped.append(b ^ ESC_XOR)
        else:
            escaped.append(b)
    return bytes([FLAG]) + bytes(escaped) + bytes([FLAG])


class FrameDecoder:
    """Mirrors command_protocol.c's decoder_feed() byte-for-byte."""

    def __init__(self):
        self.buf = bytearray()
        self.in_frame = False
        self.escape_next = False

    def feed(self, byte: int):
        if byte == FLAG:
            frame = None
            if self.in_frame and len(self.buf) >= 14:
                payload_len = self.buf[8] | (self.buf[9] << 8)
                expected_len = 10 + payload_len + 4
                if len(self.buf) == expected_len:
                    crc_rx = struct.unpack("<I", bytes(self.buf[expected_len - 4:expected_len]))[0]
                    crc_calc = crc32_of(bytes(self.buf[:10 + payload_len]))
                    if crc_rx == crc_calc:
                        pkt_type = self.buf[1]
                        session_id = self.buf[2] | (self.buf[3] << 8)
                        seq = (self.buf[4] | (self.buf[5] << 8) | (self.buf[6] << 16) | (self.buf[7] << 24))
                        payload = bytes(self.buf[10:10 + payload_len])
                        frame = (pkt_type, session_id, seq, payload)
            self.in_frame = True
            self.buf = bytearray()
            self.escape_next = False
            return frame

        if not self.in_frame:
            return None
        if byte == ESC:
            self.escape_next = True
            return None
        real = byte ^ ESC_XOR if self.escape_next else byte
        self.escape_next = False
        self.buf.append(real)
        return None


class Device:
    def __init__(self, port: str):
        # CDC-ACM ignores the baud rate value itself, pyserial still needs one.
        self.ser = serial.Serial(port, baudrate=115200, timeout=0.2)
        self.ser.reset_input_buffer()
        self.decoder = FrameDecoder()
        self.seq = 0
        # Frames decoded but not yet matched/returned to a caller -- see
        # read_frame()'s doc comment for why this exists.
        self.pending = []
        # Every raw byte ever read from the wire, regardless of whether it
        # decoded into a frame -- FLAG/escape bytes, header, CRC, all of
        # it. Lets a caller measure true USB-wire bandwidth separately
        # from payload-only throughput (see _run_stream()'s wire_mbps).
        self.raw_bytes_in = 0

    def close(self):
        self.ser.close()

    def send(self, pkt_type: int, session_id: int, payload: bytes) -> int:
        seq = self.seq
        self.seq += 1
        self.ser.write(build_frame(pkt_type, session_id, seq, payload))
        return seq

    def read_frame(self, timeout: float, session_id=None):
        # A single ser.read(n) call's worth of already-buffered bytes can
        # contain MORE than one complete frame (e.g. a leftover QRNG
        # stream push immediately followed by the response we actually
        # want). Feeding only until the first match is found and stopping
        # there silently drops whatever came right behind it in that same
        # chunk -- confirmed on real hardware as the root cause of an
        # earlier "STOP ack sometimes goes missing" bug. Fix: always feed
        # every byte of whatever was read, queue anything that doesn't
        # match yet in self.pending, and only return once a match is
        # found (checking self.pending first, since a previous call may
        # have already queued today's answer).
        deadline = time.time() + timeout
        while True:
            for i, f in enumerate(self.pending):
                if session_id is None or f[1] == session_id:
                    return self.pending.pop(i)
            if time.time() >= deadline:
                return None
            n = self.ser.in_waiting or 1
            chunk = self.ser.read(n)
            self.raw_bytes_in += len(chunk)
            for b in chunk:
                frame = self.decoder.feed(b)
                if frame:
                    self.pending.append(frame)


def request(dev: Device, pkt_type: int, session_id: int, sub_cmd: int, extra: bytes = b"", timeout=3.0):
    sent_seq = dev.send(pkt_type, session_id, bytes([sub_cmd]) + extra)
    resp = dev.read_frame(timeout, session_id=session_id)
    if resp is not None and resp[2] != sent_seq:
        print(f"  !! SEQ MISMATCH: sent seq={sent_seq}, response carried seq={resp[2]} -- reading stale/reordered data")
    return resp


def hex_dump(data: bytes, width: int = 16, indent: str = "      ") -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        lines.append(f"{indent}{i:04X}: {chunk.hex(' ')}")
    return "\n".join(lines)


def parse_hex_arg(s: str) -> bytes:
    """Parse a --sig-hex/--digest-hex value into bytes. Tolerates the
    harmless formatting variations a hand-typed or copy-pasted hex string
    can pick up -- surrounding whitespace, spaces between byte pairs
    ("30 44 02 20"), a leading "0x", a stray trailing/leading ":".

    Deliberately does NOT try to strip arbitrary non-hex characters:
    hex_dump()'s multi-line "0000: 30 44 ...\\n0010: 4d 86 ..." output
    pasted as one line/arg produces offset labels like "0000"/"0010"
    that are themselves valid-looking hex digits -- silently discarding
    only ':' and whitespace would splice those labels' digits into the
    actual data with no error raised, corrupting the signature/digest
    without any sign something went wrong. If the input still isn't
    valid hex after the safe strips below, this raises rather than
    guessing -- use the single-line `sig_hex=`/`digest_hex=` value
    `security sign`/`sha256`/`ecdsa-sign` print (not the indented hex
    dump block under it) as the copy-paste source instead."""
    cleaned = s.strip().strip(":")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace(" ", "").replace(":", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(
            f"{e} -- input was {s!r}. If this came from a hex_dump() block (the indented "
            f"\"0000: 30 44 ...\" lines), use the single-line sig_hex=/digest_hex= value printed "
            f"right above it instead."
        ) from e


# ---------------------------------------------------------------------------
# Per-service command implementations. Each prints a human-readable result
# and returns True/False (ok/not-ok) so `all` can tally a summary.
# ---------------------------------------------------------------------------

def do_hello(dev, session_id, verbose=True):
    # HELLO's payload IS the version byte itself ([proto_ver: 1B]), not
    # [sub_cmd][params...] like Security/Biometric/QRNG -- send it
    # directly instead of going through request()'s sub_cmd framing.
    dev.send(CMD_TYPE_HELLO, session_id, bytes([1]))
    resp = dev.read_frame(2.0, session_id=session_id)
    if resp is None:
        print("HELLO -> TIMEOUT (no HELLO_ACK)")
        return False
    pkt_type, sid, seq, payload = resp
    ok = pkt_type == CMD_TYPE_HELLO_ACK and len(payload) >= 1
    ver = payload[0] if payload else None
    print(f"HELLO -> HELLO_ACK proto_ver={ver} ({'OK' if ok else 'UNEXPECTED'})")
    return ok


def do_security_get_random(dev, session_id, num_bytes):
    if not (1 <= num_bytes <= 32):
        print(f"security get-random -> INVALID (num_bytes must be 1..32, got {num_bytes})")
        return False
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_GET_RANDOM, bytes([num_bytes]))
    if resp is None:
        print("security get-random -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = SEC_STATUS_NAMES.get(status, f"?({status})")
    data = payload[2:]
    ok = status == 0
    print(f"security get-random({num_bytes}) -> status={status_name} data_len={len(data)}")
    if data:
        print(hex_dump(data))
    return ok


def do_security_sha256(dev, session_id, data: bytes):
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_SHA256, data)
    if resp is None:
        print("security sha256 -> TIMEOUT")
        return False, None
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = SEC_STATUS_NAMES.get(status, f"?({status})")
    digest = payload[2:34]
    ok = status == 0
    print(f"security sha256({len(data)} byte(s)) -> status={status_name} digest={digest.hex()}")
    return ok, digest


def do_security_ensure_ec_keypair_ex(dev, session_id, curve_name: str):
    curve_id = SEC_EC_CURVE_NAMES[curve_name]
    extra = bytes([curve_id])
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_ENSURE_EC_KEYPAIR_EX, extra)
    if resp is None:
        print("security ensure-ec-keypair-ex -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"security ensure-ec-keypair-ex(curve={curve_name}) -> status={SEC_STATUS_NAMES.get(status, status)}")
    return ok


def do_security_ecdsa_sign_ex(dev, session_id, curve_name: str, hash_name: str, digest: bytes):
    curve_id = SEC_EC_CURVE_NAMES[curve_name]
    hash_id = SEC_HASH_NAMES[hash_name]
    expect_len = SEC_HASH_DIGEST_LEN[hash_id]
    if len(digest) != expect_len:
        print(f"security ecdsa-sign-ex -> INVALID (digest must be {expect_len} bytes for {hash_name}, "
              f"got {len(digest)})")
        return False, None
    extra = bytes([curve_id, hash_id, len(digest)]) + digest
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_ECDSA_SIGN_EX, extra)
    if resp is None:
        print("security ecdsa-sign-ex -> TIMEOUT")
        return False, None
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = SEC_STATUS_NAMES.get(status, f"?({status})")
    sig_len = payload[2] if len(payload) > 2 else 0
    sig = payload[3:3 + sig_len]
    ok = status == 0
    print(f"security ecdsa-sign-ex(curve={curve_name}, hash={hash_name}) -> status={status_name} sig_len={sig_len}")
    if sig:
        print(f"  sig_hex={sig.hex()}   <- copy this into --sig-hex")
        print(hex_dump(sig))
    return ok, sig


def do_security_ecdsa_verify_ex(dev, session_id, hash_name: str, digest: bytes, sig: bytes):
    """Verifies against the chip's one fixed "peer key" scratch slot -- import-ec-pubkey first."""
    hash_id = SEC_HASH_NAMES[hash_name]
    extra = bytes([hash_id, len(digest)]) + digest + bytes([len(sig)]) + sig
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_ECDSA_VERIFY_EX, extra)
    if resp is None:
        print("security ecdsa-verify-ex -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = SEC_STATUS_NAMES.get(status, f"?({status})")
    valid = bool(payload[2]) if len(payload) > 2 else False
    ok = status == 0 and valid
    print(f"security ecdsa-verify-ex(hash={hash_name}) -> status={status_name} valid={valid}")
    return ok


def do_security_ensure_rsa_keypair(dev, session_id, bits_name: str):
    bits_id = SEC_RSA_BITS_NAMES[bits_name]
    extra = bytes([bits_id])
    # On-chip RSA key generation is much slower than EC and the firmware's
    # single main loop blocks synchronously for the whole call (confirmed
    # on real hardware: RSA-4096 measured ~20s, but a 30s client timeout
    # was observed to fire before the device's reply arrived at least
    # once -- give real room here rather than risk misreporting a slow
    # keygen as a TIMEOUT).
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_ENSURE_RSA_KEYPAIR, extra, timeout=60.0)
    if resp is None:
        print("security ensure-rsa-keypair -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"security ensure-rsa-keypair(bits={bits_name}) -> status={SEC_STATUS_NAMES.get(status, status)}")
    return ok


def do_security_rsa_sign_digest(dev, session_id, bits_name: str, padding_name: str, hash_name: str, digest: bytes):
    bits_id = SEC_RSA_BITS_NAMES[bits_name]
    padding_id = SEC_RSA_PADDING_NAMES[padding_name]
    hash_id = SEC_HASH_NAMES[hash_name]
    expect_len = SEC_HASH_DIGEST_LEN[hash_id]
    if len(digest) != expect_len:
        print(f"security rsa-sign-digest -> INVALID (digest must be {expect_len} bytes for {hash_name}, "
              f"got {len(digest)})")
        return False, None
    extra = bytes([bits_id, padding_id, hash_id, len(digest)]) + digest
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_RSA_SIGN_DIGEST, extra, timeout=5.0)
    if resp is None:
        print("security rsa-sign-digest -> TIMEOUT")
        return False, None
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = SEC_STATUS_NAMES.get(status, f"?({status})")
    sig_len = (payload[2] | (payload[3] << 8)) if len(payload) > 3 else 0
    sig = payload[4:4 + sig_len]
    ok = status == 0
    print(f"security rsa-sign-digest(bits={bits_name}, padding={padding_name}, hash={hash_name}) -> "
          f"status={status_name} sig_len={sig_len}")
    if sig:
        print(f"  sig_hex={sig.hex()}   <- copy this into --sig-hex")
        print(hex_dump(sig))
    return ok, sig


def do_security_rsa_verify_digest(dev, session_id, padding_name: str, hash_name: str, digest: bytes, sig: bytes):
    """Verifies against the chip's one fixed "peer key" scratch slot -- import-rsa-pubkey first."""
    padding_id = SEC_RSA_PADDING_NAMES[padding_name]
    hash_id = SEC_HASH_NAMES[hash_name]
    extra = bytes([padding_id, hash_id, len(digest)]) + digest + struct.pack("<H", len(sig)) + sig
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_RSA_VERIFY_DIGEST, extra, timeout=5.0)
    if resp is None:
        print("security rsa-verify-digest -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = SEC_STATUS_NAMES.get(status, f"?({status})")
    valid = bool(payload[2]) if len(payload) > 2 else False
    ok = status == 0 and valid
    print(f"security rsa-verify-digest(padding={padding_name}, hash={hash_name}) -> status={status_name} valid={valid}")
    return ok


def do_security_read_rsa_public_key(dev, session_id, bits_name: str):
    bits_id = SEC_RSA_BITS_NAMES[bits_name]
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_READ_RSA_PUBLIC_KEY, bytes([bits_id]))
    if resp is None:
        print("security read-rsa-pubkey -> TIMEOUT")
        return False, None, None
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = SEC_STATUS_NAMES.get(status, f"?({status})")
    ok = status == 0
    if not ok or len(payload) < 4:
        print(f"security read-rsa-pubkey(bits={bits_name}) -> status={status_name}")
        return False, None, None
    mod_len = payload[2] | (payload[3] << 8)
    modulus = payload[4:4 + mod_len]
    exp_len = payload[4 + mod_len]
    exponent = payload[5 + mod_len:5 + mod_len + exp_len]
    print(f"security read-rsa-pubkey(bits={bits_name}) -> status={status_name} "
          f"modulus_len={mod_len} exponent={exponent.hex()}")
    print(f"  modulus_hex={modulus.hex()}")
    print(f"  exponent_hex={exponent.hex()}")
    return ok, modulus, exponent


def do_security_read_ec_public_key(dev, session_id, curve_name: str):
    curve_id = SEC_EC_CURVE_NAMES[curve_name]
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_READ_EC_PUBLIC_KEY, bytes([curve_id]))
    if resp is None:
        print("security read-ec-pubkey -> TIMEOUT")
        return False, None
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    if status != 0 or len(payload) < 3:
        print(f"security read-ec-pubkey(curve={curve_name}) -> status={SEC_STATUS_NAMES.get(status, status)}")
        return False, None
    point = payload[3:3 + payload[2]]
    print(f"security read-ec-pubkey(curve={curve_name}) -> status=SEC_OK point_len={len(point)}")
    print(f"  point_hex={point.hex()}")
    return True, point


def do_security_import_ec_public_key(dev, session_id, curve_name: str, point: bytes):
    """Imports into the chip's one fixed "peer key" scratch slot (not this device's own signing key)."""
    extra = bytes([SEC_EC_CURVE_NAMES[curve_name], len(point)]) + point
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_IMPORT_EC_PUBLIC_KEY, extra, timeout=10.0)
    if resp is None:
        print("security import-ec-pubkey -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    print(f"security import-ec-pubkey(curve={curve_name}) -> status={SEC_STATUS_NAMES.get(status, status)}")
    return status == 0


def do_security_import_rsa_public_key(dev, session_id, modulus: bytes, exponent: bytes):
    """Imports into the chip's one fixed "peer key" scratch slot (not this device's own signing key)."""
    extra = struct.pack("<H", len(modulus)) + bytes([len(exponent)]) + modulus + exponent
    resp = request(dev, CMD_TYPE_SECURITY, session_id, SEC_CMD_IMPORT_RSA_PUBLIC_KEY, extra, timeout=10.0)
    if resp is None:
        print("security import-rsa-pubkey -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    print(f"security import-rsa-pubkey({len(modulus) * 8}-bit) -> status={SEC_STATUS_NAMES.get(status, status)}")
    return status == 0


def _hash_file_chunked(file_path: str, hash_name: str, chunk_size: int = 1024 * 1024):
    """Hash `file_path` incrementally, chunk_size bytes at a time. This is
    what makes sign-file/verify-file work for a file of any size (hundreds
    of MB+, the scenario this whole *_ex/rsa_*_digest API was built for):
    the file's bytes never cross the wire to the device, only the final
    fixed-size digest does."""
    hasher = SEC_HASH_HASHLIB[hash_name]()
    total = 0
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            total += len(chunk)
    return hasher.digest(), total


def do_security_sign_file(dev, session_id, algo: str, curve_name: str, bits_name: str, padding_name: str,
                           hash_name: str, file_path: str):
    digest, total = _hash_file_chunked(file_path, hash_name)
    print(f"security sign-file: hashed {total} byte(s) from {file_path!r} in 1MB chunks "
          f"-> {hash_name} digest={digest.hex()}")
    if algo == "ecdsa":
        return do_security_ecdsa_sign_ex(dev, session_id, curve_name, hash_name, digest)
    return do_security_rsa_sign_digest(dev, session_id, bits_name, padding_name, hash_name, digest)


def do_security_verify_file(dev, session_id, algo: str, padding_name: str, hash_name: str,
                             file_path: str, sig: bytes):
    """Verifies against the chip's one fixed "peer key" scratch slot -- import-ec-pubkey/import-rsa-pubkey
    first (curve/bits are whatever was imported there, not chosen here)."""
    digest, total = _hash_file_chunked(file_path, hash_name)
    print(f"security verify-file: hashed {total} byte(s) from {file_path!r} in 1MB chunks "
          f"-> {hash_name} digest={digest.hex()}")
    if algo == "ecdsa":
        return do_security_ecdsa_verify_ex(dev, session_id, hash_name, digest, sig)
    return do_security_rsa_verify_digest(dev, session_id, padding_name, hash_name, digest, sig)


def do_biometric_is_ready(dev, session_id):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_IS_READY)
    if resp is None:
        print("biometric is-ready -> TIMEOUT")
        return False
    payload = resp[3]
    is_ready = bool(payload[1]) if len(payload) > 1 else False
    print(f"biometric is-ready -> {'ready' if is_ready else 'NOT ready'}")
    return True  # a successful round trip either way, not a pass/fail condition


def _biometric_list_ids_quiet(dev, session_id):
    """Like do_biometric_list_templates() but returns the id list (or None
    on failure) without printing -- used by run_all()'s enroll-cleanup."""
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_LIST_TEMPLATES)
    if resp is None or resp[3][1] != 0:
        return None
    payload = resp[3]
    count = payload[2]
    return list(struct.unpack_from(f"<{count}H", payload, 3)) if count else []


def do_biometric_list_templates(dev, session_id):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_LIST_TEMPLATES)
    if resp is None:
        print("biometric list-templates -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = BIO_STATUS_NAMES.get(status, f"?({status})")
    ok = status == 0
    if not ok:
        print(f"biometric list-templates -> status={status_name}")
        return False
    count = payload[2]
    ids = struct.unpack_from(f"<{count}H", payload, 3) if count else ()
    print(f"biometric list-templates -> status={status_name} count={count} ids={list(ids)}")
    return True


def do_biometric_template_exists(dev, session_id, template_id: int):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_TEMPLATE_EXISTS, struct.pack("<H", template_id))
    if resp is None:
        print("biometric template-exists -> TIMEOUT")
        return False
    exists = bool(resp[3][1]) if len(resp[3]) > 1 else False
    print(f"biometric template-exists({template_id}) -> {'exists' if exists else 'NOT found'}")
    return True


def do_biometric_enroll(dev, session_id, timeout_ms: int):
    print(f"biometric enroll -- touch the sensor within {timeout_ms / 1000.0:.1f}s (blocks until then)")
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_ENROLL, struct.pack("<I", timeout_ms),
                    timeout=timeout_ms / 1000.0 + 3.0)
    if resp is None:
        print("biometric enroll -> TIMEOUT (no response at all -- device may be stuck)")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    status_name = BIO_STATUS_NAMES.get(status, f"?({status})")
    print(f"biometric enroll -> status={status_name}"
          + (" (no touch -- not a failure)" if status == 4 else ""))
    return status in (0, 4)  # BIO_OK or BIO_TIMEOUT (no touch) both count as a clean round trip


def do_biometric_identify(dev, session_id, timeout_ms: int):
    print(f"biometric identify -- touch the sensor within {timeout_ms / 1000.0:.1f}s (blocks until then)")
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_IDENTIFY, struct.pack("<I", timeout_ms),
                    timeout=timeout_ms / 1000.0 + 3.0)
    if resp is None:
        print("biometric identify -> TIMEOUT (no response at all -- device may be stuck)")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = BIO_STATUS_NAMES.get(status, f"?({status})")
    matched_id = struct.unpack_from("<H", payload, 2)[0] if len(payload) >= 4 else None
    extra = f" matched_id={matched_id}" if status == 0 else ""
    print(f"biometric identify -> status={status_name}{extra}"
          + (" (no touch -- not a failure)" if status == 4 else ""))
    return status in (0, 4, 5)  # BIO_OK, BIO_TIMEOUT, BIO_NO_MATCH all a clean round trip


def do_biometric_enroll_with_cleanup(dev, session_id, timeout_ms):
    """Same as do_biometric_enroll(), but if a touch actually lands a new
    template (BIO_OK), deletes just that one new template id afterwards
    (found via a list-before/list-after diff, same technique
    app_main.c's app_biometric_self_test() uses) so this stays a
    repeatable, non-state-mutating smoke test -- unlike that self-test,
    this does NOT wipe any pre-existing templates first."""
    before = _biometric_list_ids_quiet(dev, session_id)
    ok = do_biometric_enroll(dev, session_id, timeout_ms)
    if not ok:
        return False
    after = _biometric_list_ids_quiet(dev, session_id)
    if before is not None and after is not None:
        new_ids = [i for i in after if i not in before]
        for new_id in new_ids:
            print(f"  cleanup: deleting scratch template id {new_id}")
            do_biometric_delete_template(dev, session_id, new_id)
    return True


def do_biometric_delete_template(dev, session_id, template_id: int):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_DELETE_TEMPLATE, struct.pack("<H", template_id))
    if resp is None:
        print("biometric delete-template -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    label = "ALL" if template_id == BIO_TEMPLATE_ID_ALL else str(template_id)
    print(f"biometric delete-template({label}) -> status={BIO_STATUS_NAMES.get(status, status)}")
    return ok


def do_biometric_reset(dev, session_id):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_RESET)
    if resp is None:
        print("biometric reset -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"biometric reset -> status={BIO_STATUS_NAMES.get(status, status)}")
    return ok


def do_biometric_nav_start(dev, session_id, orientation: int):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_NAV_START, bytes([orientation]))
    if resp is None:
        print("biometric nav-start -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"biometric nav-start(orientation={orientation}) -> status={BIO_STATUS_NAMES.get(status, status)}")
    return ok


def do_biometric_nav_poll(dev, session_id):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_NAV_POLL)
    if resp is None:
        print("biometric nav-poll -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = BIO_STATUS_NAMES.get(status, f"?({status})")
    gesture = payload[2] if len(payload) > 2 else 0
    print(f"biometric nav-poll -> status={status_name} gesture={BIO_NAV_GESTURE_NAMES.get(gesture, gesture)}")
    return status == 0


def do_biometric_nav_poll_loop(dev, session_id, seconds):
    """Poll nav-poll repeatedly for `seconds`, printing only non-NONE
    gestures -- the wire equivalent of app_main.c's navigation_poll() loop."""
    print(f"biometric nav-poll-loop for {seconds:.1f}s (move a finger over the sensor) ...")
    deadline = time.time() + seconds
    gesture_count = 0
    ok = True
    while time.time() < deadline:
        resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_NAV_POLL, timeout=1.0)
        if resp is None:
            print("  nav-poll -> TIMEOUT")
            ok = False
            break
        payload = resp[3]
        status = payload[1] if len(payload) > 1 else None
        if status != 0:
            print(f"  nav-poll -> status={BIO_STATUS_NAMES.get(status, status)}")
            ok = False
            break
        gesture = payload[2] if len(payload) > 2 else 0
        if gesture != 0:
            gesture_count += 1
            print(f"  gesture -> {BIO_NAV_GESTURE_NAMES.get(gesture, gesture)}")
    print(f"biometric nav-poll-loop -> {gesture_count} gesture(s) detected")
    return ok


def do_biometric_nav_stop(dev, session_id):
    resp = request(dev, CMD_TYPE_BIOMETRIC, session_id, BIO_CMD_NAV_STOP)
    if resp is None:
        print("biometric nav-stop -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"biometric nav-stop -> status={BIO_STATUS_NAMES.get(status, status)}")
    return ok


def _qrng_status_name(sub_cmd, raw):
    if sub_cmd == QRNG_CMD_IS_HEALTHY:
        return "healthy" if raw else "NOT healthy"
    return QRNG_STATUS_NAMES.get(raw, f"?({raw})")


def do_qrng_get_noise(dev, session_id, dump=True):
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_GET_NOISE)
    return _qrng_print_data("get-noise", resp, QRNG_CMD_GET_NOISE, dump)


def do_qrng_get_entropy(dev, session_id, dump=True):
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_GET_ENTROPY)
    return _qrng_print_data("get-entropy", resp, QRNG_CMD_GET_ENTROPY, dump)


def _qrng_print_data(label, resp, sub_cmd, dump):
    if resp is None:
        print(f"qrng {label} -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    status_name = _qrng_status_name(sub_cmd, status)
    data = payload[2:]
    ok = status == 0
    print(f"qrng {label} -> status={status_name} data_len={len(data)}")
    if dump and data:
        print(hex_dump(data[:64]) + (" ..." if len(data) > 64 else ""))
    return ok


def do_qrng_is_healthy(dev, session_id):
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_IS_HEALTHY)
    if resp is None:
        print("qrng is-healthy -> TIMEOUT")
        return False
    payload = resp[3]
    healthy = bool(payload[1]) if len(payload) > 1 else False
    print(f"qrng is-healthy -> {'healthy' if healthy else 'NOT healthy'}")
    return True


def do_qrng_set_health_test(dev, session_id, enable: bool):
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_SET_HEALTH_TEST, bytes([1 if enable else 0]))
    if resp is None:
        print("qrng set-health-test -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"qrng set-health-test({'enable' if enable else 'disable'}) -> status={QRNG_STATUS_NAMES.get(status, status)}")
    return ok


def do_qrng_get_startup_health_record(dev, session_id, dump=True):
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_GET_STARTUP_HEALTH_RECORD)
    return _qrng_print_data("get-startup-health-record", resp, QRNG_CMD_GET_STARTUP_HEALTH_RECORD, dump)


def do_qrng_set_auto_reseed(dev, session_id, enable: bool):
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_SET_AUTO_RESEED, bytes([1 if enable else 0]))
    if resp is None:
        print("qrng set-auto-reseed -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"qrng set-auto-reseed({'enable' if enable else 'disable'}) -> status={QRNG_STATUS_NAMES.get(status, status)}")
    return ok


def do_qrng_regen_key(dev, session_id):
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_REGEN_KEY)
    if resp is None:
        print("qrng regen-key -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"qrng regen-key -> status={QRNG_STATUS_NAMES.get(status, status)}")
    return ok


def do_qrng_set_extractor(dev, session_id, algo: str):
    algo_id = EXTRACTOR_IDS[algo]
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_SET_EXTRACTOR, bytes([algo_id]))
    if resp is None:
        print("qrng set-extractor -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"qrng set-extractor({algo}) -> status={QRNG_STATUS_NAMES.get(status, status)}")
    return ok


def _run_bench(dev, session_id, label, sub_cmd, duration_ms, bytes_per_draw):
    payload = struct.pack("<H", duration_ms)
    resp = request(dev, CMD_TYPE_QRNG, session_id, sub_cmd, payload, timeout=duration_ms / 1000.0 + 3.0)
    if resp is None or len(resp[3]) < 34 or resp[3][1] != 0:
        print(f"qrng {label} -> FAILED: {None if resp is None else resp[3].hex(' ')}")
        return False
    data = resp[3]
    (draws, ok_draws, elapsed_ms, wait_us_avg, process_us_avg, timing_draws,
     health_us_avg, extractor_us_avg) = struct.unpack_from("<IIIIIIII", data, 2)
    rate = draws / (elapsed_ms / 1000.0) if elapsed_ms else 0.0
    mbps = (ok_draws * bytes_per_draw * 8) / (elapsed_ms / 1000.0) / 1e6 if elapsed_ms else 0.0
    print(f"qrng {label}({duration_ms}ms) -> draws={draws} ok={ok_draws} fail={draws - ok_draws} "
          f"rate={rate:.1f}/s data={mbps:.3f}Mbps")
    print(f"    wait(ADC)={wait_us_avg}us  health_check={health_us_avg}us  "
          f"extractor/copy={extractor_us_avg}us  process_total={process_us_avg}us")
    return True


def do_qrng_bench_noise(dev, session_id, duration_ms):
    return _run_bench(dev, session_id, "bench-noise", QRNG_CMD_BENCH_NOISE, duration_ms, QRNG_NOISE_BYTES)


def do_qrng_bench_entropy(dev, session_id, duration_ms):
    return _run_bench(dev, session_id, "bench-entropy", QRNG_CMD_BENCH_ENTROPY, duration_ms, QRNG_ENTROPY_BYTES)


def do_qrng_stream_debug_timing(dev, session_id):
    """Reads qrng_protocol_poll()'s per-push cycle-counter breakdown --
    draw time (qrng_service_get_noise()/get_entropy()) vs send time
    (command_protocol_send(), including the wait-for-previous-TX-complete
    poll). Only meaningful right after a stream-noise/stream-entropy run
    in the same session -- averages reset to 0 on every read, so call
    this immediately after stopping a stream, before anything else
    resets the counters by pushing more frames."""
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_STREAM_DEBUG_TIMING)
    if resp is None:
        print("qrng stream-debug-timing -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    if status != 0 or len(payload) < 14:
        print(f"qrng stream-debug-timing -> status={QRNG_STATUS_NAMES.get(status, status)}")
        return False
    draw_us, send_us, count = struct.unpack_from("<III", payload, 2)
    total_us = draw_us + send_us
    print(f"qrng stream-debug-timing -> over {count} push(es):")
    print(f"  draw (qrng_service_get_noise/get_entropy)      : {draw_us} us/push")
    print(f"  send (command_protocol_send, incl. USB TX wait): {send_us} us/push")
    if len(payload) >= 26:
        wait_us, build_tx_us, send_count = struct.unpack_from("<III", payload, 14)
        print(f"    -> wait_tx_ready (blocked on PREVIOUS frame's USB hw transfer): {wait_us} us/send")
        print(f"    -> escape+CRC build / CDC_Transmit_FS (arms NEXT transfer)    : {build_tx_us} us/send")
        if wait_us + build_tx_us:
            print(f"    -> USB hardware transfer time is {100.0 * wait_us / (wait_us + build_tx_us):.1f}% of "
                  f"send -- {'genuine USB bus time dominates' if wait_us > build_tx_us * 3 else 'framing/escape overhead is not negligible'}")
    if total_us:
        print(f"  -> send is {100.0 * send_us / total_us:.1f}% of per-push time "
              f"({1e6 / total_us:.1f} pushes/s theoretical max at this ratio)")
    return True


def do_qrng_echo(dev, session_id, data: bytes):
    """Pure transport-layer loopback (QRNG_CMD_ECHO) -- sends `data` and
    checks it comes back unchanged. No QRNG/crypto/secure-element
    involved, so this is the right way to test command_protocol.c's
    large-payload path (CMD_PROTO_MAX_PAYLOAD) up to its full capacity
    without hitting some handler's own smaller data-size limit (e.g. the
    SE05x secure element's one-shot digest APDU cap, which is much
    smaller than CMD_PROTO_MAX_PAYLOAD)."""
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_ECHO, data, timeout=5.0)
    if resp is None:
        print(f"qrng echo({len(data)} bytes) -> TIMEOUT")
        return False
    payload = resp[3]
    status = payload[1] if len(payload) > 1 else None
    echoed = payload[2:]
    match = echoed == data
    ok = status == 0 and match
    print(f"qrng echo({len(data)} bytes) -> status={QRNG_STATUS_NAMES.get(status, status)} "
          f"echoed_len={len(echoed)} match={match}")
    return ok


def _run_stream(dev, session_id, label, start_sub_cmd, seconds, verbose=False):
    print(f"\n--- qrng stream-{label} for {seconds:.1f}s{' (verbose)' if verbose else ''} ---")
    resp = request(dev, CMD_TYPE_QRNG, session_id, start_sub_cmd)
    if resp is None or resp[3][1] != 0:
        print(f"  START failed: {None if resp is None else resp[3].hex(' ')}")
        return False

    frame_count = 0
    data_bytes = 0
    status_counts = {}
    raw_bytes_start = dev.raw_bytes_in
    start = time.time()
    deadline = start + seconds
    last_frame_time = None
    auto_stopped_at = None  # wall-clock time.time() of the first non-OK draw, if any
    while time.time() < deadline:
        frame = dev.read_frame(0.2, session_id=session_id)
        if frame is None:
            continue
        payload = frame[3]
        if len(payload) < 2:
            continue
        status = payload[1]
        status_counts[status] = status_counts.get(status, 0) + 1
        data = payload[2:]
        last_frame_time = time.time()
        if status == 0:
            data_bytes += len(data)
            frame_count += 1
        else:
            # qrng_protocol_poll() sets s_streaming=false on ANY non-OK
            # draw (health-test failure, timeout, ...) -- the device
            # stops pushing frames right here, not at `deadline`. If we
            # divide by the full requested window below instead of by
            # how long frames actually flowed, an early stop makes the
            # rate look artificially awful (confirmed: this, not FIFO
            # size or USB bandwidth, was the actual explanation for wild
            # run-to-run rate swings seen while chasing this).
            if auto_stopped_at is None:
                auto_stopped_at = last_frame_time
        if verbose:
            status_name = QRNG_STATUS_NAMES.get(status, f"?({status})")
            preview = data[:8].hex(" ") if data else ""
            print(f"  #{frame_count + sum(v for k, v in status_counts.items() if k != 0)} "
                  f"seq={frame[2]} status={status_name} data_len={len(data)} {preview}")
    wall_elapsed = time.time() - start
    # Rate is computed over the window frames actually flowed in, not the
    # full requested `seconds` -- see the auto_stopped_at comment above.
    active_elapsed = (last_frame_time - start) if last_frame_time else wall_elapsed
    raw_bytes = dev.raw_bytes_in - raw_bytes_start

    dev.send(CMD_TYPE_QRNG, session_id, bytes([QRNG_CMD_STREAM_STOP]))
    ack = None
    stop_deadline = time.time() + 5.0
    while time.time() < stop_deadline:
        frame = dev.read_frame(1.0, session_id=session_id)
        if frame is None:
            continue
        if frame[3] and frame[3][0] == QRNG_CMD_STREAM_STOP:
            ack = frame
            break

    if auto_stopped_at is not None:
        print(f"  NOTE: stream auto-stopped {auto_stopped_at - start:.2f}s into the {seconds:.1f}s window "
              f"(a draw returned non-OK -- qrng_protocol_poll() stops on the first one, see its doc comment). "
              f"Rate below is computed over the {active_elapsed:.2f}s frames actually flowed in, not the full "
              f"{wall_elapsed:.2f}s wall-clock window.")

    mbps = (data_bytes * 8) / active_elapsed / 1e6 if active_elapsed else 0.0
    wire_mbps = (raw_bytes * 8) / active_elapsed / 1e6 if active_elapsed else 0.0
    elapsed = active_elapsed
    overhead_pct = (raw_bytes / data_bytes - 1.0) * 100.0 if data_bytes else 0.0
    total = sum(status_counts.values())
    print(f"  frames OK: {frame_count}/{total} ({frame_count / elapsed:.1f}/s)")
    print(f"  random data (payload only) : {data_bytes} bytes -> {mbps:.3f} Mbps")
    print(f"  USB wire (all bytes, incl. framing/CRC/escaping) : {raw_bytes} bytes -> {wire_mbps:.3f} Mbps "
          f"({overhead_pct:.1f}% protocol overhead)")
    print(f"  STOP ack: {'received' if ack else 'MISSING'}")
    return ack is not None


def do_qrng_stream_noise(dev, session_id, seconds, verbose=False):
    return _run_stream(dev, session_id, "noise", QRNG_CMD_STREAM_NOISE_START, seconds, verbose)


def do_qrng_stream_entropy(dev, session_id, seconds, verbose=False):
    return _run_stream(dev, session_id, "entropy", QRNG_CMD_STREAM_ENTROPY_START, seconds, verbose)


def do_qrng_stream_stop(dev, session_id):
    """Standalone STREAM_STOP -- for recovering a stream left running on
    the device because a previous `stream-noise`/`stream-entropy` run was
    killed (Ctrl+C, crash, ...) before it reached its own STOP call.
    QRNG_CMD_STREAM_STOP always succeeds even if no stream was active
    (see qrng_protocol.c), so this is safe to run speculatively any time
    you're not sure whether one is still going. Drains and discards any
    leftover push frames still in flight first, same as _run_stream()'s
    own stop sequence, so they don't show up as spurious "response" data
    for whatever command you run next on this session_id."""
    drained = 0
    while True:
        frame = dev.read_frame(0.3, session_id=session_id)
        if frame is None:
            break
        drained += 1
    if drained:
        print(f"  (drained {drained} leftover push frame(s) before stopping)")
    resp = request(dev, CMD_TYPE_QRNG, session_id, QRNG_CMD_STREAM_STOP, timeout=5.0)
    if resp is None:
        print("qrng stream-stop -> TIMEOUT")
        return False
    status = resp[3][1] if len(resp[3]) > 1 else None
    ok = status == 0
    print(f"qrng stream-stop -> status={QRNG_STATUS_NAMES.get(status, status)}")
    return ok


# ---------------------------------------------------------------------------

def run_all(dev, session_id, skip_streams, stream_seconds, bench_ms, skip_touch, touch_timeout_ms, nav_seconds):
    results = []

    def rec(name, fn, *a, **kw):
        print(f"\n=== {name} ===")
        ok = fn(*a, **kw)
        results.append((name, ok))

    rec("hello", do_hello, dev, session_id)

    # --- security ---
    rec("security get-random(16)", do_security_get_random, dev, session_id, 16)
    rec("security sha256", do_security_sha256, dev, session_id, b"evt2_cli self-test")

    def sec_ecdsa_ex_roundtrip():
        """security sign/ecdsa-sign/verify-message/ecdsa-verify (0x02, 0x09-0x0B) were removed 2026-09-22 (see
        security_protocol.c) -- this replaces that roundtrip with the EX family (0x0C-0x0E) that superseded them.
        ECDSA_VERIFY_EX always checks against the fixed "peer key" scratch slot, never the signing key itself
        (see security_protocol.c's own doc comment), so a self-signed roundtrip has to read the signing key's own
        public half back and import it as a "peer" before verify-ex will accept it -- exactly the same shape a
        real verifier (another device) would follow, just against itself here."""
        if not do_security_ensure_ec_keypair_ex(dev, session_id, "p256"):
            return False
        ok_h, digest = do_security_sha256(dev, session_id, b"ecdsa-ex roundtrip payload")
        if not ok_h or digest is None:
            return False
        ok_s, sig = do_security_ecdsa_sign_ex(dev, session_id, "p256", "sha256", digest)
        if not ok_s or not sig:
            return False
        ok_p, point = do_security_read_ec_public_key(dev, session_id, "p256")
        if not ok_p or not point:
            return False
        if not do_security_import_ec_public_key(dev, session_id, "p256", point):
            return False
        return do_security_ecdsa_verify_ex(dev, session_id, "sha256", digest, sig)
    rec("security ecdsa-sign-ex+verify-ex roundtrip", sec_ecdsa_ex_roundtrip)

    # security store/load/delete_secret/key-exists/ensure-ec-keypair (raw key_id) roundtrip REMOVED 2026-09-23 --
    # those sub_cmds no longer exist on the wire (security_protocol.c); the same store/load/delete/exists
    # behavior is already exercised in C (not over USB) by app_main.c's app_self_test() every boot.

    # --- biometric ---
    rec("biometric is-ready", do_biometric_is_ready, dev, session_id)
    rec("biometric list-templates", do_biometric_list_templates, dev, session_id)
    rec("biometric template-exists(0, likely absent)", do_biometric_template_exists, dev, session_id, 0)
    if not skip_touch:
        rec("biometric enroll", do_biometric_enroll_with_cleanup, dev, session_id, touch_timeout_ms)
        rec("biometric identify", do_biometric_identify, dev, session_id, touch_timeout_ms)
        rec("biometric reset (required before navigation)", do_biometric_reset, dev, session_id)
        rec("biometric nav-start", do_biometric_nav_start, dev, session_id, 0)
        rec("biometric nav-poll-loop", do_biometric_nav_poll_loop, dev, session_id, nav_seconds)
        rec("biometric nav-stop", do_biometric_nav_stop, dev, session_id)
    else:
        print("\n(--skip-touch: enroll/identify/reset/nav-* skipped)")

    # --- qrng ---
    rec("qrng get-noise", do_qrng_get_noise, dev, session_id, False)
    rec("qrng get-entropy", do_qrng_get_entropy, dev, session_id, False)
    rec("qrng is-healthy", do_qrng_is_healthy, dev, session_id)
    rec("qrng set-health-test(disable)", do_qrng_set_health_test, dev, session_id, False)
    rec("qrng set-health-test(enable)", do_qrng_set_health_test, dev, session_id, True)
    rec("qrng get-startup-health-record", do_qrng_get_startup_health_record, dev, session_id, False)
    rec("qrng set-auto-reseed(enable)", do_qrng_set_auto_reseed, dev, session_id, True)
    rec("qrng set-auto-reseed(disable)", do_qrng_set_auto_reseed, dev, session_id, False)
    for algo in ("toeplitz", "hmac", "aes"):
        rec(f"qrng set-extractor({algo})", do_qrng_set_extractor, dev, session_id, algo)
        rec(f"qrng bench-entropy({algo})", do_qrng_bench_entropy, dev, session_id, bench_ms)
    rec("qrng bench-noise", do_qrng_bench_noise, dev, session_id, bench_ms)
    rec("qrng regen-key", do_qrng_regen_key, dev, session_id)
    if not skip_streams:
        rec("qrng stream-noise", do_qrng_stream_noise, dev, session_id, stream_seconds)
        rec("qrng stream-entropy", do_qrng_stream_entropy, dev, session_id, stream_seconds)

    print("\n=== summary ===")
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
    print(f"{passed}/{len(results)} passed")
    return passed == len(results)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="COM13", help="Serial port for the board's USB CDC device (default: COM13)")
    ap.add_argument("--session-id", type=lambda x: int(x, 0), default=0x0001, help="Session id (default: 0x0001)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("hello", help="Send CMD_TYPE_HELLO, expect HELLO_ACK")

    sec = sub.add_parser("security", help="Security service commands")
    secsub = sec.add_subparsers(dest="sec_cmd", required=True)
    p = secsub.add_parser("get-random", help="SEC_CMD_GET_RANDOM")
    p.add_argument("--num-bytes", type=int, default=16, help="1..32 (default: 16)")
    # ensure-ec-keypair/delete-key/key-exists/store-secret/load-secret (raw key_id, 0x03-0x07) REMOVED 2026-09-23 --
    # security_protocol.c no longer exposes them on the wire (arbitrary-key_id keystore oracle, unused by the real
    # product -- see that file's doc comment).
    p = secsub.add_parser("sha256", help="SEC_CMD_SHA256")
    p.add_argument("--message", default="hello world", help="Data to hash (UTF-8 text)")
    # NOTE (2026-09-22): none of the sub-commands below take --key-id any more -- security_protocol.c now
    # computes the chip's actual SE052F object id internally from --curve/--bits, and the verify-side "peer
    # key" scratch slot is purely internal to the firmware too (no wire command can even name it). See
    # security_protocol.c's SEC_CMD_ENSURE_EC_KEYPAIR_EX doc comment for the full reasoning -- this closed a
    # real gap where a raw host-chosen key_id could name ANY key on the chip, not just this feature's own.
    p = secsub.add_parser("ensure-ec-keypair-ex", help="SEC_CMD_ENSURE_EC_KEYPAIR_EX -- multi-curve key generation")
    p.add_argument("--curve", choices=sorted(SEC_EC_CURVE_NAMES), default="p256")
    p = secsub.add_parser("ecdsa-sign-ex", help="SEC_CMD_ECDSA_SIGN_EX -- multi-hash ECDSA sign of a "
                                                 "pre-computed digest with this device's own --curve key")
    p.add_argument("--curve", choices=sorted(SEC_EC_CURVE_NAMES), default="p256")
    p.add_argument("--hash", choices=sorted(SEC_HASH_NAMES), default="sha256")
    p.add_argument("--digest-hex", required=True)
    p = secsub.add_parser("ecdsa-verify-ex", help="SEC_CMD_ECDSA_VERIFY_EX -- against the chip's one fixed "
                                                   "\"peer key\" scratch slot (import-ec-pubkey first)")
    p.add_argument("--hash", choices=sorted(SEC_HASH_NAMES), default="sha256")
    p.add_argument("--digest-hex", required=True)
    p.add_argument("--sig-hex", required=True)
    p = secsub.add_parser("ensure-rsa-keypair", help="SEC_CMD_ENSURE_RSA_KEYPAIR -- on-chip RSA key generation "
                                                      "(can take several seconds, especially at 4096 bits)")
    p.add_argument("--bits", choices=sorted(SEC_RSA_BITS_NAMES), default="2048")
    p = secsub.add_parser("rsa-sign-digest", help="SEC_CMD_RSA_SIGN_DIGEST -- host-side EMSA-PKCS1-v1_5 or "
                                                   "EMSA-PSS padding + the chip's raw RSA private-key primitive, "
                                                   "with this device's own --bits key")
    p.add_argument("--bits", choices=sorted(SEC_RSA_BITS_NAMES), default="2048")
    p.add_argument("--padding", choices=sorted(SEC_RSA_PADDING_NAMES), default="pkcs1v15")
    p.add_argument("--hash", choices=sorted(SEC_HASH_NAMES), default="sha256")
    p.add_argument("--digest-hex", required=True)
    p = secsub.add_parser("rsa-verify-digest", help="SEC_CMD_RSA_VERIFY_DIGEST -- against the chip's one fixed "
                                                     "\"peer key\" scratch slot (import-rsa-pubkey first)")
    p.add_argument("--padding", choices=sorted(SEC_RSA_PADDING_NAMES), default="pkcs1v15")
    p.add_argument("--hash", choices=sorted(SEC_HASH_NAMES), default="sha256")
    p.add_argument("--digest-hex", required=True)
    p.add_argument("--sig-hex", required=True)
    p = secsub.add_parser("read-rsa-pubkey", help="SEC_CMD_READ_RSA_PUBLIC_KEY -- read modulus+exponent so a peer "
                                                   "can independently verify this device's RSA signatures")
    p.add_argument("--bits", choices=sorted(SEC_RSA_BITS_NAMES), default="2048")
    p = secsub.add_parser("read-ec-pubkey", help="SEC_CMD_READ_EC_PUBLIC_KEY -- uncompressed point 0x04||X||Y")
    p.add_argument("--curve", choices=sorted(SEC_EC_CURVE_NAMES), default="p256")
    p = secsub.add_parser("import-ec-pubkey", help="SEC_CMD_IMPORT_EC_PUBLIC_KEY -- store a PEER's EC public key "
                                                    "in the chip's one fixed scratch slot, so this device can "
                                                    "verify that peer's signatures")
    p.add_argument("--curve", choices=sorted(SEC_EC_CURVE_NAMES), default="p256")
    p.add_argument("--point-hex", required=True, help="Uncompressed point 0x04||X||Y as hex")
    p = secsub.add_parser("import-rsa-pubkey", help="SEC_CMD_IMPORT_RSA_PUBLIC_KEY -- store a PEER's RSA public "
                                                     "key in the chip's one fixed scratch slot")
    p.add_argument("--modulus-hex", required=True)
    p.add_argument("--exponent-hex", default="010001")
    p = secsub.add_parser("sign-file", help="Hash a file (of any size -- 1MB chunks on the host) then sign only "
                                             "the resulting digest; the file's bytes never reach the device")
    p.add_argument("--algo", choices=["ecdsa", "rsa"], default="ecdsa")
    p.add_argument("--curve", choices=sorted(SEC_EC_CURVE_NAMES), default="p256", help="Only used when --algo ecdsa")
    p.add_argument("--bits", choices=sorted(SEC_RSA_BITS_NAMES), default="2048", help="Only used when --algo rsa")
    p.add_argument("--padding", choices=sorted(SEC_RSA_PADDING_NAMES), default="pkcs1v15",
                    help="Only used when --algo rsa")
    p.add_argument("--hash", choices=sorted(SEC_HASH_NAMES), default="sha256")
    p.add_argument("--file", required=True)
    p = secsub.add_parser("verify-file", help="Re-hash a file the same way sign-file did, then verify a "
                                               "signature against the chip's one fixed \"peer key\" scratch "
                                               "slot (import-ec-pubkey/import-rsa-pubkey first)")
    p.add_argument("--algo", choices=["ecdsa", "rsa"], default="ecdsa")
    p.add_argument("--padding", choices=sorted(SEC_RSA_PADDING_NAMES), default="pkcs1v15",
                    help="Only used when --algo rsa")
    p.add_argument("--hash", choices=sorted(SEC_HASH_NAMES), default="sha256")
    p.add_argument("--file", required=True)
    p.add_argument("--sig-hex", required=True)

    bio = sub.add_parser("biometric", help="Biometric service commands")
    biosub = bio.add_subparsers(dest="bio_cmd", required=True)
    biosub.add_parser("is-ready", help="BIO_CMD_IS_READY")
    biosub.add_parser("list-templates", help="BIO_CMD_LIST_TEMPLATES")
    p = biosub.add_parser("template-exists", help="BIO_CMD_TEMPLATE_EXISTS")
    p.add_argument("--template-id", type=int, required=True)
    p = biosub.add_parser("enroll", help="BIO_CMD_ENROLL -- blocks until a touch or timeout")
    p.add_argument("--timeout-ms", type=int, default=15000)
    p = biosub.add_parser("identify", help="BIO_CMD_IDENTIFY -- blocks until a touch or timeout")
    p.add_argument("--timeout-ms", type=int, default=10000)
    p = biosub.add_parser("delete-template", help="BIO_CMD_DELETE_TEMPLATE")
    p.add_argument("--template-id", type=int, default=None, help="Omit for --all")
    p.add_argument("--all", action="store_true", help="Delete every enrolled template")
    biosub.add_parser("reset", help="BIO_CMD_RESET -- required before nav-start if enroll/identify/delete ran first")
    p = biosub.add_parser("nav-start", help="BIO_CMD_NAV_START")
    p.add_argument("--orientation", choices=["0", "90", "180", "270"], default="0")
    p = biosub.add_parser("nav-poll", help="BIO_CMD_NAV_POLL -- one non-blocking check")
    p = biosub.add_parser("nav-poll-loop", help="Poll in a loop for N seconds, printing each gesture as it arrives")
    p.add_argument("--seconds", type=float, default=5.0)
    biosub.add_parser("nav-stop", help="BIO_CMD_NAV_STOP")

    qrng = sub.add_parser("qrng", help="QRNG service commands")
    qsub = qrng.add_subparsers(dest="qrng_cmd", required=True)
    qsub.add_parser("get-noise", help="One QRNG_NOISE_BYTES draw")
    qsub.add_parser("get-entropy", help="One QRNG_ENTROPY_BYTES draw (current extractor)")
    qsub.add_parser("is-healthy", help="Current online health-test status")
    p = qsub.add_parser("set-health-test", help="Enable/disable the RCT/APT online health test")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--enable", action="store_true")
    g.add_argument("--disable", action="store_true")
    p = qsub.add_parser("stream-noise", help="Continuous GET_NOISE stream for N seconds")
    p.add_argument("--seconds", type=float, default=3.0)
    p.add_argument("--verbose", action="store_true", help="Print each frame as it arrives (default: summary only)")
    p = qsub.add_parser("stream-entropy", help="Continuous GET_ENTROPY stream for N seconds")
    p.add_argument("--seconds", type=float, default=3.0)
    p.add_argument("--verbose", action="store_true", help="Print each frame as it arrives (default: summary only)")
    p = qsub.add_parser("echo", help="QRNG_CMD_ECHO -- transport-layer loopback test, no QRNG/crypto involved")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--message", help="Text to echo (UTF-8)")
    g.add_argument("--size", type=int, help="Echo this many bytes of deterministic filler data instead of --message "
                                             "(e.g. --size 32760 to test near CMD_PROTO_MAX_PAYLOAD's ceiling)")
    qsub.add_parser("stream-debug-timing", help="Read qrng_protocol_poll()'s per-push draw-vs-USB-send cycle "
                                                 "breakdown -- call right after stopping a stream-noise/"
                                                 "stream-entropy run in the same session")
    qsub.add_parser("stream-stop", help="Standalone STREAM_STOP -- recovers a stream left running on the "
                                         "device by a previous stream-noise/stream-entropy run that got killed "
                                         "(Ctrl+C, crash) before reaching its own stop. Safe to run any time.")
    qsub.add_parser("get-startup-health-record", help="Snapshot from the boot-time health-test pass")
    p = qsub.add_parser("set-auto-reseed", help="Enable/disable automatic extractor reseed")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--enable", action="store_true")
    g.add_argument("--disable", action="store_true")
    qsub.add_parser("regen-key", help="Force an extractor reseed now")
    p = qsub.add_parser("set-extractor", help="Select the entropy-extractor algorithm")
    p.add_argument("--algo", choices=["toeplitz", "hmac", "aes"], required=True)
    p = qsub.add_parser("bench-noise", help="Device-side draw-rate benchmark (raw noise, no extractor)")
    p.add_argument("--duration-ms", type=int, default=4000)
    p = qsub.add_parser("bench-entropy", help="Device-side draw-rate benchmark (current/given extractor)")
    p.add_argument("--duration-ms", type=int, default=4000)
    p.add_argument("--algo", choices=["toeplitz", "hmac", "aes"], default=None,
                    help="Select this extractor first (default: leave whatever is already selected)")

    p = sub.add_parser("all", help="Run a full non-destructive sweep across every command above")
    p.add_argument("--skip-streams", action="store_true", help="Skip stream-noise/stream-entropy (faster)")
    p.add_argument("--stream-seconds", type=float, default=2.0)
    p.add_argument("--bench-ms", type=int, default=1000)
    p.add_argument("--skip-touch", action="store_true",
                    help="Skip enroll/identify/reset/nav-* (they need a physical touch)")
    p.add_argument("--touch-timeout-ms", type=int, default=3000,
                    help="Per-call timeout for enroll/identify during the sweep (default: 3000, "
                         "short so an unattended run doesn't stall -- pass a real value like 15000 "
                         "if you intend to actually touch the sensor)")
    p.add_argument("--nav-seconds", type=float, default=3.0)

    args = ap.parse_args()

    # Validate/parse any --sig-hex/--digest-hex up front, before opening
    # the serial port -- fails fast on bad input instead of connecting
    # first and only then hitting a stack trace mid-command.
    try:
        for attr in ("sig_hex", "digest_hex", "point_hex", "modulus_hex", "exponent_hex"):
            if hasattr(args, attr):
                setattr(args, attr, parse_hex_arg(getattr(args, attr)))
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print(f"Opening {args.port} ...")
    dev = Device(args.port)
    session_id = args.session_id
    ok = True

    try:
        if args.cmd == "hello":
            ok = do_hello(dev, session_id)
        elif args.cmd == "security":
            if args.sec_cmd == "get-random":
                ok = do_security_get_random(dev, session_id, args.num_bytes)
            elif args.sec_cmd == "sha256":
                ok, _digest = do_security_sha256(dev, session_id, args.message.encode("utf-8"))
            elif args.sec_cmd == "ensure-ec-keypair-ex":
                ok = do_security_ensure_ec_keypair_ex(dev, session_id, args.curve)
            elif args.sec_cmd == "ecdsa-sign-ex":
                ok, _sig = do_security_ecdsa_sign_ex(dev, session_id, args.curve, args.hash, args.digest_hex)
            elif args.sec_cmd == "ecdsa-verify-ex":
                ok = do_security_ecdsa_verify_ex(dev, session_id, args.hash, args.digest_hex, args.sig_hex)
            elif args.sec_cmd == "ensure-rsa-keypair":
                ok = do_security_ensure_rsa_keypair(dev, session_id, args.bits)
            elif args.sec_cmd == "rsa-sign-digest":
                ok, _sig = do_security_rsa_sign_digest(dev, session_id, args.bits, args.padding, args.hash,
                                                        args.digest_hex)
            elif args.sec_cmd == "rsa-verify-digest":
                ok = do_security_rsa_verify_digest(dev, session_id, args.padding, args.hash,
                                                    args.digest_hex, args.sig_hex)
            elif args.sec_cmd == "read-rsa-pubkey":
                ok, _mod, _exp = do_security_read_rsa_public_key(dev, session_id, args.bits)
            elif args.sec_cmd == "read-ec-pubkey":
                ok, _pt = do_security_read_ec_public_key(dev, session_id, args.curve)
            elif args.sec_cmd == "import-ec-pubkey":
                ok = do_security_import_ec_public_key(dev, session_id, args.curve, args.point_hex)
            elif args.sec_cmd == "import-rsa-pubkey":
                ok = do_security_import_rsa_public_key(dev, session_id, args.modulus_hex, args.exponent_hex)
            elif args.sec_cmd == "sign-file":
                ok, _sig = do_security_sign_file(dev, session_id, args.algo, args.curve, args.bits, args.padding,
                                                  args.hash, args.file)
            elif args.sec_cmd == "verify-file":
                ok = do_security_verify_file(dev, session_id, args.algo, args.padding, args.hash,
                                              args.file, args.sig_hex)
        elif args.cmd == "biometric":
            if args.bio_cmd == "is-ready":
                ok = do_biometric_is_ready(dev, session_id)
            elif args.bio_cmd == "list-templates":
                ok = do_biometric_list_templates(dev, session_id)
            elif args.bio_cmd == "template-exists":
                ok = do_biometric_template_exists(dev, session_id, args.template_id)
            elif args.bio_cmd == "enroll":
                ok = do_biometric_enroll(dev, session_id, args.timeout_ms)
            elif args.bio_cmd == "identify":
                ok = do_biometric_identify(dev, session_id, args.timeout_ms)
            elif args.bio_cmd == "delete-template":
                if args.all:
                    ok = do_biometric_delete_template(dev, session_id, BIO_TEMPLATE_ID_ALL)
                elif args.template_id is not None:
                    ok = do_biometric_delete_template(dev, session_id, args.template_id)
                else:
                    print("delete-template: pass --template-id N or --all")
                    ok = False
            elif args.bio_cmd == "reset":
                ok = do_biometric_reset(dev, session_id)
            elif args.bio_cmd == "nav-start":
                ok = do_biometric_nav_start(dev, session_id, BIO_NAV_ORIENTATION_IDS[args.orientation])
            elif args.bio_cmd == "nav-poll":
                ok = do_biometric_nav_poll(dev, session_id)
            elif args.bio_cmd == "nav-poll-loop":
                ok = do_biometric_nav_poll_loop(dev, session_id, args.seconds)
            elif args.bio_cmd == "nav-stop":
                ok = do_biometric_nav_stop(dev, session_id)
        elif args.cmd == "qrng":
            if args.qrng_cmd == "get-noise":
                ok = do_qrng_get_noise(dev, session_id)
            elif args.qrng_cmd == "get-entropy":
                ok = do_qrng_get_entropy(dev, session_id)
            elif args.qrng_cmd == "is-healthy":
                ok = do_qrng_is_healthy(dev, session_id)
            elif args.qrng_cmd == "set-health-test":
                ok = do_qrng_set_health_test(dev, session_id, args.enable)
            elif args.qrng_cmd == "stream-noise":
                ok = do_qrng_stream_noise(dev, session_id, args.seconds, args.verbose)
            elif args.qrng_cmd == "stream-entropy":
                ok = do_qrng_stream_entropy(dev, session_id, args.seconds, args.verbose)
            elif args.qrng_cmd == "echo":
                if args.size is not None:
                    data = bytes((i * 7 + 3) % 256 for i in range(args.size))
                else:
                    data = (args.message or "hello").encode("utf-8")
                ok = do_qrng_echo(dev, session_id, data)
            elif args.qrng_cmd == "stream-debug-timing":
                ok = do_qrng_stream_debug_timing(dev, session_id)
            elif args.qrng_cmd == "stream-stop":
                ok = do_qrng_stream_stop(dev, session_id)
            elif args.qrng_cmd == "get-startup-health-record":
                ok = do_qrng_get_startup_health_record(dev, session_id)
            elif args.qrng_cmd == "set-auto-reseed":
                ok = do_qrng_set_auto_reseed(dev, session_id, args.enable)
            elif args.qrng_cmd == "regen-key":
                ok = do_qrng_regen_key(dev, session_id)
            elif args.qrng_cmd == "set-extractor":
                ok = do_qrng_set_extractor(dev, session_id, args.algo)
            elif args.qrng_cmd == "bench-noise":
                ok = do_qrng_bench_noise(dev, session_id, args.duration_ms)
            elif args.qrng_cmd == "bench-entropy":
                if args.algo is not None:
                    do_qrng_set_extractor(dev, session_id, args.algo)
                ok = do_qrng_bench_entropy(dev, session_id, args.duration_ms)
        elif args.cmd == "all":
            ok = run_all(dev, session_id, args.skip_streams, args.stream_seconds, args.bench_ms,
                         args.skip_touch, args.touch_timeout_ms, args.nav_seconds)
    finally:
        dev.close()

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
