#!/usr/bin/env python3
"""
toeplitz_condition.py -- Toeplitz-hash conditioning (randomness extraction) of raw QRNG ADC samples, on the PC.

Input : raw .bin from the capture tool -- little-endian uint16 per sample, 12 bits used (0..4095), in blocks of
        1024 contiguous samples (the blocks are not contiguous with each other; each is conditioned on its own).
Output: packed random bits (binary file), e.g. for `dieharder -a -g 201 -f out.bin`.

Per block: the 12 meaningful bits of each sample, most significant first (the 4 always-zero bits are dropped),
give n = 1024 x 12 = 12288 input bits x. The output is m bits,
        y_i = XOR_j ( x_j AND k_(i+j) ),   i = 0..m-1,  j = 0..n-1,
with a key k of n + m - 1 bits: the Toeplitz-matrix hash in the bit order of the Microsoft RSS "Toeplitz hash"
(the matrix rows are windows of the key), which is a universal hash family, so the leftover hash lemma applies:
m must stay below the block's min-entropy minus a security margin. m = --out-bits-per-sample x 1024.

Key / reseed: every --reseed-blocks conditioning runs (blocks actually hashed; blocks dropped by --drop-health-fail
do not count -- the user's rule, 2026-09-30) a new key comes from os.urandom (independent of the noise source; it may
be public). All keys are written to OUT.seeds (one per line: the first conditioned block and the first raw block it
was used for, then the key in hex), so the output can be reproduced and checked.

Correctness checks (run automatically before conditioning, or alone with --selftest):
  1. the 10 published Microsoft RSS Toeplitz hash test vectors (IPv4 and IPv4+TCP, key 6d5a56da...),
  2. the fast FFT path against a direct GF(2) matrix product at the real block size (n = 12288).

    python Tools/toeplitz_condition.py --selftest
    python Tools/toeplitz_condition.py --in captures/raw.bin --out captures/cond.bin --out-bits-per-sample 6
    python Tools/toeplitz_condition.py --in raw.bin --out cond.bin --out-bits-per-sample 6.5 --reseed-blocks 1000
    python Tools/toeplitz_condition.py --in raw.bin --out cond.bin --out-bits-per-sample 6 --max-out-bytes 1000000000
    python Tools/toeplitz_condition.py --in raw1.bin raw2.bin --out cond.bin --out-bits-per-sample 5.5         --drop-health-fail --max-out-bytes 1000000000          # only blocks that pass the firmware's RCT/APT test

Needs: pip install numpy
"""
import argparse
import os
import sys
import time

import numpy as np

BLOCK = 1024           # samples per contiguous block (QRNG_RAW_CAPTURE_SAMPLES)
BITS = 12              # meaningful bits per sample
N_IN = BLOCK * BITS    # input bits per block

# ---- Microsoft RSS Toeplitz hash verification suite ("Verifying the RSS Hash Calculation") ----
RSS_KEY = bytes([0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
                 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
                 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa])
# (destination ip:port, source ip:port, IPv4-only hash, IPv4+TCP hash); input = src ip, dst ip [, src port, dst port]
RSS_VECTORS = [
    ("161.142.100.80", 1766, "66.9.149.187", 2794, 0x323E8FC2, 0x51CCC178),
    ("65.69.140.83", 4739, "199.92.111.2", 14230, 0xD718262A, 0xC626B0EA),
    ("12.22.207.184", 38024, "24.19.198.95", 12898, 0xD2D0A5DE, 0x5C2B394A),
    ("209.142.163.6", 2217, "38.27.205.30", 48228, 0x82989176, 0xAFC7327F),
    ("202.188.127.2", 1303, "153.39.163.191", 44251, 0x5D1809C5, 0x10E828A2),
]


def bytes_to_bits(b):
    return np.unpackbits(np.frombuffer(bytes(b), dtype=np.uint8))  # MSB first


def toeplitz_reference(x_bits, key_bits, m):
    """Direct GF(2) product, y_i = XOR_j x_j k_(i+j). Slow; the reference for the checks."""
    n = len(x_bits)
    idx = np.arange(m)[:, None] + np.arange(n)[None, :]
    return (key_bits[idx].astype(np.int64) @ x_bits.astype(np.int64)) & 1


class Toeplitz:
    """Fast batched version: y_i = sum_j x_j k_(i+j) is a correlation, computed with real FFTs over the integers
    (sums <= n = 12288, exact in float64 after rounding) and reduced mod 2."""

    def __init__(self, n, m):
        self.n, self.m = n, m
        self.L = 1 << int(np.ceil(np.log2(n + (n + m - 1))))
        self.K = None

    def set_key(self, key_bits):
        assert len(key_bits) == self.n + self.m - 1
        self.K = np.fft.rfft(key_bits.astype(np.float64), self.L)

    def hash(self, x_bits):
        """x_bits: (blocks, n) array of 0/1 -> (blocks, m) array of 0/1."""
        X = np.fft.rfft(x_bits[:, ::-1].astype(np.float64), self.L, axis=1)   # reversed x: correlation
        c = np.fft.irfft(X * self.K[None, :], self.L, axis=1)
        y = np.rint(c[:, self.n - 1:self.n - 1 + self.m]).astype(np.int64)
        return (y & 1).astype(np.uint8)


def selftest(verbose=True):
    ok = True
    key_bits = bytes_to_bits(RSS_KEY)
    for dst, dport, src, sport, h_ip, h_tcp in RSS_VECTORS:
        ip = bytes(int(v) for v in src.split(".")) + bytes(int(v) for v in dst.split("."))
        tcp = ip + sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
        for data, want, label in ((ip, h_ip, "IPv4"), (tcp, h_tcp, "IPv4+TCP")):
            x = bytes_to_bits(data)
            t = Toeplitz(len(x), 32)
            t.set_key(key_bits[:len(x) + 31])
            got_fast = int("".join(map(str, t.hash(x[None, :])[0])), 2)
            got_ref = int("".join(map(str, toeplitz_reference(x, key_bits, 32))), 2)
            good = got_fast == want and got_ref == want
            ok &= good
            if verbose:
                print(f"  RSS {label:8s} {src}:{sport} -> {dst}:{dport}: expected 0x{want:08X}, fast 0x{got_fast:08X}, "
                      f"reference 0x{got_ref:08X}  {'OK' if good else 'FAIL'}")
    rng = np.random.default_rng(12345)
    for m in (1, 6144, 8192):
        key = rng.integers(0, 2, N_IN + m - 1, dtype=np.uint8)
        xs = rng.integers(0, 2, (3, N_IN), dtype=np.uint8)
        t = Toeplitz(N_IN, m)
        t.set_key(key)
        fast = t.hash(xs)
        good = all(np.array_equal(fast[b], toeplitz_reference(xs[b], key, m)) for b in range(3))
        ok &= good
        if verbose:
            print(f"  FFT path vs direct GF(2) product, n={N_IN}, m={m}, 3 random blocks: {'OK' if good else 'FAIL'}")
    return ok


def samples_to_bits(samples):
    """(blocks, 1024) uint16 -> (blocks, 12288) bits: the 12 low bits of each sample, MSB first."""
    s = samples.astype(np.uint16)
    shifts = np.arange(BITS - 1, -1, -1, dtype=np.uint16)
    return ((s[:, :, None] >> shifts) & 1).astype(np.uint8).reshape(len(s), -1)


def iter_blocks(paths, drop_fail, stats):
    """Yield 1024-sample blocks (uint16, 12-bit) from the raw files in order; with drop_fail, blocks failing the
    firmware's RCT/APT health test (qrng_health.health_check) are skipped and counted in stats."""
    from qrng_health import health_check
    for path in paths:
        raw = np.memmap(path, dtype="<u2", mode="r")
        nblk = len(raw) // BLOCK
        stats["files"].append((path, len(raw), nblk))
        for b0 in range(0, nblk, 4096):
            chunk = np.asarray(raw[b0 * BLOCK:min(nblk, b0 + 4096) * BLOCK]).reshape(-1, BLOCK) & 0x0FFF
            for blk in chunk:
                stats["read"] += 1
                if drop_fail:
                    res = health_check(blk)[0]
                    if res != "PASS":
                        stats[res] += 1
                        continue
                yield blk


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", nargs="+",
                    help="raw .bin file(s) (uint16 LE, 12-bit samples, blocks of 1024), processed in order")
    ap.add_argument("--out", help="conditioned output (packed bits)")
    ap.add_argument("--out-bits-per-sample", type=float, default=None,
                    help="output bits per input sample (m = this x 1024 per block). Must be below the measured "
                         "min-entropy per sample minus a margin")
    ap.add_argument("--drop-health-fail", action="store_true",
                    help="skip blocks that fail the firmware's RCT/APT health test (qrng_health.py), like the "
                         "QRNG service does -- only PASS blocks are conditioned")
    ap.add_argument("--reseed-blocks", type=int, default=1000,
                    help="new Toeplitz key (os.urandom) every this many conditioning runs, i.e. conditioned blocks; "
                         "blocks dropped by the health filter do not count (default 1000)")
    ap.add_argument("--max-out-bytes", type=int, default=None, help="stop once this many output bytes are written")
    ap.add_argument("--batch", type=int, default=64, help="blocks per FFT batch (memory vs speed)")
    ap.add_argument("--selftest", action="store_true", help="run the RSS test vectors and the FFT check, then exit")
    args = ap.parse_args()

    print("self-test: Microsoft RSS Toeplitz vectors + FFT path vs direct GF(2) product")
    if not selftest():
        print("SELF-TEST FAILED -- not conditioning anything")
        sys.exit(2)
    print("self-test passed")
    if args.selftest:
        return
    if not (args.inp and args.out and args.out_bits_per_sample):
        ap.error("--in, --out and --out-bits-per-sample are needed (or --selftest)")
    m = int(round(args.out_bits_per_sample * BLOCK))
    if not 0 < m < N_IN:
        ap.error(f"output bits per block {m} must be between 1 and {N_IN - 1}")
    if m % 8:
        m -= m % 8  # whole output bytes per block
    for path in args.inp:
        head = np.memmap(path, dtype="<u2", mode="r")
        if len(head) < BLOCK:
            ap.error(f"{path}: less than one 1024-sample block")
        if int(head[:min(len(head), 1 << 20)].max()) > 0x0FFF:
            print(f"WARNING: {path}: values above 4095 -- is it really 12-bit raw ADC data?")
    print(f"inputs: {', '.join(args.inp)}")
    print(f"Toeplitz {N_IN} -> {m} bits per block ({m / BLOCK:.3f} bits per sample, ratio {m / N_IN:.3f}), "
          f"new key every {args.reseed_blocks} conditioned blocks, "
          f"{'only health-test PASS blocks' if args.drop_health_fail else 'all blocks (no health filter)'}")
    t = Toeplitz(N_IN, m)
    stats = {"files": [], "read": 0, "RCT": 0, "APT": 0}
    written = kept = 0
    t0 = t_print = time.time()
    batch = []

    def flush(fout):
        nonlocal written
        y = t.hash(samples_to_bits(np.stack(batch)))
        out = np.packbits(y, axis=1).tobytes()
        if args.max_out_bytes is not None:
            out = out[:max(0, args.max_out_bytes - written)]
        fout.write(out)
        written += len(out)
        batch.clear()

    with open(args.out, "wb") as fout, open(args.out + ".seeds", "w", encoding="ascii") as fseed:
        fseed.write(f"# toeplitz_condition.py: n={N_IN} m={m} key_bits={N_IN + m - 1} "
                    f"reseed_blocks={args.reseed_blocks} health_filter={'firmware RCT/APT (qrng_health.py)' if args.drop_health_fail else 'none'} "
                    f"inputs={','.join(os.path.basename(p) for p in args.inp)}\n"
                    f"# <first conditioned block using the key> <first raw block using the key> "
                    f"<key hex, MSB first, {N_IN + m - 1} bits>\n")
        for blk in iter_blocks(args.inp, args.drop_health_fail, stats):
            raw_index = stats["read"] - 1          # this block's position in the raw input (for OUT.seeds only)
            if kept % args.reseed_blocks == 0:     # every --reseed-blocks conditioning runs
                if batch:
                    flush(fout)          # finish the old key's batch before switching keys
                key_bytes = os.urandom((N_IN + m - 1 + 7) // 8)
                t.set_key(bytes_to_bits(key_bytes)[:N_IN + m - 1])
                fseed.write(f"{kept} {raw_index} {key_bytes.hex()}\n")
            batch.append(blk)
            kept += 1
            if len(batch) >= args.batch:
                flush(fout)
            if args.max_out_bytes is not None and written >= args.max_out_bytes:
                break
            if time.time() - t_print > 10:
                t_print = time.time()
                print(f"  read {stats['read']:,} blocks, kept {kept:,}, dropped RCT {stats['RCT']:,} APT "
                      f"{stats['APT']:,}, {written / 1e6:,.1f} MB out, {stats['read'] / (t_print - t0):,.0f} "
                      f"blocks/s", flush=True)
        if batch and (args.max_out_bytes is None or written < args.max_out_bytes):
            flush(fout)
    el = time.time() - t0
    dropped = stats["RCT"] + stats["APT"]
    print(f"done in {el / 60:.1f} min: read {stats['read']:,} blocks, conditioned {kept:,}, dropped {dropped:,} "
          f"(RCT {stats['RCT']:,}, APT {stats['APT']:,}, {100.0 * dropped / max(stats['read'], 1):.1f} %)")
    print(f"output {args.out}: {written:,} bytes; keys in {args.out}.seeds")
    if args.max_out_bytes is not None and written < args.max_out_bytes:
        print(f"WARNING: only {written:,} of the requested {args.max_out_bytes:,} bytes -- capture more raw data")


if __name__ == "__main__":
    main()
