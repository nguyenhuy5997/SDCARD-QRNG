#!/usr/bin/env python3
"""
quick_randtest.py -- fast sanity checks of a binary random file before running dieharder / NIST STS on it
(an `ent`-like summary; passing these does NOT replace the real test suites).

    python Tools/quick_randtest.py captures/cond_1GB.bin
    python Tools/quick_randtest.py captures/cond_1GB.bin --max-mb 200     # look at the first 200 MB only

Checks (p-values are two-sided where it applies; a single p below 0.001 is suspicious, many are a failure):
  monobit      fraction of 1 bits (z test)
  byte chi^2   256-bin byte histogram vs uniform (255 degrees of freedom)
  entropy      Shannon entropy per byte (8.0 = ideal)
  serial corr  correlation of consecutive bytes (0 = ideal)
  runs         number of runs of equal bits vs the expected n/2 (z test)
  compression  zlib level 9 on a 16 MB slice (random data does not compress: ratio >= ~1.0)
"""
import argparse
import math
import zlib

import numpy as np


def normal_p(z):
    return math.erfc(abs(z) / math.sqrt(2))


def chi2_p(x, k):
    # Wilson-Hilferty approximation of the chi-square upper tail
    z = ((x / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return 0.5 * math.erfc(z / math.sqrt(2))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--max-mb", type=float, default=None)
    args = ap.parse_args()
    data = np.memmap(args.path, dtype=np.uint8, mode="r")
    if args.max_mb:
        data = data[:int(args.max_mb * 1e6)]
    n = len(data)
    print(f"{args.path}: {n:,} bytes ({n * 8:,} bits)")

    counts = np.zeros(256, dtype=np.int64)
    ones = 0
    runs = 0
    s1 = s2 = s11 = 0.0
    prev_last_bit = None
    prev_last_byte = None
    step = 1 << 26
    popcount = np.array([bin(i).count("1") for i in range(256)], dtype=np.int64)
    for off in range(0, n, step):
        chunk = np.asarray(data[off:off + step])
        counts += np.bincount(chunk, minlength=256)
        ones += int(popcount[chunk].sum())
        bits = np.unpackbits(chunk)
        runs += int(np.count_nonzero(bits[1:] != bits[:-1]))
        if prev_last_bit is not None and bits[0] != prev_last_bit:
            runs += 1
        prev_last_bit = bits[-1]
        x = chunk.astype(np.float64)
        if prev_last_byte is not None:
            x_prev = np.concatenate(([prev_last_byte], x[:-1]))
            s11 += float(np.dot(x_prev, x))
        else:
            s11 += float(np.dot(x[:-1], x[1:]))
        s1 += float(x.sum())
        s2 += float(np.dot(x, x))
        prev_last_byte = x[-1]
    runs += 1
    nb = n * 8

    p1 = ones / nb
    z = (ones - nb / 2) / math.sqrt(nb / 4)
    print(f"  monobit      ones {p1:.6f} (ideal 0.5)                      z {z:+.2f}  p {normal_p(z):.4f}")
    exp = n / 256
    chi = float(((counts - exp) ** 2 / exp).sum())
    print(f"  byte chi^2   {chi:.1f} (255 dof, ideal ~255 +/- 23)          p {chi2_p(chi, 255):.4f}")
    pr = counts / n
    h = -float(np.sum(pr[pr > 0] * np.log2(pr[pr > 0])))
    print(f"  entropy      {h:.6f} bits per byte (ideal 8)")
    mean = s1 / n
    var = s2 / n - mean * mean
    cov = s11 / (n - 1) - mean * mean
    r = cov / var
    zr = r * math.sqrt(n)
    print(f"  serial corr  {r:+.6f} (ideal 0)                               z {zr:+.2f}  p {normal_p(zr):.4f}")
    exp_runs = (nb - 1) * 2 * p1 * (1 - p1) + 1
    zr2 = (runs - exp_runs) / math.sqrt(2 * nb * p1 * (1 - p1) * (1 - 2 * p1 * (1 - p1)) + 1e-12)
    print(f"  runs         {runs:,} (expected {exp_runs:,.0f})              z {zr2:+.2f}  p {normal_p(zr2):.4f}")
    sl = bytes(np.asarray(data[:16 << 20]))
    ratio = len(zlib.compress(sl, 9)) / len(sl)
    print(f"  compression  zlib -9 on {len(sl) >> 20} MB: {ratio:.4f} of the original (>= ~1.0 = incompressible)")


if __name__ == "__main__":
    main()
