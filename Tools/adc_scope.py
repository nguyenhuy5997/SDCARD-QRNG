"""Raw ADC scope for the QRNG analog front end: capture raw samples over USB, plot them and their spectrum.

The board (V8Y firmware) returns 1024 consecutive 12-bit ADC samples per request (QRNG_CMD_RAW_CAPTURE, no health
test); if the QRNG service is not running it first powers the analog front end (PS_FIRST -> PS_SECOND -> LED ->
AD5398 20 mA) and starts the ADC. Blocks are contiguous inside, with gaps between them (USB is slower than the ADC),
so the spectrum is the average of per-block FFTs (Welch, Hann window).

    python Tools/adc_scope.py --port COM19                 # 64 blocks, plot + stats, save adc_scope.png/.npz/.csv
    python Tools/adc_scope.py --port COM19 --blocks 256 --no-show
    python Tools/adc_scope.py --port COM19 --keep-on       # leave the analog front end on afterwards

Needs: pip install pyserial numpy matplotlib
"""
import argparse
import struct
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evt2_cli as c  # noqa: E402

QRNG_CMD_RAW_CAPTURE = 0x13
QRNG_CMD_RAW_STOP = 0x14
QRNG_CMD_ADC_RATE = 0x12
QRNG_CMD_DEVICE_STATUS = 0x11
ADC_BITS = 12
VREF = 3.3


def device_status(dev):
    r = c.request(dev, c.CMD_TYPE_QRNG, 1, QRNG_CMD_DEVICE_STATUS)
    if r is None or len(r[3]) < 18:
        return None
    t, tmax, permille, _ = struct.unpack_from("<iiII", r[3], 2)
    return t, tmax, permille / 10.0


def adc_rate(dev):
    r = c.request(dev, c.CMD_TYPE_QRNG, 1, QRNG_CMD_ADC_RATE, struct.pack("<H", 300), timeout=5.0)
    if r is None or len(r[3]) < 10:
        return None
    return struct.unpack_from("<II", r[3], 2)[1]


def capture(dev, blocks):
    out = []
    t0 = time.time()
    for i in range(blocks):
        r = c.request(dev, c.CMD_TYPE_QRNG, 1, QRNG_CMD_RAW_CAPTURE, timeout=10.0 if i == 0 else 3.0)
        if r is None:
            raise RuntimeError(f"block {i}: no reply")
        p = r[3]
        if p[1] != 0:
            raise RuntimeError(f"block {i}: status {c.QRNG_STATUS_NAMES.get(p[1], p[1])}")
        n = struct.unpack_from("<H", p, 2)[0]
        out.append(np.frombuffer(bytes(p[4:4 + 2 * n]), dtype="<u2").astype(np.float64))
    print(f"captured {blocks} x {len(out[0])} samples in {time.time() - t0:.1f} s")
    return np.stack(out)


def spectrum(blocks, fs):
    n = blocks.shape[1]
    win = np.hanning(n)
    scale = 1.0 / (fs * np.sum(win ** 2))
    psd = np.zeros(n // 2 + 1)
    for b in blocks:
        x = (b - b.mean()) * win
        psd += scale * np.abs(np.fft.rfft(x)) ** 2
    psd /= len(blocks)
    psd[1:-1] *= 2.0  # one-sided
    return np.fft.rfftfreq(n, 1.0 / fs), psd


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True)
    ap.add_argument("--blocks", type=int, default=64)
    ap.add_argument("--fs", type=float, default=0.0, help="sample rate in Hz (default: measured on the board)")
    ap.add_argument("--out", default="adc_scope", help="output file prefix (.png, .npz)")
    ap.add_argument("--no-show", action="store_true")
    ap.add_argument("--keep-on", action="store_true", help="do not stop the ADC/analog front end afterwards")
    args = ap.parse_args()

    dev = c.Device(args.port)
    try:
        st = device_status(dev)
        if st:
            print(f"chip temperature before: {st[0]} C (max {st[1]} C)")
        data = capture(dev, args.blocks)
        fs = args.fs or (adc_rate(dev) or 1.5e6)
        st2 = device_status(dev)
        if st2:
            print(f"chip temperature after:  {st2[0]} C (max {st2[1]} C)")
        if not args.keep_on:
            c.request(dev, c.CMD_TYPE_QRNG, 1, QRNG_CMD_RAW_STOP)
            print("analog front end + ADC stopped")
    finally:
        dev.close()

    flat = data.ravel()
    lsb_v = VREF / (1 << ADC_BITS)
    print(f"sample rate {fs / 1e6:.4f} MS/s, {data.size} samples")
    print(f"mean {flat.mean():.2f} LSB ({flat.mean() * lsb_v:.4f} V)  std {flat.std():.3f} LSB "
          f"({flat.std() * lsb_v * 1e3:.3f} mV rms)  min {flat.min():.0f}  max {flat.max():.0f}  "
          f"span {flat.max() - flat.min():.0f} LSB  distinct values {len(np.unique(flat))}")
    freqs, psd = spectrum(data, fs)
    top = np.argsort(psd[1:])[::-1][:8] + 1
    print("strongest spectral lines (excluding DC):")
    for i in sorted(top, key=lambda k: -psd[k]):
        print(f"  {freqs[i] / 1e3:9.2f} kHz   {10 * np.log10(psd[i] + 1e-30):7.1f} dB(LSB^2/Hz)")
    np.savez(args.out + ".npz", samples=data, fs=fs)
    with open(args.out + ".csv", "w", encoding="ascii") as f:
        f.write(f"# fs_hz={fs:.0f} vref={VREF} bits={ADC_BITS} blocks={data.shape[0]} samples_per_block={data.shape[1]}\n")
        f.write("block,index,adc,volts\n")
        for bi, blk in enumerate(data):
            f.writelines(f"{bi},{i},{int(v)},{v * lsb_v:.5f}\n" for i, v in enumerate(blk))

    import matplotlib
    if args.no_show:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(3, 1, figsize=(11, 10))
    t_us = np.arange(data.shape[1]) / fs * 1e6
    ax[0].plot(t_us, data[0], lw=0.7)
    ax[0].set_title(f"Raw ADC, first block ({data.shape[1]} consecutive samples @ {fs / 1e6:.3f} MS/s)")
    ax[0].set_xlabel("time [us]")
    ax[0].set_ylabel("ADC [LSB]")
    ax[0].grid(True, alpha=0.3)
    lo, hi = int(flat.min()), int(flat.max())
    ax[1].hist(flat, bins=min(256, hi - lo + 1), color="tab:orange")
    ax[1].set_title(f"Histogram: mean {flat.mean():.1f}, std {flat.std():.2f} LSB, span {hi - lo} LSB")
    ax[1].set_xlabel("ADC [LSB]")
    ax[1].grid(True, alpha=0.3)
    ax[2].plot(freqs / 1e3, 10 * np.log10(psd + 1e-30), lw=0.8, color="tab:green")
    ax[2].set_title(f"Spectrum: Welch average of {len(data)} blocks, Hann, resolution {fs / data.shape[1] / 1e3:.2f} kHz")
    ax[2].set_xlabel("frequency [kHz]")
    ax[2].set_ylabel("PSD [dB LSB^2/Hz]")
    ax[2].grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(args.out + ".png", dpi=110)
    print(f"saved {args.out}.png, {args.out}.npz and {args.out}.csv")
    if not args.no_show:
        plt.show()


if __name__ == "__main__":
    main()
