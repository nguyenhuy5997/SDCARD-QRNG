#!/usr/bin/env python3
"""
adc_stream.py -- stream raw QRNG ADC samples from the V8Y board to the PC, save them, and look at them live:
waveform, accumulated FFT and histogram, RMS per front-end state; switch the analog front end (PS_FIRST_STAGE,
PS_SECOND_STAGE, LED_ENABLE, AD5398) with buttons and set the AD5398 current with a slider (0..30 mA).

Uses QRNG_CMD_RAW_CAPTURE (0x13, qrng_protocol.c): every request returns one block of 1024 consecutive 12-bit ADC
samples, with NO health test. By default the first request powers the analog front end with the normal sequence and
starts the ADC (about 3 s settle). With --manual the ADC starts with the front end left as it is (off after a
RAW_STOP) and you switch each part yourself (QRNG_CMD_ANALOG_CTRL 0x15). If the QRNG service itself runs (it passed
its startup health check and owns the front end), the tool releases it first (QRNG off until the next reset).

Sample rate: ADC2 does one conversion per TIM1 trigger, 120 MHz / 60 = 2.000 MS/s (board.h). That is 4 MB/s, more
than USB Full Speed carries (~1 MB/s), so the stream is NOT gapless: each 1024-sample block (0.512 ms) is contiguous,
with a gap before the next block. So the FFT is done on each block (Hann window) and the power spectra are averaged;
the RMS is computed per block (block mean removed = AC RMS) and accumulated. Histogram, FFT and RMS start again on
every front-end change (button or slider), and the finished state's numbers are printed on the console.

Output (only with --out): one CSV file with exactly --samples data rows:
    # fs_hz=... vref=... bits=12 samples_per_block=1024 ...      (comment line)
    block,index,adc,volts
    block = which 1024-sample block (contiguous inside, gaps between blocks), index = position in the block,
    adc = raw 12-bit value (0..4095), volts = adc * 2.5 / 4096 (VREF+ = external 2.5 V reference, VREF_2V5).
With the plot window, the view stays live after the file is complete, so the controls keep working; close the window
(or Ctrl+C) to stop. Without it (--no-plot) the run ends when the file is complete.

    python Tools/adc_stream.py --port COM25 --samples 1000000 --out captures/raw.csv
    python Tools/adc_stream.py --port COM25 --samples 200000 --out captures/raw.csv --manual   # start with all off
    python Tools/adc_stream.py --port COM25 --samples 5000000 --out raw.csv --no-plot         # headless, fastest
    python Tools/adc_stream.py --port COM25 --samples 100000 --out raw.csv --keep-on          # leave the ADC running
    python Tools/adc_stream.py --port COM25                    # live view only: no CSV, nothing kept in memory
    python Tools/adc_stream.py --port COM25 --manual           # live view, front end off at the start
    python Tools/adc_stream.py --port COM25 --hist-range 100 2000   # histogram shows only 100..2000 LSB
    In the window: "histogram range" boxes (number + Enter, empty = automatic), Auto, and Y: linear/log.
    python Tools/adc_stream.py --port COM25 --no-plot --samples 2000000   # no file, just the statistics of 2M samples
    At the end the front end and the ADC are switched off (RAW_STOP) unless --keep-on.

Needs: pip install pyserial numpy matplotlib
"""
import argparse
import queue
import struct
import sys
import threading
import time
import zlib
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evt2_cli as c  # noqa: E402  (USB framing: Device, request)

QRNG_CMD_ADC_RATE = 0x12
QRNG_CMD_RAW_CAPTURE = 0x13
QRNG_CMD_RAW_STOP = 0x14
QRNG_CMD_ANALOG_CTRL = 0x15
ANALOG_ELEMENTS = ["PS_FIRST", "PS_SECOND", "LED_EN", "AD5398"]  # qrng_analog_elem_t order (qrng_service.h)
AD5398_IDX = 3
ANALOG_RELEASE = 0xFE           # ANALOG_CTRL element: stop the QRNG service so manual switching is allowed
ANALOG_SET_UA = 0xFD            # ANALOG_CTRL element: AD5398 current setpoint, u32 uA follows
QRNG_SERVICE_OWNS_BIT = 0x80    # state bit 7: the QRNG service runs and owns the front end
AD5398_MAX_MA = 30.0            # QRNG_ANALOG_AD5398_MAX_UA in the firmware (it refuses more)
AD5398_STEP_MA = 120.0 / 1024   # one DAC code = 117 uA
BLOCK = 1024                    # QRNG_RAW_CAPTURE_SAMPLES in the firmware
ADC_BITS = 12
ADC_MAX = (1 << ADC_BITS) - 1
VREF = 2.5                      # VREF+ = net VREF_2V5, external 2.5 V reference IC (schematic)
LSB_MV = VREF / (1 << ADC_BITS) * 1e3
DEFAULT_FS = 2.0e6              # TIM1 120 MHz / 60 (board.h); the measured rate is used when available
PLOT_INTERVAL_S = 0.1           # redraw at most 10 times a second, so plotting does not slow the capture


class FastDevice:
    """Drop-in for evt2_cli.Device (same send()/read_frame()/close(), so evt2_cli.request() works with it) with a
    fast decoder: a whole read chunk is split on the 0x7E flags and un-escaped with bytes operations instead of one
    Python call per byte (0.29 ms -> ~0.02 ms per 2 KB block). Frames are checked the same way: length and CRC32."""

    def __init__(self, port):
        import serial
        self.ser = serial.Serial(port, baudrate=115200, timeout=0.05)
        try:
            self.ser.set_buffer_size(rx_size=1 << 20, tx_size=1 << 16)  # Windows: a big driver buffer, no overruns
        except (AttributeError, ValueError):
            pass
        self.ser.reset_input_buffer()
        self.seq = 0
        self.pending = []
        self.tail = b""
        self.raw_bytes_in = 0

    def close(self):
        self.ser.close()

    def send(self, pkt_type, session_id, payload):
        seq = self.seq
        self.seq += 1
        self.ser.write(c.build_frame(pkt_type, session_id, seq, payload))
        return seq

    @staticmethod
    def _unescape(seg):
        if b"\x7d" not in seg:
            return seg
        parts = seg.split(b"\x7d")
        out = bytearray(parts[0])
        for p in parts[1:]:
            if p:
                out.append(p[0] ^ 0x20)
                out += p[1:]
        return bytes(out)

    def _feed(self, chunk):
        data = self.tail + chunk
        segs = data.split(b"\x7e")
        self.tail = segs[-1]                    # after the last flag: an unfinished frame (or nothing)
        for seg in segs[:-1]:
            if len(seg) < 14:
                continue
            raw = self._unescape(seg)
            if len(raw) < 14:
                continue
            plen = raw[8] | (raw[9] << 8)
            if len(raw) != 14 + plen:
                continue
            if (zlib.crc32(raw[:10 + plen]) & 0xFFFFFFFF) != struct.unpack_from("<I", raw, 10 + plen)[0]:
                continue
            self.pending.append((raw[1], raw[2] | (raw[3] << 8), struct.unpack_from("<I", raw, 4)[0],
                                 raw[10:10 + plen]))

    def read_frame(self, timeout, session_id=None):
        deadline = time.time() + timeout
        while True:
            for i, f in enumerate(self.pending):
                if session_id is None or f[1] == session_id:
                    return self.pending.pop(i)
            if time.time() >= deadline:
                return None
            chunk = self.ser.read(self.ser.in_waiting or 1)
            if chunk:
                self.raw_bytes_in += len(chunk)
                self._feed(chunk)


class CaptureThread(threading.Thread):
    """Owns the USB port while capturing: keeps `depth` RAW_CAPTURE requests in flight and puts every block on
    self.out, so plotting in the main thread never stalls USB. Front-end commands from the main thread go through
    self.ctrl (items ("elem", idx, on) or ("ua", ua)); in-flight blocks are finished first so replies never mix.
    Messages on self.out: ("block", array), ("fs", hz), ("state", result), ("ctrl", request, result),
    ("error", text)."""

    def __init__(self, dev, sid, manual, depth, keep_on):
        super().__init__(daemon=True)
        self.dev, self.sid, self.manual, self.depth, self.keep_on = dev, sid, manual, depth, keep_on
        self.out = queue.Queue()
        self.ctrl = queue.Queue()
        self.stop_evt = threading.Event()

    def run(self):
        dev, sid = self.dev, self.sid
        inflight = 0
        blocks = 0
        try:
            while not self.stop_evt.is_set():
                if not self.ctrl.empty():
                    while inflight:
                        self.out.put(("block", read_capture(dev, sid, False)))
                        inflight -= 1
                    while not self.ctrl.empty():
                        req = self.ctrl.get()
                        if req[0] == "elem":
                            res = analog_ctrl(dev, sid, req[1], req[2])
                        else:
                            res = analog_ctrl(dev, sid, ANALOG_SET_UA, ua=req[1])
                        self.out.put(("ctrl", req, res))
                depth = 1 if blocks == 0 else self.depth
                while inflight < depth:
                    send_capture(dev, sid, self.manual)
                    inflight += 1
                block = read_capture(dev, sid, blocks == 0)
                inflight -= 1
                if blocks == 0:
                    fs = measure_rate(dev, sid)
                    self.out.put(("fs", fs))
                    self.out.put(("state", analog_ctrl(dev, sid)))  # the default start powered the front end
                blocks += 1
                self.out.put(("block", block))
        except RuntimeError as e:
            self.out.put(("error", f"block {blocks}: {e}"))
        finally:
            while inflight > 0 and dev.read_frame(3.0, session_id=sid) is not None:
                inflight -= 1  # drain replies still on the way, so RAW_STOP's answer is not mistaken for one
            if not self.keep_on:
                c.request(dev, c.CMD_TYPE_QRNG, sid, QRNG_CMD_RAW_STOP)


def measure_rate(dev, sid):
    """Sample rate measured on the chip from the DMA position (QRNG_CMD_ADC_RATE), or None."""
    r = c.request(dev, c.CMD_TYPE_QRNG, sid, QRNG_CMD_ADC_RATE, struct.pack("<H", 300), timeout=5.0)
    if r is None or len(r[3]) < 10 or r[3][1] != 0:
        return None
    live = struct.unpack_from("<I", r[3], 6)[0]
    return float(live) if live else None


def analog_ctrl(dev, sid, elem=0xFF, on=False, ua=None):
    """One ANALOG_CTRL command: switch element `elem` (index into ANALOG_ELEMENTS), read only (0xFF), release the
    QRNG service (ANALOG_RELEASE) or set the AD5398 current (ANALOG_SET_UA with ua). Returns
    (status name, state bits, programmed AD5398 uA, setpoint uA or None) or None when the board does not answer."""
    extra = bytes([elem]) + (struct.pack("<I", ua) if elem == ANALOG_SET_UA else bytes([1 if on else 0]))
    r = c.request(dev, c.CMD_TYPE_QRNG, sid, QRNG_CMD_ANALOG_CTRL, extra, timeout=3.0)
    if r is None or len(r[3]) < 7 or r[3][0] != QRNG_CMD_ANALOG_CTRL:
        return None
    p = r[3]
    setpoint = struct.unpack_from("<I", p, 7)[0] if len(p) >= 11 else None
    return c.QRNG_STATUS_NAMES.get(p[1], p[1]), p[2], struct.unpack_from("<I", p, 3)[0], setpoint


def send_capture(dev, sid, manual, packed=True):
    # payload[1] bit 0 = start the ADC without powering the front end (only matters for the request that starts it),
    # bit 1 = packed 12-bit stream (1536 instead of 2048 bytes per block; older firmware ignores it and sends uint16)
    dev.send(c.CMD_TYPE_QRNG, sid, bytes([QRNG_CMD_RAW_CAPTURE, (1 if manual else 0) | (2 if packed else 0)]))


def unpack12(buf):
    """MSB-first 12-bit stream (firmware RAW_CAPTURE packed mode: 2 samples in 3 bytes) -> uint16 array."""
    b = np.frombuffer(buf, dtype=np.uint8).reshape(-1, 3).astype(np.uint16)
    out = np.empty(len(b) * 2, dtype=np.uint16)
    out[0::2] = (b[:, 0] << 4) | (b[:, 1] >> 4)
    out[1::2] = ((b[:, 1] & 0x0F) << 8) | b[:, 2]
    return out


def read_capture(dev, sid, first):
    """The reply to one earlier send_capture() as a uint16 array; raises RuntimeError on timeout or a non-OK status.
    Replies come back in request order (the firmware handles one command at a time)."""
    r = dev.read_frame(10.0 if first else 3.0, session_id=sid)
    if r is None:
        raise RuntimeError("no reply (board busy, or firmware without QRNG_CMD_RAW_CAPTURE 0x13?)")
    p = r[3]
    if not p or p[0] != QRNG_CMD_RAW_CAPTURE:
        raise RuntimeError(f"unexpected reply {bytes(p[:8]).hex()}")
    if len(p) < 4 or p[1] != 0:
        status = p[1] if len(p) > 1 else None
        raise RuntimeError(f"status {c.QRNG_STATUS_NAMES.get(status, status)}")
    n = struct.unpack_from("<H", p, 2)[0]
    body = bytes(p[4:])
    if len(body) == 2 * n:
        return np.frombuffer(body, dtype="<u2")
    if len(body) == (3 * n) // 2 and n % 2 == 0:
        return unpack12(body)
    raise RuntimeError(f"reply length {len(body)} fits neither {n} x uint16 nor {n} packed 12-bit samples")


# Online health test, the same as the firmware's (Drivers/QRNG/entropy.c): shared with raw_capture.py and
# toeplitz_condition.py. The firmware skips it for RAW_CAPTURE, so the tool runs it on every block itself.
from qrng_health import APT_CUTOFF, APT_WINDOW, RCT_CUTOFF, health_check  # noqa: E402,F401


def fmt_rms(lsb):
    return f"{lsb * LSB_MV:.3f} mV ({lsb:.2f} LSB)"


def state_name(bits, ad_ua):
    parts = [n for i, n in enumerate(ANALOG_ELEMENTS) if bits & (1 << i)]
    if bits & (1 << AD5398_IDX):
        parts[-1] = f"AD5398@{ad_ua / 1000:.2f}mA"
    return "+".join(parts) or "all off"


class StateStats:
    """Everything accumulated for one front-end state: histogram, AC RMS, Welch-averaged spectrum."""

    def __init__(self, name):
        self.name = name
        self.counts = np.zeros(ADC_MAX + 1, dtype=np.int64)
        self.window = np.hanning(BLOCK)
        self.win_power = float(np.sum(self.window ** 2))
        self.psd_sum = None
        self.fft_blocks = 0
        self.samples = 0
        self.var_sum = 0.0      # sum over blocks of (block variance x block length)
        self.sq_sum = 0.0       # sum of x^2 (total RMS, DC included)
        self.vmin, self.vmax = ADC_MAX, 0
        self.health = {"PASS": 0, "RCT": 0, "APT": 0}   # blocks per health-test result
        self.last_health = ("PASS", None)

    def add(self, block, fs):
        if len(block) == BLOCK:  # the firmware tests whole 1024-sample buffers only
            self.last_health = health_check(block)
            self.health[self.last_health[0]] += 1
        x = block.astype(np.float64)
        np.add.at(self.counts, np.minimum(block, ADC_MAX), 1)
        ac = x - x.mean()
        self.var_sum += float(np.sum(ac * ac))
        self.sq_sum += float(np.sum(x * x))
        self.samples += len(x)
        self.vmin, self.vmax = min(self.vmin, int(block.min())), max(self.vmax, int(block.max()))
        if len(x) == BLOCK:  # FFT of this block alone (blocks are not contiguous), power spectra averaged
            p = np.abs(np.fft.rfft(ac * self.window)) ** 2 / (fs * self.win_power)
            p[1:-1] *= 2.0   # one-sided
            self.psd_sum = p if self.psd_sum is None else self.psd_sum + p
            self.fft_blocks += 1

    def rms_ac(self):
        return (self.var_sum / self.samples) ** 0.5 if self.samples else 0.0

    def rms_total(self):
        return (self.sq_sum / self.samples) ** 0.5 if self.samples else 0.0

    def psd(self):
        return self.psd_sum / self.fft_blocks if self.fft_blocks else None

    def health_text(self):
        n = sum(self.health.values())
        if not n:
            return "health: no complete block"
        return (f"health: {self.health['PASS']}/{n} blocks PASS ({100.0 * self.health['PASS'] / n:.1f} %), "
                f"fail RCT {self.health['RCT']}, APT {self.health['APT']}")

    def summary(self):
        if not self.samples:
            return f"state {self.name}: no samples"
        return (f"state {self.name}: {self.samples:,} samples, RMS (AC) {fmt_rms(self.rms_ac())}, "
                f"RMS (total) {self.rms_total() * LSB_MV:.1f} mV, min {self.vmin} max {self.vmax}, "
                f"{self.health_text()}")


class LivePlot:
    """Real-time view: newest block, accumulated FFT, histogram; toggle buttons and the AD5398 current slider.
    Clicks and slider moves are only queued here (requests, pending_ma); the capture loop sends them between blocks."""

    def __init__(self, target, setpoint_ma, hist_range=(None, None)):
        import matplotlib.pyplot as plt
        from matplotlib.widgets import Button, Slider, TextBox
        self.plt = plt
        plt.ion()
        self.fig = plt.figure(figsize=(12, 11))
        self.fig.canvas.manager.set_window_title("V8Y raw ADC stream")
        self.ax_wave = self.fig.add_axes((0.08, 0.76, 0.88, 0.17))
        self.ax_fft = self.fig.add_axes((0.08, 0.52, 0.88, 0.17))
        self.ax_hist = self.fig.add_axes((0.08, 0.30, 0.88, 0.14))
        self.target = target
        self.fs = DEFAULT_FS
        (self.wave,) = self.ax_wave.plot(np.zeros(BLOCK), lw=0.7)
        self.ax_wave.set_xlabel("time in block [us]")
        self.ax_wave.set_ylabel("ADC [LSB]")
        self.ax_wave.grid(True, alpha=0.3)
        (self.fft_last,) = self.ax_fft.plot([], [], lw=0.5, color="tab:gray", alpha=0.5, label="newest block")
        (self.fft_avg,) = self.ax_fft.plot([], [], lw=0.9, color="tab:green", label="accumulated (average)")
        self.ax_fft.set_xlabel("frequency [kHz]")
        self.ax_fft.set_ylabel("PSD [dB LSB^2/Hz]")
        self.ax_fft.grid(True, alpha=0.3)
        self.ax_fft.legend(loc="upper right", fontsize=8)
        (self.hist,) = self.ax_hist.plot(np.arange(ADC_MAX + 1), np.zeros(ADC_MAX + 1), lw=0.8, color="tab:orange",
                                         drawstyle="steps-mid")
        self.ax_hist.set_xlabel("ADC [LSB]")
        self.ax_hist.set_ylabel("count")
        self.ax_hist.grid(True, alpha=0.3)
        # Histogram view range [LSB]: None = automatic (all values seen). Type a number + Enter; empty = automatic.
        self.hist_lo, self.hist_hi = hist_range
        self.hist_log = False
        self.fig.text(0.57, 0.19, "histogram range [LSB]:", ha="right", va="center", fontsize=9)
        self.tb_lo = TextBox(self.fig.add_axes((0.58, 0.175, 0.07, 0.03)), "",
                             initial="" if self.hist_lo is None else str(self.hist_lo))
        self.fig.text(0.66, 0.19, "to", ha="center", va="center", fontsize=9)
        self.tb_hi = TextBox(self.fig.add_axes((0.67, 0.175, 0.07, 0.03)), "",
                             initial="" if self.hist_hi is None else str(self.hist_hi))
        self.tb_lo.on_submit(lambda text: self._hist_limit_set("lo", text))
        self.tb_hi.on_submit(lambda text: self._hist_limit_set("hi", text))
        self.b_auto = Button(self.fig.add_axes((0.76, 0.175, 0.08, 0.03)), "Auto")
        self.b_auto.on_clicked(lambda _event: self._hist_auto())
        self.b_log = Button(self.fig.add_axes((0.86, 0.175, 0.10, 0.03)), "Y: linear")
        self.b_log.on_clicked(lambda _event: self._hist_toggle_log())

        self.requests = []       # element indexes clicked, not sent yet
        self.pending_ma = None   # newest slider value not sent yet
        self.state_bits = 0
        self._syncing = False    # True while the code (not the user) moves the slider
        self.buttons = []
        for i, name in enumerate(ANALOG_ELEMENTS):
            ax = self.fig.add_axes((0.08 + i * 0.22, 0.10, 0.20, 0.05))
            b = Button(ax, name)
            b.on_clicked(lambda _event, idx=i: self.requests.append(idx))
            self.buttons.append(b)
        ax_s = self.fig.add_axes((0.25, 0.03, 0.55, 0.03))
        self.slider = Slider(ax_s, "AD5398 current [mA]", 0.0, AD5398_MAX_MA, valinit=setpoint_ma,
                             valstep=AD5398_STEP_MA, valfmt="%.2f")
        self.slider.on_changed(self._slider_moved)
        self.status = self.fig.text(0.08, 0.17, "", ha="left", va="center", fontsize=10, color="red",
                                    fontweight="bold")
        # Firmware RCT/APT health test of the newest block, run on the PC (health_check()): green PASS / red FAIL
        self.health_txt = self.fig.text(0.08, 0.225, "HEALTH: waiting for data", ha="left", va="center", fontsize=9,
                                        fontweight="bold", color="black",
                                        bbox=dict(boxstyle="round,pad=0.3", facecolor="#d9d9d9", edgecolor="none"))
        self.set_state(0, 0, "")
        self.last = 0.0
        plt.show(block=False)

    def _hist_limit_set(self, which, text):
        text = text.strip()
        try:
            val = None if text == "" else min(max(int(float(text)), 0), ADC_MAX)
        except ValueError:
            self.status.set_text(f"histogram range: '{text}' is not a number")
            return
        if which == "lo":
            self.hist_lo = val
        else:
            self.hist_hi = val
        self.last = 0.0          # redraw with the next block

    def _hist_auto(self):
        self.hist_lo = self.hist_hi = None
        self.tb_lo.set_val("")   # set_val fires on_submit -> None, fine
        self.tb_hi.set_val("")
        self.last = 0.0

    def _hist_toggle_log(self):
        self.hist_log = not self.hist_log
        top = self.ax_hist.get_ylim()[1]
        if self.hist_log:        # log needs a positive lower limit before the next draw
            self.ax_hist.set_ylim(0.8, max(top, 1.0) * 2.0)
        self.ax_hist.set_yscale("log" if self.hist_log else "linear")
        if not self.hist_log:
            self.ax_hist.set_ylim(0, top)
        self.b_log.label.set_text("Y: log" if self.hist_log else "Y: linear")
        self.last = 0.0

    def _slider_moved(self, val):
        if not self._syncing:
            self.pending_ma = float(val)

    def set_slider(self, ma):
        self._syncing = True
        self.slider.set_val(min(max(ma, 0.0), AD5398_MAX_MA))
        self._syncing = False

    def alive(self):
        return self.plt.fignum_exists(self.fig.number)

    def pump(self):
        """Let the window process clicks/redraws without a full update."""
        self.fig.canvas.flush_events()

    def set_state(self, bits, ad5398_ua, note):
        self.state_bits = bits
        for i, b in enumerate(self.buttons):
            on = bool(bits & (1 << i))
            label = f"{ANALOG_ELEMENTS[i]}: {'ON' if on else 'OFF'}"
            if i == AD5398_IDX and on:
                label += f" {ad5398_ua / 1000:.2f} mA"
            b.label.set_text(label)
            color = "#7fd67f" if on else "#d9d9d9"
            b.ax.set_facecolor(color)
            b.color = color
            b.hovercolor = "#bde8bd" if on else "#eeeeee"
        self.status.set_text(note)
        self.fig.canvas.draw_idle()
        self.fig.canvas.flush_events()

    def update(self, block, st, saved, rate_sps, force=False):
        now = time.time()
        if not force and now - self.last < PLOT_INTERVAL_S:
            self.pump()
            return
        self.last = now
        x = block.astype(np.float64)
        t_us = np.arange(len(x)) / self.fs * 1e6
        self.wave.set_data(t_us, x)
        self.ax_wave.set_xlim(0, t_us[-1] if len(t_us) > 1 else 1)
        lo, hi = int(block.min()), int(block.max())
        pad = max(4, (hi - lo) // 10)
        self.ax_wave.set_ylim(max(-pad, lo - pad), min(ADC_MAX + pad, hi + pad))
        rms_ac = float(np.sqrt(np.mean((x - x.mean()) ** 2)))
        rms_tot = float(np.sqrt(np.mean(x * x)))
        self.ax_wave.set_title(f"newest block: RMS (AC) {fmt_rms(rms_ac)}   RMS (total) {rms_tot * LSB_MV:.1f} mV   "
                               f"min {lo * LSB_MV:.1f} mV  max {hi * LSB_MV:.1f} mV", fontsize=9)
        result, where = st.last_health
        if result == "PASS":
            self.health_txt.set_text("HEALTH (firmware RCT/APT test), newest block: PASS\n"
                                     f"this state: {st.health_text()}")
            self.health_txt.set_color("white")
            self.health_txt.get_bbox_patch().set_facecolor("#2e9e44")
        else:
            why = "RCT: one value repeated %d times in a row" % RCT_CUTOFF if result == "RCT" else \
                "APT: a value occurred %d times in a %d-sample window" % (APT_CUTOFF, APT_WINDOW)
            self.health_txt.set_text(f"HEALTH (firmware RCT/APT test), newest block: FAIL at sample {where} "
                                     f"({why})\nthis state: {st.health_text()}")
            self.health_txt.set_color("white")
            self.health_txt.get_bbox_patch().set_facecolor("#c62828")

        psd = st.psd()
        if psd is not None:
            f_khz = np.fft.rfftfreq(BLOCK, 1.0 / self.fs)[1:] / 1e3
            avg_db = 10 * np.log10(psd[1:] + 1e-12)
            last = np.abs(np.fft.rfft((x - x.mean()) * st.window)) ** 2 / (self.fs * st.win_power)
            last[1:-1] *= 2.0
            last_db = 10 * np.log10(last[1:] + 1e-12)
            self.fft_avg.set_data(f_khz, avg_db)
            self.fft_last.set_data(f_khz, last_db)
            self.ax_fft.set_xlim(0, f_khz[-1])
            lo_db = min(float(np.percentile(avg_db, 1)), float(np.percentile(last_db, 5))) - 5
            self.ax_fft.set_ylim(lo_db, max(float(avg_db.max()), float(last_db.max())) + 5)
            self.ax_fft.set_title(f"FFT per block (Hann), accumulated over {st.fft_blocks} blocks -- "
                                  f"resolution {self.fs / BLOCK / 1e3:.2f} kHz, state {st.name}", fontsize=9)

        self.hist.set_ydata(st.counts)
        nz = np.nonzero(st.counts)[0]
        in_range = ""
        if len(nz):
            lo = self.hist_lo if self.hist_lo is not None else max(0, nz[0] - 8)
            hi = self.hist_hi if self.hist_hi is not None else min(ADC_MAX, nz[-1] + 8)
            if hi <= lo:
                hi = min(ADC_MAX, lo + 1)
            self.ax_hist.set_xlim(lo, hi)
            view = st.counts[lo:hi + 1]
            top = max(int(view.max()), 1)
            if self.hist_log:
                self.ax_hist.set_ylim(0.8, top * 2.0)
            else:
                self.ax_hist.set_ylim(0, top * 1.1)
            if self.hist_lo is not None or self.hist_hi is not None:
                in_range = (f", range {lo}..{hi}: {int(view.sum()):,} samples "
                            f"({100.0 * view.sum() / max(st.samples, 1):.2f} %)")
        self.ax_hist.set_title(f"histogram of this state: {st.samples:,} samples, accumulated RMS (AC) "
                               f"{fmt_rms(st.rms_ac())}, {len(nz)} distinct values{in_range}", fontsize=9)
        if self.target is None:
            done = "live view (no file) -- close the window to stop"
        elif saved >= self.target:
            done = "file complete -- live view, close the window to stop"
        else:
            done = f"saving {saved:,} / {self.target:,} ({100.0 * saved / self.target:.1f} %)"
        self.fig.suptitle(f"{done}   fs = {self.fs / 1e6:.4f} MS/s   transfer {rate_sps / 1e3:.0f} kS/s")
        self.fig.canvas.draw_idle()
        self.fig.canvas.flush_events()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="the board's USB CDC port, e.g. COM25")
    ap.add_argument("--samples", type=int, default=None,
                    help="number of samples to save (required with --out); without --out, with --no-plot: stop "
                         "after this many samples (default: run until Ctrl+C)")
    ap.add_argument("--out", default=None, metavar="FILE.csv",
                    help="CSV file: block,index,adc,volts. Leave it out for a live view only (faster: no samples "
                         "kept in memory, no file written)")
    ap.add_argument("--manual", action="store_true",
                    help="start the ADC without powering the analog front end; switch it with the buttons")
    ap.add_argument("--no-plot", action="store_true", help="no window/controls (headless)")
    ap.add_argument("--keep-on", action="store_true", help="do not stop the ADC/analog front end afterwards")
    ap.add_argument("--depth", type=int, default=2, choices=[1, 2, 3, 4],
                    help="capture requests kept in flight (default: 2). Measured on the board with a bare reader: "
                         "1 = 341 kS/s, 2 = 511 kS/s (~1.03 MB/s, the USB Full Speed limit), 4 = 497 kS/s; "
                         "8 lost a reply, hence the cap at 4")
    ap.add_argument("--hist-range", nargs=2, type=int, default=None, metavar=("MIN", "MAX"),
                    help="histogram view range in LSB at the start, e.g. --hist-range 100 2000 (can be changed in "
                         "the window; default: automatic)")
    ap.add_argument("--session-id", type=lambda x: int(x, 0), default=0x0001)
    args = ap.parse_args()
    if args.samples is not None and args.samples <= 0:
        ap.error("--samples must be > 0")
    if args.out and args.samples is None:
        ap.error("--out needs --samples (how many samples to save)")
    if args.manual and args.no_plot:
        print("note: --manual without the plot window leaves the front end as it is (no buttons to switch it)")

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    to_save = args.samples if args.out else 0      # samples kept for the CSV (0 = live view only)
    sid = args.session_id
    dev = FastDevice(args.port)

    st0 = analog_ctrl(dev, sid)
    if st0 is not None and st0[1] & QRNG_SERVICE_OWNS_BIT:
        # The QRNG service passed its startup check and owns the front end: the firmware refuses manual switching.
        # Release it (qrng_service_deinit(): ADC stop, front end off); the capture below starts the ADC again.
        print("NOTE: the QRNG service is running and owns the analog front end -> releasing it for manual control "
              "(QRNG stays off until the board is reset; random numbers fall back to the TRNG meanwhile)")
        r = analog_ctrl(dev, sid, ANALOG_RELEASE)
        print(f"  release -> {r[0] if r else 'no answer'}")
        st0 = analog_ctrl(dev, sid)
    setpoint_ma = (st0[3] / 1000.0) if (st0 is not None and st0[3] is not None) else 8.0

    plot = None if args.no_plot else LivePlot(args.samples if args.out else None, setpoint_ma,
                                               tuple(args.hist_range) if args.hist_range else (None, None))
    fs = DEFAULT_FS
    state = StateStats("?")
    saved_parts = []               # (block number, samples) for the CSV, written once at the end
    saved = blocks = seen = 0
    stop_reason = None
    t_first = None                 # arrival of the first block (the power-up/settle time is not counted)
    t_saved = None
    last_block = None

    def apply_state(res, note=""):
        """New front-end state from the board: update the controls, close the old state's statistics."""
        nonlocal state
        name = state_name(res[1], res[2])
        if plot is not None:
            plot.set_state(res[1], res[2], note)
            if res[3] is not None:
                plot.set_slider(res[3] / 1000.0)
        if name != state.name:
            if state.samples:
                print("  " + state.summary())
            state = StateStats(name)

    def ctrl_result(req, res):
        if req[0] == "elem":
            idx, want_on = req[1], req[2]
            name, action = ANALOG_ELEMENTS[idx], ("ON" if want_on else "OFF")
            if res is None:
                note = f"{name} {action}: no answer -- firmware without QRNG_CMD_ANALOG_CTRL (0x15)?"
                print(f"  button {name} -> {action}: {note}")
                if plot is not None:
                    plot.set_state(plot.state_bits, 0, note)
                return
            changed = bool(res[1] & (1 << idx)) == want_on
            if res[0] != "QRNG_OK":
                hint = {"QRNG_ERROR": "refused/failed (QRNG service owns the front end, or AD5398 not answering "
                                      "on I2C)",
                        "QRNG_INVALID_PARAM": "unknown element (firmware too old?)"}.get(res[0], res[0])
                note = f"{name} {action}: {hint}"
            elif not changed:
                note = f"{name} {action}: command OK but the read-back state did not change"
            else:
                note = ""
            print(f"  button {name} -> {action}: {res[0]}{'' if changed else ' (state unchanged!)'} -- now: "
                  f"{state_name(res[1], res[2])}")
            apply_state(res, note)
        else:
            ma = req[1] / 1000.0
            if res is None:
                note = "AD5398 current: no answer -- firmware without the setpoint command (0xFD)?"
                print(f"  slider -> {ma:.2f} mA: {note}")
                if plot is not None:
                    plot.set_state(plot.state_bits, 0, note)
                return
            note = "" if res[0] == "QRNG_OK" else f"AD5398 {ma:.2f} mA: {res[0]}"
            on = bool(res[1] & (1 << AD5398_IDX))
            print(f"  slider AD5398 -> {ma:.2f} mA: {res[0]} -- "
                  + (f"applied now, programmed {res[2] / 1000:.2f} mA" if on else "used at the next AD5398 ON"))
            apply_state(res, note)

    if st0 is None:
        msg = "no answer to QRNG_CMD_ANALOG_CTRL (0x15): firmware too old? flash the current Appli"
        print("WARNING: " + msg)
        if plot is not None:
            plot.set_state(0, 0, msg)
    else:
        apply_state(st0)
    what = (f"capturing {args.samples:,} samples for {args.out}" if args.out else
            f"live view, no file{f' (stops after {args.samples:,} samples)' if args.samples and not plot else ''}")
    print(f"{what} from {args.port}"
          + (" -- front end left as it is (--manual)" if args.manual else
             " -- first block ~3 s: analog front end power-up + settle"))

    cap = CaptureThread(dev, sid, args.manual, args.depth, args.keep_on)
    cap.start()
    try:
        while True:
            if plot is not None and not plot.alive():
                stop_reason = "plot window closed"
                break
            if plot is None and args.samples and (saved if args.out else seen) >= args.samples:
                break
            if plot is not None:        # buttons/slider -> the capture thread sends them between blocks
                while plot.requests:
                    idx = plot.requests.pop(0)
                    cap.ctrl.put(("elem", idx, not bool(plot.state_bits & (1 << idx))))
                if plot.pending_ma is not None:
                    ma, plot.pending_ma = plot.pending_ma, None
                    cap.ctrl.put(("ua", int(round(ma * 1000))))
            deadline = time.time() + 0.05  # handle queued messages for at most 50 ms, then let the window breathe
            while time.time() < deadline:
                try:
                    msg = cap.out.get(timeout=0.02)
                except queue.Empty:
                    break
                kind = msg[0]
                if kind == "block":
                    block = msg[1]
                    if t_first is None:
                        t_first = time.time()
                    blocks += 1
                    seen += len(block)
                    if saved < to_save:
                        part = block[:to_save - saved]
                        saved_parts.append((blocks - 1, part))
                        saved += len(part)
                        if saved >= to_save:
                            t_saved = time.time()
                            print(f"{saved:,} samples captured"
                                  + (" -- still live, close the window to stop (the CSV is written then)"
                                     if plot is not None else ""))
                    state.add(block, fs)
                    last_block = block
                elif kind == "fs":
                    if msg[1]:
                        fs = msg[1]
                    if plot is not None:
                        plot.fs = fs
                    print(f"ADC sample rate {fs / 1e6:.4f} MS/s ({'measured on the chip' if msg[1] else 'nominal'})")
                elif kind == "state":
                    if msg[1] is not None:
                        apply_state(msg[1])
                elif kind == "ctrl":
                    ctrl_result(msg[1], msg[2])
                elif kind == "error":
                    stop_reason = msg[1]
                    break
            if stop_reason:
                break
            if not cap.is_alive() and cap.out.empty():
                stop_reason = "capture thread ended"
                break
            rate = (blocks - 1) * BLOCK / (time.time() - t_first) if (t_first and blocks > 1) else 0.0
            if plot is not None:
                if last_block is not None:
                    plot.update(last_block, state, saved, rate)
                else:
                    plot.pump()
            elif blocks and blocks % 200 == 0:
                done = f"{saved:,} / {args.samples:,}" if args.out else f"{seen:,}"
                print(f"  {done} samples ({rate / 1e3:.0f} kS/s)", flush=True)
    except KeyboardInterrupt:
        stop_reason = "Ctrl+C"
    finally:
        cap.stop_evt.set()
        cap.join(timeout=15)
        dev.close()

    if state.samples:
        print("  " + state.summary())
    t_end = time.time()
    if stop_reason and args.out and saved < args.samples:
        print(f"stopped early: {stop_reason}")
    elif stop_reason and stop_reason not in ("plot window closed", "Ctrl+C"):
        print(f"stopped: {stop_reason}")
    if not args.out:
        if t_first and blocks > 1:
            print(f"live view: {seen:,} samples, transfer {(blocks - 1) * BLOCK / (t_end - t_first) / 1e3:.0f} kS/s "
                  f"(the ADC makes {fs / 1e3:.0f} kS/s); no file written")
        print("analog front end + ADC left running (--keep-on)" if args.keep_on else
              "analog front end + ADC stopped")
        sys.exit(0 if blocks else 1)
    if saved_parts:
        t = time.time()
        allv = np.concatenate([p for _, p in saved_parts]).astype(np.float64)
        lsb_v = LSB_MV / 1e3
        with open(args.out, "w", encoding="ascii", newline="\n") as fcsv:
            fcsv.write(f"# fs_hz={fs:.0f} vref={VREF} bits={ADC_BITS} samples_per_block={BLOCK} "
                       f"(blocks are contiguous inside, with gaps between them)\n")
            fcsv.write("block,index,adc,volts\n")
            for bn, part in saved_parts:
                fcsv.writelines(f"{bn},{i},{int(v)},{v * lsb_v:.5f}\n" for i, v in enumerate(part))
        print(f"saved {saved:,} samples to {args.out} (written in {time.time() - t:.1f} s)")
        mean = allv.mean()
        rms_ac = float(np.sqrt(np.mean((allv - mean) ** 2)))
        rms_tot = float(np.sqrt(np.mean(allv * allv)))
        span = (t_saved or time.time()) - (t_first or time.time())
        if span > 0 and len(saved_parts) > 1:
            print(f"transfer {(len(saved_parts) - 1) * BLOCK / span / 1e3:.0f} kS/s while saving "
                  f"(the ADC makes {fs / 1e3:.0f} kS/s)")
        print(f"saved data: RMS (AC, whole file) {fmt_rms(rms_ac)}, RMS (total) {rms_tot * LSB_MV:.1f} mV, "
              f"min {allv.min() * LSB_MV:.1f} mV max {allv.max() * LSB_MV:.1f} mV")
    else:
        print(f"nothing captured, {args.out} not written")
    print("analog front end + ADC left running (--keep-on)" if args.keep_on else "analog front end + ADC stopped")
    sys.exit(0 if saved == args.samples else 1)


if __name__ == "__main__":
    main()
