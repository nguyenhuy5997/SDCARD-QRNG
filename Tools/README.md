# Tools for the V8Y board (CA provisioning, status)

| File | What |
|---|---|
| `ca_provision.py` | Writes the CA identity into the board's secure element (GUI; `--cli provision/info/refresh-token/erase`). Needs the FACTORY firmware image (`python ../Patches/factory_flag.py on`, rebuild, flash); flash the product image again afterwards. |
| `ca_tool.py` | The CA itself: `init-root`, `init-issuing`, `issue-device`, `status`, `revoke`, `verify`, `inspect`. Also the reference strict certificate verifier. Copy of `D:\EVT2\tools\ca_tool.py`. |
| `evt2_cli.py` | USB framing used by `ca_provision.py`. Copy of `D:\EVT2\tools\evt2_cli.py`. |
| `adc_stream.py` | Streams raw QRNG ADC samples (2.0 MS/s, 12 bit, no health test on the board; powers the analog front end itself) to a CSV file (block,index,adc,volts) with a live view: waveform, per-block FFT averaged, histogram, RMS in mV, the firmware's RCT/APT health test per block (PASS/FAIL), ON/OFF buttons for PS_FIRST, PS_SECOND, LED_EN, AD5398 and an AD5398 current slider (0..30 mA): `python adc_stream.py --port COM25 --samples 1000000 --out raw.csv [--manual] [--no-plot]`, or without `--out` for a live view only (no CSV, nothing kept in memory, runs until the window is closed). Blocks of 1024 contiguous samples with gaps; USB Full Speed carries ~510 kS/s (capture runs in its own thread). Needs numpy, matplotlib. |
| `adc_histogram.py` | Counts the raw ADC samples per level 0..4095 (RAW_CAPTURE 0x13 over USB, or a `raw_capture.py` .bin with `--from-bin`) into a CSV with all 4096 levels (`level,volts,count,fraction`, zero counts included). Default runs until Ctrl+C (overnight): CSV saved every `--save-every` s (atomic), USB drops -> reopen the port and count on, an error status from the board -> RAW_STOP and retry after `--error-wait` s, `--resume` continues an earlier CSV, `--plot` = live histogram, `--skip-ad5398` = switch only PS_FIRST/PS_SECOND/LED_EN on with ANALOG_CTRL and send RAW_CAPTURE with bit 0 (the AD5398 is never touched). Prints min/max/mean/std, levels hit, empty levels inside the used range, rail counts, odd/even split: `python adc_histogram.py --port COM25 --out hist_night.csv [--resume] [--plot] [--skip-ad5398] [--manual] [--samples N]`. Needs numpy (matplotlib for `--plot`). |
| `board_status.py` | Reads the die temperature (DTS) and the share of time the main loop sleeps over SWD, without resetting the board: `python board_status.py [--watch 5]`. Works while a phone owns the USB port. |
| `ca/root/` | Root CA "EVT2 DEV Root CA" -- `cert.pem` (trust anchor written into the chip) and `key.pem` (root PRIVATE key). |
| `ca/issuing/` | Issuing (intermediate) CA "EVT2 DEV Issuing CA" -- signs device certificates and status tokens; `issued.json` = every certificate issued from here. |
| `ca/provisioned/<UID>/` | One folder per provisioned board: device certificate, status token, `record.json`. |

TEST PKI: the root and issuing private keys are unencrypted. It is the same PKI as `D:\EVT2\tools\dev_ca` (same root,
same issuing CA), so boards provisioned here and the EVT2 PC tools (`ca_peer_sim.py`, `pc_call_peer.py`, which use the
`device_2` identity from there) trust each other. For production: make a new root with `ca_tool.py init-root`, keep it
offline, and point `ca_provision.py` at the new CA folder.

Requires: `pip install pyserial cryptography`.
