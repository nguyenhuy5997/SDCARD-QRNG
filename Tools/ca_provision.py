#!/usr/bin/env python3
"""
ca_provision.py -- factory provisioning of an EVT2 board's CA identity into its secure element (SE050F2 / SE052F).

WHAT IT DOES (one "Nạp danh tính" run)
  1. connects to the board (it must run the FACTORY image: firmware built with EVT2_FACTORY_PROVISION=1, which adds the
     CMD_TYPE_PROVISION (0x16) commands -- see provision_protocol.c; the product image does not have them),
  2. reads the chip's 18-byte UNIQUE_ID (becomes the device id and the certificate CN),
  3. loads the CA (default Tools/ca -- the V8Y project's copy of the EVT2 dev PKI): <ca-dir>/root/cert.pem (trust anchor; the root PRIVATE key is not needed) and <ca-dir>/issuing/
     {cert.pem,key.pem} (the issuing CA that signs the device certificate and status token),
  4. has the chip GENERATE its identity key pair inside itself (the private key never exists outside the chip),
  5. proof of possession: the chip signs SHA-256("EVT2-POP-v1" || N || Q || uid) for a fresh random N; checked here,
  6. issues the device certificate (CN = UID) and a GOOD status token (10 years) with tools/ca_tool.py's own functions,
  7. runs ca_tool.verify_chain() -- the reference strict verifier -- on exactly what is about to be written,
  8. writes the six values (root public key, root subject, issuing CA cert, device id, device cert, status token), reads
     every one back and compares, then asks the chip to re-load and self-check them (ca_service_init() must be CA_OK),
  9. records the result in <out-dir>/<UID>/ (cert, token, record.json).
  Then flash the normal (product) image again.

Other actions: "Đọc thông tin" (what the chip holds), "Làm mới thẻ trạng thái" (new status token for the stored
certificate), "Xóa danh tính" (delete the identity key and the six values -- to re-provision a dev board).

USAGE
  python Tools/ca_provision.py                          # GUI
  python Tools/ca_provision.py --cli provision --port COM18
  python Tools/ca_provision.py --cli info --port COM18
  python Tools/ca_provision.py --cli refresh-token --port COM18
  python Tools/ca_provision.py --cli erase --port COM18 [--yes]

Requires: pip install pyserial cryptography
"""
import argparse
import contextlib
import io
import json
import os
import queue
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ca_tool as ct  # noqa: E402
import evt2_cli  # noqa: E402

TOOLS = Path(__file__).resolve().parent
DEFAULT_CA_DIR = TOOLS / "ca"
DEFAULT_OUT_DIR = TOOLS / "ca" / "provisioned"
DEVICE_CERT_DAYS = 3650          # 10 years, like the dev PKI (tools/gen_ca_dev_cfg.py)
TOKEN_HOURS = 87600              # 10 years: the device has no clock, the status token IS its clock

# ---- wire protocol (provision_protocol.c) -------------------------------------------------------------------------
CMD_TYPE_PROVISION = 0x16
PROV_GET_INFO, PROV_GEN_IDENTITY, PROV_SIGN_POP, PROV_WRITE_BLOB, PROV_READ_BLOB, PROV_FINALIZE, PROV_ERASE = range(1, 8)
POP_CONTEXT = b"EVT2-POP-v1"
UID_LEN = 18

# ca_prov_blob_t order
BLOBS = ["root_pubkey", "root_subject", "issuing_cert", "device_id", "device_cert", "status_token"]
BLOB_LABEL = {
    "root_pubkey": "khóa công khai root",
    "root_subject": "tên root (DER)",
    "issuing_cert": "chứng chỉ CA trung gian",
    "device_id": "mã thiết bị",
    "device_cert": "chứng chỉ thiết bị",
    "status_token": "thẻ trạng thái",
}

# ca_status_t (ca_service.h)
CA_STATUS = {
    0: "CA_OK", 1: "CA_NOT_READY", 2: "CA_INVALID_PARAM", 3: "CA_ERR_NOT_PROVISIONED", 4: "CA_ERR_PROVISION",
    5: "CA_ERR_READBACK", 6: "CA_ERR_KEY_MISMATCH", 7: "CA_ERR_SIGN_TEST", 8: "CA_ERR_EXISTS",
}


class StepError(Exception):
    pass


def ca_name(code: int) -> str:
    return CA_STATUS.get(code, f"status {code}")


class ProvisionLink:
    """CMD_TYPE_PROVISION commands to the board over its USB CDC port."""

    def __init__(self, port: str):
        self.dev = evt2_cli.Device(port)
        self.sid = 7

    def close(self):
        self.dev.close()

    def wait_ready(self, budget_s: float = 90.0) -> None:
        # the board answers nothing while it boots (SE05x init etc.) -- keep sending HELLO
        deadline = time.time() + budget_s
        while time.time() < deadline:
            self.dev.send(evt2_cli.CMD_TYPE_HELLO, self.sid, bytes([1]))
            if self.dev.read_frame(2.0, session_id=self.sid) is not None:
                return
        raise StepError("thiết bị không trả lời HELLO (đang khởi động? sai cổng COM?)")

    def req(self, sub: int, extra: bytes = b"", timeout: float = 30.0) -> bytes:
        resp = evt2_cli.request(self.dev, CMD_TYPE_PROVISION, self.sid, sub, extra, timeout=timeout)
        if resp is None:
            raise StepError(f"lệnh 0x{sub:02X} không có phản hồi -- board có đang chạy firmware NHÀ MÁY "
                            "(EVT2_FACTORY_PROVISION=1) không? Bản sản phẩm không có lệnh nạp.")
        p = resp[3]
        if len(p) < 2 or p[0] != sub:
            raise StepError("phản hồi không hợp lệ -- board có đang chạy firmware NHÀ MÁY (EVT2_FACTORY_PROVISION=1) không?")
        return p

    def info(self) -> dict:
        p = self.req(PROV_GET_INFO, timeout=6.0)  # first provisioning command: fail fast on a product image
        if p[1] != 0:
            raise StepError(f"secure element chưa sẵn sàng ({ca_name(p[1])})")
        o = 2
        presence = p[o]; o += 1
        uid_ok = p[o] == 1; o += 1
        uid = p[o:o + UID_LEN]; o += UID_LEN
        pub_ok = p[o] == 1; o += 1
        pub = p[o:o + 65]; o += 65
        ca_ready = p[o]
        return {"presence": presence, "uid": uid if uid_ok else None, "pub": pub if pub_ok else None, "ca_status": ca_ready}

    def gen_identity(self) -> bytes:
        p = self.req(PROV_GEN_IDENTITY, timeout=60.0)
        if p[1] != 0:
            raise StepError(f"sinh khóa thất bại: {ca_name(p[1])}")
        return p[2:2 + 65]

    def sign_pop(self, nonce: bytes) -> bytes:
        p = self.req(PROV_SIGN_POP, nonce)
        if p[1] != 0:
            raise StepError(f"ký PoP thất bại: {ca_name(p[1])}")
        return p[3:3 + p[2]]

    def write_blob(self, idx: int, data: bytes) -> None:
        p = self.req(PROV_WRITE_BLOB, bytes([idx]) + data)
        if p[1] != 0:
            raise StepError(f"ghi {BLOB_LABEL[BLOBS[idx]]} thất bại: {ca_name(p[1])}")

    def read_blob(self, idx: int):
        p = self.req(PROV_READ_BLOB, bytes([idx]))
        if p[1] != 0:
            return None
        n = int.from_bytes(p[2:4], "little")
        return p[4:4 + n]

    def finalize(self) -> int:
        return self.req(PROV_FINALIZE)[1]

    def erase(self) -> int:
        return self.req(PROV_ERASE)[1]


def load_ca(ca_dir: Path) -> dict:
    root_pem = ca_dir / "root" / "cert.pem"
    iss_dir = ca_dir / "issuing"
    for f in (root_pem, iss_dir / "cert.pem", iss_dir / "key.pem"):
        if not f.exists():
            raise StepError(f"thiếu {f}")
    root = ct.parse_cert(ct.pem_to_der(root_pem))
    if root.role != ct.ROLE_ROOT or not ct.verify_sig(root.point, root.tbs, root.sig):
        raise StepError("root/cert.pem không phải chứng chỉ root tự ký hợp lệ")
    issuing_der = ct.pem_to_der(iss_dir / "cert.pem")
    iss = ct.parse_cert(issuing_der)
    if iss.role != ct.ROLE_ISSUING or iss.issuer[2] != root.subject[2] or not ct.verify_sig(root.point, iss.tbs, iss.sig):
        raise StepError("issuing/cert.pem không được root này ký")
    return {"root": root, "issuing_der": issuing_der, "issuing": iss, "iss_dir": iss_dir}


def quiet(fn, *args):
    """Run a ca_tool command without its stdout chatter."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args)


# ---- step runner ---------------------------------------------------------------------------------------------------
PENDING, RUNNING, OK, FAIL, SKIP = "pending", "running", "ok", "fail", "skip"


class Runner:
    """Runs a list of named steps, reporting each state change through `on_step(index, state, detail)` and free text
    through `log(text)`. Stops at the first failure; later steps are reported as skipped."""

    def __init__(self, on_step, log):
        self.on_step = on_step
        self.log = log

    def run(self, steps):
        for i, (_, fn) in enumerate(steps):
            self.on_step(i, RUNNING, "")
            t0 = time.time()
            try:
                detail = fn() or ""
            except (StepError, ct.ProfileError) as e:
                self.on_step(i, FAIL, str(e))
                self.log(f"LỖI: {e}")
                for j in range(i + 1, len(steps)):
                    self.on_step(j, SKIP, "")
                return False
            except Exception as e:  # noqa: BLE001 -- a tool: show every failure, do not crash the UI
                self.on_step(i, FAIL, f"{type(e).__name__}: {e}")
                self.log(f"LỖI: {type(e).__name__}: {e}")
                for j in range(i + 1, len(steps)):
                    self.on_step(j, SKIP, "")
                return False
            self.on_step(i, OK, f"{detail}  ({time.time() - t0:.1f} s)" if detail else f"({time.time() - t0:.1f} s)")
        return True


class Job:
    """State shared by the steps of one action."""

    def __init__(self, port, ca_dir, out_dir, reuse_key, log):
        self.port, self.ca_dir, self.out_dir, self.reuse_key, self.log = port, Path(ca_dir), Path(out_dir), reuse_key, log
        self.link = None
        self.info = None
        self.ca = None
        self.pub = None
        self.uid = None
        self.cert_der = None
        self.token = None
        self.values = None

    def close(self):
        if self.link:
            self.link.close()
            self.link = None

    # -- shared steps
    def s_connect(self):
        self.link = ProvisionLink(self.port)
        self.link.wait_ready()
        return f"{self.port}"

    def s_info(self):
        self.info = self.link.info()
        if self.info["uid"] is None:
            raise StepError("không đọc được UNIQUE_ID của chip")
        self.uid = self.info["uid"]
        pres = self.info["presence"]
        have = [n for i, n in enumerate(["khóa danh tính"] + [BLOB_LABEL[b] for b in BLOBS]) if pres & (1 << i)]
        self.log(f"UID: {self.uid.hex().upper()}")
        self.log("Trong chip đang có: " + (", ".join(have) if have else "(chưa có gì)"))
        self.log(f"ca_service_init() hiện tại: {ca_name(self.info['ca_status'])}")
        return f"UID {self.uid.hex().upper()}"

    # -- provisioning
    def s_check_free(self):
        if self.info["presence"] & 0x01:
            if not self.reuse_key:
                raise StepError("chip đã có khóa danh tính -- chọn 'Dùng lại khóa đã có' hoặc 'Xóa danh tính' trước")
            return "đã có khóa, sẽ dùng lại"
        return "chưa có danh tính"

    def s_load_ca(self):
        self.ca = load_ca(self.ca_dir)
        return f"root '{self.ca['root'].subject[1]}', CA trung gian '{self.ca['issuing'].subject[1]}'"

    def s_gen_key(self):
        if self.info["presence"] & 0x01:
            self.pub = self.info["pub"]
            if self.pub is None:
                raise StepError("không đọc được khóa công khai của khóa đã có")
            return "dùng lại khóa trong chip"
        self.pub = self.link.gen_identity()
        self.log(f"Khóa công khai: {self.pub.hex().upper()}")
        return "sinh trong chip xong"

    def s_pop(self):
        nonce = secrets.token_bytes(32)
        sig = self.link.sign_pop(nonce)
        if not ct.verify_sig(self.pub, POP_CONTEXT + nonce + self.pub + self.uid, sig):
            raise StepError("chữ ký PoP sai: chip không giữ khóa riêng của khóa công khai này")
        return "chip giữ đúng khóa riêng"

    def s_issue_cert(self):
        dev_dir = self.out_dir / self.uid.hex().upper()
        dev_dir.mkdir(parents=True, exist_ok=True)
        cert_pem = dev_dir / "device_cert.pem"
        ns = argparse.Namespace
        quiet(ct.cmd_issue_device, ns(dir=str(self.ca["iss_dir"]), device_id=self.uid.hex(), pubkey=self.pub.hex(),
                                      days=DEVICE_CERT_DAYS, out=str(cert_pem)))
        self.cert_der = ct.pem_to_der(cert_pem)
        leaf = ct.parse_cert(self.cert_der)
        self.log(f"Chứng chỉ: serial {ct.hexs(leaf.serial)}, CN {leaf.subject[1]}, {len(self.cert_der)} byte")
        return f"serial {ct.hexs(leaf.serial)}"

    def s_issue_token(self):
        leaf = ct.parse_cert(self.cert_der)
        tok_path = self.out_dir / self.uid.hex().upper() / "status_token.bin"
        quiet(ct.cmd_status, argparse.Namespace(dir=str(self.ca["iss_dir"]), serial=ct.hexs(leaf.serial),
                                                hours=TOKEN_HOURS, out=str(tok_path), now=None))
        self.token = tok_path.read_bytes()
        t = ct.parse_token(self.token)
        if t.revoked:
            raise StepError("CA báo chứng chỉ này đã bị THU HỒI")
        return f"tốt, hết hạn {ct.utc(t.next_update):%Y-%m-%d}"

    def s_verify(self):
        root = self.ca["root"]
        leaf = ct.verify_chain(root.point, root.subject[2], self.ca["issuing_der"], self.cert_der, self.token)
        if leaf.point != self.pub:
            raise StepError("khóa trong chứng chỉ khác khóa của chip")
        if leaf.subject[1] != self.uid.hex().upper():
            raise StepError("CN của chứng chỉ khác UNIQUE_ID")
        self.values = [root.point, root.subject[2], self.ca["issuing_der"], self.uid, self.cert_der, self.token]
        return "chuỗi root → CA trung gian → thiết bị hợp lệ"

    def s_write(self):
        for i, data in enumerate(self.values):
            self.link.write_blob(i, data)
            self.log(f"  đã ghi {BLOB_LABEL[BLOBS[i]]} ({len(data)} byte)")
        return "6/6 giá trị"

    def s_readback(self):
        for i, data in enumerate(self.values):
            got = self.link.read_blob(i)
            if got != data:
                raise StepError(f"đọc lại {BLOB_LABEL[BLOBS[i]]} không khớp")
        return "6/6 khớp"

    def s_finalize(self):
        st = self.link.finalize()
        if st != 0:
            raise StepError(f"chip kiểm tra danh tính thất bại: {ca_name(st)}")
        return "ca_service_init() = CA_OK"

    def s_record(self):
        leaf = ct.parse_cert(self.cert_der)
        rec = {
            "uid": self.uid.hex().upper(),
            "serial": ct.hexs(leaf.serial),
            "public_key": self.pub.hex().upper(),
            "root": self.ca["root"].subject[1],
            "issuing": self.ca["issuing"].subject[1],
            "cert_not_after": ct.utc(leaf.not_after).isoformat(),
            "token_next_update": ct.utc(ct.parse_token(self.token).next_update).isoformat(),
            "provisioned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "port": self.port,
        }
        path = self.out_dir / self.uid.hex().upper() / "record.json"
        path.write_text(json.dumps(rec, indent=2))
        return str(path)

    # -- refresh token
    def s_read_cert(self):
        if not self.info["presence"] & (1 << (1 + BLOBS.index("device_cert"))):
            raise StepError("chip chưa có chứng chỉ thiết bị -- hãy nạp danh tính trước")
        self.cert_der = self.link.read_blob(BLOBS.index("device_cert"))
        leaf = ct.parse_cert(self.cert_der)
        self.pub = leaf.point
        return f"serial {ct.hexs(leaf.serial)}"

    def s_write_token(self):
        self.link.write_blob(BLOBS.index("status_token"), self.token)
        if self.link.read_blob(BLOBS.index("status_token")) != self.token:
            raise StepError("đọc lại thẻ trạng thái không khớp")
        return f"{len(self.token)} byte"

    # -- erase
    def s_erase(self):
        st = self.link.erase()
        if st != 0:
            raise StepError(f"xóa thất bại: {ca_name(st)}")
        left = self.link.info()["presence"]
        if left:
            raise StepError(f"vẫn còn object (mask 0x{left:02X})")
        return "đã xóa khóa danh tính + 6 giá trị"


def actions(job: Job):
    return {
        "provision": [
            ("Kết nối thiết bị", job.s_connect),
            ("Đọc thông tin chip (UNIQUE_ID)", job.s_info),
            ("Kiểm tra chip chưa có danh tính", job.s_check_free),
            ("Nạp CA (root + CA trung gian)", job.s_load_ca),
            ("Sinh khóa danh tính trong chip", job.s_gen_key),
            ("Chứng minh sở hữu khóa (PoP)", job.s_pop),
            ("Cấp chứng chỉ thiết bị (CN = UID)", job.s_issue_cert),
            ("Cấp thẻ trạng thái (10 năm)", job.s_issue_token),
            ("Kiểm chuỗi chứng chỉ trên PC", job.s_verify),
            ("Ghi 6 giá trị vào SE", job.s_write),
            ("Đọc lại và so sánh", job.s_readback),
            ("Chip tự kiểm tra danh tính", job.s_finalize),
            ("Lưu biên bản", job.s_record),
        ],
        "info": [
            ("Kết nối thiết bị", job.s_connect),
            ("Đọc thông tin chip", job.s_info),
        ],
        "refresh-token": [
            ("Kết nối thiết bị", job.s_connect),
            ("Đọc thông tin chip", job.s_info),
            ("Nạp CA (root + CA trung gian)", job.s_load_ca),
            ("Đọc chứng chỉ thiết bị trong chip", job.s_read_cert),
            ("Cấp thẻ trạng thái mới (10 năm)", job.s_issue_token),
            ("Ghi thẻ trạng thái vào SE", job.s_write_token),
            ("Chip tự kiểm tra danh tính", job.s_finalize),
        ],
        "erase": [
            ("Kết nối thiết bị", job.s_connect),
            ("Đọc thông tin chip", job.s_info),
            ("Xóa danh tính", job.s_erase),
        ],
    }


def find_port():
    import serial.tools.list_ports as list_ports
    for p in list_ports.comports():
        if p.vid == 0x0483 and p.pid == 0x5740:
            return p.device
    return None


# ---- CLI -----------------------------------------------------------------------------------------------------------
def run_cli(a) -> int:
    port = a.port or find_port()
    if not port:
        print("không tìm thấy board (USB 0483:5740) -- dùng --port")
        return 2
    job = Job(port, a.ca_dir, a.out_dir, a.reuse_key, lambda s: print(f"      {s}"))
    steps = actions(job)[a.action]
    mark = {RUNNING: "..", OK: "OK", FAIL: "LỖI", SKIP: "--"}

    def on_step(i, state, detail):
        if state == RUNNING:
            return
        print(f"[{mark[state]:>3}] {i + 1:2}. {steps[i][0]}" + (f" -- {detail}" if detail else ""))

    try:
        ok = Runner(on_step, job.log).run(steps)
    finally:
        job.close()
    print("THÀNH CÔNG" if ok else "THẤT BẠI")
    return 0 if ok else 1


# ---- GUI -----------------------------------------------------------------------------------------------------------
def run_gui(a) -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    import serial.tools.list_ports as list_ports

    root = tk.Tk()
    root.title("EVT2 — Nạp danh tính CA vào SE")
    root.geometry("900x820")
    root.minsize(820, 760)
    ui_q = queue.Queue()
    STYLE = {
        PENDING: ("○", "#8a8a8a", "chưa chạy"),
        RUNNING: ("▶", "#1565c0", "đang chạy…"),
        OK: ("✔", "#2e7d32", "thành công"),
        FAIL: ("✖", "#c62828", "thất bại"),
        SKIP: ("–", "#8a8a8a", "bỏ qua"),
    }

    # -- settings
    top = ttk.LabelFrame(root, text="Thiết lập", padding=8)
    top.pack(fill="x", padx=10, pady=(10, 4))
    ttk.Label(top, text="Cổng COM:").grid(row=0, column=0, sticky="w")
    port_var = tk.StringVar(value=a.port or find_port() or "")
    port_box = ttk.Combobox(top, textvariable=port_var, width=14)
    port_box.grid(row=0, column=1, sticky="w", padx=4)

    def refresh_ports():
        ports = [p.device for p in list_ports.comports()]
        port_box["values"] = ports
        board = find_port()
        if board and not port_var.get():
            port_var.set(board)

    ttk.Button(top, text="Làm mới", command=refresh_ports).grid(row=0, column=2, padx=4)
    ttk.Label(top, text="Thư mục CA:").grid(row=1, column=0, sticky="w", pady=(6, 0))
    ca_var = tk.StringVar(value=str(a.ca_dir))
    ttk.Entry(top, textvariable=ca_var, width=70).grid(row=1, column=1, columnspan=3, sticky="we", padx=4, pady=(6, 0))
    ttk.Button(top, text="…", width=3,
               command=lambda: ca_var.set(filedialog.askdirectory(initialdir=ca_var.get()) or ca_var.get())
               ).grid(row=1, column=4, pady=(6, 0))
    ttk.Label(top, text="Lưu biên bản vào:").grid(row=2, column=0, sticky="w", pady=(6, 0))
    out_var = tk.StringVar(value=str(a.out_dir))
    ttk.Entry(top, textvariable=out_var, width=70).grid(row=2, column=1, columnspan=3, sticky="we", padx=4, pady=(6, 0))
    reuse_var = tk.BooleanVar(value=a.reuse_key)
    ttk.Checkbutton(top, text="Dùng lại khóa danh tính đã có trong chip (nếu có)", variable=reuse_var
                    ).grid(row=3, column=1, columnspan=3, sticky="w", pady=(6, 0))
    top.columnconfigure(3, weight=1)
    refresh_ports()

    # -- buttons
    bar = ttk.Frame(root, padding=(10, 4))
    bar.pack(fill="x")
    buttons = []

    # -- steps
    steps_frame = ttk.LabelFrame(root, text="Các bước", padding=8)
    steps_frame.pack(fill="x", padx=10, pady=4)
    step_rows = []
    summary = tk.Label(root, text="Sẵn sàng.", font=("Segoe UI", 11, "bold"), anchor="w")
    summary.pack(fill="x", padx=12)

    # -- log
    log_frame = ttk.LabelFrame(root, text="Nhật ký", padding=4)
    log_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))
    log_txt = tk.Text(log_frame, height=10, font=("Consolas", 9), wrap="word")
    log_txt.pack(side="left", fill="both", expand=True)
    sb = ttk.Scrollbar(log_frame, command=log_txt.yview)
    sb.pack(side="right", fill="y")
    log_txt["yscrollcommand"] = sb.set

    def build_steps(names):
        for w in steps_frame.winfo_children():
            w.destroy()
        step_rows.clear()
        for i, n in enumerate(names):
            icon = tk.Label(steps_frame, text=STYLE[PENDING][0], fg=STYLE[PENDING][1], font=("Segoe UI", 12, "bold"), width=2)
            icon.grid(row=i, column=0)
            name = tk.Label(steps_frame, text=f"{i + 1}. {n}", anchor="w", width=36)
            name.grid(row=i, column=1, sticky="w")
            state = tk.Label(steps_frame, text=STYLE[PENDING][2], fg=STYLE[PENDING][1], anchor="w", width=12)
            state.grid(row=i, column=2, sticky="w")
            detail = tk.Label(steps_frame, text="", anchor="w", fg="#444", wraplength=400, justify="left")
            detail.grid(row=i, column=3, sticky="w")
            step_rows.append((icon, state, detail))

    def set_step(i, st, detail):
        icon, state, det = step_rows[i]
        sym, color, text = STYLE[st]
        icon.config(text=sym, fg=color)
        state.config(text=text, fg=color)
        det.config(text=detail, fg="#c62828" if st == FAIL else "#444")

    def add_log(s):
        log_txt.insert("end", f"{datetime.now():%H:%M:%S}  {s}\n")
        log_txt.see("end")

    def pump():
        try:
            while True:
                kind, *args = ui_q.get_nowait()
                if kind == "step":
                    set_step(*args)
                elif kind == "log":
                    add_log(args[0])
                elif kind == "done":
                    ok, title = args
                    summary.config(text=f"{title}: {'THÀNH CÔNG' if ok else 'THẤT BẠI'}",
                                   fg="#2e7d32" if ok else "#c62828")
                    for b in buttons:
                        b.config(state="normal")
        except queue.Empty:
            pass
        root.after(80, pump)

    def start(action, title):
        port = port_var.get().strip()
        if not port:
            messagebox.showerror("Thiếu cổng", "Chọn cổng COM của board.")
            return
        if action == "erase" and not messagebox.askyesno(
                "Xóa danh tính", "Xóa khóa danh tính và 6 giá trị CA khỏi secure element?\nKhông thể khôi phục khóa cũ."):
            return
        job = Job(port, ca_var.get(), out_var.get(), reuse_var.get(), lambda s: ui_q.put(("log", s)))
        steps = actions(job)[action]
        build_steps([n for n, _ in steps])
        summary.config(text=f"{title}: đang chạy…", fg="#1565c0")
        add_log(f"=== {title} ({port}) ===")
        for b in buttons:
            b.config(state="disabled")

        def work():
            try:
                ok = Runner(lambda i, st, d: ui_q.put(("step", i, st, d)), job.log).run(steps)
            finally:
                job.close()
            ui_q.put(("done", ok, title))

        threading.Thread(target=work, daemon=True).start()

    for action, title in (("provision", "Nạp danh tính"), ("info", "Đọc thông tin"),
                          ("refresh-token", "Làm mới thẻ trạng thái"), ("erase", "Xóa danh tính")):
        b = ttk.Button(bar, text=title, command=lambda ac=action, t=title: start(ac, t))
        b.pack(side="left", padx=(0, 8))
        buttons.append(b)

    build_steps([n for n, _ in actions(Job("", a.ca_dir, a.out_dir, False, print))["provision"]])
    add_log("Board phải chạy firmware NHÀ MÁY (EVT2_FACTORY_PROVISION=1). Nạp xong thì nạp lại firmware sản phẩm.")
    pump()
    root.mainloop()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", dest="action", choices=["provision", "info", "refresh-token", "erase"],
                    help="run without the GUI")
    ap.add_argument("--port", help="board COM port (default: find USB 0483:5740)")
    ap.add_argument("--ca-dir", default=str(DEFAULT_CA_DIR), help="CA directory with root/ and issuing/ (default Tools/ca)")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="where records/certs go (default Tools/ca/provisioned)")
    ap.add_argument("--reuse-key", action="store_true", help="reuse an identity key that is already in the chip")
    ap.add_argument("--yes", action="store_true", help="erase without asking")
    a = ap.parse_args()
    if a.action:
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(AttributeError, ValueError):
                stream.reconfigure(encoding="utf-8", errors="replace")  # Vietnamese text on a cp1252 Windows console
        if a.action == "erase" and not a.yes:
            if input("Xóa khóa danh tính và 6 giá trị CA khỏi chip? gõ YES: ").strip() != "YES":
                return 1
        return run_cli(a)
    return run_gui(a)


if __name__ == "__main__":
    sys.exit(main())
