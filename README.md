# SDQRNG_V8Y — firmware EVT2 cho board STM32H7S3V8Y6TR

Board sản phẩm: MCU STM32H7S3V8Y6TR (WLCSP101), flash ngoài GD25Q128E (XIP qua XSPIM port 1), secure element SE050F2.
Ghi chú chi tiết (lịch sử, kết quả đo, việc còn mở): `CLAUDE.md`. Tool nạp danh tính CA: `Tools/README.md`.

## Macro công tắc (compile-time)

### Macro đặt bằng cờ biên dịch (`Appli/.cproject`, không nằm trong file)

| Macro | Giá trị hiện tại | Rào phần gì |
|---|---|---|
| `EVT2_DIAGNOSTICS` | 0 | Mọi self-test, benchmark, chẩn đoán lúc khởi động |
| `EVT2_ENABLE_BIOMETRIC` | 0 | Cảm biến vân tay + `CMD_TYPE_BIOMETRIC` (`board.h` báo `#error` nếu bật trên V8Y) |
| `EVT2_FACTORY_PROVISION` | 0 (không định nghĩa) | Firmware nhà máy: lệnh nạp danh tính CA `CMD_TYPE_PROVISION`. Bật/tắt: `python Patches/factory_flag.py on\|off` |
| `EVT2_MEDIA_ALLOW_UNAUTHENTICATED` | 0 (không định nghĩa) | Cho gọi media bằng khóa toàn 0 khi chưa bắt tay CA |
| `EVT2_CA_ALLOW_TEST_IDENTITY` | 0 (không định nghĩa) | Chặn include nhầm danh tính CA thử (`ca_identity_cfg.h`) |
| `PLUG_AND_TRUST_STM32_ENABLE_SCP03` | bật | Kênh SCP03 tới SE050 (thiếu thì không mở được SE) |

`EVT2_DIAGNOSTICS=0` và `EVT2_ENABLE_BIOMETRIC=0` hiện chỉ có trong cấu hình Debug; Release không định nghĩa = 0.

### Macro trong code

| Macro | Giá trị | Rào phần gì | File |
|---|---|---|---|
| `BOARD_QRNG_ANALOG_ENABLE` | 0 | **Khóa an toàn**: không bật PS_FIRST/PS_SECOND/LED_ENABLE, giữ AD5398 power-down, QRNG không khởi động | `Appli/Core_app/BSP/board.h` |
| `BOARD_DEBUG_UART` | không định nghĩa | Log UART (board không có UART → `app_log` không làm gì) | `board.h` |
| `PLATFORM_USB_BACKEND` | `PLATFORM_USB_BACKEND_STM32LIB` | Chọn stack USB (ST lib / TinyUSB) | `Appli/Core_app/Platform/platform_usb_config.h` |
| `EVT2_XSPI_AB_SLOW` | 0 | Boot: XSPI 25 MHz + SSHIFT (công tắc thử) | `Boot/Core/Src/extmem_manager.c` |
| `EVT2_SCP03_SE050F2_A92A` | 1 | Khóa SCP03 gốc của SE050F2 (OEF A92A) | `Appli/Core_app/Middleware/Security/scp03_keys_cfg.h` |
| `EVT2_SCP03_USE_TEST_KEYS` | 0 | Khóa SCP03 thử `0x40..0x4F` (SE052F đã đổi khóa) | `scp03_keys_cfg.h` |
| `SSS_HAVE_SE05X_VER_03_XX` | 1 | Applet 3.x (SE050F2) | `Appli/Core_app/Drivers/SE05x/config/fsl_sss_ftr.h` |
| `SSS_HAVE_SE05X_VER_07_02` | 0 | | `fsl_sss_ftr.h` |
| `SSS_HAVE_SE05X_VER_GTE_07_02` | 0 (suy ra) | ECDH/HKDF trong chip; = 0 → ECDH phần mềm (p256-m) + dẫn xuất trên MCU; mô hình bộ đếm SCP03 | `fsl_sss_ftr.h` |
| `SSS_HAVE_FIPS_NONE` | 1 | Cờ phía host của thư viện NXP (không đổi chế độ FIPS trong chip) | `fsl_sss_ftr.h` |
| `EVT2_SE05X_POLL_MIN_MS` | 10 | Khoảng tối thiểu giữa hai lần hỏi SE050 đang bận (sửa lỗi treo) | `.../smCom/T1oI2C/phNxpEsePal_i2c.c` |
| `EVT2_TRACE` | 1 | Bản ghi trace sau reset tại `0x24071800` | `Appli/Core_app/App/app_trace.h` |
| `EVT2_SE05X_PROBE` (+ `_LOOPS`, `_PAUSE_MS`) | 0 (5, 0) | Dò khả năng SE050 (1 = đầy đủ, 2 = chỉ HKDF) | `Appli/Core_app/App/app_se05x_probe.h` |
| `EVT2_SE05X_IDENTIFY` | 0 | Chẩn đoán: đọc IDENTIFY của SE | `scp03_keys_cfg.h` |
| `EVT2_SE05X_STATE_DIAG` | 0 | Chẩn đoán: trạng thái/bộ nhớ SE | `scp03_keys_cfg.h` |
| `EVT2_SE05X_HKDF_PERSIST_TEST` | 0 | Chẩn đoán HKDF với khóa bền vững | `scp03_keys_cfg.h` |
| `EVT2_SE05X_HKDF_CASES` | 0 | Chẩn đoán HKDF 8 trường hợp | `scp03_keys_cfg.h` |
| `PQC_SIGN_MAX_ENABLED_LEVEL` | 2 | Mức ML-DSA cao nhất được biên dịch (0 = 44, 1 = 65, 2 = 87) | `Appli/Core_app/Middleware/PQC/pqc_stack_call.h` |
| `EVT2_CA_DEV_SELECT` | 1 | Chọn danh tính dev trong `ca_identity_cfg.h` (file hiện không được biên dịch) | `Appli/Core_app/Middleware/CA/ca_identity_cfg.h` |

Không liệt kê: include guard `*_H`, cờ nội bộ của thư viện NXP SE05x (`SSS_HAVE_APPLET_*`, `SSS_HAVE_HOSTCRYPTO_*`, `USE_RTOS`...) và `HAL_*_MODULE_ENABLED` do CubeMX sinh.

### Một macro vừa có trong `.cproject` vừa có `#define` trong code

Giá trị trong `.cproject` được đưa vào dưới dạng `-D` trên dòng lệnh, nên có hiệu lực **trước dòng đầu tiên** của mọi file;
sau đó mới tới các `#define` trong code, theo thứ tự trình biên dịch gặp. `-DX` không kèm giá trị = `X` là 1.

| Code viết | Kết quả |
|---|---|
| `#ifndef X` / `#define X 0` / `#endif` | **Giá trị trong `.cproject` thắng**; code chỉ là mặc định khi không có `-D`. Cách nên dùng. |
| `#define X 0` (không kiểm tra), **khác** giá trị `-D` | Cảnh báo *"X redefined"*, **giá trị trong code thắng** từ dòng đó trở đi. Nguy hiểm: file nào **không include** header đó vẫn thấy giá trị `-D` → các file dùng hai giá trị khác nhau cho cùng một macro. |
| `#define X 1`, **giống hệt** giá trị `-D` | Không cảnh báo, không có vấn đề. |
| `#undef X` rồi `#define X ...` | Giá trị trong code thắng, không cảnh báo, vẫn có rủi ro lệch giữa các file như trường hợp thứ hai. |

Quy tắc của dự án: macro mà **mọi file phải thấy cùng một giá trị** (`EVT2_DIAGNOSTICS`, `EVT2_ENABLE_BIOMETRIC`,
`EVT2_FACTORY_PROVISION`) chỉ đặt bằng cờ biên dịch, không `#define` trong code. Macro cần vừa có mặc định trong code
vừa đổi được từ `.cproject` thì viết:

```c
#ifndef EVT2_TRACE
#define EVT2_TRACE 1   /* mặc định; ghi đè bằng -DEVT2_TRACE=0 trong .cproject */
#endif
```

Các macro `EVT2_TRACE`, `EVT2_SE05X_*`, `EVT2_SCP03_*` hiện được `#define` thẳng (không có `#ifndef`): nếu thêm cùng tên vào
`.cproject` với giá trị khác sẽ rơi vào trường hợp thứ hai ở bảng trên.
