# QRNG security review — 2026-09-27

## Phạm vi và cách đọc kết quả

Review toàn bộ `Appli/Core_app/Drivers/QRNG`, sau đó lần theo middleware QRNG, USB adapter, Platform ADC/RNG/HASH/CRYP và các consumer CA/media/PQC. Không thay đổi firmware, cấu hình phần cứng hoặc flash bo mạch. Các file trong thư mục này chỉ là báo cáo và probe trên host.

**Điều chỉnh quan trọng so với review ban đầu:** `BSP/board.h:50` đặt `BOARD_QRNG_ANALOG_ENABLE=0`. `qrng_service_init()` trả `QRNG_ERROR` trước khi chạy ADC/extractor. `.cproject` cũng đặt `EVT2_DIAGNOSTICS=0`. Vì vậy, lỗi extractor/DMA/health-test bên dưới chủ yếu là lỗi tiềm ẩn khi bật lại QRNG; không phải bằng chứng firmware hiện tại đang dùng entropy Toeplitz yếu. CA/media/PQC có fallback TRNG. Lỗi xử lý thất bại TRNG trong PQC vẫn liên quan cấu hình hiện tại.

Mức độ được đánh giá theo tác động và điều kiện kích hoạt; không khẳng định đã có khai thác thực tế. Host probe dùng source C hiện có, mock phần cứng, GCC MinGW 15.2/O2. Không có đo ADC, timing, power hay chạy probe trên STM32.

## Các phát hiện

### F01 — Cao: ML-KEM vẫn thành công khi không có randomness

- `Middleware/PQC/pqc_randombytes.c:52`: khi QRNG không sẵn sàng và TRNG lỗi, trả `-1`, không ghi output của caller.
- `Middleware/PQC/pqclean/ml-kem-768-clean/kem.c:52,114`: bỏ return của `randombytes()`, dùng `coins` trên stack chưa được khởi tạo, sau đó trả `0`.
- `Middleware/PQC/pqc_kem.c:29,50`: wrapper tin return `0` này là thành công; không có lớp chặn lỗi randomness khác tại đây.
- Probe liên kết **toàn bộ ML-KEM clean thực tế + pqc_randombytes.c thực tế**, chỉ mock QRNG unavailable/TRNG failed. Kết quả: `randombytes=-1`, buffer caller giữ mẫu A5, nhưng keypair và encapsulation đều trả `0`.
- Hậu quả: có thể tạo khóa/shared secret từ dữ liệu cũ hoặc chưa xác định thay vì randomness hợp lệ. Mức độ dự đoán được phụ thuộc nội dung stack; probe không chứng minh trích xuất private key thực tế.
- **Sửa:** lấy randomness có kiểm tra trước khi gọi các entry point `*_derand`, hoặc truyền lỗi xuyên thư viện; khi lỗi không xuất khóa/ciphertext/shared secret như một kết quả hợp lệ. Rà tương tự `ml-dsa-{44,65,87}-clean/sign.c:124` (bỏ lỗi random cho signing). ML-DSA keygen từ seed được pin bởi wrapper nên không quy kết mọi keygen ML-DSA chịu cùng lỗi; bỏ lỗi randomness ở signing cũng chưa tự nó chứng minh giả mạo chữ ký.

### F02 — Cao: Toeplitz sai cấu trúc, entropy không được trộn như yêu cầu

- `Drivers/QRNG/toeplitz.c:94`: bỏ toàn bộ input từ bit 1024 trở đi trong mỗi block 2048 bit.
- `toeplitz.c:107-135`: chỉ dùng `lookup[0..3]`. Tra ngược `toeplitz_build_lookup()` cho thấy chỉ `seed[0..3]` ảnh hưởng output; 92 word seed còn lại không được sử dụng trong kết quả.
- Probe xác nhận hai nguồn **đều trong dải ADC 12 bit, đều qua RCT/APT**, khác nhau ở nửa bị bỏ của từng block, cho cùng toàn bộ output 1024 byte khi output được xóa trước. Đây là tập con đầu vào có entropy hoàn toàn bị mất, không phải chỉ là một collision thông thường của phép nén.
- 12 byte đầu output chỉ phụ thuộc 12 byte đầu input và seed: sáu mẫu ADC. `Core/Src/main.c:275-276` cấu hình ADC 12 bit/right-aligned, khác với hằng `QRNG_ADC_RESOLUTION=16`. Do đó với seed cố định và output ban đầu zero, nonce đầu này nhận **không quá 72 bit dữ liệu nguồn biến thiên**, ngay cả giả sử sáu mẫu độc lập và đồng đều. Đây là giới hạn trên, không phải ước lượng min-entropy đo được. Media có đường lấy đúng 12 byte đầu; PQC cũng lấy prefix của draw.
- `toeplitz.c:36`: dịch một uint32 sang phải 32 bit khi `bit=0` là UB. Đã chạy instrumentation GCC `-fsanitize=shift`, với callback báo lỗi tối thiểu thay cho libubsan thiếu: báo `rhs=32`, exit 77. Đây không phải một lượt chạy đầy đủ UBSan/ASan.
- Self-test `App/app_self_test.c:69` so với bản upstream cùng implementation, không phải chứng minh toán học độc lập. Diagnostic self-test còn thay lookup đang dùng bằng seed cố định và không restore (`qrng_service_adc_noise.c:694`); hiện diagnostics bị tắt, và boot thông thường chạy KAT trước init.
- **Sửa:** thay bằng phép nhân GF(2) đúng, chốt rõ convention bit/row/column, kiểm tra với reference độc lập và basis vectors; đánh giá entropy nguồn trước khi chốt tỷ lệ nén. Chỉ vá memset hoặc dịch bit chưa giải quyết F02.

### F03 — Cao, leakage có điều kiện: output giữ dữ liệu cũ

- `toeplitz.c:107` và các dòng tiếp theo dùng XOR vào output mà không khởi tạo; `extractor.c:58` và `qrng_service_adc_noise.c:553` cũng không khởi tạo output.
- Probe đầu vào zero giữ nguyên buffer A5. Với cùng input/seed, kết quả phụ thuộc buffer trước đó. Khi seed word đầu chẵn, bit thấp nhất output đầu tiên giữ nguyên bit cũ, không phụ thuộc ADC.
- `App/protocol_adapters/ca_protocol.c:608` đưa buffer stack chưa khởi tạo vào service; USB sử dụng TX staging tái dùng. Đây là các đường thực tế để dữ liệu cũ tham gia kết quả công khai. Media xóa scratch sau draw, PQC xóa sau mỗi lời gọi randombytes: vì vậy không quy kết mọi consumer đều rò stack.
- All-zero ADC thông thường bị health test chặn; không dùng riêng probe zero-input để kết luận có thể đọc toàn bộ RAM qua USB. Chưa chứng minh rò private key hay đọc bộ nhớ ngoài biên từ xa.
- **Sửa:** bảo đảm extractor ghi đầy đủ output, độc lập nội dung trước đó; không bắt caller tự nhớ memset.

### F04 — Cao: bỏ lỗi RNG và có thể treo vô hạn khi reseed

- `extractor.c:29-30`: bỏ lỗi RNG sinh HMAC/AES key. Probe cho RNG bytes fail nhưng RNG word hoạt động: init hoàn tất, cả hai primitive nhận khóa zero.
- `extractor.c:127-132`: bỏ lỗi generate seed rồi đánh giá balance trên buffer cũ/ghi dở; RNG fail ở cold start làm vòng lặp không kết thúc; RNG fail sau một seed cân bằng có thể được báo reseed thành công mà seed không đổi.
- Đã tái hiện cả khóa zero, reseed success giả, và cold-init vượt timeout host 2 giây. Kết luận vô hạn dựa thêm vào điều kiện vòng lặp: seed zero không đổi và không đạt balance.
- **Sửa:** init trả status; seed/key sinh vào buffer tạm và chỉ commit khi đầy đủ; giới hạn retry; lỗi phải đến được consumer. Khóa conditioner zero không tự động đồng nghĩa phá được HMAC/AES, nhưng vi phạm hợp đồng seed và che lỗi phần cứng.

### F05 — Cao: chọn nhầm buffer DMA và không bảo đảm mẫu ổn định

- `qrng_service_adc_noise.c:152` xem mọi `pos < s_last_dma_pos` là nửa thứ hai đã sẵn sàng. Nếu bỏ lỡ vòng DMA: last=1900, pos=1800, DMA hiện đang ghi nửa thứ hai nhưng code vẫn giao chính nửa đó cho CPU. Probe chạy hàm thực tế xác nhận `claimed_half=1`, `dma_current_half=1`.
- Ngay cả chọn đúng ban đầu, `:540` kiểm tra health rồi `:553` đọc lại raw DMA để extract, không có ownership, snapshot hay kiểm tra generation/overrun. DMA có thể quay lại giữa hai bước.
- Đã xác nhận lỗi logic với vị trí DMA giả lập; chưa đo tần suất hoặc timing trên bo. Không dùng số ADC throughput của H753 trong comment để suy ra V8Y đang chạy cùng tốc độ.
- **Sửa:** quản lý completed-buffer/generation từ DMA, có phát hiện overrun và snapshot ổn định; chỉ xuất dữ liệu đã health-test trên cùng snapshot. Bản thân memcpy không bảo đảm an toàn nếu DMA ghi trong lúc copy.

### F06 — Cao khi QRNG bật: USB tắt được health test của consumer mật mã

- `App/protocol_adapters/qrng_protocol.c:130` cho SET_HEALTH_TEST ngoài guard diagnostics; đường `CommandProtocol/command_protocol.c:597-610` không xác thực/ủy quyền cho lệnh QRNG.
- Cờ global `qrng_service_adc_noise.c:605` ảnh hưởng cả `get_entropy_with()`: chọn riêng thuật toán không cô lập chính sách health test cho PQC/media/CA.
- Init/deinit không gán lại `s_health_test_enabled=true`, khác hợp đồng “enabled by default after init”. Thay đổi cấu hình có thể tồn tại qua deinit/init trong cùng phiên boot.
- Điều kiện đối tượng gửi được lệnh USB; không chứng minh đây là đường tấn công từ Internet. Cấu hình safety lock hiện tại vẫn ngăn QRNG chạy.
- **Sửa:** API entropy cho mật mã luôn kiểm tra health; các điều khiển thử nghiệm cần tách khỏi trạng thái sản xuất và khỏi consumer nội bộ.

### F07 — Trung bình: RCT mất tính liên tục qua ranh giới buffer

- `entropy.c:46-55` reset global RCT/APT; `qrng_service_adc_noise.c:171` gọi mỗi lần lấy buffer.
- Probe hai lần `60000` cuối buffer trước, một lần đầu buffer sau: cả hai OK dù cutoff=3. Các mẫu đó hợp lệ theo kiểu sample_t 16 bit của driver; cùng lỗi xảy ra với giá trị 12 bit tương ứng.
- APT window=512 hiện chia hết buffer 1024, nên không khẳng định riêng reset APT tạo lỗi vượt boundary tương tự RCT trong cấu hình này. RCT có bằng chứng trực tiếp.
- **Sửa:** tách trạng thái test liên tục khỏi tiến độ xử lý buffer, giữ RCT qua các buffer liên tiếp. Cần định nghĩa rõ xử lý khoảng mẫu bị bỏ do consumer đọc không liên tục.

### F08 — Trung bình, cấu hình hiện tại: healthy=true khi chưa ready/init thất bại

- `qrng_service_adc_noise.c:609` chỉ kiểm tra health_status mặc định zero, không kiểm tra ready/đã có kết quả test.
- Probe source service với board.h thực tế: trước init `ready=0 healthy=1`; sau safety-locked init `result=QRNG_ERROR ready=0 healthy=1`. USB IS_HEALTHY công bố giá trị này.
- Đây là lỗi trạng thái/giám sát; không đồng nghĩa get_entropy vượt qua kiểm tra ready (nó có kiểm tra đúng).
- **Sửa:** biểu diễn riêng unavailable/not-tested/healthy/failed; không trả healthy khi chưa có nguồn hoạt động và test hợp lệ.

### F09 — Trung bình khi bật QRNG: init thất bại không dọn phần cứng

- `qrng_service_adc_noise.c:348-360`: timer/startup-health failure trả ngay sau khi có thể đã bật analog/ADC/DMA.
- `:372`: deinit trả ngay nếu s_ready=false; s_ready chỉ được bật sau toàn bộ init thành công. Vì vậy caller gọi deinit sau failed-init vẫn không dọn phần cứng đã bật.
- **Sửa:** theo dõi phần cứng đã khởi động và có một đường unwind cho mọi lỗi; deinit phải dọn được trạng thái khởi tạo dở. Chưa kiểm chứng trên bo.

### F10 — Trung bình: HMAC chờ phần cứng không có timeout hữu hạn

- `Platform/STM32H7RSxx/platform_hash.c:83` truyền HAL_MAX_DELAY cho HAL_HASH_HMAC_Start.
- HAL thực tế `Drivers/STM32H7RSxx_HAL_Driver/Src/stm32h7rsxx_hal_hash.c:3115` bỏ logic timeout khi nhận HAL_MAX_DELAY.
- Nếu HASH không hoàn tất, main loop không trở về để trả QRNG_ERROR/fallback; đây là điều kiện lỗi phần cứng, chưa chứng minh host bình thường kích hoạt được.
- **Sửa:** timeout hữu hạn phù hợp thời gian HASH dự kiến, trả lỗi và khôi phục peripheral có kiểm soát.

## Những điểm chưa được nâng thành lỗ hổng đã khai thác

- Driver không cấp phát động: chưa thấy heap memory leak. Không thấy khóa bí mật hard-code hay lệnh log khóa trong driver. GET_NOISE/STARTUP_HEALTH_RECORD là API xuất mẫu có chủ đích; chưa chứng minh các mẫu đó trùng dữ liệu sinh khóa đang dùng.
- Toeplitz lookup có chỉ số phụ thuộc raw samples, và nhánh bỏ byte zero phụ thuộc dữ liệu. Có bề mặt timing/power, nhưng chưa đo side-channel, không gán mức rò khóa đã chứng minh. Toeplitz seed không nhất thiết phải bí mật; vấn đề chính là tính đúng và entropy.
- Key conditioner/static buffers và temp/stack không được xóa an toàn khi kết thúc/deinit. Đây là rủi ro remanence nếu có memory disclosure/debug access; chưa tìm được primitive đọc chúng trực tiếp qua QRNG API.
- Public low-level API không kiểm tra đầy đủ NULL/size: `temp[1000]` bị tràn nếu in_len>1000, out_len bị bỏ qua, generate/check seed có thể overflow/underflow với m/n bất thường. Các caller đã lần theo dùng kích thước cố định an toàn; không kết luận USB điều khiển trực tiếp được các kích thước này. Nên thu hẹp API hoặc kiểm tra giới hạn.
- uint8_t/uint16_t buffer được cast sang uint32_t: có rủi ro alignment/aliasing theo C. Streaming dùng `frame+2`; GET_ENTROPY thường dùng staging offset 10+2, nên không được đánh đồng cả hai. Assembly Cortex-M7 O2 đã xem chưa chứng minh chắc chắn lỗi HardFault trên output này; không nâng thành lỗi crash đã tái hiện.
- RCT/APT không chứng minh min-entropy, độc lập mẫu hoặc nguồn quantum. `QRNG_MIN_ENTROPY_THRESHOLD` không được dùng để ước lượng nguồn; ADC 12 bit và continuous-conversion cũng cần đánh giá lại tương quan/cutoff khi bật phần cứng. Không có dữ liệu đo nguồn trong phạm vi review này.

## Tái hiện và giới hạn

Chạy `run.ps1` bằng PowerShell với GCC MinGW và Python trong PATH; có thể truyền đường compiler qua `-Gcc`. Nếu ExecutionPolicy chặn script, dùng tùy chọn chỉ áp dụng cho tiến trình chạy review, không đổi policy hệ thống. Binary/object được đặt trong `%TEMP%/qrng-review-repro-20260927`, không trong firmware.

Probe là ca tái hiện lỗi, không phải test suite chứng nhận: giá trị `1` thường có nghĩa lỗi đã tái hiện. `pqc_failure` sử dụng crypto thực tế, nhưng các primitive HMAC/AES trong `driver_deep` là stub chỉ để quan sát khóa và trạng thái, không kiểm chứng toán học HMAC/AES. `service_probe` giữ safety lock nguyên trạng và đặt vị trí DMA giả lập; không điều khiển thiết bị.

Ưu tiên: sửa F01 cho luồng TRNG hiện tại; trước khi bật lại QRNG phải xử lý F02–F07, đồng thời hoàn thiện trạng thái và cleanup F08–F10. Sau đó cần reference/KAT độc lập, fault injection, đo overrun trên bo và đánh giá entropy nguồn; build thành công hoặc vượt test thống kê output không thay thế các bước này.
