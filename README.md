# 🔐 Minh Họa Vét Cạn AES

> **Đồ án môn Mật Mã Học** — Minh họa phương pháp tấn công vét cạn lên AES-128 với khóa entropy thấp  
> Triển khai AES **từ Scratch** bằng Python thuần — không dùng thư viện mã hóa

---

## 📋 Giới thiệu

Ứng dụng minh họa **tấn công vét cạn** lên thuật toán **AES-128** khi chỉ một phần nhỏ của khóa là bí mật. Cụ thể, project dùng AES-128 với khóa có entropy 8 / 12 / 16 / 20 / 24 / 32 bit — các byte còn lại được cố định bằng `0x00`.

### Mục tiêu học thuật
- Hiểu khái niệm **không gian khóa** (`2^n`) và sự tăng trưởng theo hàm mũ
- Quan sát trực tiếp tốc độ vét cạn qua giao diện đồ họa
- Rút ra kết luận: **khóa ngắn = KHÔNG AN TOÀN**

---

## 🗂️ Cấu trúc dự án

```
AES-Brute-Force/
├── src/
│   ├── aes_engine.py      # AES-128 thuần Python: S-box, GF(2^8), KeyExpansion, ECB, PKCS#7
│   ├── brute_force.py     # Vét cạn tuần tự + multiprocessing + fast mode
│   ├── benchmark.py       # Đo lường hiệu năng & vẽ biểu đồ matplotlib
│   ├── gui.py             # Giao diện Tkinter 3 tab
│   ├── main.py            # Entry point (GUI / CLI)
│   └── __init__.py
├── tests/
│   └── test_aes.py        # 23 test cases: kiểm thử đơn vị + vector NIST FIPS-197
├── results/
│   ├── benchmark_chart.png
│   └── benchmark_data.json
├── docs/
│   └── Bao_cao_de_an_AES_Brute_Force.docx
├── requirements.txt
├── run.bat                # Chạy nhanh trên Windows
├── run.sh                 # Chạy nhanh trên Linux/macOS
└── README.md
```

---

## ⚙️ Cài đặt

### Yêu cầu
- Python 3.8+
- pip

### Cài thư viện
```bash
pip install -r requirements.txt
```

`requirements.txt` bao gồm:
```
matplotlib>=3.7.0
pytest>=7.0.0
pycryptodome>=3.19.0
```

### Kiểm tra nhanh
```bash
python -c "from src.aes_engine import PureAES; print('AES sẵn sàng')"
python -c "import matplotlib; print('matplotlib sẵn sàng')"
```

---

## 🚀 Chạy ứng dụng

### Cách 1 — Script nhanh (khuyến nghị)
```bash
# Windows
run.bat

# Linux / macOS
bash run.sh
```

### Cách 2 — Giao diện đồ họa (GUI)
```bash
cd src
python main.py
```

### Cách 3 — Dòng lệnh (CLI)
```bash
cd src
python main.py --cli --text SECRET --bits 16

# Với chế độ nhanh (PyCryptodome, nhanh hơn ~5-10x):
python main.py --cli --text SECRET --bits 20 --fast

# Multiprocessing (nhiều core):
python main.py --cli --text SECRET --bits 20 --workers 4
```

### Cách 4 — Đo hiệu năng riêng
```bash
cd src
python benchmark.py --bits 8 12 16 --text SECRET --key-int 0x2A

# Lưu vào thư mục riêng để không ghi đè kết quả cũ:
python benchmark.py --bits 8 12 16 --output-dir results/run_demo
```

### Chạy tests
```bash
python -m pytest tests/ -v
# 23 passed
```

---

## 🎯 Hướng dẫn sử dụng GUI

### Tab 1 — Mã hóa / Giải mã
1. Nhập **bản rõ** (ví dụ: `HELLO WORLD`)
2. Chọn **Độ dài khóa**: `8` / `12` / `16` / `20` / `24` / `32` bit
3. (Tùy chọn) Tích **Dùng khóa cố định** và nhập giá trị (thập phân hoặc `0x...`)
4. Bấm **🔒 Mã hóa** → xem bản mã và khóa thực
5. Bấm **🔓 Giải mã** → xác nhận kết quả đúng

### Tab 2 — Tấn công vét cạn
1. Bản mã từ Tab 1 được tự động copy sang
2. Chọn **Độ dài khóa** cần tấn công (phải khớp với khi mã hóa)
3. (Tùy chọn) Bật **🚀 Chế độ nhanh** — dùng PyCryptodome thay PureAES, nhanh hơn ~5–10×
4. Bấm **⚡ Bắt đầu tấn công**
5. Quan sát: thanh tiến trình, khóa/giây, thời gian thực
6. Kết quả: khóa tìm được, bản rõ giải mã, so sánh lý thuyết

### Tab 3 — Lý thuyết
Bảng ước tính thời gian vét cạn và giải thích nguyên lý hoạt động.

---

## 📊 Nguyên lý hoạt động

### Khóa ngắn trong demo

Thay vì dùng khóa 128-bit đầy đủ, demo dùng khóa có entropy nhỏ và pad bằng `0x00`:

```
Khóa 16-bit = 0xABCD:
  Khóa AES-128: AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               └── 2 bytes bí mật ──┘└────── 14 bytes zeros ──────┘
```

### Thuật toán vét cạn

```python
for i in range(2 ** key_bits):           # Thử tất cả khóa
    key = i.to_bytes(...).ljust(16, b'\x00')
    raw = AES.decrypt(ciphertext, key)
    unpadded = PKCS7_unpad(raw)          # Loại bỏ ~99.97% key sai
    if score_plaintext(unpadded) >= 0.9: # Kiểm tra ASCII printable
        return key                        # TÌM THẤY!
```

**Heuristic lọc**: PKCS#7 padding hợp lệ + tỉ lệ ASCII printable ≥ 90% → loại bỏ gần như toàn bộ kết quả giải mã sai mà không cần biết plaintext trước.

### Không gian khóa

| Entropy khóa | Không gian khóa | Thực nghiệm (~100K khóa/s) | Trung bình lý thuyết |
|-------------|------------------|----------------------------|----------------------|
| 8-bit       | 256              | < 0.001 giây               | < 0.01 giây          |
| 12-bit      | 4,096            | ~0.05 giây                 | < 0.1 giây           |
| 16-bit      | 65,536           | ~0.4 giây                  | ~0.6 giây            |
| 20-bit      | 1,048,576        | ~6 giây                    | ~10 giây             |
| 24-bit      | 16,777,216       | ~90 giây                   | ~3 phút              |
| 32-bit      | 4,294,967,296    | —                          | ~12 giờ              |
| **128-bit** | **3.4 × 10³⁸**   | —                          | **KHÔNG THỂ**        |

> *Đo hiệu năng thực tế: ~94K–103K khóa/giây (PureAES, chạy tuần tự, Python 3.13)*

> ⚠️ **Chế độ ECB**: ECB không dùng IV, cùng khối bản rõ → cùng khối bản mã. Dùng **CBC/GCM** trong thực tế!

---

## 🔧 Công nghệ sử dụng

| Công nghệ        | Mục đích                                        |
|------------------|-------------------------------------------------|
| Python 3.8+      | Ngôn ngữ chính                                  |
| **AES thuần Python** | AES-128 tự triển khai (S-box, GF(2^8), 10 vòng) |
| tkinter          | Giao diện đồ họa (built-in)                     |
| matplotlib       | Vẽ biểu đồ đo hiệu năng                         |
| threading        | Chạy vét cạn không làm đơ GUI                   |
| multiprocessing  | Tăng tốc vét cạn (tùy chọn)                     |
| pycryptodome     | AES chuẩn cho chế độ nhanh (tùy chọn)           |
| unittest / pytest| Kiểm thử đơn vị                                 |

---

## 🧪 Test Cases (23 tests — tất cả pass)

| ID            | Loại        | Mô tả                                          |
|---------------|-------------|------------------------------------------------|
| TC01          | AES Engine  | Mã hóa/giải mã khóa 8-bit, bản rõ `"A"`        |
| TC02          | AES Engine  | Mã hóa/giải mã khóa 16-bit, bản rõ `"HELLO"`   |
| TC03          | AES Engine  | Mã hóa/giải mã khóa 24-bit                     |
| TC04          | AES Engine  | Mã hóa/giải mã khóa 32-bit                     |
| TC05          | AES Engine  | Khóa xác định (cùng key_int → cùng kết quả)    |
| TC06          | AES Engine  | Chuyển đổi bytes ↔ hex                         |
| TC07          | AES Engine  | Khóa sai → giải mã không ra bản rõ gốc         |
| NIST-B        | NIST Vector | FIPS-197 Appendix B: mã hóa ✅                 |
| NIST-B2       | NIST Vector | FIPS-197 Appendix B: giải mã ✅                |
| NIST-C1-RT    | NIST Vector | FIPS-197 Appendix C.1: kiểm tra vòng đi-về ✅  |
| NIST-C1-KAT   | NIST Vector | FIPS-197 Appendix C.1: kiểm thử hồi quy        |
| NIST-0        | NIST Vector | Khóa 0 + bản rõ 0 KAT ✅                       |
| TC08          | Vét cạn     | Khóa 8-bit phải tìm thấy                       |
| TC09          | Vét cạn     | Khóa 12-bit tìm thấy trong < 30 giây           |
| TC10          | Vét cạn     | `is_valid_plaintext()` hoạt động đúng          |
| TC11 / TC11b  | Vét cạn     | `estimate_time()` cho 16-bit và 128-bit        |
| TC12          | Vét cạn     | Không gian khóa = 2^n                          |
| TC13          | Tích hợp    | Quy trình đầy đủ: mã hóa → vét cạn → xác minh  |
| TC14          | Đo hiệu năng| `--key-int` đọc được giá trị dạng hex          |
| TC15          | Đo hiệu năng| Đo hiệu năng với khóa cố định tìm đúng kết quả  |
| TC16          | Đo hiệu năng| Đường dẫn kết quả mặc định không ghi đè         |
| TC17          | Đo hiệu năng| Không tạo đường dẫn khi tắt lưu biểu đồ/JSON    |

---

## 👥 Phân công

| Thành viên | Phần lập trình                    | Phần báo cáo          |
|-----------|-----------------------------------|-----------------------|
| M1        | `gui.py` (Tkinter UI)             | Chương 1, 2           |
| M2        | `aes_engine.py`, `brute_force.py` | Chương 3 (Phần 1)     |
| M3        | `benchmark.py`, biểu đồ          | Chương 3 (Phần 2), 4  |
| M4        | `main.py`, tích hợp, tests        | Chương 5, Kết luận    |

---

## 📚 Tài liệu tham khảo

1. NIST FIPS-197 — Advanced Encryption Standard: <https://csrc.nist.gov/publications/detail/fips/197/final>
2. Stallings, W. *Cryptography and Network Security* (8th ed.)
3. Paar, C. *Understanding Cryptography*
4. matplotlib Documentation: <https://matplotlib.org/>
5. PyCryptodome Documentation: <https://pycryptodome.readthedocs.io/>

---

## ⚠️ Lưu ý

> Dự án này chỉ phục vụ mục đích **học thuật và giáo dục**.  
> Không áp dụng kỹ thuật này để tấn công hệ thống thực tế.
