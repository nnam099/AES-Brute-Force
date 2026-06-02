# 🔐 AES Brute-Force Demo

> **Đồ án môn Mật Mã Học** — Minh họa phương pháp tấn công Brute-Force lên AES-128 với khóa entropy thấp  
> Triển khai AES **từ Scratch** bằng Python thuần — không dùng thư viện mã hóa

---

## 📋 Giới thiệu

Ứng dụng minh họa **tấn công Brute-Force (vét cạn)** lên thuật toán **AES-128** khi chỉ một phần nhỏ của khóa là bí mật. Cụ thể, project dùng AES-128 với khóa có entropy 8 / 12 / 16 / 20 / 24 / 32 bit — các byte còn lại được cố định bằng `0x00`.

### Mục tiêu học thuật
- Hiểu khái niệm **không gian khóa** (`2^n`) và sự tăng trưởng theo hàm mũ
- Quan sát trực tiếp tốc độ brute-force qua giao diện đồ họa
- Rút ra kết luận: **khóa ngắn = KHÔNG AN TOÀN**

---

## 🗂️ Cấu trúc dự án

```
AES-Brute-Force/
├── src/
│   ├── aes_engine.py      # AES-128 từ Scratch: S-box, GF(2^8), KeyExpansion, ECB, PKCS#7
│   ├── brute_force.py     # Vét cạn tuần tự + multiprocessing + fast mode
│   ├── benchmark.py       # Đo lường hiệu năng & vẽ biểu đồ matplotlib
│   ├── gui.py             # Giao diện Tkinter 3 tab
│   ├── main.py            # Entry point (GUI / CLI)
│   └── __init__.py
├── tests/
│   └── test_aes.py        # 19 test cases: unit tests + NIST FIPS-197 vectors
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
git clone https://github.com/nnam099/aes-bruteforce.git
cd aes-bruteforce
```

`requirements.txt` bao gồm:
```
matplotlib>=3.7.0
pytest>=7.0.0
pycryptodome>=3.19.0
```

### Kiểm tra nhanh
```bash
python -c "from src.aes_engine import PureAES; print('OK AES engine')"
python -c "import matplotlib; print('OK matplotlib')"
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

# Với Fast Mode (PyCryptodome, nhanh hơn ~5-10x):
python main.py --cli --text SECRET --bits 20 --fast

# Multiprocessing (nhiều core):
python main.py --cli --text SECRET --bits 20 --workers 4
```

### Cách 4 — Benchmark riêng
```bash
cd src
python benchmark.py --bits 8 12 16 --text SECRET
```

### Chạy tests
```bash
python -m pytest tests/ -v
# 19 passed
```

---

## 🎯 Hướng dẫn sử dụng GUI

### Tab 1 — Mã hóa / Giải mã
1. Nhập **Plaintext** (ví dụ: `HELLO WORLD`)
2. Chọn **Độ dài khóa**: `8` / `12` / `16` / `20` / `24` / `32` bit
3. (Tùy chọn) Tích **Dùng key cố định** và nhập giá trị (decimal hoặc `0x...`)
4. Bấm **🔒 Mã hóa** → xem ciphertext và key thực
5. Bấm **🔓 Giải mã** → xác nhận decrypt đúng

### Tab 2 — Brute-Force Attack
1. Ciphertext từ Tab 1 được tự động copy sang
2. Chọn **Độ dài khóa** cần tấn công (phải khớp với khi mã hóa)
3. (Tùy chọn) Bật **🚀 Fast Mode** — dùng PyCryptodome thay PureAES, nhanh hơn ~5–10×
4. Bấm **⚡ Bắt đầu tấn công**
5. Quan sát: progress bar, keys/giây, thời gian thực
6. Kết quả: key tìm được, plaintext giải mã, so sánh lý thuyết

### Tab 3 — Lý thuyết
Bảng ước tính thời gian brute-force và giải thích nguyên lý hoạt động.

---

## 📊 Nguyên lý hoạt động

### Khóa ngắn trong demo

Thay vì dùng khóa 128-bit đầy đủ, demo dùng khóa có entropy nhỏ và pad bằng `0x00`:

```
Key 16-bit = 0xABCD:
  Key AES-128: AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               └── 2 bytes bí mật ──┘└────── 14 bytes zeros ──────┘
```

### Thuật toán Brute-Force

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

| Key entropy | Keyspace         | Thực nghiệm (~100K keys/s) | Trung bình lý thuyết |
|-------------|------------------|----------------------------|----------------------|
| 8-bit       | 256              | < 0.001 giây               | < 0.01 giây          |
| 12-bit      | 4,096            | ~0.05 giây                 | < 0.1 giây           |
| 16-bit      | 65,536           | ~0.4 giây                  | ~0.6 giây            |
| 20-bit      | 1,048,576        | ~6 giây                    | ~10 giây             |
| 24-bit      | 16,777,216       | ~90 giây                   | ~3 phút              |
| 32-bit      | 4,294,967,296    | —                          | ~12 giờ              |
| **128-bit** | **3.4 × 10³⁸**   | —                          | **KHÔNG THỂ**        |

> *Benchmark thực tế đo được: ~94K–103K keys/giây (PureAES, sequential, Python 3.13)*

> ⚠️ **ECB Mode**: ECB không dùng IV, cùng plaintext block → cùng ciphertext block. Dùng **CBC/GCM** trong thực tế!

---

## 🔧 Công nghệ sử dụng

| Công nghệ        | Mục đích                                        |
|------------------|-------------------------------------------------|
| Python 3.8+      | Ngôn ngữ chính                                  |
| **Pure AES**     | AES-128 từ Scratch (S-box, GF(2^8), 10 rounds) |
| tkinter          | Giao diện đồ họa (built-in)                     |
| matplotlib       | Vẽ biểu đồ benchmark                            |
| threading        | Chạy brute-force không đơ GUI                   |
| multiprocessing  | Tăng tốc brute-force (tùy chọn)                 |
| pycryptodome     | AES chuẩn cho Fast Mode (tùy chọn)              |
| unittest / pytest| Unit testing                                    |

---

## 🧪 Test Cases (19 tests — tất cả pass)

| ID            | Loại        | Mô tả                                          |
|---------------|-------------|------------------------------------------------|
| TC01          | AES Engine  | Encrypt/Decrypt 8-bit key, plaintext `"A"`     |
| TC02          | AES Engine  | Encrypt/Decrypt 16-bit key, plaintext `"HELLO"`|
| TC03          | AES Engine  | Encrypt/Decrypt 24-bit key                     |
| TC04          | AES Engine  | Encrypt/Decrypt 32-bit key                     |
| TC05          | AES Engine  | Key deterministic (cùng key_int → cùng kết quả)|
| TC06          | AES Engine  | Bytes ↔ Hex conversion                        |
| TC07          | AES Engine  | Key sai → decrypt không ra plaintext gốc       |
| NIST-B        | NIST Vector | FIPS-197 Appendix B: encrypt ✅               |
| NIST-B2       | NIST Vector | FIPS-197 Appendix B: decrypt ✅               |
| NIST-C1-RT    | NIST Vector | FIPS-197 Appendix C.1: round-trip ✅          |
| NIST-C1-KAT   | NIST Vector | FIPS-197 Appendix C.1: regression guard       |
| NIST-0        | NIST Vector | All-zero key + all-zero plaintext KAT ✅      |
| TC08          | Brute-Force | 8-bit key phải tìm thấy                        |
| TC09          | Brute-Force | 12-bit key tìm thấy trong < 30 giây            |
| TC10          | Brute-Force | `is_valid_plaintext()` hoạt động đúng          |
| TC11 / TC11b  | Brute-Force | `estimate_time()` cho 16-bit và 128-bit        |
| TC12          | Brute-Force | Keyspace = 2^n                                 |
| TC13          | Integration | Full pipeline: encrypt → brute-force → verify  |

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
