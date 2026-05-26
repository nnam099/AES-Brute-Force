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
python -c "from src.aes_engine import PureAES; print('✅ AES engine OK')"
python -c "import matplotlib; print('✅ matplotlib OK')"
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

# Với Fast Mode (PyCryptodome):
python main.py --cli --text SECRET --bits 20 --fast

# Multiprocessing:
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
3. (Tùy chọn) Bật **🚀 Fast Mode** — dùng PyCryptodome thay PureAES, nhanh hơn ~5-10×
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
| **128-bit** | **3.4 × 10³⁸** | **KHÔNG THỂ**                   |

> ⚠️ **ECB Mode Warning**: ECB không dùng IV, plaintext giống nhau → ciphertext giống nhau. Dùng CBC/GCM trong thực tế!

---

## 🧪 Test Cases

| ID   | Key Bits | Plaintext   | Mô tả                              |
|------|----------|-------------|-------------------------------------|
| TC01 | 8        | "A"         | Encrypt/Decrypt cơ bản              |
| TC02 | 16       | "HELLO"     | Encrypt/Decrypt 16-bit              |
| TC03 | 24       | "HELLO WORLD" | Encrypt/Decrypt 24-bit            |
| TC04 | 32       | "TEST1234"  | Encrypt/Decrypt 32-bit              |
| TC05 | 16       | "HELLO"     | Key deterministic                   |
| TC06 | —        | —           | Hex conversion                      |
| TC07 | 16       | "SECRET"    | Wrong key → wrong result            |
| **NIST-B** | Full 128-bit | hex | NIST FIPS-197 Appendix B encrypt |
| **NIST-B2** | Full 128-bit | hex | NIST FIPS-197 Appendix B decrypt |
| **NIST-C1** | Full 128-bit | hex | NIST FIPS-197 Appendix C.1       |
| **NIST-0** | Full 128-bit | zeros | All-zero KAT                    |
| TC08 | 8        | "ABCDE"     | Brute-force 8-bit (phải thành công) |
| TC09 | 12       | "HELLO"     | Brute-force 12-bit < 30s            |
| TC10 | —        | —           | is_valid_plaintext()                |
| TC11 | 16       | —           | estimate_time() hợp lệ              |
| TC12 | 8-20     | —           | Keyspace = 2^n                      |
| TC13 | 8        | "SECRET"    | Full pipeline: encrypt→brute→verify |

---

## 🔧 Công nghệ sử dụng

| Công nghệ       | Mục đích                        |
|----------------|---------------------------------|
| Python 3.8+    | Ngôn ngữ lập trình chính        |
| **Pure AES**   | **AES from scratch (không thư viện)** |
| tkinter        | Giao diện đồ họa (có sẵn)       |
| matplotlib     | Vẽ biểu đồ benchmark            |
| threading      | Chạy brute-force không đơ GUI   |
| unittest/pytest| Unit testing                    |

---

## 👥 Phân công

| Member | Phần lập trình          | Phần báo cáo        |
|--------|-------------------------|---------------------|
| M1     | gui.py (Tkinter UI)     | Chương 1, 2         |
| M2     | aes_engine.py, brute_force.py | Chương 3 (P1) |
| M3     | benchmark.py, biểu đồ  | Chương 3 (P2), 4    |
| M4     | main.py, tích hợp       | Chương 5, Kết luận  |

---

## 📚 Tài liệu tham khảo

1. NIST FIPS-197: https://csrc.nist.gov/publications/detail/fips/197/final
2. matplotlib: https://matplotlib.org/
3. Stallings, W. *Cryptography and Network Security* (8th ed.)
4. Paar, C. *Understanding Cryptography*

---

## ⚠️ Lưu ý

> Dự án này chỉ phục vụ mục đích **học thuật và giáo dục**.  
> Không áp dụng kỹ thuật này để tấn công hệ thống thực tế.

---

