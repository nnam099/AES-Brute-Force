# 🔐 AES Brute-Force Demo

> **Đồ án môn An toàn thông tin** — Minh họa phương pháp thám mã khóa bí mật nhỏ  
> Tập trung: AES với khóa ngắn & tấn công Brute-Force tuần tự

---

## 📋 Giới thiệu

Ứng dụng này minh họa **tấn công Brute-Force** (vét cạn) lên thuật toán mã hóa **AES** khi sử dụng khóa có độ dài ngắn (8 – 32 bits), thay vì khóa chuẩn 128-bit.

### Mục tiêu học thuật
- Hiểu khái niệm **không gian khóa** (`2^n`)  
- Quan sát trực tiếp tốc độ brute-force tăng theo hàm mũ  
- Rút ra kết luận: **khóa ngắn = KHÔNG AN TOÀN**

---

## 🗂️ Cấu trúc dự án

```
aes-bruteforce/
├── src/
│   ├── aes_engine.py      # AES mã hóa/giải mã (pycryptodome)
│   ├── brute_force.py     # Vòng lặp brute-force tuần tự
│   ├── benchmark.py       # Đo lường & vẽ biểu đồ
│   ├── gui.py             # Giao diện Tkinter
│   └── main.py            # Entry point
├── tests/
│   └── test_aes.py        # Unit tests (13 test cases)
├── results/               # Biểu đồ & dữ liệu benchmark
├── docs/                  # Báo cáo & slide
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Cài đặt

### Yêu cầu
- Python 3.8+
- pip

### Bước 1: Clone repo
```bash
git clone https://github.com/your-username/aes-bruteforce.git
cd aes-bruteforce
```

### Bước 2: Cài thư viện
```bash
pip install -r requirements.txt
```

### Bước 3: Kiểm tra
```bash
python -c "from Crypto.Cipher import AES; print('✅ pycryptodome OK')"
python -c "import matplotlib; print('✅ matplotlib OK')"
```

---

## 🚀 Chạy ứng dụng

### Giao diện đồ họa (GUI)
```bash
cd src
python main.py
```

### Chế độ dòng lệnh (CLI)
```bash
cd src
python main.py --cli --text SECRET --bits 16
```

### Benchmark riêng lẻ
```bash
cd src
python benchmark.py --bits 8 12 16 --text SECRET
```

### Chạy tests
```bash
python -m pytest tests/ -v
# hoặc
python tests/test_aes.py
```

---

## 🎯 Hướng dẫn sử dụng GUI

### Tab 1: Mã hóa / Giải mã
1. Nhập **Plaintext** (ví dụ: `SECRET`)
2. Chọn **Độ dài khóa** (ví dụ: `16-bit`)
3. Bấm **🔒 Mã hóa** → xem ciphertext và key thực
4. Bấm **🔓 Giải mã** → xác nhận decrypt hoạt động

### Tab 2: Brute-Force Attack
1. (Ciphertext được tự động copy từ Tab 1)
2. Chọn **Độ dài khóa** phù hợp
3. Bấm **⚡ Bắt đầu tấn công**
4. Quan sát: **progress bar**, **keys/giây**, **thời gian**
5. Kết quả: key tìm được và plaintext giải mã

### Tab 3: Lý thuyết
Xem bảng ước tính thời gian brute-force cho các độ dài khóa khác nhau.

---

## 📊 Nguyên lý hoạt động

### AES với khóa ngắn
```
Key 16-bit: 0xABCD
             ↓
Key AES:    AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            └─ 2 bytes ─┘└────────────── 14 bytes zeros ──────────────┘
```

### Brute-Force thuật toán
```python
for i in range(2 ** key_bits):           # Thử tất cả khóa
    key = i.to_bytes(...).ljust(16, b'\x00')
    decrypted = AES.decrypt(ciphertext, key)
    if is_printable(decrypted):           # Kiểm tra ASCII
        return key                        # TÌM THẤY!
```

### Không gian khóa
| Key bits | Keyspace       | Thời gian trung bình (~50K keys/s) |
|----------|----------------|------------------------------------|
| 8-bit    | 256            | < 0.01 giây                       |
| 12-bit   | 4,096          | < 0.1 giây                        |
| 16-bit   | 65,536         | ~0.6 giây                         |
| 20-bit   | 1,048,576      | ~10 giây                           |
| 24-bit   | 16,777,216     | ~3 phút                            |
| 32-bit   | 4,294,967,296  | ~12 giờ                            |
| **128-bit** | **3.4 × 10³⁸** | **KHÔNG THỂ**                   |

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
| pycryptodome   | Thư viện AES                    |
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
2. PyCryptodome: https://www.pycryptodome.org/
3. Stallings, W. *Cryptography and Network Security* (8th ed.)
4. Paar, C. *Understanding Cryptography*

---

## ⚠️ Lưu ý

> Dự án này chỉ phục vụ mục đích **học thuật và giáo dục**.  
> Không áp dụng kỹ thuật này để tấn công hệ thống thực tế.

---

