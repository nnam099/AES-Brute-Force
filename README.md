# 🔐 AES Brute-Force Demo

[![CI](https://github.com/nnam099/AES-Brute-Force/actions/workflows/ci.yml/badge.svg)](https://github.com/nnam099/AES-Brute-Force/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Đồ án môn Mật Mã Học** — Minh họa tấn công vét cạn lên AES-128 với khóa entropy thấp.
> AES-128 được triển khai **từ scratch** bằng Python thuần — không dùng thư viện mã hóa.

---

## 📋 Giới thiệu

Ứng dụng minh họa **tấn công vét cạn** lên **AES-128** khi chỉ một phần nhỏ của khóa là bí mật (8–32 bit entropy). Phần còn lại của khóa 128-bit được cố định bằng `0x00`.

### Mục tiêu học thuật
- Hiểu **không gian khóa** (`2^n`) và sự tăng trưởng theo hàm mũ
- Quan sát trực tiếp tốc độ vét cạn qua giao diện đồ họa
- Kết luận: **khóa ngắn = KHÔNG AN TOÀN**

---

## 🗂️ Cấu trúc dự án

```
AES-Brute-Force/
├── src/aes_brute_force/           # Python package
│   ├── core/
│   │   ├── aes_engine.py          # AES-128 thuần Python (S-box, GF(2⁸), ECB, PKCS#7)
│   │   ├── brute_force.py         # Vét cạn: sequential + multiprocessing + fast mode
│   │   └── constants.py           # S-box, Rcon, shared config
│   ├── gui/
│   │   ├── app.py                 # Main window orchestrator
│   │   ├── theme.py               # Catppuccin Mocha color palette
│   │   └── tabs/                  # Decomposed UI components
│   │       ├── encrypt_tab.py     # Tab mã hóa / giải mã
│   │       ├── attack_tab.py      # Tab vét cạn khóa
│   │       └── theory_tab.py      # Tab lý thuyết
│   ├── cli/app.py                 # CLI entry point
│   ├── benchmark/runner.py        # Đo hiệu năng & biểu đồ matplotlib
│   ├── utils/logging.py           # Structured logging
│   └── __main__.py                # python -m aes_brute_force
├── tests/
│   └── test_aes_v2.py             # 23 test cases (NIST FIPS-197 KAT + unit + integration)
├── results/                       # Benchmark outputs
├── docs/                          # Báo cáo
├── .github/workflows/ci.yml       # GitHub Actions CI
├── pyproject.toml                 # Modern Python packaging
└── README.md
```

---

## ⚙️ Cài đặt

### Yêu cầu
- Python 3.10+
- pip

### Cài đặt package

```bash
# Cài đặt cơ bản
pip install -e .

# Cài đặt với dev tools (pytest, ruff, pycryptodome)
pip install -e ".[dev]"

# Chỉ cài fast mode backend
pip install -e ".[fast]"
```

### Chạy tests

```bash
pytest tests/test_aes_v2.py -v
# 23 passed
```

---

## 🚀 Chạy ứng dụng

### GUI (mặc định)
```bash
python -m aes_brute_force
# hoặc sau khi pip install:
aes-brute-force
```

### CLI
```bash
python -m aes_brute_force --cli --text SECRET --bits 16

# Chế độ nhanh (PyCryptodome, ~5-10x):
python -m aes_brute_force --cli --text SECRET --bits 20 --fast

# Multiprocessing:
python -m aes_brute_force --cli --text SECRET --bits 20 --workers 4

# Debug logging:
python -m aes_brute_force --cli --bits 16 -v
```

### Benchmark
```bash
python -m aes_brute_force.benchmark.runner --bits 8 12 16 --text SECRET
```

---

## 📊 Nguyên lý hoạt động

### Khóa entropy thấp

```
Khóa 16-bit = 0xABCD:
  Khóa AES-128: AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                └── 2 bytes bí mật ──┘└────── 14 bytes zeros ──────┘
```

### Thuật toán vét cạn

```python
for i in range(2 ** key_bits):
    key = i.to_bytes(...).ljust(16, b'\x00')
    raw = AES.decrypt(ciphertext, key)
    if PKCS7_valid(raw) and score_ascii(raw) >= 0.9:
        return key  # FOUND
```

### Hiệu năng đo thực tế

> **Lưu ý**: Tốc độ phụ thuộc vào phần cứng. Số liệu dưới đây đo trên Python 3.13, chạy tuần tự.

| Entropy khóa | Không gian khóa | PureAES (~1.4K keys/s) | PyCryptodome (fast mode) |
|:---:|---:|---:|---:|
| 8-bit | 256 | < 0.2s | < 0.01s |
| 12-bit | 4,096 | ~2s | ~0.2s |
| 16-bit | 65,536 | ~18s | ~1.5s |
| 20-bit | 1,048,576 | ~12 phút | ~1 phút |
| 24-bit | 16,777,216 | ~3 giờ | ~20 phút |
| **128-bit** | **3.4 × 10³⁸** | **KHÔNG THỂ** | **KHÔNG THỂ** |

> ⚠️ **ECB mode**: Chỉ dùng cho demo. Trong thực tế dùng **CBC/GCM** với IV/nonce.

---

## 🧪 Test Cases (23 tests)

| ID | Loại | Mô tả |
|---|---|---|
| TC01–TC04 | AES Engine | Mã hóa/giải mã với khóa 8/16/24/32-bit |
| TC05 | AES Engine | Khóa xác định → kết quả xác định |
| TC06 | AES Engine | Chuyển đổi bytes ↔ hex |
| TC07 | AES Engine | Khóa sai → giải mã sai |
| NIST-B | FIPS-197 | Appendix B: mã hóa + giải mã ✅ |
| NIST-C1 | FIPS-197 | Appendix C.1: round-trip + KAT ✅ |
| NIST-0 | FIPS-197 | Khóa toàn 0 + bản rõ toàn 0 ✅ |
| TC08–TC09 | Vét cạn | Tìm khóa 8-bit và 12-bit |
| TC10–TC12 | Vét cạn | Heuristic + ước tính thời gian |
| TC13 | Tích hợp | Pipeline đầy đủ: encrypt → brute-force → verify |
| TC14–TC17 | Benchmark | CLI args + output paths |

---

## 🔧 Công nghệ

| Thành phần | Công nghệ |
|---|---|
| AES-128 | Python thuần (S-box, GF(2⁸), 10 vòng) |
| GUI | Tkinter (decomposed tabs + theme system) |
| Biểu đồ | matplotlib |
| Fast mode | PyCryptodome (optional) |
| Đa tiến trình | multiprocessing.Pool |
| Testing | pytest |
| CI/CD | GitHub Actions |
| Packaging | pyproject.toml + setuptools |
| Linting | ruff |

---

## 👥 Phân công

| Thành viên | Lập trình | Báo cáo |
|---|---|---|
| M1 | GUI (Tkinter) | Chương 1, 2 |
| M2 | AES engine, brute-force | Chương 3 (Phần 1) |
| M3 | Benchmark, biểu đồ | Chương 3 (Phần 2), 4 |
| M4 | CLI, tích hợp, tests | Chương 5, Kết luận |

---

## 📚 Tài liệu tham khảo

1. NIST FIPS-197 — [Advanced Encryption Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
2. Stallings, W. *Cryptography and Network Security* (8th ed.)
3. Paar, C. *Understanding Cryptography*

---

## ⚠️ Disclaimer

> Dự án này chỉ phục vụ mục đích **học thuật và giáo dục**.
> Không áp dụng kỹ thuật này để tấn công hệ thống thực tế.
