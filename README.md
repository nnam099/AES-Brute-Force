# 🔐 AES Brute-Force Demo

[![CI](https://github.com/nnam099/AES-Brute-Force/actions/workflows/ci.yml/badge.svg)](https://github.com/nnam099/AES-Brute-Force/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Đồ án môn Mật Mã Học** — Minh họa tấn công vét cạn lên AES-128 với khóa entropy thấp.  
> AES-128 được triển khai **từ scratch** bằng Python thuần — không dùng thư viện mã hóa.

---

## 📋 Giới thiệu

Ứng dụng minh họa **tấn công vét cạn (brute-force)** lên **AES-128** khi chỉ một phần nhỏ của khóa là bí mật (8–32 bit entropy). Phần còn lại của khóa 128-bit được cố định bằng `0x00`.

### Mục tiêu học thuật
- Hiểu **không gian khóa** (`2^n`) và sự tăng trưởng theo hàm mũ
- Quan sát trực tiếp tốc độ vét cạn qua giao diện đồ họa
- Kết luận: **khóa ngắn = KHÔNG AN TOÀN**

---

## 🗂️ Cấu trúc dự án

```
AES-Brute-Force/
├── src/aes_brute_force/           # Python package chính
│   ├── core/
│   │   ├── aes_engine.py          # AES-128 thuần Python (S-box, GF(2⁸), ECB, PKCS#7)
│   │   ├── brute_force.py         # Vét cạn: sequential + multiprocessing + fast mode
│   │   └── constants.py           # S-box, Inv-S-box, Rcon, cấu hình dùng chung
│   ├── gui/
│   │   ├── app.py                 # Main window (CustomTkinter)
│   │   ├── theme.py               # Bảng màu Catppuccin Mocha
│   │   ├── tabs/
│   │   │   ├── encrypt_tab.py     # Tab mã hóa / giải mã
│   │   │   ├── attack_tab.py      # Tab vét cạn khóa (live progress)
│   │   │   └── theory_tab.py      # Tab lý thuyết AES
│   │   └── widgets/
│   │       └── stat_card.py       # Widget thẻ thống kê tái sử dụng
│   ├── cli/app.py                 # CLI entry point (argparse)
│   ├── benchmark/runner.py        # Đo hiệu năng & sinh biểu đồ matplotlib
│   ├── utils/logging.py           # Structured logging helper
│   └── __main__.py                # python -m aes_brute_force
├── tests/
│   └── test_aes_v2.py             # 23 test cases (NIST FIPS-197 KAT + unit + tích hợp)
├── results/                       # Benchmark outputs (chart + JSON)
├── docs/                          # Báo cáo đồ án
├── .github/workflows/ci.yml       # GitHub Actions CI
├── pyproject.toml                 # Packaging (setuptools, v2.0.0)
└── README.md
```

---

## ⚙️ Cài đặt

### Yêu cầu
- Python **3.10+**
- pip

### Cài đặt package

```bash
# Cài đặt cơ bản (GUI + matplotlib)
pip install -e .

# Cài đặt với dev tools (pytest, pycryptodome, ruff)
pip install -e ".[dev]"

# Chỉ cài fast mode backend (PyCryptodome)
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

Giao diện gồm 3 tab: **Mã hóa**, **Tấn công vét cạn**, **Lý thuyết**.  
Cửa sổ mở ở kích thước **960 × 720**, canh giữa màn hình.

### CLI

```bash
# Cơ bản
python -m aes_brute_force --cli --text SECRET --bits 16

# Fast mode (PyCryptodome, ~5–10x nhanh hơn):
python -m aes_brute_force --cli --text SECRET --bits 20 --fast

# Multiprocessing:
python -m aes_brute_force --cli --text SECRET --bits 20 --workers 4

# Debug logging:
python -m aes_brute_force --cli --bits 16 --verbose
```

**Tham số CLI:**

| Flag | Mô tả | Mặc định |
|---|---|---|
| `--cli` | Chạy chế độ CLI | — |
| `--gui` | Ép chạy GUI | — |
| `--text TEXT` | Bản rõ cần mã hóa | `SECRET` |
| `--bits {8,12,16,20,24,32}` | Số bit entropy của khóa | `16` |
| `--workers N` | Số tiến trình song song | `1` |
| `--fast` | Dùng PyCryptodome backend | `False` |
| `-v / --verbose` | Bật debug logging | `False` |

### Benchmark

```bash
python -m aes_brute_force.benchmark.runner --bits 8 12 16 --text SECRET
```

**Tham số Benchmark:**

| Flag | Mô tả | Mặc định |
|---|---|---|
| `--bits` | Danh sách số bit cần đo | `8 12 16` |
| `--text TEXT` | Bản rõ test | `SECRET` |
| `--workers N` | Số tiến trình | `1` |
| `--key-int 0xNN` | Khóa cố định (hex/dec) | ngẫu nhiên |
| `--output-dir DIR` | Thư mục lưu kết quả | tự tạo `results/benchmark_YYYYMMDD_HHMMSS/` |
| `--output FILE` | Đường dẫn ảnh biểu đồ | `benchmark_chart.png` |
| `--json FILE` | Đường dẫn file JSON | `benchmark_data.json` |
| `--no-plot` | Bỏ qua biểu đồ | `False` |
| `--no-json` | Bỏ qua file JSON | `False` |

---

## 📊 Nguyên lý hoạt động

### Cấu trúc khóa entropy thấp

Khóa AES-128 luôn đủ 16 byte; chỉ `n` bit đầu mang entropy thực sự, phần còn lại là `0x00`:

```
Khóa 16-bit = 0xABCD:
  Khóa AES-128: AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                └── 2 bytes bí mật ──┘└────── 14 bytes zeros ──────┘
```

### Heuristic nhận dạng bản rõ

Kết quả giải mã được chấp nhận khi:
1. **PKCS#7 padding hợp lệ** — byte padding đồng nhất, giá trị trong `[1, 16]`
2. **Điểm bản rõ ≥ 0.9** — tỉ lệ ký tự ASCII in được (32–126 và tab/LF/CR)

```python
for i in range(2 ** key_bits):
    key = i.to_bytes(key_bytes_len, "big").ljust(16, b"\x00")
    raw = AES.decrypt(ciphertext, key)
    if PKCS7_valid(raw) and score_ascii(raw) >= 0.9:
        return key  # FOUND
```

### Các mode hoạt động

| Mode | Backend | Ghi chú |
|---|---|---|
| Sequential (mặc định) | `PureAES` (Python thuần) | ~1,400 keys/s trên Python 3.13 |
| Fast mode (`--fast`) | PyCryptodome ECB | ~5–10× nhanh hơn |
| Multiprocessing (`--workers N`) | `multiprocessing.Pool` + `imap_unordered` | Chia keyspace thành chunk 10,000 |

### Hiệu năng thực tế

> Số liệu đo trên Python 3.13, chạy tuần tự, phần cứng phổ thông.

| Entropy khóa | Không gian khóa | PureAES (~1,400 keys/s) | PyCryptodome (fast) |
|:---:|---:|---:|---:|
| 8-bit | 256 | < 0.2s | < 0.01s |
| 12-bit | 4,096 | ~3s | ~0.3s |
| 16-bit | 65,536 | ~47s | ~5s |
| 20-bit | 1,048,576 | ~12 phút | ~1 phút |
| 24-bit | 16,777,216 | ~3 giờ | ~20 phút |
| **128-bit** | **3.4 × 10³⁸** | **KHÔNG THỂ** | **KHÔNG THỂ** |

> ⚠️ **ECB mode**: Chỉ dùng cho mục đích demo. Trong thực tế dùng **CBC/GCM** với IV/nonce.

---

## 🧪 Test Cases (23 tests)

| ID | Class | Mô tả |
|---|---|---|
| `test_tc01_8bit` | `TestAESEngine` | Round-trip mã hóa/giải mã 8-bit key |
| `test_tc02_16bit` | `TestAESEngine` | Round-trip 16-bit key |
| `test_tc03_24bit` | `TestAESEngine` | Round-trip 24-bit key |
| `test_tc04_32bit` | `TestAESEngine` | Round-trip 32-bit key |
| `test_tc05_deterministic` | `TestAESEngine` | Khóa xác định → kết quả xác định |
| `test_tc06_hex_roundtrip` | `TestAESEngine` | `bytes_to_hex` ↔ `hex_to_bytes` |
| `test_tc07_wrong_key` | `TestAESEngine` | Khóa sai → giải mã sai |
| `test_appendix_b_encrypt` | `TestNISTVectors` | FIPS-197 Appendix B: mã hóa ✅ |
| `test_appendix_b_decrypt` | `TestNISTVectors` | FIPS-197 Appendix B: giải mã ✅ |
| `test_appendix_c1_roundtrip` | `TestNISTVectors` | FIPS-197 Appendix C.1: round-trip ✅ |
| `test_appendix_c1_kat` | `TestNISTVectors` | FIPS-197 Appendix C.1: KAT ✅ |
| `test_zero_key_zero_plaintext` | `TestNISTVectors` | Khóa 0x00…0 + bản rõ 0x00…0 ✅ |
| `test_tc08_8bit` | `TestBruteForce` | Tìm khóa 8-bit |
| `test_tc09_12bit` | `TestBruteForce` | Tìm khóa 12-bit (< 30s) |
| `test_tc10_is_valid_plaintext` | `TestBruteForce` | Heuristic ASCII |
| `test_tc11_estimate_time` | `TestBruteForce` | Ước tính thời gian 16-bit |
| `test_tc11b_estimate_128bit` | `TestBruteForce` | Ước tính thời gian 128-bit |
| `test_tc12_keyspace` | `TestBruteForce` | Kiểm tra `2^n` keyspace |
| `test_tc13_full_pipeline_8bit` | `TestIntegration` | Encrypt → brute-force → verify |
| `test_tc14_hex_key_int` | `TestBenchmark` | Parse `--key-int 0x2A` → 42 |
| `test_tc15_fixed_key` | `TestBenchmark` | Benchmark với khóa cố định |
| `test_tc16_output_paths` | `TestBenchmark` | Resolve đường dẫn output |
| `test_tc17_no_output` | `TestBenchmark` | `--no-plot --no-json` trả về None |

```bash
# Chạy toàn bộ:
pytest tests/test_aes_v2.py -v

# Chạy riêng một nhóm:
pytest tests/test_aes_v2.py -v -k "NIST"
pytest tests/test_aes_v2.py -v -k "BruteForce"
```

---

## 🔧 Công nghệ

| Thành phần | Công nghệ |
|---|---|
| AES-128 | Python thuần (S-box, GF(2⁸), 10 vòng, column-major state) |
| GUI | CustomTkinter (theme Catppuccin Mocha) |
| Biểu đồ | matplotlib (dual-panel: measured + estimated) |
| Fast mode | PyCryptodome ECB (optional) |
| Đa tiến trình | `multiprocessing.Pool.imap_unordered`, chunk = 10,000 |
| Testing | pytest + unittest |
| CI/CD | GitHub Actions |
| Packaging | pyproject.toml + setuptools (`src/` layout) |
| Linting | ruff (target Python 3.10) |

---

## 👥 Phân công

| Thành viên | Lập trình | Báo cáo |
|---|---|---|
| M1 | GUI (CustomTkinter, tabs, widgets) | Chương 1, 2 |
| M2 | AES engine, brute-force core | Chương 3 (Phần 1) |
| M3 | Benchmark, biểu đồ matplotlib | Chương 3 (Phần 2), 4 |
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
