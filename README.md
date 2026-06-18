# AES Brute-Force Demo

Demo đồ án môn Mật Mã Học: minh họa tấn công vét cạn lên AES-128 khi khóa có entropy thấp. Lõi AES-128 mặc định được cài đặt bằng Python thuần, không dùng thư viện mã hóa.

> Dự án chỉ phục vụ mục đích học tập và trình bày. Không sử dụng kỹ thuật này để tấn công hệ thống thực tế.

## Mục tiêu

- Hiểu cách AES-128 xử lý block 16 byte, key schedule và 10 vòng biến đổi.
- Thấy ảnh hưởng của không gian khóa `2^n` đến thời gian brute-force.
- Minh họa vì sao khóa ngắn hoặc khóa có entropy thấp là không an toàn.
- So sánh brute-force thuần Python, multiprocessing và fast mode bằng PyCryptodome.
- Ghi nhận rủi ro false positive khi đoán plaintext bằng heuristic.

## Cấu trúc project

```text
AES-Brute-Force/
|-- src/aes_brute_force/
|   |-- __main__.py                  # python -m aes_brute_force
|   |-- cli/app.py                   # CLI và entry point mặc định
|   |-- core/
|   |   |-- aes_engine.py            # AES-128 thuần Python, ECB, PKCS#7
|   |   |-- brute_force.py           # brute-force sequential/multiprocessing/fast mode
|   |   `-- constants.py             # cấu hình chung, key bits, block size
|   |-- gui/
|   |   |-- app.py                   # cửa sổ CustomTkinter
|   |   |-- tabs/encrypt_tab.py      # mã hóa/giải mã demo
|   |   |-- tabs/attack_tab.py       # vét cạn khóa, log tiến trình
|   |   |-- tabs/theory_tab.py       # ghi chú lý thuyết trong GUI
|   |   |-- theme.py                 # theme màu và font
|   |   `-- widgets/stat_card.py     # widget thống kê
|   |-- benchmark/runner.py          # chạy benchmark, xuất PNG/JSON
|   `-- utils/logging.py             # logging helper
|-- tests/
|   |-- test_aes_v2.py               # test AES, brute-force, benchmark, edge cases
|   `-- test_false_positive_fix.py   # regression test cho lỗi false positive
|-- docs/
|   |-- aes_core_walkthrough.md
|   |-- aes_theory_notes.md
|   `-- Bao_cao_de_an_AES_Brute_Force.docx
|-- results/
|   |-- benchmark_chart.png
|   `-- benchmark_data.json
|-- pyproject.toml
`-- README.md
```

Ghi chú: project hiện dùng `pyproject.toml` để khai báo dependency và packaging. Repo không có `requirements.txt`, `run.bat`, hoặc `run.sh`.

## Cài đặt

Yêu cầu Python 3.10+.

```bash
pip install -e .
```

Cài thêm công cụ dev và fast backend:

```bash
pip install -e ".[dev]"
```

Chỉ cài fast backend:

```bash
pip install -e ".[fast]"
```

Dependency chính:

- `customtkinter`: GUI.
- `matplotlib`: benchmark chart.
- `pycryptodome`: optional fast mode và dev tests.
- `pytest`, `pytest-cov`, `ruff`: optional dev tools.

## Chạy ứng dụng

### GUI

```bash
python -m aes_brute_force
```

Hoặc sau khi cài package:

```bash
aes-brute-force
```

GUI gồm 3 màn hình:

- Mã hóa & Giải mã: nhập plaintext, chọn độ dài entropy, tạo ciphertext.
- Vét cạn: nhận ciphertext hex, chạy brute-force, hiển thị progress/log.
- Góc lý thuyết: tóm tắt AES và keyspace.

### CLI

```bash
python -m aes_brute_force --cli --text SECRET --bits 16
```

Fast mode bằng PyCryptodome:

```bash
python -m aes_brute_force --cli --text SECRET --bits 20 --fast
```

Multiprocessing:

```bash
python -m aes_brute_force --cli --text SECRET --bits 20 --workers 4
```

Debug logging:

```bash
python -m aes_brute_force --cli --bits 16 --verbose
```

Tham số CLI:

| Flag | Ý nghĩa | Mặc định |
|---|---|---|
| `--cli` | Chạy chế độ dòng lệnh | `False` |
| `--gui` | Ép chạy GUI | `False` |
| `--text TEXT` | Plaintext để mã hóa trong CLI | `SECRET` |
| `--bits {8,12,16,20,24,32}` | Số bit entropy của khóa | `16` |
| `--workers N` | Số process cho brute-force | `1` |
| `--fast` | Dùng PyCryptodome backend | `False` |
| `-v`, `--verbose` | Bật debug logging | `False` |

## Luồng chạy chính

Entry point:

```text
python -m aes_brute_force
    -> src/aes_brute_force/__main__.py
    -> aes_brute_force.cli.app:main()
```

Trong `main()`:

1. Parse tham số dòng lệnh bằng `argparse`.
2. Cấu hình logging và console UTF-8.
3. Kiểm tra dependency `matplotlib`.
4. Nếu không có `--cli`, thử mở GUI.
5. Nếu chạy CLI, thực hiện:
   - `encrypt_aes(text, bits)`;
   - `brute_force_aes(ciphertext, bits, ...)`;
   - in khóa tìm được, plaintext, thời gian và tốc độ.

## AES engine

File quan trọng: `src/aes_brute_force/core/aes_engine.py`.

Project cài đặt AES-128 từ đầu:

- Block size: 16 byte.
- Key size: 16 byte.
- Số vòng AES-128: 10.
- Mode demo: ECB.
- Padding: PKCS#7.

Những hàm nên học theo thứ tự:

1. `pad()` và `unpad()`: thêm/kiểm tra padding PKCS#7.
2. `generate_short_key()` và `key_int_to_bytes()`: biến khóa ngắn thành khóa AES-128.
3. `bytes2matrix()` và `matrix2bytes()`: chuyển block 16 byte sang state.
4. `sub_bytes()`, `shift_rows()`, `mix_columns()`, `add_round_key()`: các bước AES.
5. `key_expansion()`: sinh 44 word khóa vòng.
6. `encrypt_block()` và `decrypt_block()`: mã hóa/giải mã một block.
7. `PureAES.encrypt()` và `PureAES.decrypt()`: xử lý nhiều block.
8. `encrypt_aes()` và `decrypt_aes()`: API tiện lợi cho project.

Lưu ý: key material trong `PureAES` được lưu trong `_key_buf` và có hàm `clear()` để zeroize buffer này. Key schedule vẫn tồn tại để phục vụ mã hóa/giải mã.

## Cấu trúc khóa entropy thấp

AES-128 yêu cầu khóa 16 byte. Để brute-force trong demo, project chỉ cho `n` bit đầu là bí mật, phần còn lại là zero.

Ví dụ khóa 16 bit:

```text
key_int       = 0xABCD
AES-128 key   = AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
keyspace      = 2^16 = 65,536
```

Hàm liên quan:

- `generate_short_key(bits, key_int=None)`
- `key_int_to_bytes(key_int, key_bits)`

Supported key bits hiện tại:

```text
8, 12, 16, 20, 24, 32
```

## Brute-force logic

File quan trọng: `src/aes_brute_force/core/brute_force.py`.

Thuật toán cơ bản:

```python
for i in range(2 ** key_bits):
    key = i.to_bytes(key_bytes_len, "big").ljust(16, b"\x00")
    raw = AES.decrypt(ciphertext, key)
    unpadded = unpad(raw)
    if plaintext_is_accepted:
        return key
```

`brute_force_aes()` hỗ trợ:

- Sequential mode khi `workers=1`.
- Multiprocessing khi `workers > 1`.
- Fast mode khi `fast_mode=True` và đã cài `pycryptodome`.
- Progress callback qua `callback`.
- Log chi tiết qua `detail_callback`.
- Stop flag cho GUI.
- Exact-match mode qua `known_plaintext`.

### Hai cách nhận diện plaintext

1. Exact-match mode:

Khi `known_plaintext` được truyền vào, project so sánh byte-to-byte:

```text
unpadded == known_plaintext.encode("utf-8")
```

Đây là cách GUI dùng khi ciphertext được tạo từ tab Mã hóa. Cách này tránh nhận nhầm khóa sai.

2. Heuristic mode:

Khi không biết plaintext, project dùng:

- PKCS#7 padding hợp lệ.
- Điểm ASCII printable >= `DEFAULT_SCORE_THRESHOLD`, hiện là `0.9`.

Heuristic có thể bị false positive. Vì vậy repo có file `tests/test_false_positive_fix.py` để ghi lại bug cũ: một khóa sai có thể giải mã ra chuỗi printable và vượt threshold.

## GUI flow

File chính: `src/aes_brute_force/gui/app.py`.

Luồng GUI:

1. `AESBruteForceApp` tạo sidebar và 3 page.
2. `EncryptTab`:
   - người dùng nhập plaintext;
   - chọn key bits;
   - tùy chọn fixed key;
   - gọi `encrypt_aes()`;
   - lưu `shared_ciphertext`, `shared_key_int`, `shared_key_bits`, `shared_plaintext`;
   - copy ciphertext sang `AttackTab`.
3. `AttackTab`:
   - đọc ciphertext hex;
   - chọn bits;
   - chạy `brute_force_aes()` trong background thread;
   - dùng multiprocessing với số worker gần bằng CPU count - 1;
   - cập nhật card, progress bar, log;
   - truyền `known_plaintext=self.app.shared_plaintext` nếu có.
4. `TheoryTab`:
   - hiển thị ghi chú lý thuyết AES và brute-force.

## Benchmark

File chính: `src/aes_brute_force/benchmark/runner.py`.

Chạy benchmark mặc định:

```bash
python -m aes_brute_force.benchmark.runner --bits 8 12 16 --text SECRET
```

Ví dụ với fixed key:

```bash
python -m aes_brute_force.benchmark.runner --bits 8 12 16 --text SECRET --key-int 0x2A
```

Tắt output file:

```bash
python -m aes_brute_force.benchmark.runner --bits 8 --no-plot --no-json
```

Tham số benchmark:

| Flag | Ý nghĩa | Mặc định |
|---|---|---|
| `--bits` | Danh sách bit entropy cần đo | `8 12 16` |
| `--text TEXT` | Plaintext benchmark | `SECRET` |
| `--workers N` | Số process brute-force | `1` |
| `--key-int VALUE` | Khóa cố định, hỗ trợ dec/hex | random |
| `--output-dir DIR` | Thư mục lưu kết quả | `results/benchmark_YYYYMMDD_HHMMSS/` |
| `--output FILE` | Đường dẫn chart PNG | `benchmark_chart.png` |
| `--json FILE` | Đường dẫn JSON | `benchmark_data.json` |
| `--no-plot` | Không xuất chart | `False` |
| `--no-json` | Không xuất JSON | `False` |

Kết quả hiện có trong `results/`:

- `benchmark_chart.png`
- `benchmark_data.json`

Dữ liệu benchmark đã lưu cho thấy Pure Python đạt khoảng 1,300-1,400 keys/s trên các lần đo 8, 12, 16 bit.

## Tests

Chạy toàn bộ test:

```bash
pytest -q
```

Chạy test chính:

```bash
pytest tests/test_aes_v2.py -v
```

Chạy regression false positive:

```bash
pytest tests/test_false_positive_fix.py -v
```

Chạy theo nhóm:

```bash
pytest tests/test_aes_v2.py -v -k "NIST"
pytest tests/test_aes_v2.py -v -k "BruteForce"
pytest tests/test_aes_v2.py -v -k "Benchmark"
```

Phạm vi test hiện có:

- Round-trip mã hóa/giải mã với key 8, 16, 24, 32 bit.
- NIST FIPS-197 known answer tests.
- PKCS#7 padding hợp lệ/không hợp lệ.
- Hex conversion.
- Wrong key.
- Brute-force 8/12 bit.
- Full pipeline encrypt -> brute-force -> verify.
- Benchmark argument/output path.
- Stop flag.
- Key zero/max.
- False positive regression.
- Exact-match mode.
- Heuristic mode.
- Zeroize `_key_buf`.

## Bảo mật và giới hạn

- Đây là demo giáo dục, không phải công cụ tấn công thực tế.
- AES-128 đầy đủ với `2^128` khóa là không thể brute-force bằng máy tính thông thường.
- Project brute-force được vì cố tình giảm entropy khóa xuống 8-32 bit.
- ECB không an toàn trong ứng dụng thực tế vì lộ mẫu lặp lại của plaintext.
- Heuristic plaintext có thể nhận nhầm khóa sai; khi biết plaintext nên dùng exact-match.
- Không có authentication/MAC, nên không bảo vệ tính toàn vẹn ciphertext.

Trong hệ thống thực tế nên dùng AES-GCM hoặc chế độ mã hóa có xác thực, với khóa đủ entropy, nonce/IV dùng đúng cách và thư viện mật mã đã được kiểm định.

## Lộ trình học project

1. Chạy CLI 8 bit:

   ```bash
   python -m aes_brute_force --cli --text SECRET --bits 8
   ```

2. Tăng lên 12/16 bit để thấy thời gian tăng theo `2^n`.
3. Đọc `aes_engine.py` từ padding, state, round function đến `PureAES`.
4. Đọc `brute_force.py`, đặc biệt `known_plaintext`, `score_plaintext`, multiprocessing.
5. Chạy GUI và quan sát Encrypt tab copy ciphertext sang Attack tab.
6. Chạy benchmark và đọc JSON/chart trong `results/`.
7. Đọc tests NIST để hiểu cách chứng minh AES implementation đúng.
8. Đọc `test_false_positive_fix.py` để hiểu rủi ro khi dùng heuristic.

## Công nghệ

| Thành phần | Công nghệ |
|---|---|
| AES-128 | Python thuần |
| GUI | CustomTkinter |
| Benchmark chart | matplotlib |
| Fast mode | PyCryptodome optional |
| Song song | multiprocessing |
| Test | pytest + unittest style |
| Packaging | setuptools với `src/` layout |
| CI | GitHub Actions |

## Tài liệu tham khảo

1. NIST FIPS-197, Advanced Encryption Standard.
2. William Stallings, Cryptography and Network Security.
3. Christof Paar, Understanding Cryptography.
