# AES Brute-Force Demo

Demo do an mon Mat Ma Hoc: minh hoa tan cong vet can len AES-128 khi khoa co entropy thap. Loi AES-128 duoc cai dat bang Python thuan, khong dung thu vien ma hoa cho backend mac dinh.

> Muc dich cua project la hoc tap va trinh bay. Khong su dung ky thuat nay de tan cong he thong thuc te.

## Muc tieu

- Hieu cach AES-128 xu ly block 16 byte, key schedule va 10 vong bien doi.
- Thay anh huong cua khong gian khoa `2^n` den thoi gian brute-force.
- Minh hoa vi sao khoa ngan hoac khoa co entropy thap la khong an toan.
- So sanh brute-force thuan Python, multiprocessing va fast mode bang PyCryptodome.
- Ghi nhan rui ro false positive khi doan plaintext bang heuristic.

## Cau truc project

```text
AES-Brute-Force/
|-- src/aes_brute_force/
|   |-- __main__.py                  # python -m aes_brute_force
|   |-- cli/app.py                   # CLI va entry point mac dinh
|   |-- core/
|   |   |-- aes_engine.py            # AES-128 thuan Python, ECB, PKCS#7
|   |   |-- brute_force.py           # brute-force sequential/multiprocessing/fast mode
|   |   `-- constants.py             # cau hinh chung, key bits, block size
|   |-- gui/
|   |   |-- app.py                   # cua so CustomTkinter
|   |   |-- tabs/encrypt_tab.py      # ma hoa/giai ma demo
|   |   |-- tabs/attack_tab.py       # vet can khoa, log tien trinh
|   |   |-- tabs/theory_tab.py       # ghi chu ly thuyet trong GUI
|   |   |-- theme.py                 # theme mau va font
|   |   `-- widgets/stat_card.py     # widget thong ke
|   |-- benchmark/runner.py          # chay benchmark, xuat PNG/JSON
|   `-- utils/logging.py             # logging helper
|-- tests/
|   |-- test_aes_v2.py               # test AES, brute-force, benchmark, edge cases
|   `-- test_false_positive_fix.py   # regression test cho loi false positive
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

Ghi chu: project hien dung `pyproject.toml` de khai bao dependency va packaging. Repo khong co `requirements.txt`, `run.bat`, hoac `run.sh`.

## Cai dat

Yeu cau Python 3.10+.

```bash
pip install -e .
```

Cai them cong cu dev va fast backend:

```bash
pip install -e ".[dev]"
```

Chi cai fast backend:

```bash
pip install -e ".[fast]"
```

Dependency chinh:

- `customtkinter`: GUI.
- `matplotlib`: benchmark chart.
- `pycryptodome`: optional fast mode va dev tests.
- `pytest`, `pytest-cov`, `ruff`: optional dev tools.

## Chay ung dung

### GUI

```bash
python -m aes_brute_force
```

Hoac sau khi cai package:

```bash
aes-brute-force
```

GUI gom 3 man hinh:

- Ma hoa & Giai ma: nhap plaintext, chon do dai entropy, tao ciphertext.
- Vet can: nhan ciphertext hex, chay brute-force, hien progress/log.
- Goc ly thuyet: tom tat AES va keyspace.

### CLI

```bash
python -m aes_brute_force --cli --text SECRET --bits 16
```

Fast mode bang PyCryptodome:

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

Tham so CLI:

| Flag | Y nghia | Mac dinh |
|---|---|---|
| `--cli` | Chay che do dong lenh | `False` |
| `--gui` | Ep chay GUI | `False` |
| `--text TEXT` | Plaintext de ma hoa trong CLI | `SECRET` |
| `--bits {8,12,16,20,24,32}` | So bit entropy cua khoa | `16` |
| `--workers N` | So process cho brute-force | `1` |
| `--fast` | Dung PyCryptodome backend | `False` |
| `-v`, `--verbose` | Bat debug logging | `False` |

## Luong chay chinh

Entry point:

```text
python -m aes_brute_force
    -> src/aes_brute_force/__main__.py
    -> aes_brute_force.cli.app:main()
```

Trong `main()`:

1. Parse tham so dong lenh bang `argparse`.
2. Cau hinh logging va console UTF-8.
3. Kiem tra dependency `matplotlib`.
4. Neu khong co `--cli`, thu mo GUI.
5. Neu chay CLI, thuc hien:
   - `encrypt_aes(text, bits)`;
   - `brute_force_aes(ciphertext, bits, ...)`;
   - in khoa tim duoc, plaintext, thoi gian va toc do.

## AES engine

File quan trong: `src/aes_brute_force/core/aes_engine.py`.

Project cai dat AES-128 tu dau:

- Block size: 16 byte.
- Key size: 16 byte.
- So vong AES-128: 10.
- Mode demo: ECB.
- Padding: PKCS#7.

Nhung ham nen hoc theo thu tu:

1. `pad()` va `unpad()`: them/kiem tra padding PKCS#7.
2. `generate_short_key()` va `key_int_to_bytes()`: bien khoa ngan thanh khoa AES-128.
3. `bytes2matrix()` va `matrix2bytes()`: chuyen block 16 byte sang state.
4. `sub_bytes()`, `shift_rows()`, `mix_columns()`, `add_round_key()`: cac buoc AES.
5. `key_expansion()`: sinh 44 word khoa vong.
6. `encrypt_block()` va `decrypt_block()`: ma hoa/giai ma mot block.
7. `PureAES.encrypt()` va `PureAES.decrypt()`: xu ly nhieu block.
8. `encrypt_aes()` va `decrypt_aes()`: API tien loi cho project.

Luu y: key material trong `PureAES` duoc luu trong `_key_buf` va co ham `clear()` de zeroize buffer nay. Key schedule van ton tai de phuc vu ma hoa/giai ma.

## Cau truc khoa entropy thap

AES-128 yeu cau khoa 16 byte. De brute-force trong demo, project chi cho `n` bit dau la bi mat, phan con lai la zero.

Vi du khoa 16 bit:

```text
key_int       = 0xABCD
AES-128 key   = AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
keyspace      = 2^16 = 65,536
```

Ham lien quan:

- `generate_short_key(bits, key_int=None)`
- `key_int_to_bytes(key_int, key_bits)`

Supported key bits hien tai:

```text
8, 12, 16, 20, 24, 32
```

## Brute-force logic

File quan trong: `src/aes_brute_force/core/brute_force.py`.

Thuat toan co ban:

```python
for i in range(2 ** key_bits):
    key = i.to_bytes(key_bytes_len, "big").ljust(16, b"\x00")
    raw = AES.decrypt(ciphertext, key)
    unpadded = unpad(raw)
    if plaintext_is_accepted:
        return key
```

`brute_force_aes()` ho tro:

- Sequential mode khi `workers=1`.
- Multiprocessing khi `workers > 1`.
- Fast mode khi `fast_mode=True` va da cai `pycryptodome`.
- Progress callback qua `callback`.
- Log chi tiet qua `detail_callback`.
- Stop flag cho GUI.
- Exact-match mode qua `known_plaintext`.

### Hai cach nhan dien plaintext

1. Exact-match mode:

Khi `known_plaintext` duoc truyen vao, project so sanh byte-to-byte:

```text
unpadded == known_plaintext.encode("utf-8")
```

Day la cach GUI dung khi ciphertext duoc tao tu tab Ma hoa. Cach nay tranh nhan nham khoa sai.

2. Heuristic mode:

Khi khong biet plaintext, project dung:

- PKCS#7 padding hop le.
- Diem ASCII printable >= `DEFAULT_SCORE_THRESHOLD`, hien la `0.9`.

Heuristic co the bi false positive. Vi vay repo co file `tests/test_false_positive_fix.py` de ghi lai bug cu: mot khoa sai co the giai ma ra chuoi printable va vuot threshold.

## GUI flow

File chinh: `src/aes_brute_force/gui/app.py`.

Luong GUI:

1. `AESBruteForceApp` tao sidebar va 3 page.
2. `EncryptTab`:
   - nguoi dung nhap plaintext;
   - chon key bits;
   - tuy chon fixed key;
   - goi `encrypt_aes()`;
   - luu `shared_ciphertext`, `shared_key_int`, `shared_key_bits`, `shared_plaintext`;
   - copy ciphertext sang `AttackTab`.
3. `AttackTab`:
   - doc ciphertext hex;
   - chon bits;
   - chay `brute_force_aes()` trong background thread;
   - dung multiprocessing voi so worker gan bang CPU count - 1;
   - cap nhat card, progress bar, log;
   - truyen `known_plaintext=self.app.shared_plaintext` neu co.
4. `TheoryTab`:
   - hien ghi chu ly thuyet AES va brute-force.

## Benchmark

File chinh: `src/aes_brute_force/benchmark/runner.py`.

Chay benchmark mac dinh:

```bash
python -m aes_brute_force.benchmark.runner --bits 8 12 16 --text SECRET
```

Vi du voi fixed key:

```bash
python -m aes_brute_force.benchmark.runner --bits 8 12 16 --text SECRET --key-int 0x2A
```

Tat output file:

```bash
python -m aes_brute_force.benchmark.runner --bits 8 --no-plot --no-json
```

Tham so benchmark:

| Flag | Y nghia | Mac dinh |
|---|---|---|
| `--bits` | Danh sach bit entropy can do | `8 12 16` |
| `--text TEXT` | Plaintext benchmark | `SECRET` |
| `--workers N` | So process brute-force | `1` |
| `--key-int VALUE` | Khoa co dinh, ho tro dec/hex | random |
| `--output-dir DIR` | Thu muc luu ket qua | `results/benchmark_YYYYMMDD_HHMMSS/` |
| `--output FILE` | Duong dan chart PNG | `benchmark_chart.png` |
| `--json FILE` | Duong dan JSON | `benchmark_data.json` |
| `--no-plot` | Khong xuat chart | `False` |
| `--no-json` | Khong xuat JSON | `False` |

Ket qua hien co trong `results/`:

- `benchmark_chart.png`
- `benchmark_data.json`

Du lieu benchmark da luu cho thay Pure Python dat khoang 1,300-1,400 keys/s tren cac lan do 8, 12, 16 bit.

## Tests

Chay toan bo test:

```bash
pytest -q
```

Chay test chinh:

```bash
pytest tests/test_aes_v2.py -v
```

Chay regression false positive:

```bash
pytest tests/test_false_positive_fix.py -v
```

Chay theo nhom:

```bash
pytest tests/test_aes_v2.py -v -k "NIST"
pytest tests/test_aes_v2.py -v -k "BruteForce"
pytest tests/test_aes_v2.py -v -k "Benchmark"
```

Pham vi test hien co:

- Round-trip ma hoa/giai ma voi key 8, 16, 24, 32 bit.
- NIST FIPS-197 known answer tests.
- PKCS#7 padding hop le/khong hop le.
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

## Bao mat va gioi han

- Day la demo giao duc, khong phai cong cu tan cong thuc te.
- AES-128 day du voi `2^128` khoa la khong the brute-force bang may tinh thong thuong.
- Project brute-force duoc vi co tinh giam entropy khoa xuong 8-32 bit.
- ECB khong an toan trong ung dung thuc te vi lo mau lap lai cua plaintext.
- Heuristic plaintext co the nhan nham khoa sai; khi biet plaintext nen dung exact-match.
- Khong co authentication/MAC, nen khong bao ve tinh toan ven ciphertext.

Trong he thong thuc te nen dung AES-GCM hoac che do ma hoa co xac thuc, voi khoa du entropy, nonce/IV dung cach va thu vien mat ma da duoc kiem dinh.

## Lo trinh hoc project

1. Chay CLI 8 bit:

   ```bash
   python -m aes_brute_force --cli --text SECRET --bits 8
   ```

2. Tang len 12/16 bit de thay thoi gian tang theo `2^n`.
3. Doc `aes_engine.py` tu padding, state, round function den `PureAES`.
4. Doc `brute_force.py`, dac biet `known_plaintext`, `score_plaintext`, multiprocessing.
5. Chay GUI va quan sat Encrypt tab copy ciphertext sang Attack tab.
6. Chay benchmark va doc JSON/chart trong `results/`.
7. Doc tests NIST de hieu cach chung minh AES implementation dung.
8. Doc `test_false_positive_fix.py` de hieu rui ro khi dung heuristic.

## Cong nghe

| Thanh phan | Cong nghe |
|---|---|
| AES-128 | Python thuan |
| GUI | CustomTkinter |
| Benchmark chart | matplotlib |
| Fast mode | PyCryptodome optional |
| Song song | multiprocessing |
| Test | pytest + unittest style |
| Packaging | setuptools voi `src/` layout |
| CI | GitHub Actions |

## Tai lieu tham khao

1. NIST FIPS-197, Advanced Encryption Standard.
2. William Stallings, Cryptography and Network Security.
3. Christof Paar, Understanding Cryptography.
