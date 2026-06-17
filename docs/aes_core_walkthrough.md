# Hướng Dẫn Chi Tiết Lõi Mã Hóa AES-128 (Tự Code Từ Đầu)

Tài liệu này giải thích chi tiết cấu trúc toán học và mã nguồn của lõi mã hóa **AES-128** (Advanced Encryption Standard) được lập trình hoàn toàn từ đầu (from scratch) trong tệp `src/aes_brute_force/core/aes_engine.py`.

---

## 1. Tổng Quan Về AES-128
Mã hóa AES-128 hoạt động trên:
* **Kích thước khối (Block Size):** 128-bit (16 bytes) đầu vào được biểu diễn dưới dạng ma trận trạng thái **State** kích thước $4 \times 4$.
* **Kích thước khóa (Key Size):** 128-bit (16 bytes).
* **Số vòng lặp (Rounds):** 10 vòng chính thức (vòng 1 đến 10) cộng với 1 vòng khởi tạo (vòng 0).

---

## 2. Tổ Chức Dữ Liệu: Ma Trận State
Theo chuẩn **NIST FIPS-197**, 16 bytes dữ liệu đầu vào không được xếp theo hàng mà được xếp theo **cột trước, hàng sau (Column-major order)**.

Ví dụ: 16 bytes dữ liệu `[b0, b1, b2, ..., b15]` được chuyển thành ma trận:
$$\begin{pmatrix} b_0 & b_4 & b_8 & b_{12} \\ b_1 & b_5 & b_9 & b_{13} \\ b_2 & b_6 & b_{10} & b_{14} \\ b_3 & b_7 & b_{11} & b_{15} \end{pmatrix}$$

### Mã nguồn tương ứng:
```python
def bytes2matrix(data: bytes) -> list[list[int]]:
    # Xếp 16 bytes thành ma trận 4x4 (mỗi cột là 4 bytes liên tiếp)
    return [list(data[i : i + 4]) for i in range(0, 16, 4)]

def matrix2bytes(matrix: list[list[int]]) -> bytes:
    # Gộp ma trận 4x4 trở lại thành mảng 16 bytes phẳng
    return bytes(sum(matrix, []))
```

---

## 3. Các Phép Biến Đổi Core (4 Phép Toán Chính)

### 3.1. AddRoundKey (Cộng khóa vòng)
* **Khái niệm:** Lấy từng byte của ma trận State thực hiện phép toán XOR với byte tương ứng của khóa vòng (Round Key).
* **Toán học:** Phép XOR trên máy tính chính là phép cộng trong trường Galois $GF(2)$.

```python
def add_round_key(state: list[list[int]], key_schedule: list[list[int]], rnd: int) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] ^= key_schedule[rnd * 4 + c][r]
```

---

### 3.2. SubBytes (Thay thế byte)
* **Khái niệm:** Thay thế phi tuyến tính từng byte của State bằng một byte tương ứng trong bảng tra **S-Box** (Substitution Box).
* **Bản chất toán học:** Tìm nghịch đảo nhân của byte đó trong trường $GF(2^8)$, sau đó thực hiện một phép biến đổi affine.
* **Mã hóa ngược (Giải mã):** Dùng bảng **Inv S-Box** để đổi ngược lại.

```python
def sub_bytes(state: list[list[int]]) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] = S_BOX[state[c][r]]

def inv_sub_bytes(state: list[list[int]]) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] = INV_S_BOX[state[c][r]]
```

---

### 3.3. ShiftRows (Dịch chuyển hàng)
* **Khái niệm:** Dịch chuyển vòng (cyclically shift) các hàng của ma trận State sang trái:
  * Hàng 0: Giữ nguyên (dịch 0 vị trí).
  * Hàng 1: Dịch trái 1 vị trí.
  * Hàng 2: Dịch trái 2 vị trí.
  * Hàng 3: Dịch trái 3 vị trí.
* **Mã hóa ngược (Giải mã):** Dịch chuyển sang phải tương ứng (`inv_shift_rows`).

```python
def shift_rows(state: list[list[int]]) -> None:
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[1][1], state[2][1], state[3][1], state[0][1]
    )
    # Hàng 2 dịch 2 vị trí, hàng 3 dịch 3 vị trí...
```

---

### 3.4. MixColumns (Trộn cột)
Đây là phép toán phức tạp nhất của AES, giúp khuếch tán (diffusion) dữ liệu:
* **Khái niệm:** Coi mỗi cột là một đa thức bậc 3 trên trường $GF(2^8)$ và nhân nó với một đa thức cố định $c(x) = \{03\}x^3 + \{01\}x^2 + \{01\}x + \{02\} \pmod{x^4 + 1}$.
* **Toán học trên trường Galois $GF(2^8)$:** 
  * Phép cộng là phép XOR (`^`).
  * Phép nhân với $\{02\}$ được thực hiện bằng hàm `xtime(a)` (nếu bit cao nhất bằng 1 thì dịch trái rồi XOR với đa thức bất khả quy `0x1B`).

```python
def xtime(a: int) -> int:
    # Nhân với 2 (tức là x) trong GF(2^8)
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def multiply(x: int, y: int) -> int:
    # Nhân hai số bất kỳ trong GF(2^8) bằng thuật toán nhân nông dân (Russian Peasant)
    result = 0
    for _ in range(8):
        if y & 1:
            result ^= x
        hi = x & 0x80
        x = (x << 1) & 0xFF
        if hi:
            x ^= 0x1B
        y >>= 1
    return result
```

Trong thực tế để tăng tốc độ giải mã (MixColumns ngược), dự án sử dụng các bảng nhân được tính toán trước (Table Lookups) như `_MUL_0E`, `_MUL_0B`, `_MUL_0D`, `_MUL_09`.

---

## 4. Key Expansion (Mở rộng khóa)
Khóa ban đầu dài 16 bytes (128-bit) cần được mở rộng thành **11 khóa vòng** (tổng cộng 44 từ 32-bit, tương đương 176 bytes) thông qua hàm `key_expansion`.

Quy trình mở rộng khóa:
1. Sao chép 4 từ đầu tiên trực tiếp từ khóa bí mật.
2. Với các từ tiếp theo (chỉ số $i$):
   * Nếu $i$ chia hết cho 4: Áp dụng hàm phụ **RotWord** (dịch vòng byte trái), **SubWord** (tra S-Box), và XOR với hằng số vòng **RCON**.
   * Nếu không chia hết cho 4: XOR từ trước đó ($w[i-1]$) với từ cách đó 4 vị trí ($w[i-4]$).

```python
def key_expansion(key: bytes) -> list[list[int]]:
    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [S_BOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // 4]  # XOR RCON
        words.append([words[i - 4][r] ^ temp[r] for r in range(4)])
    return words
```

---

## 5. Quy Trình Mã Hóa Và Giải Mã Toàn Bộ (Round Flow)

### 5.1. Quy trình Mã hóa (`encrypt_block`)
Gồm 10 vòng chạy tuần tự:
1. **Khởi động (Vòng 0):** `AddRoundKey` với khóa vòng đầu tiên.
2. **9 vòng lặp chuẩn (Vòng 1 - 9):**
   * `SubBytes`
   * `ShiftRows`
   * `MixColumns`
   * `AddRoundKey`
3. **Vòng cuối cùng (Vòng 10):**
   * `SubBytes`
   * `ShiftRows`
   * `AddRoundKey` *(Không có MixColumns để cấu trúc mã hóa/giải mã đối xứng)*.

```python
def encrypt_block(plaintext: bytes, key_schedule: list[list[int]]) -> bytes:
    state = bytes2matrix(plaintext)
    add_round_key(state, key_schedule, 0)
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, rnd)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, 10)
    return matrix2bytes(state)
```

### 5.2. Quy trình Giải mã (`decrypt_block`)
Thực hiện ngược hoàn toàn các bước mã hóa theo thứ tự từ vòng 10 về vòng 0:
```python
def decrypt_block(ciphertext: bytes, key_schedule: list[list[int]]) -> bytes:
    state = bytes2matrix(ciphertext)
    add_round_key(state, key_schedule, 10)
    for rnd in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, rnd)
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, 0)
    return matrix2bytes(state)
```
