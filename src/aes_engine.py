import os
from typing import Optional, Tuple

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
)

def xtime(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def multiply(x: int, y: int) -> int:
    ans = 0
    for i in range(8):
        if y & 1:
            ans ^= x
        hi_bit_set = x & 0x80
        x <<= 1
        if hi_bit_set:
            x ^= 0x1B
        x &= 0xFF
        y >>= 1
    return ans

def bytes2matrix(text: bytes) -> list:
    """Chuyển 16 bytes thành state 4x4. Mỗi phần tử là 1 cột: state[c][r] = text[4c+r]."""
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix: list) -> bytes:
    """Chuyển state 4x4 về bytes (cột-chính)."""
    return bytes(sum(matrix, []))

def add_round_key(state: list, key_schedule: list, round_num: int):
    """XOR mỗi cột c của state với word tương ứng trong key schedule."""
    for c in range(4):
        for r in range(4):
            state[c][r] ^= key_schedule[round_num * 4 + c][r]

def sub_bytes(state: list):
    for c in range(4):
        for r in range(4):
            state[c][r] = Sbox[state[c][r]]

def inv_sub_bytes(state: list):
    for c in range(4):
        for r in range(4):
            state[c][r] = InvSbox[state[c][r]]

def shift_rows(state: list):
    """Rotate trái từng hàng r đi r vị trí. Với convention state[col][row],
    hàng r = [state[c][r] for c in range(4)]."""
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

def inv_shift_rows(state: list):
    """Nghịch đảo ShiftRows: rotate phải từng hàng r."""
    state[1][1], state[2][1], state[3][1], state[0][1] = state[0][1], state[1][1], state[2][1], state[3][1]
    state[2][2], state[3][2], state[0][2], state[1][2] = state[0][2], state[1][2], state[2][2], state[3][2]
    state[3][3], state[0][3], state[1][3], state[2][3] = state[0][3], state[1][3], state[2][3], state[3][3]

def mix_single_column(a: list):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(state: list):
    """MixColumns: áp dụng lên từng cột state[c] (NIST FIPS-197 §5.1.3)."""
    for i in range(4):
        mix_single_column(state[i])

def inv_mix_single_column(a: list):
    u = multiply(a[0], 0x0e) ^ multiply(a[1], 0x0b) ^ multiply(a[2], 0x0d) ^ multiply(a[3], 0x09)
    v = multiply(a[0], 0x09) ^ multiply(a[1], 0x0e) ^ multiply(a[2], 0x0b) ^ multiply(a[3], 0x0d)
    w = multiply(a[0], 0x0d) ^ multiply(a[1], 0x09) ^ multiply(a[2], 0x0e) ^ multiply(a[3], 0x0b)
    x = multiply(a[0], 0x0b) ^ multiply(a[1], 0x0d) ^ multiply(a[2], 0x09) ^ multiply(a[3], 0x0e)
    a[0] = u
    a[1] = v
    a[2] = w
    a[3] = x

def inv_mix_columns(state: list):
    """InvMixColumns: áp dụng lên từng cột."""
    for i in range(4):
        inv_mix_single_column(state[i])

def key_expansion(key: bytes) -> list:
    key_symbols = [list(key[i:i+4]) for i in range(0, 16, 4)]
    key_schedule = []
    for i in range(4):
        key_schedule.append(key_symbols[i])
    
    for i in range(4, 4 * 11):
        temp = key_schedule[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [Sbox[b] for b in temp]
            temp[0] ^= Rcon[i // 4]
        
        word = [key_schedule[i - 4][r] ^ temp[r] for r in range(4)]
        key_schedule.append(word)
    return key_schedule

def encrypt_block(plaintext: bytes, key_schedule: list) -> bytes:
    state = bytes2matrix(plaintext)
    add_round_key(state, key_schedule, 0)
    
    for round_num in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round_num)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, 10)
    return matrix2bytes(state)

def decrypt_block(ciphertext: bytes, key_schedule: list) -> bytes:
    state = bytes2matrix(ciphertext)
    add_round_key(state, key_schedule, 10)
    
    for round_num in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, round_num)
        inv_mix_columns(state)
        
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, 0)
    return matrix2bytes(state)

def pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes, block_size: int = 16) -> bytes:
    if len(data) == 0:
        raise ValueError("Dữ liệu trống.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding không hợp lệ.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding không hợp lệ.")
    return data[:-pad_len]

class PureAES:
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("Chỉ hỗ trợ AES-128 (khóa 16 bytes).")
        self.key_schedule = key_expansion(key)
        
    def encrypt(self, data: bytes) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("Dữ liệu cần được pad thành bội số của 16 bytes.")
        ciphertext = b""
        for i in range(0, len(data), 16):
            ciphertext += encrypt_block(data[i:i+16], self.key_schedule)
        return ciphertext
        
    def decrypt(self, data: bytes) -> bytes:
        if len(data) % 16 != 0:
            raise ValueError("Dữ liệu mã hóa phải là bội số của 16 bytes.")
        plaintext = b""
        for i in range(0, len(data), 16):
            plaintext += decrypt_block(data[i:i+16], self.key_schedule)
        return plaintext

SUPPORTED_KEY_BITS = [8, 12, 16, 20, 24, 32]

def validate_key_bits(bits: int) -> None:
    if bits not in SUPPORTED_KEY_BITS:
        raise ValueError(
            f"Độ dài khóa không hợp lệ: {bits}. Hỗ trợ: {SUPPORTED_KEY_BITS}"
        )

def generate_short_key(bits: int, key_int: Optional[int] = None) -> bytes:
    validate_key_bits(bits)

    key_bytes_len = (bits + 7) // 8
    max_val = (1 << bits) - 1

    if key_int is None:
        key_int = int.from_bytes(os.urandom(4), 'big') & max_val
    elif key_int < 0 or key_int > max_val:
        raise ValueError(
            f"key_int phải nằm trong khoảng [0, 2^{bits} - 1]."
        )

    key_part = key_int.to_bytes(key_bytes_len, byteorder='big')
    return key_part.ljust(16, b'\x00')

def key_int_to_bytes(key_int: int, key_bits: int) -> bytes:
    validate_key_bits(key_bits)
    max_val = (1 << key_bits) - 1
    if key_int < 0 or key_int > max_val:
        raise ValueError(
            f"key_int phải nằm trong khoảng [0, 2^{key_bits} - 1]."
        )

    key_bytes_len = (key_bits + 7) // 8
    key_part = key_int.to_bytes(key_bytes_len, byteorder='big')
    return key_part.ljust(16, b'\x00')

def encrypt_aes(
    plaintext: str,
    key_bits: int,
    key: Optional[bytes] = None,
    key_int: Optional[int] = None,
) -> Tuple[bytes, bytes, int]:
    validate_key_bits(key_bits)

    if key is not None and key_int is not None:
        key_bytes_len = (key_bits + 7) // 8
        real_int = int.from_bytes(key[:key_bytes_len], byteorder='big') & ((1 << key_bits) - 1)
        if real_int != key_int:
            raise ValueError("Mâu thuẫn giữa key bytes và key_int.")

    if key is None:
        if key_int is None:
            key = generate_short_key(key_bits)
        else:
            key = key_int_to_bytes(key_int, key_bits)

    cipher = PureAES(key)
    padded_data = pad(plaintext.encode('utf-8'), 16)
    ciphertext = cipher.encrypt(padded_data)

    key_bytes_len = (key_bits + 7) // 8
    key_int = int.from_bytes(key[:key_bytes_len], byteorder='big') & ((1 << key_bits) - 1)

    return ciphertext, key, key_int

def decrypt_aes(ciphertext: bytes, key: bytes) -> Optional[str]:
    try:
        cipher = PureAES(key)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, 16).decode('utf-8')
    except Exception:
        return None

def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()

def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.strip())

if __name__ == "__main__":
    print("=== KIỂM TRA BỘ MÃ HÓA AES (Python thuần) ===")
    test_text = "HELLO WORLD"

    for bits in [16, 24, 32]:
        ciphertext, key, key_int = encrypt_aes(test_text, bits)
        decrypted = decrypt_aes(ciphertext, key)

        print(f"\n[Khóa {bits}-bit]")
        print(f"  Bản rõ          : {test_text}")
        print(f"  Khóa (hex)      : {bytes_to_hex(key)}")
        print(f"  Giá trị khóa    : {key_int} (0x{key_int:0{bits//4}X})")
        print(f"  Bản mã          : {bytes_to_hex(ciphertext)}")
        print(f"  Sau giải mã     : {decrypted}")
        print(f"  Khớp bản rõ gốc : {test_text == decrypted}")
