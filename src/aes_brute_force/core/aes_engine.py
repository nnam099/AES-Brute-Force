from __future__ import annotations

import hmac
import os
import warnings
from typing import Optional, Tuple

from aes_brute_force.core.constants import (
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    INV_S_BOX,
    RCON,
    S_BOX,
    validate_key_bits,
)
from aes_brute_force.utils.logging import get_logger

logger = get_logger("aes_engine")


def xtime(a: int) -> int:
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def multiply(x: int, y: int) -> int:
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


def bytes2matrix(data: bytes) -> list[list[int]]:
    return [list(data[i : i + 4]) for i in range(0, AES_BLOCK_SIZE, 4)]


def matrix2bytes(matrix: list[list[int]]) -> bytes:
    return bytes(sum(matrix, []))


def add_round_key(state: list[list[int]], key_schedule: list[list[int]], rnd: int) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] ^= key_schedule[rnd * 4 + c][r]


def sub_bytes(state: list[list[int]]) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] = S_BOX[state[c][r]]


def inv_sub_bytes(state: list[list[int]]) -> None:
    for c in range(4):
        for r in range(4):
            state[c][r] = INV_S_BOX[state[c][r]]


def shift_rows(state: list[list[int]]) -> None:
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[1][1],
        state[2][1],
        state[3][1],
        state[0][1],
    )
    state[0][2], state[1][2], state[2][2], state[3][2] = (
        state[2][2],
        state[3][2],
        state[0][2],
        state[1][2],
    )
    state[0][3], state[1][3], state[2][3], state[3][3] = (
        state[3][3],
        state[0][3],
        state[1][3],
        state[2][3],
    )


def inv_shift_rows(state: list[list[int]]) -> None:
    state[1][1], state[2][1], state[3][1], state[0][1] = (
        state[0][1],
        state[1][1],
        state[2][1],
        state[3][1],
    )
    state[2][2], state[3][2], state[0][2], state[1][2] = (
        state[0][2],
        state[1][2],
        state[2][2],
        state[3][2],
    )
    state[3][3], state[0][3], state[1][3], state[2][3] = (
        state[0][3],
        state[1][3],
        state[2][3],
        state[3][3],
    )


def _mix_column(a: list[int]) -> None:
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(state: list[list[int]]) -> None:
    for col in state:
        _mix_column(col)


def _inv_mix_column(a: list[int]) -> None:
    u = multiply(a[0], 0x0E) ^ multiply(a[1], 0x0B) ^ multiply(a[2], 0x0D) ^ multiply(a[3], 0x09)
    v = multiply(a[0], 0x09) ^ multiply(a[1], 0x0E) ^ multiply(a[2], 0x0B) ^ multiply(a[3], 0x0D)
    w = multiply(a[0], 0x0D) ^ multiply(a[1], 0x09) ^ multiply(a[2], 0x0E) ^ multiply(a[3], 0x0B)
    x = multiply(a[0], 0x0B) ^ multiply(a[1], 0x0D) ^ multiply(a[2], 0x09) ^ multiply(a[3], 0x0E)
    a[0], a[1], a[2], a[3] = u, v, w, x


def inv_mix_columns(state: list[list[int]]) -> None:
    for col in state:
        _inv_mix_column(col)


def key_expansion(key: bytes) -> list[list[int]]:
    words: list[list[int]] = [list(key[i : i + 4]) for i in range(0, AES_KEY_SIZE, 4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]
        words.append([words[i - 4][r] ^ temp[r] for r in range(4)])
    return words


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


def pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    if not data:
        raise ValueError("Empty data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length.")

    expected = bytes([pad_len] * pad_len)
    if not hmac.compare_digest(data[-pad_len:], expected):
        raise ValueError("Invalid padding bytes.")
    return data[:-pad_len]


class PureAES:
    def __init__(self, key: bytes) -> None:
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes (AES-128).")

        self._key_buf: bytearray = bytearray(key)
        self.key_schedule = key_expansion(bytes(self._key_buf))

    def clear(self) -> None:
        for i in range(len(self._key_buf)):
            self._key_buf[i] = 0

    def __del__(self) -> None:
        try:
            self.clear()
        except Exception:  # noqa: BLE001
            pass

    def encrypt(self, data: bytes) -> bytes:
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError("Plaintext length must be a multiple of 16.")
        out = b""
        for i in range(0, len(data), AES_BLOCK_SIZE):
            out += encrypt_block(data[i : i + AES_BLOCK_SIZE], self.key_schedule)
        return out

    def decrypt(self, data: bytes) -> bytes:
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of 16.")
        out = b""
        for i in range(0, len(data), AES_BLOCK_SIZE):
            out += decrypt_block(data[i : i + AES_BLOCK_SIZE], self.key_schedule)
        return out


def generate_short_key(bits: int, key_int: Optional[int] = None) -> bytes:
    validate_key_bits(bits)
    key_bytes_len = (bits + 7) // 8
    max_val = (1 << bits) - 1
    if key_int is None:
        key_int = int.from_bytes(os.urandom(4), "big") & max_val
    elif not 0 <= key_int <= max_val:
        raise ValueError(f"key_int must be in [0, 2^{bits} - 1].")
    return key_int.to_bytes(key_bytes_len, byteorder="big").ljust(AES_KEY_SIZE, b"\x00")


def key_int_to_bytes(key_int: int, key_bits: int) -> bytes:
    validate_key_bits(key_bits)
    max_val = (1 << key_bits) - 1
    if not 0 <= key_int <= max_val:
        raise ValueError(f"key_int must be in [0, 2^{key_bits} - 1].")
    key_bytes_len = (key_bits + 7) // 8
    return key_int.to_bytes(key_bytes_len, byteorder="big").ljust(AES_KEY_SIZE, b"\x00")


def encrypt_aes(
    plaintext: str,
    key_bits: int,
    key: Optional[bytes] = None,
    key_int: Optional[int] = None,
) -> Tuple[bytes, bytes, int]:
    validate_key_bits(key_bits)
    if key is None:
        key = generate_short_key(key_bits, key_int=key_int)
    cipher = PureAES(key)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8")))
    key_bytes_len = (key_bits + 7) // 8
    actual_int = int.from_bytes(key[:key_bytes_len], "big") & ((1 << key_bits) - 1)
    return ciphertext, key, actual_int


def decrypt_aes(ciphertext: bytes, key: bytes) -> Optional[str]:
    try:
        return unpad(PureAES(key).decrypt(ciphertext)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.strip())
