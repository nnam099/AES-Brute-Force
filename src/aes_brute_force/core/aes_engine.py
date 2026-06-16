"""
Pure-Python AES-128 engine (ECB mode, PKCS#7 padding).

Written from scratch to expose the mathematical steps:
SubBytes, ShiftRows, MixColumns over GF(2^8), AddRoundKey, and KeyExpansion.

For the brute-force demo the key is always 16 bytes but only the leading
*n* bits carry entropy; the rest is zero-padded.
"""

from __future__ import annotations

import os
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

# ---------------------------------------------------------------------------
# GF(2^8) arithmetic
# ---------------------------------------------------------------------------

def xtime(a: int) -> int:
    """Multiply by x (i.e. {02}) in GF(2^8)."""
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def multiply(x: int, y: int) -> int:
    """Multiply two bytes in GF(2^8) with irreducible polynomial 0x11B."""
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


# ---------------------------------------------------------------------------
# Precomputed GF(2^8) multiplication tables for InvMixColumns
#
# InvMixColumns uses multiply-by-{09, 0B, 0D, 0E} on every column of every
# round during decryption.  With 9 rounds × 4 columns × 16 multiply() calls
# = 576 calls per block, each running an 8-iteration loop.  Replacing them
# with O(1) table lookups is the single biggest speedup for PureAES.
# ---------------------------------------------------------------------------

def _build_mul_table(constant: int) -> tuple[int, ...]:
    """Precompute multiply(a, constant) for a in [0..255]."""
    return tuple(multiply(a, constant) for a in range(256))

_MUL_09: tuple[int, ...] = _build_mul_table(0x09)
_MUL_0B: tuple[int, ...] = _build_mul_table(0x0B)
_MUL_0D: tuple[int, ...] = _build_mul_table(0x0D)
_MUL_0E: tuple[int, ...] = _build_mul_table(0x0E)


# ---------------------------------------------------------------------------
# State helpers (column-major: state[col][row])
# ---------------------------------------------------------------------------

def bytes2matrix(data: bytes) -> list[list[int]]:
    """Convert 16 bytes into a 4x4 column-major state matrix."""
    return [list(data[i : i + 4]) for i in range(0, AES_BLOCK_SIZE, 4)]


def matrix2bytes(matrix: list[list[int]]) -> bytes:
    """Flatten a 4x4 state matrix back to 16 bytes."""
    return bytes(sum(matrix, []))


# ---------------------------------------------------------------------------
# AES round operations
# ---------------------------------------------------------------------------

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
    """Rotate left each row *r* by *r* positions (column-major convention)."""
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[1][1], state[2][1], state[3][1], state[0][1]
    )
    state[0][2], state[1][2], state[2][2], state[3][2] = (
        state[2][2], state[3][2], state[0][2], state[1][2]
    )
    state[0][3], state[1][3], state[2][3], state[3][3] = (
        state[3][3], state[0][3], state[1][3], state[2][3]
    )


def inv_shift_rows(state: list[list[int]]) -> None:
    state[1][1], state[2][1], state[3][1], state[0][1] = (
        state[0][1], state[1][1], state[2][1], state[3][1]
    )
    state[2][2], state[3][2], state[0][2], state[1][2] = (
        state[0][2], state[1][2], state[2][2], state[3][2]
    )
    state[3][3], state[0][3], state[1][3], state[2][3] = (
        state[0][3], state[1][3], state[2][3], state[3][3]
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
    # Table lookups instead of 16 × multiply() calls (each with 8-iter loop).
    a0, a1, a2, a3 = a[0], a[1], a[2], a[3]
    a[0] = _MUL_0E[a0] ^ _MUL_0B[a1] ^ _MUL_0D[a2] ^ _MUL_09[a3]
    a[1] = _MUL_09[a0] ^ _MUL_0E[a1] ^ _MUL_0B[a2] ^ _MUL_0D[a3]
    a[2] = _MUL_0D[a0] ^ _MUL_09[a1] ^ _MUL_0E[a2] ^ _MUL_0B[a3]
    a[3] = _MUL_0B[a0] ^ _MUL_0D[a1] ^ _MUL_09[a2] ^ _MUL_0E[a3]


def inv_mix_columns(state: list[list[int]]) -> None:
    for col in state:
        _inv_mix_column(col)


# ---------------------------------------------------------------------------
# Key expansion
# ---------------------------------------------------------------------------

def key_expansion(key: bytes) -> list[list[int]]:
    """Expand 16-byte key into 44 round-key words for 10-round AES-128."""
    words: list[list[int]] = [list(key[i : i + 4]) for i in range(0, AES_KEY_SIZE, 4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]
        words.append([words[i - 4][r] ^ temp[r] for r in range(4)])
    return words


# ---------------------------------------------------------------------------
# Block encrypt / decrypt
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding (always adds at least 1 byte)."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """Remove and validate PKCS#7 padding."""
    if not data:
        raise ValueError("Empty data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes.")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# High-level PureAES class (ECB mode)
# ---------------------------------------------------------------------------

class PureAES:
    """AES-128 ECB cipher using pure-Python internals."""

    def __init__(self, key: bytes) -> None:
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes (AES-128).")
        self.key_schedule = key_expansion(key)

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


# ---------------------------------------------------------------------------
# Demo key helpers
# ---------------------------------------------------------------------------

def generate_short_key(bits: int, key_int: Optional[int] = None) -> bytes:
    """Create a 16-byte AES key with only the leading *bits* carrying entropy."""
    validate_key_bits(bits)
    key_bytes_len = (bits + 7) // 8
    max_val = (1 << bits) - 1
    if key_int is None:
        key_int = int.from_bytes(os.urandom(4), "big") & max_val
    elif not 0 <= key_int <= max_val:
        raise ValueError(f"key_int must be in [0, 2^{bits} - 1].")
    return key_int.to_bytes(key_bytes_len, byteorder="big").ljust(AES_KEY_SIZE, b"\x00")


def key_int_to_bytes(key_int: int, key_bits: int) -> bytes:
    """Convert an integer in ``[0, 2^key_bits)`` to a 16-byte demo key."""
    validate_key_bits(key_bits)
    max_val = (1 << key_bits) - 1
    if not 0 <= key_int <= max_val:
        raise ValueError(f"key_int must be in [0, 2^{key_bits} - 1].")
    key_bytes_len = (key_bits + 7) // 8
    return key_int.to_bytes(key_bytes_len, byteorder="big").ljust(AES_KEY_SIZE, b"\x00")


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def encrypt_aes(
    plaintext: str,
    key_bits: int,
    key: Optional[bytes] = None,
    key_int: Optional[int] = None,
) -> Tuple[bytes, bytes, int]:
    """Encrypt a UTF-8 string with a short demo key, return (ciphertext, key, key_int)."""
    validate_key_bits(key_bits)
    if key is None:
        key = generate_short_key(key_bits, key_int=key_int)
    cipher = PureAES(key)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8")))
    key_bytes_len = (key_bits + 7) // 8
    actual_int = int.from_bytes(key[:key_bytes_len], "big") & ((1 << key_bits) - 1)
    return ciphertext, key, actual_int


def decrypt_aes(ciphertext: bytes, key: bytes) -> Optional[str]:
    """Decrypt and return the UTF-8 plaintext, or ``None`` on failure."""
    try:
        return unpad(PureAES(key).decrypt(ciphertext)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.strip())
