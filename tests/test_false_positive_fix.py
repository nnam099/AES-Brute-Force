"""
Regression test: reproduce the exact false-positive bug from the bug report.

Scenario
--------
plaintext  = "danhlodai"
key_bits   = 32
key_int    = 394272804  (0x17802024)
ciphertext = BFF5C2750970A2CB90ECC93269701577

Before the fix, the brute-force stopped at key 44205071 (0x02A2840F) because
its decryption produced a 13-char printable-ASCII string that passed the
heuristic score threshold (>= 0.9).

After the fix, when `known_plaintext` is supplied the engine does a
byte-for-byte exact comparison, so only the true key is ever accepted.
"""

import pytest
from aes_brute_force.core.aes_engine import PureAES, pad, unpad
from aes_brute_force.core.brute_force import brute_force_aes, score_plaintext

PLAINTEXT = "danhlodai"
KEY_INT_CORRECT = 394272804       # 0x17802024
KEY_INT_FALSE_POS = 44205071      # 0x02A2840F  — the false positive from the bug report
KEY_BITS = 32
EXPECTED_CT_HEX = "BFF5C2750970A2CB90ECC93269701577"


def _make_key(key_int: int) -> bytes:
    return key_int.to_bytes(4, "big").ljust(16, b"\x00")


def _encrypt(plaintext: str, key_int: int) -> bytes:
    key = _make_key(key_int)
    return PureAES(key).encrypt(pad(plaintext.encode(), 16))


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def ciphertext() -> bytes:
    ct = _encrypt(PLAINTEXT, KEY_INT_CORRECT)
    assert ct.hex().upper() == EXPECTED_CT_HEX, "Ciphertext mismatch — AES engine changed?"
    return ct


# ── test 1: prove the false positive still triggers in heuristic mode ────────

def test_false_positive_key_passes_heuristic(ciphertext):
    """Key 0x02A2840F decrypts to valid-padded, printable ASCII → would fool heuristic."""
    key = _make_key(KEY_INT_FALSE_POS)
    raw = PureAES(key).decrypt(ciphertext)
    unpadded = unpad(raw, 16)           # must NOT raise — padding is valid
    score = score_plaintext(unpadded)
    assert score >= 0.9, (
        f"Expected false-positive key to have score >= 0.9, got {score:.2f}. "
        "The bug may have changed character."
    )
    assert unpadded.decode("utf-8") != PLAINTEXT, (
        "False-positive key should NOT decrypt to the real plaintext."
    )


# ── test 2: exact-match mode must reject the false positive ─────────────────

def test_exact_match_rejects_false_positive_key(ciphertext):
    """In exact-match mode the false-positive key must NOT be returned."""
    # We run a very limited range that only covers key 0 … KEY_INT_FALSE_POS+1000
    # (far below the true key) so the search ends quickly.
    # If the fix is working, "found" must be False in this range.
    from aes_brute_force.core.brute_force import _bruteforce_worker
    start = KEY_INT_FALSE_POS
    end   = KEY_INT_FALSE_POS + 1   # only that exact key
    result = _bruteforce_worker((
        start, end,
        KEY_BITS, ciphertext,
        0.9,          # threshold (irrelevant in exact-match mode)
        False,        # fast_mode
        PLAINTEXT.encode("utf-8"),   # known_plaintext_bytes  ← exact-match
    ))
    assert not result["found"], (
        f"False-positive key {KEY_INT_FALSE_POS} was accepted even with exact-match mode! "
        f"Result: {result}"
    )


# ── test 3: exact-match mode must find the TRUE key ─────────────────────────

def test_exact_match_finds_correct_key(ciphertext):
    """In exact-match mode the worker returns the correct key and plaintext."""
    from aes_brute_force.core.brute_force import _bruteforce_worker
    start = KEY_INT_CORRECT
    end   = KEY_INT_CORRECT + 1
    result = _bruteforce_worker((
        start, end,
        KEY_BITS, ciphertext,
        0.9,
        False,
        PLAINTEXT.encode("utf-8"),
    ))
    assert result["found"], "Correct key was NOT found in exact-match mode."
    assert result["key_int"] == KEY_INT_CORRECT
    assert result["plaintext"] == PLAINTEXT


# ── test 4: full integration — brute_force_aes with known_plaintext ──────────

def test_brute_force_exact_match_end_to_end():
    """
    Full end-to-end: encrypt with a small 16-bit key then brute-force it
    using exact-match mode.  Verifies no false positive is returned before
    the correct key.
    """
    plaintext = "hello"
    key_bits  = 16
    key_int   = 0xABCD

    key = key_int.to_bytes(2, "big").ljust(16, b"\x00")
    ct  = PureAES(key).encrypt(pad(plaintext.encode(), 16))

    result = brute_force_aes(
        ct,
        key_bits=key_bits,
        workers=4,
        known_plaintext=plaintext,
        fast_mode=False,
    )
    assert result["found"], "Key not found in 16-bit keyspace."
    assert result["key_int"] == key_int, (
        f"Wrong key returned: {result['key_int']} (expected {key_int})"
    )
    assert result["plaintext"] == plaintext


# ── test 5: heuristic mode still works when known_plaintext is None ──────────

def test_heuristic_mode_still_works():
    """Without known_plaintext, the old score-based heuristic must still find keys."""
    plaintext = "hello"
    key_bits  = 8
    key_int   = 0x42

    key = key_int.to_bytes(1, "big").ljust(16, b"\x00")
    ct  = PureAES(key).encrypt(pad(plaintext.encode(), 16))

    result = brute_force_aes(
        ct,
        key_bits=key_bits,
        workers=1,
        known_plaintext=None,   # heuristic mode
        fast_mode=False,
    )
    assert result["found"]
    assert result["key_int"] == key_int
    assert result["plaintext"] == plaintext
