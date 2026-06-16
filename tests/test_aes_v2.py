"""
Tests for the AES engine, brute-force logic, and benchmark utilities.

Run: pytest tests/ -v
"""

import os
import tempfile
import unittest

from aes_brute_force.core.aes_engine import (
    PureAES,
    bytes_to_hex,
    decrypt_aes,
    encrypt_aes,
    hex_to_bytes,
    key_int_to_bytes,
    pad,
    unpad,
)
from aes_brute_force.core.brute_force import brute_force_aes, estimate_time, is_valid_plaintext
from aes_brute_force.benchmark.runner import benchmark_key_length, parse_args, resolve_output_paths


# ── AES Engine Tests ───────────────────────────────────────

class TestAESEngine(unittest.TestCase):
    """Core encrypt / decrypt round-trips."""

    def test_tc01_8bit(self):
        ct, key, ki = encrypt_aes("A", 8)
        self.assertEqual(decrypt_aes(ct, key), "A")

    def test_tc02_16bit(self):
        ct, key, ki = encrypt_aes("HELLO", 16)
        self.assertEqual(decrypt_aes(ct, key), "HELLO")

    def test_tc03_24bit(self):
        ct, key, ki = encrypt_aes("HELLO WORLD", 24)
        self.assertEqual(decrypt_aes(ct, key), "HELLO WORLD")

    def test_tc04_32bit(self):
        ct, key, ki = encrypt_aes("TEST1234", 32)
        self.assertEqual(decrypt_aes(ct, key), "TEST1234")

    def test_tc05_deterministic(self):
        key = key_int_to_bytes(0xABCD, 16)
        r1 = decrypt_aes(encrypt_aes("HELLO", 16, key)[0], key)
        r2 = decrypt_aes(encrypt_aes("HELLO", 16, key)[0], key)
        self.assertEqual(r1, r2)

    def test_tc06_hex_roundtrip(self):
        original = b"\xAB\xCD\xEF\x00"
        self.assertEqual(hex_to_bytes(bytes_to_hex(original)), original)

    def test_tc07_wrong_key(self):
        ct, key, ki = encrypt_aes("SECRET", 16)
        wrong = key_int_to_bytes(ki + 1, 16)
        self.assertNotEqual(decrypt_aes(ct, wrong), "SECRET")


# ── NIST FIPS-197 Known Answer Tests ──────────────────────

class TestNISTVectors(unittest.TestCase):
    """Validate against official NIST FIPS-197 test vectors."""

    def test_appendix_b_encrypt(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(PureAES(key).encrypt(pt), expected)

    def test_appendix_b_decrypt(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        expected = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        self.assertEqual(PureAES(key).decrypt(ct), expected)

    def test_appendix_c1_roundtrip(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        aes = PureAES(key)
        self.assertEqual(aes.decrypt(aes.encrypt(pt)), pt)

    def test_appendix_c1_kat(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(PureAES(key).encrypt(pt), expected)

    def test_zero_key_zero_plaintext(self):
        expected = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")
        self.assertEqual(PureAES(bytes(16)).encrypt(bytes(16)), expected)


# ── Brute-Force Tests ─────────────────────────────────────

class TestBruteForce(unittest.TestCase):

    def test_tc08_8bit(self):
        ct, key, ki = encrypt_aes("ABCDE", 8)
        result = brute_force_aes(ct, 8)
        self.assertTrue(result["found"])
        self.assertEqual(result["key_int"], ki)

    def test_tc09_12bit(self):
        import time
        ct, key, ki = encrypt_aes("HELLO", 12)
        t0 = time.time()
        result = brute_force_aes(ct, 12)
        self.assertTrue(result["found"])
        self.assertLess(time.time() - t0, 30)

    def test_tc10_is_valid_plaintext(self):
        self.assertTrue(is_valid_plaintext(b"HELLO WORLD123"))
        self.assertFalse(is_valid_plaintext(bytes([0, 1, 2, 3, 4, 5, 6])))

    def test_tc11_estimate_time(self):
        est = estimate_time(16, keys_per_second=50_000)
        self.assertEqual(est["keyspace"], 65536)
        self.assertGreater(est["avg_time_seconds"], 0)

    def test_tc11b_estimate_128bit(self):
        est = estimate_time(128, keys_per_second=50_000)
        self.assertEqual(est["key_bits"], 128)

    def test_tc12_keyspace(self):
        for bits in [8, 12, 16, 20]:
            self.assertEqual(estimate_time(bits)["keyspace"], 2**bits)


# ── Integration Tests ─────────────────────────────────────

class TestIntegration(unittest.TestCase):

    def test_tc13_full_pipeline_8bit(self):
        ct, key, ki = encrypt_aes("SECRET", 8)
        result = brute_force_aes(ct, 8)
        self.assertTrue(result["found"])
        self.assertEqual(result["key_int"], ki)
        self.assertEqual(result["plaintext"].strip(), "SECRET")


# ── Benchmark Utility Tests ───────────────────────────────

class TestBenchmark(unittest.TestCase):

    def test_tc14_hex_key_int(self):
        args = parse_args(["--bits", "8", "--key-int", "0x2A", "--no-plot", "--no-json"])
        self.assertEqual(args.key_int, 42)

    def test_tc15_fixed_key(self):
        result = benchmark_key_length(8, test_text="SECRET", verbose=False, key_int=42)
        self.assertTrue(result["found"])
        self.assertEqual(result["actual_key_int"], 42)
        self.assertEqual(result["found_key_int"], 42)

    def test_tc16_output_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            chart, data = resolve_output_paths(None, None, tmp, False, False)
            self.assertTrue(chart.endswith(os.path.join(tmp, "benchmark_chart.png")))
            self.assertTrue(data.endswith(os.path.join(tmp, "benchmark_data.json")))

    def test_tc17_no_output(self):
        chart, data = resolve_output_paths(None, None, None, True, True)
        self.assertIsNone(chart)
        self.assertIsNone(data)


# ── Edge Case Tests ───────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    """Edge cases and boundary conditions found in code review."""

    # --- AES edge cases ---

    def test_key_int_zero(self):
        """key_int=0 (all-zero key) must encrypt and decrypt correctly."""
        key = key_int_to_bytes(0, 8)
        ct, _, ki = encrypt_aes("ZERO", 8, key=key)
        self.assertEqual(ki, 0)
        self.assertEqual(decrypt_aes(ct, key), "ZERO")

    def test_key_int_max(self):
        """key_int=2^n-1 (max key) must encrypt and decrypt correctly."""
        key = key_int_to_bytes(0xFF, 8)
        ct, _, ki = encrypt_aes("MAX", 8, key=key)
        self.assertEqual(ki, 0xFF)
        self.assertEqual(decrypt_aes(ct, key), "MAX")

    def test_unpad_invalid_padding_bytes(self):
        """unpad should raise ValueError on malformed PKCS#7 padding."""
        bad = bytes(15) + b"\x02"   # claims pad=2 but only 1 pad byte matches
        with self.assertRaises(ValueError):
            unpad(bad)

    def test_unpad_empty(self):
        """unpad should raise ValueError on empty input."""
        with self.assertRaises(ValueError):
            unpad(b"")

    def test_pad_unpad_roundtrip(self):
        """pad then unpad must be identity for various lengths."""
        import pytest
        for n in [1, 15, 16, 17, 31, 32]:
            data = bytes(range(n % 256)) * (n // 256 + 1)
            data = data[:n]
            self.assertEqual(unpad(pad(data)), data)

    # --- Brute-force edge cases ---

    def test_bf_invalid_ciphertext_empty(self):
        """brute_force_aes must raise ValueError on empty ciphertext."""
        with self.assertRaises(ValueError):
            brute_force_aes(b"", 8)

    def test_bf_invalid_ciphertext_wrong_length(self):
        """brute_force_aes must raise ValueError when len % 16 != 0."""
        with self.assertRaises(ValueError):
            brute_force_aes(b"\x00" * 15, 8)

    def test_bf_key_int_zero(self):
        """Brute-force must find key_int=0 (first key tried)."""
        key = key_int_to_bytes(0, 8)
        ct, _, ki = encrypt_aes("HELLO", 8, key=key)
        result = brute_force_aes(ct, 8)
        self.assertTrue(result["found"])
        self.assertEqual(result["key_int"], 0)

    def test_bf_stop_flag_terminates(self):
        """stop_flag.set() must terminate brute-force before exhaustion."""
        import threading
        ct, _, _ = encrypt_aes("TEST", 16)
        stop = threading.Event()
        stop.set()   # set immediately — should stop after first check
        result = brute_force_aes(ct, 16, stop_flag=stop)
        # Either stopped early (not found) or found key=0 on first try
        self.assertIn("keys_tested", result)
        self.assertLess(result["keys_tested"], 65536)

    # --- Parametrize-style round-trips ---

    def test_roundtrip_parametrized(self):
        """Round-trip for multiple (text, bits) combinations."""
        cases = [
            ("A", 8),
            ("Hello World", 12),
            ("0123456789ABCDEF", 16),
            ("x" * 100, 8),
        ]
        for text, bits in cases:
            with self.subTest(text=text[:20], bits=bits):
                ct, key, _ = encrypt_aes(text, bits)
                self.assertEqual(decrypt_aes(ct, key), text)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ── Security Tests ────────────────────────────────────────

class TestSecurity(unittest.TestCase):
    """Verify security hardening introduced in the review fixes."""

    def test_unpad_valid_padding(self):
        """unpad must return correct data for valid PKCS#7 padding."""
        padded = b"A" + bytes([15] * 15)
        self.assertEqual(unpad(padded), b"A")

    def test_unpad_rejects_wrong_byte(self):
        """unpad must reject padding where one byte differs (timing-safe path).

        Construct a 16-byte block where pad_len=2 (last byte=0x02), but the
        second-to-last byte is 0x01 instead of 0x02 — so the expected padding
        [0x02, 0x02] does not match [0x01, 0x02].
        """
        # 14 bytes of data + 0x01 + 0x02 → pad_len=2, expected=[2,2], actual=[1,2]
        bad = bytes([0xAA] * 14) + bytes([0x01, 0x02])
        with self.assertRaises(ValueError):
            unpad(bad)


    def test_pure_aes_key_zeroize(self):
        """PureAES.clear() must overwrite the internal key buffer with zeros."""
        key = bytes(range(16))
        cipher = PureAES(key)
        cipher.clear()
        self.assertEqual(bytes(cipher._key_buf), bytes(16))

    def test_pure_aes_nist_after_refactor(self):
        """PureAES with bytearray key buf must still pass FIPS-197 Appendix B."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(PureAES(key).encrypt(pt), expected)

    def test_pure_aes_key_buf_independent_of_schedule(self):
        """key_schedule is pre-expanded from original key, independent of key_buf.
        This documents expected behavior: clear() zeroes the buffer but the
        pre-expanded schedule (used for encrypt/decrypt) remains intact."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        cipher = PureAES(key)
        cipher.clear()
        self.assertEqual(bytes(cipher._key_buf), bytes(16))
        # key_schedule still valid — encrypt should not raise
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        self.assertEqual(len(cipher.encrypt(pt)), 16)
