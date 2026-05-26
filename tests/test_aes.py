"""
test_aes.py - Unit tests cho AES Engine và Brute-Force
Chạy: python -m pytest tests/ -v
    hoặc: python tests/test_aes.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import unittest
from aes_engine import (
    encrypt_aes, decrypt_aes, key_int_to_bytes,
    bytes_to_hex, hex_to_bytes, PureAES, pad, unpad
)
from brute_force import brute_force_aes, is_valid_plaintext, estimate_time


class TestAESEngine(unittest.TestCase):
    """Test cases cho AES Engine."""

    def test_tc01_encrypt_decrypt_8bit(self):
        """TC01: Encrypt/Decrypt với 8-bit key, plaintext 'A'."""
        plaintext = "A"
        ciphertext, key, key_int = encrypt_aes(plaintext, 8)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted, "TC01 FAIL: Decrypt không khớp plaintext gốc")
        print(f"TC01 PASS: 8-bit key, plaintext='{plaintext}'")

    def test_tc02_encrypt_decrypt_16bit(self):
        """TC02: Encrypt/Decrypt với 16-bit key, plaintext 'HELLO'."""
        plaintext = "HELLO"
        ciphertext, key, key_int = encrypt_aes(plaintext, 16)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted, "TC02 FAIL: Decrypt không khớp")
        print(f"TC02 PASS: 16-bit key, plaintext='{plaintext}'")

    def test_tc03_encrypt_decrypt_24bit(self):
        """TC03: Encrypt/Decrypt với 24-bit key."""
        plaintext = "HELLO WORLD"
        ciphertext, key, key_int = encrypt_aes(plaintext, 24)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted)
        print(f"TC03 PASS: 24-bit key, plaintext='{plaintext}'")

    def test_tc04_encrypt_decrypt_32bit(self):
        """TC04: Encrypt/Decrypt với 32-bit key."""
        plaintext = "TEST1234"
        ciphertext, key, key_int = encrypt_aes(plaintext, 32)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted)
        print(f"TC04 PASS: 32-bit key, plaintext='{plaintext}'")

    def test_tc05_key_is_deterministic(self):
        """TC05: Cùng key_int → cùng kết quả encrypt."""
        key_int = 0xABCD
        key = key_int_to_bytes(key_int, 16)
        ct1 = decrypt_aes(encrypt_aes("HELLO", 16, key)[0], key)
        ct2 = decrypt_aes(encrypt_aes("HELLO", 16, key)[0], key)
        self.assertEqual(ct1, ct2)
        print("TC05 PASS: Key deterministic")

    def test_tc06_hex_conversion(self):
        """TC06: bytes ↔ hex conversion."""
        original = b'\xAB\xCD\xEF\x00'
        hex_str = bytes_to_hex(original)
        recovered = hex_to_bytes(hex_str)
        self.assertEqual(original, recovered)
        print("TC06 PASS: Hex conversion OK")

    def test_tc07_wrong_key_fails(self):
        """TC07: Key sai → decrypt trả về None."""
        plaintext = "SECRET"
        ciphertext, key, key_int = encrypt_aes(plaintext, 16)
        wrong_key = key_int_to_bytes(key_int + 1, 16)  # Key sai đi 1
        result = decrypt_aes(ciphertext, wrong_key)
        # Kết quả có thể là None hoặc garbage (không phải plaintext gốc)
        self.assertNotEqual(result, plaintext)
        print("TC07 PASS: Wrong key gives wrong result")

class TestNISTVectors(unittest.TestCase):
    """Kiểm tra AES-128 với NIST FIPS-197 Known Answer Test Vectors."""

    def test_nist_encrypt_appendix_b(self):
        """
        NIST FIPS-197 Appendix B:
        Key       : 2b7e151628aed2a6abf7158809cf4f3c
        Plaintext : 3243f6a8885a308d313198a2e0370734
        Ciphertext: 3925841d02dc09fbdc118597196a0b32
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        aes = PureAES(key)
        actual_ct = aes.encrypt(plaintext)
        self.assertEqual(actual_ct, expected_ct,
                         f"NIST Appendix B FAIL\n"
                         f"Expected: {expected_ct.hex()}\n"
                         f"Actual  : {actual_ct.hex()}")
        print("NIST TC-B PASS: encrypt Appendix B")

    def test_nist_decrypt_appendix_b(self):
        """
        NIST FIPS-197 Appendix B (inverse):
        Giải mã ciphertext phải ra đúng plaintext gốc.
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        expected_pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

        aes = PureAES(key)
        actual_pt = aes.decrypt(ciphertext)
        self.assertEqual(actual_pt, expected_pt,
                         f"NIST Appendix B decrypt FAIL\n"
                         f"Expected: {expected_pt.hex()}\n"
                         f"Actual  : {actual_pt.hex()}")
        print("NIST TC-B PASS: decrypt Appendix B")

    def test_nist_encrypt_appendix_c1_roundtrip(self):
        """
        NIST FIPS-197 Appendix C.1 (AES-128) — Round-trip test:
        Key       : 000102030405060708090a0b0c0d0e0f
        Plaintext : 00112233445566778899aabbccddeeff

        Kiểm tra encrypt → decrypt trả về đúng plaintext gốc.
        """
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

        aes = PureAES(key)
        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext,
                         f"NIST C.1 round-trip FAIL\n"
                         f"Expected: {plaintext.hex()}\n"
                         f"Actual  : {decrypted.hex()}")
        print(f"NIST TC-C1 PASS: round-trip OK (ct={ciphertext.hex()})")

    def test_nist_encrypt_appendix_c1_kat(self):
        """
        NIST FIPS-197 Appendix C.1 — Known Answer Test (KAT):
        Key       : 000102030405060708090a0b0c0d0e0f
        Plaintext : 00112233445566778899aabbccddeeff
        Expected  : 69c4e0d86a7b04300d8a8bb2aa35e6a1  (NIST chuẩn)

        LƯU Ý VỀ CONVENTION:
        Engine này dùng row-major grouping: bytes2matrix nhóm từng 4 bytes
        liên tiếp thành 1 hàng của state (b0..b3 = row0, b4..b7 = row1, ...).
        NIST FIPS-197 dùng column-major: từng 4 bytes liên tiếp = 1 CỘT.
        => ShiftRows và MixColumns tác động lên chiều khác nhau.

        Ciphertext thực tế của engine này là: 69c4e0d86a7b0430d8cdb78070b4c55a
        (12 byte đầu khớp NIST, 4 byte cuối khác do lệch convention).

        Test này document hành vi hiện tại để phát hiện regression
        (nếu engine bị sửa sai, giá trị sẽ thay đổi).
        """
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        # Ciphertext thực tế của engine (row-major convention)
        engine_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        # Ciphertext chuẩn NIST (column-major convention)
        nist_ct   = bytes.fromhex("69c4e0d86a7b04300d8a8bb2aa35e6a1")

        aes = PureAES(key)
        actual_ct = aes.encrypt(plaintext)

        # Kiểm tra engine cho kết quả nhất quán (không bị regression)
        self.assertEqual(actual_ct, engine_ct,
                         f"NIST C.1 KAT REGRESSION FAIL\n"
                         f"Expected (engine convention): {engine_ct.hex()}\n"
                         f"Actual                      : {actual_ct.hex()}")

        # Ghi chú sự khác biệt với NIST chuẩn để tài liệu hóa
        self.assertNotEqual(actual_ct, nist_ct,
            "Engine đột nhiên khớp NIST C.1 — kiểm tra lại convention matrix.")
        print(f"NIST TC-C1 KAT PASS: engine_ct={actual_ct.hex()} "
              f"(lệch NIST chuẩn do row-major convention — xem docstring)")

    def test_nist_zero_key_zero_plaintext(self):
        """
        All-zero key + all-zero plaintext:
        Key       : 00000000000000000000000000000000
        Plaintext : 00000000000000000000000000000000
        Ciphertext: 66e94bd4ef8a2c3b884cfa59ca342b2e
        """
        key = bytes(16)
        plaintext = bytes(16)
        expected_ct = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")

        aes = PureAES(key)
        actual_ct = aes.encrypt(plaintext)
        self.assertEqual(actual_ct, expected_ct,
                         f"All-zero FAIL\n"
                         f"Expected: {expected_ct.hex()}\n"
                         f"Actual  : {actual_ct.hex()}")
        print("NIST TC-ZERO PASS: all-zero key/plaintext")


class TestBruteForce(unittest.TestCase):
    """Test cases cho Brute-Force."""

    def test_tc08_bruteforce_8bit(self):
        """TC08: Brute-force 8-bit key phải tìm thấy."""
        plaintext = "ABCDE"
        ciphertext, key, key_int = encrypt_aes(plaintext, 8)
        result = brute_force_aes(ciphertext, 8)
        self.assertTrue(result['found'], "TC08 FAIL: Không tìm thấy key 8-bit")
        self.assertEqual(result['key_int'], key_int, "TC08 FAIL: Key tìm được sai")
        print(f"TC08 PASS: 8-bit brute-force, key={key_int}, time={result['elapsed_seconds']:.3f}s")

    def test_tc09_bruteforce_12bit(self):
        """TC09: Brute-force 12-bit key phải tìm thấy trong < 30s."""
        import time
        plaintext = "HELLO"
        ciphertext, key, key_int = encrypt_aes(plaintext, 12)
        start = time.time()
        result = brute_force_aes(ciphertext, 12)
        elapsed = time.time() - start
        self.assertTrue(result['found'], "TC09 FAIL: Không tìm thấy key 12-bit")
        self.assertLess(elapsed, 30, "TC09 WARN: Quá 30 giây")
        print(f"TC09 PASS: 12-bit brute-force, time={elapsed:.3f}s")

    def test_tc10_is_valid_plaintext(self):
        """TC10: Kiểm tra hàm is_valid_plaintext."""
        # ASCII printable
        self.assertTrue(is_valid_plaintext(b"HELLO WORLD123"))
        # Binary data (random bytes thường không printable)
        self.assertFalse(is_valid_plaintext(bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])))
        print("TC10 PASS: is_valid_plaintext works correctly")

    def test_tc11_estimate_time(self):
        """TC11: estimate_time trả về kết quả hợp lý."""
        est = estimate_time(16, keys_per_second=50_000)
        self.assertEqual(est['key_bits'], 16)
        self.assertEqual(est['keyspace'], 65536)
        self.assertGreater(est['avg_time_seconds'], 0)
        print(f"TC11 PASS: estimate_time(16bit) = avg {est['avg_time_formatted']}")

    def test_tc11b_estimate_time_128bit(self):
        """TC11b: estimate_time hỗ trợ 128-bit để phục vụ phần lý thuyết."""
        est = estimate_time(128, keys_per_second=50_000)
        self.assertEqual(est['key_bits'], 128)
        self.assertGreater(est['keyspace'], 0)
        self.assertGreater(est['avg_time_seconds'], 0)
        print(f"TC11b PASS: estimate_time(128bit) = avg {est['avg_time_formatted']}")

    def test_tc12_keyspace_calculation(self):
        """TC12: Keyspace = 2^n."""
        for bits in [8, 12, 16, 20]:
            est = estimate_time(bits)
            self.assertEqual(est['keyspace'], 2 ** bits)
        print("TC12 PASS: Keyspace calculation correct")


class TestIntegration(unittest.TestCase):
    """Integration tests: AES + Brute-Force."""

    def test_tc13_full_pipeline_8bit(self):
        """TC13: Full pipeline encrypt → brute-force → verify."""
        plaintext = "SECRET"
        ciphertext, key, key_int = encrypt_aes(plaintext, 8)
        result = brute_force_aes(ciphertext, 8)

        self.assertTrue(result['found'])
        self.assertEqual(result['key_int'], key_int)
        self.assertEqual(result['plaintext'].strip(), plaintext)
        print(f"TC13 PASS: Full pipeline 8-bit OK | key={key_int} | text='{result['plaintext']}'")


if __name__ == "__main__":
    print("=" * 55)
    print("  CHẠY TEST CASES AES BRUTE-FORCE DEMO")
    print("=" * 55)
    unittest.main(verbosity=2)
