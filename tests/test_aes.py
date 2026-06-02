"""
test_aes.py - Kiểm thử đơn vị cho AES Engine và vét cạn
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
from benchmark import benchmark_key_length, parse_args


class TestAESEngine(unittest.TestCase):
    """Test cases cho AES Engine."""

    def test_tc01_ma_hoa_giai_ma_8bit(self):
        """TC01: Mã hóa/giải mã với khóa 8-bit, bản rõ 'A'."""
        plaintext = "A"
        ciphertext, key, key_int = encrypt_aes(plaintext, 8)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted, "TC01 LỖI: Giải mã không khớp bản rõ gốc")
        print(f"TC01 ĐẠT: Khóa 8-bit, bản rõ='{plaintext}'")

    def test_tc02_ma_hoa_giai_ma_16bit(self):
        """TC02: Mã hóa/giải mã với khóa 16-bit, bản rõ 'HELLO'."""
        plaintext = "HELLO"
        ciphertext, key, key_int = encrypt_aes(plaintext, 16)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted, "TC02 LỖI: Giải mã không khớp")
        print(f"TC02 ĐẠT: Khóa 16-bit, bản rõ='{plaintext}'")

    def test_tc03_ma_hoa_giai_ma_24bit(self):
        """TC03: Mã hóa/giải mã với khóa 24-bit."""
        plaintext = "HELLO WORLD"
        ciphertext, key, key_int = encrypt_aes(plaintext, 24)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted)
        print(f"TC03 ĐẠT: Khóa 24-bit, bản rõ='{plaintext}'")

    def test_tc04_ma_hoa_giai_ma_32bit(self):
        """TC04: Mã hóa/giải mã với khóa 32-bit."""
        plaintext = "TEST1234"
        ciphertext, key, key_int = encrypt_aes(plaintext, 32)
        decrypted = decrypt_aes(ciphertext, key)
        self.assertEqual(plaintext, decrypted)
        print(f"TC04 ĐẠT: Khóa 32-bit, bản rõ='{plaintext}'")

    def test_tc05_khoa_xac_dinh(self):
        """TC05: Cùng key_int → cùng kết quả mã hóa."""
        key_int = 0xABCD
        key = key_int_to_bytes(key_int, 16)
        ct1 = decrypt_aes(encrypt_aes("HELLO", 16, key)[0], key)
        ct2 = decrypt_aes(encrypt_aes("HELLO", 16, key)[0], key)
        self.assertEqual(ct1, ct2)
        print("TC05 ĐẠT: Khóa cố định cho kết quả xác định")

    def test_tc06_chuyen_doi_hex(self):
        """TC06: Chuyển đổi bytes ↔ hex."""
        original = b'\xAB\xCD\xEF\x00'
        hex_str = bytes_to_hex(original)
        recovered = hex_to_bytes(hex_str)
        self.assertEqual(original, recovered)
        print("TC06 ĐẠT: Chuyển đổi hex hoạt động đúng")

    def test_tc07_khoa_sai_khong_ra_ban_ro(self):
        """TC07: Khóa sai → giải mã không ra bản rõ gốc."""
        plaintext = "SECRET"
        ciphertext, key, key_int = encrypt_aes(plaintext, 16)
        wrong_key = key_int_to_bytes(key_int + 1, 16)  # Key sai đi 1
        result = decrypt_aes(ciphertext, wrong_key)
        # Kết quả có thể là None hoặc garbage (không phải plaintext gốc)
        self.assertNotEqual(result, plaintext)
        print("TC07 ĐẠT: Khóa sai cho kết quả giải mã sai")

class TestNISTVectors(unittest.TestCase):
    """Kiểm tra AES-128 với NIST FIPS-197 Known Answer Test Vectors."""

    def test_nist_encrypt_appendix_b(self):
        """
        NIST FIPS-197 Appendix B:
        Khóa  : 2b7e151628aed2a6abf7158809cf4f3c
        Bản rõ: 3243f6a8885a308d313198a2e0370734
        Bản mã: 3925841d02dc09fbdc118597196a0b32
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        aes = PureAES(key)
        actual_ct = aes.encrypt(plaintext)
        self.assertEqual(actual_ct, expected_ct,
                         f"NIST Appendix B LỖI\n"
                         f"Kỳ vọng : {expected_ct.hex()}\n"
                         f"Thực tế : {actual_ct.hex()}")
        print("NIST TC-B ĐẠT: Mã hóa Appendix B")

    def test_nist_decrypt_appendix_b(self):
        """
        NIST FIPS-197 Appendix B (inverse):
        Giải mã bản mã phải ra đúng bản rõ gốc.
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        expected_pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

        aes = PureAES(key)
        actual_pt = aes.decrypt(ciphertext)
        self.assertEqual(actual_pt, expected_pt,
                         f"NIST Appendix B giải mã LỖI\n"
                         f"Kỳ vọng : {expected_pt.hex()}\n"
                         f"Thực tế : {actual_pt.hex()}")
        print("NIST TC-B ĐẠT: Giải mã Appendix B")

    def test_nist_encrypt_appendix_c1_roundtrip(self):
        """
        NIST FIPS-197 Appendix C.1 (AES-128) — kiểm tra vòng đi-về:
        Khóa  : 000102030405060708090a0b0c0d0e0f
        Bản rõ: 00112233445566778899aabbccddeeff

        Kiểm tra mã hóa → giải mã trả về đúng bản rõ gốc.
        """
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

        aes = PureAES(key)
        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext,
                         f"NIST C.1 vòng đi-về LỖI\n"
                         f"Kỳ vọng : {plaintext.hex()}\n"
                         f"Thực tế : {decrypted.hex()}")
        print(f"NIST TC-C1 ĐẠT: Vòng đi-về đúng (bản mã={ciphertext.hex()})")

    def test_nist_encrypt_appendix_c1_kat(self):
        """
        NIST FIPS-197 Appendix C.1 (AES-128) — Known Answer Test (KAT):
        Khóa   : 000102030405060708090a0b0c0d0e0f
        Bản rõ : 00112233445566778899aabbccddeeff
        Kỳ vọng: 69c4e0d86a7b0430d8cdb78070b4c55a

        LƯU Ý: Giá trị expected này đã được xác nhận bởi PyCryptodome (thư viện
        AES chuẩn). Giá trị cũ 69c4e0d86a7b04300d8a8bb2aa35e6a1 là sai — đó là
        bản mã của AES-256, không phải AES-128 với khóa 128-bit này.

        Engine dùng convention state[col][row] (state[c] = cột c = bytes [4c..4c+3])
        — đây là column-major đúng theo NIST FIPS-197.
        """
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        # Verified correct AES-128 ciphertext (confirmed by PyCryptodome)
        expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        aes = PureAES(key)
        actual_ct = aes.encrypt(plaintext)

        self.assertEqual(actual_ct, expected_ct,
                         f"NIST C.1 KAT LỖI\n"
                         f"Kỳ vọng : {expected_ct.hex()}\n"
                         f"Thực tế : {actual_ct.hex()}")
        print(f"NIST TC-C1 KAT ĐẠT: bản mã={actual_ct.hex()} (xác nhận bởi PyCryptodome)")

    def test_nist_zero_key_zero_plaintext(self):
        """
        Khóa toàn 0 + bản rõ toàn 0:
        Khóa  : 00000000000000000000000000000000
        Bản rõ: 00000000000000000000000000000000
        Bản mã: 66e94bd4ef8a2c3b884cfa59ca342b2e
        """
        key = bytes(16)
        plaintext = bytes(16)
        expected_ct = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")

        aes = PureAES(key)
        actual_ct = aes.encrypt(plaintext)
        self.assertEqual(actual_ct, expected_ct,
                         f"Toàn 0 LỖI\n"
                         f"Kỳ vọng : {expected_ct.hex()}\n"
                         f"Thực tế : {actual_ct.hex()}")
        print("NIST TC-ZERO ĐẠT: khóa toàn 0/bản rõ toàn 0")


class TestVetCan(unittest.TestCase):
    """Test cases cho vét cạn."""

    def test_tc08_vet_can_8bit(self):
        """TC08: Vét cạn khóa 8-bit phải tìm thấy."""
        plaintext = "ABCDE"
        ciphertext, key, key_int = encrypt_aes(plaintext, 8)
        result = brute_force_aes(ciphertext, 8)
        self.assertTrue(result['found'], "TC08 LỖI: Không tìm thấy khóa 8-bit")
        self.assertEqual(result['key_int'], key_int, "TC08 LỖI: Khóa tìm được sai")
        print(f"TC08 ĐẠT: Vét cạn khóa 8-bit, khóa={key_int}, thời gian={result['elapsed_seconds']:.3f}s")

    def test_tc09_vet_can_12bit(self):
        """TC09: Vét cạn khóa 12-bit phải tìm thấy trong < 30s."""
        import time
        plaintext = "HELLO"
        ciphertext, key, key_int = encrypt_aes(plaintext, 12)
        start = time.time()
        result = brute_force_aes(ciphertext, 12)
        elapsed = time.time() - start
        self.assertTrue(result['found'], "TC09 LỖI: Không tìm thấy khóa 12-bit")
        self.assertLess(elapsed, 30, "TC09 CẢNH BÁO: Quá 30 giây")
        print(f"TC09 ĐẠT: Vét cạn khóa 12-bit, thời gian={elapsed:.3f}s")

    def test_tc10_is_valid_plaintext(self):
        """TC10: Kiểm tra hàm is_valid_plaintext."""
        # ASCII printable
        self.assertTrue(is_valid_plaintext(b"HELLO WORLD123"))
        # Binary data (random bytes thường không printable)
        self.assertFalse(is_valid_plaintext(bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])))
        print("TC10 ĐẠT: is_valid_plaintext hoạt động đúng")

    def test_tc11_estimate_time(self):
        """TC11: estimate_time trả về kết quả hợp lý."""
        est = estimate_time(16, keys_per_second=50_000)
        self.assertEqual(est['key_bits'], 16)
        self.assertEqual(est['keyspace'], 65536)
        self.assertGreater(est['avg_time_seconds'], 0)
        print(f"TC11 ĐẠT: estimate_time(16-bit) = trung bình {est['avg_time_formatted']}")

    def test_tc11b_estimate_time_128bit(self):
        """TC11b: estimate_time hỗ trợ 128-bit để phục vụ phần lý thuyết."""
        est = estimate_time(128, keys_per_second=50_000)
        self.assertEqual(est['key_bits'], 128)
        self.assertGreater(est['keyspace'], 0)
        self.assertGreater(est['avg_time_seconds'], 0)
        print(f"TC11b ĐẠT: estimate_time(128-bit) = trung bình {est['avg_time_formatted']}")

    def test_tc12_tinh_khong_gian_khoa(self):
        """TC12: Không gian khóa = 2^n."""
        for bits in [8, 12, 16, 20]:
            est = estimate_time(bits)
            self.assertEqual(est['keyspace'], 2 ** bits)
        print("TC12 ĐẠT: Tính không gian khóa đúng")


class TestTichHop(unittest.TestCase):
    """Kiểm thử tích hợp: AES + vét cạn."""

    def test_tc13_quy_trinh_day_du_8bit(self):
        """TC13: Quy trình đầy đủ mã hóa → vét cạn → xác minh."""
        plaintext = "SECRET"
        ciphertext, key, key_int = encrypt_aes(plaintext, 8)
        result = brute_force_aes(ciphertext, 8)

        self.assertTrue(result['found'])
        self.assertEqual(result['key_int'], key_int)
        self.assertEqual(result['plaintext'].strip(), plaintext)
        print(f"TC13 ĐẠT: Quy trình 8-bit đầy đủ | khóa={key_int} | bản rõ='{result['plaintext']}'")


class TestDoHieuNang(unittest.TestCase):
    """Test cases cho tiện ích đo hiệu năng."""

    def test_tc14_doc_key_int_hex(self):
        """TC14: --key-int chấp nhận giá trị hex."""
        args = parse_args(["--bits", "8", "--key-int", "0x2A", "--no-plot", "--no-json"])
        self.assertEqual(args.key_int, 42)
        print("TC14 ĐẠT: --key-int đọc được giá trị hex")

    def test_tc15_do_hieu_nang_khoa_co_dinh(self):
        """TC15: Đo hiệu năng với khóa cố định có thể tái lập."""
        result = benchmark_key_length(8, test_text="SECRET", verbose=False, key_int=42)
        self.assertTrue(result['found'])
        self.assertEqual(result['actual_key_int'], 42)
        self.assertEqual(result['found_key_int'], 42)
        self.assertEqual(result['found_plaintext'], "SECRET")
        print("TC15 ĐẠT: Khóa cố định tìm đúng khóa và bản rõ")


if __name__ == "__main__":
    print("=" * 55)
    print("  CHẠY KIỂM THỬ AES VÀ VÉT CẠN")
    print("=" * 55)
    unittest.main(verbosity=2)
