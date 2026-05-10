"""
brute_force.py - AES Brute-Force Attack Module
Tấn công vét cạn tuần tự (sequential brute-force) lên AES khóa ngắn.
"""

import time
from typing import Callable, Dict, Optional
from aes_engine import PureAES, unpad

SUPPORTED_KEY_BITS = [8, 12, 16, 20, 24, 32]
CallbackType = Callable[[int, int, float], None]


def validate_key_bits(bits: int) -> None:
    """Kiểm tra xem độ dài khóa có nằm trong danh sách hỗ trợ."""
    if bits not in SUPPORTED_KEY_BITS:
        raise ValueError(
            f"Độ dài khóa không hợp lệ: {bits}. Hỗ trợ: {SUPPORTED_KEY_BITS}"
        )


def is_valid_plaintext(data: bytes) -> bool:
    """
    Kiểm tra xem bytes (đã bỏ padding) có phải là plaintext ASCII hợp lệ.
    Chấp nhận ký tự printable ASCII (0x20-0x7E) và whitespace tab/newline.
    """
    if len(data) == 0:
        return False
    return all(32 <= b <= 126 or b in (9, 10, 13) for b in data)


def brute_force_aes(
    ciphertext: bytes,
    key_bits: int,
    callback: Optional[CallbackType] = None,
    stop_flag: Optional[object] = None,
) -> Dict[str, object]:
    """
    Thử tất cả khóa từ 0 đến 2^key_bits - 1.

    Args:
        ciphertext: Dữ liệu đã mã hóa
        key_bits: Độ dài khóa cần tìm
        callback: Hàm callback(current, total, elapsed)
        stop_flag: Object có is_set() để dừng sớm

    Returns:
        dict: Kết quả brute-force
    """
    validate_key_bits(key_bits)

    max_keys = 1 << key_bits
    key_bytes_len = (key_bits + 7) // 8
    start_time = time.time()
    keys_tested = 0
    update_interval = max(1, min(100_000, max_keys // 100))

    for i in range(max_keys):
        if stop_flag is not None and stop_flag.is_set():
            break

        current = i + 1
        key_part = i.to_bytes(key_bytes_len, byteorder='big')
        key = key_part.ljust(16, b'\x00')

        try:
            cipher = PureAES(key)
            decrypted_raw = cipher.decrypt(ciphertext)

            # Unpad trước, nếu padding không hợp lệ → bỏ qua ngay
            try:
                unpadded = unpad(decrypted_raw, 16)
            except ValueError:
                continue

            # Validate toàn bộ dữ liệu sau unpad
            if is_valid_plaintext(unpadded):
                try:
                    plaintext = unpadded.decode('utf-8')
                    elapsed = time.time() - start_time
                    kps = current / elapsed if elapsed > 0 else 0

                    return {
                        'found': True,
                        'key_int': i,
                        'key_hex': key_part.hex().upper(),
                        'key_full_hex': key.hex().upper(),
                        'plaintext': plaintext,
                        'elapsed_seconds': elapsed,
                        'keys_tested': current,
                        'keys_per_second': kps,
                        'total_keyspace': max_keys,
                        'percent_searched': (current / max_keys) * 100,
                    }
                except UnicodeDecodeError:
                    pass
        except Exception:
            pass

        keys_tested = current
        if callback is not None and keys_tested % update_interval == 0:
            elapsed = time.time() - start_time
            callback(keys_tested, max_keys, elapsed)

    elapsed = time.time() - start_time
    kps = keys_tested / elapsed if elapsed > 0 else 0

    return {
        'found': False,
        'key_int': None,
        'key_hex': None,
        'key_full_hex': None,
        'plaintext': None,
        'elapsed_seconds': elapsed,
        'keys_tested': keys_tested,
        'keys_per_second': kps,
        'total_keyspace': max_keys,
        'percent_searched': 100.0,
    }


def estimate_time(key_bits: int, keys_per_second: float = None) -> Dict[str, object]:
    """
    Ước tính thời gian brute-force dựa trên lý thuyết.

    Args:
        key_bits: Độ dài khóa (bits)
        keys_per_second: Tốc độ thực tế (nếu đã đo được)

    Returns:
        dict: Thông tin ước tính
    """
    validate_key_bits(key_bits)
    keyspace = 1 << key_bits

    if keys_per_second is None or keys_per_second <= 0:
        keys_per_second = 50_000

    avg_time = (keyspace / 2) / keys_per_second
    worst_time = keyspace / keys_per_second

    def format_time(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f} giây"
        if seconds < 3600:
            return f"{seconds / 60:.1f} phút"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} giờ"
        if seconds < 86400 * 365:
            return f"{seconds / 86400:.1f} ngày"
        return f"{seconds / 86400 / 365:.2e} năm"

    return {
        'key_bits': key_bits,
        'keyspace': keyspace,
        'keyspace_formatted': f"2^{key_bits} = {keyspace:,}",
        'keys_per_second': keys_per_second,
        'avg_time_seconds': avg_time,
        'worst_time_seconds': worst_time,
        'avg_time_formatted': format_time(avg_time),
        'worst_time_formatted': format_time(worst_time),
    }


if __name__ == "__main__":
    from aes_engine import encrypt_aes, bytes_to_hex

    print("=== Test Brute-Force ===")
    plaintext = "SECRET"
    key_bits = 16

    print(f"Plaintext: {plaintext}")
    print(f"Key length: {key_bits} bits (keyspace: 2^{key_bits} = {2**key_bits:,})")

    ciphertext, key, key_int = encrypt_aes(plaintext, key_bits)
    print(f"Key value: {key_int} (0x{key_int:04X})")
    print(f"Ciphertext: {bytes_to_hex(ciphertext)}")
    print(f"\nBắt đầu brute-force...")

    def progress_cb(current, total, elapsed):
        pct = current / total * 100
        print(f"  [{pct:.1f}%] {current:,}/{total:,} keys | {elapsed:.1f}s")

    result = brute_force_aes(ciphertext, key_bits, callback=progress_cb)

    print(f"\n=== KẾT QUẢ ===")
    if result['found']:
        print(f"✅ Tìm thấy!")
        print(f"   Key (int)  : {result['key_int']}")
        print(f"   Key (hex)  : 0x{result['key_hex']}")
        print(f"   Plaintext  : {result['plaintext']}")
        print(f"   Thời gian  : {result['elapsed_seconds']:.2f}s")
        print(f"   Keys/giây  : {result['keys_per_second']:,.0f}")
    else:
        print("❌ Không tìm thấy!")

    print("\n=== ƯỚC TÍNH THỜI GIAN ===")
    kps = result['keys_per_second']
    for bits in [16, 20, 24, 32, 64, 128]:
        est = estimate_time(bits, kps)
        print(f"  {bits:3d}-bit: {est['keyspace_formatted']:30s} | Avg: {est['avg_time_formatted']}")
