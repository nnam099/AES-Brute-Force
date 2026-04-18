"""
brute_force.py - AES Brute-Force Attack Module
Tấn công vét cạn tuần tự (sequential brute-force) lên AES khóa ngắn
"""

import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def is_valid_plaintext(data: bytes) -> bool:
    """
    Kiểm tra xem bytes có phải là plaintext ASCII hợp lệ không.
    Chỉ check 4 bytes đầu để tránh đụng vùng padding.

    Returns:
        bool: True nếu 4 bytes đầu đều là ký tự ASCII in được
    """
    check_len = min(len(data), 4)
    if check_len == 0:
        return False
    return all(32 <= b <= 126 for b in data[:check_len])


def brute_force_aes(
    ciphertext: bytes,
    key_bits: int,
    callback=None,
    stop_flag=None
) -> dict:
    """
    Brute-force tuần tự đơn giản: thử tất cả khóa từ 0 đến 2^key_bits - 1.

    Args:
        ciphertext: Dữ liệu đã mã hóa
        key_bits: Độ dài khóa cần tìm (bits)
        callback: Hàm callback(current, total, elapsed) để cập nhật tiến trình
        stop_flag: Object có thuộc tính .is_set() để dừng brute-force

    Returns:
        dict: kết quả brute-force
    """
    max_keys = 2 ** key_bits
    key_bytes_len = (key_bits + 7) // 8  # ceil: số bytes cần cho key
    start_time = time.time()
    keys_tested = 0

    # Tần suất gọi callback (khoảng 100 lần trong toàn bộ keyspace)
    UPDATE_INTERVAL = max(1, max_keys // 100)

    for i in range(max_keys):
        # Dừng sớm nếu có tín hiệu
        if stop_flag is not None and stop_flag.is_set():
            break

        # Tạo key: phần thực (key_bytes_len bytes) + padding zeros → 16 bytes
        key_part = i.to_bytes(key_bytes_len, byteorder='big')
        key = key_part.ljust(16, b'\x00')

        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_raw = cipher.decrypt(ciphertext)

            # Kiểm tra nhanh: 4 bytes đầu phải là ASCII printable
            if is_valid_plaintext(decrypted_raw):
                try:
                    plaintext = unpad(decrypted_raw, AES.block_size).decode('utf-8')
                    elapsed = time.time() - start_time
                    kps = keys_tested / elapsed if elapsed > 0 else 0

                    return {
                        'found': True,
                        'key_int': i,
                        'key_hex': key_part.hex().upper(),
                        'key_full_hex': key.hex().upper(),
                        'plaintext': plaintext,
                        'elapsed_seconds': elapsed,
                        'keys_tested': keys_tested + 1,
                        'keys_per_second': kps,
                        'total_keyspace': max_keys,
                        'percent_searched': ((i + 1) / max_keys) * 100
                    }
                except (ValueError, UnicodeDecodeError):
                    pass  # Padding sai hoặc không phải UTF-8
        except Exception:
            pass

        keys_tested += 1

        # Gọi callback để cập nhật UI
        if callback is not None and keys_tested % UPDATE_INTERVAL == 0:
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
        'percent_searched': 100.0
    }


def estimate_time(key_bits: int, keys_per_second: float = None) -> dict:
    """
    Ước tính thời gian brute-force dựa trên lý thuyết.

    Args:
        key_bits: Độ dài khóa (bits)
        keys_per_second: Tốc độ thực tế (nếu đã đo được)

    Returns:
        dict: Thông tin ước tính
    """
    keyspace = 2 ** key_bits

    if keys_per_second is None or keys_per_second <= 0:
        keys_per_second = 50_000

    avg_time = (keyspace / 2) / keys_per_second
    worst_time = keyspace / keys_per_second

    def format_time(seconds):
        if seconds < 60:
            return f"{seconds:.1f} giây"
        elif seconds < 3600:
            return f"{seconds/60:.1f} phút"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} giờ"
        elif seconds < 86400 * 365:
            return f"{seconds/86400:.1f} ngày"
        else:
            return f"{seconds/86400/365:.2e} năm"

    return {
        'key_bits': key_bits,
        'keyspace': keyspace,
        'keyspace_formatted': f"2^{key_bits} = {keyspace:,}",
        'keys_per_second': keys_per_second,
        'avg_time_seconds': avg_time,
        'worst_time_seconds': worst_time,
        'avg_time_formatted': format_time(avg_time),
        'worst_time_formatted': format_time(worst_time)
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
