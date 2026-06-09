"""
brute_force.py - Thuật toán vét cạn khóa AES trong phạm vi đồ án.

Ý tưởng chính: với n bit bí mật, không gian khóa có |K| = 2^n phần tử.
Chương trình thử lần lượt từng giá trị i, dựng lại khóa AES-128 dạng
bytes(i) || 00...00, giải mã bản mã và kiểm tra xem bản rõ có hợp lý không.
"""

import time
from multiprocessing import Pool, cpu_count
from typing import Callable, Dict, Optional, Tuple
from aes_engine import PureAES, unpad, SUPPORTED_KEY_BITS

# PyCryptodome (tuỳ chọn), dùng cho chế độ nhanh
try:
    from Crypto.Cipher import AES as _CryptoAES
    _PYCRYPTODOME_AVAILABLE = True
except ImportError:
    _CryptoAES = None  # type: ignore
    _PYCRYPTODOME_AVAILABLE = False

CallbackType = Callable[[int, int, float], None]
DetailCallbackType = Callable[[Dict[str, object]], None]


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


def score_plaintext(data: bytes) -> float:
    """
    Tính điểm bản rõ theo tỉ lệ ký tự ASCII in được.
    Điểm nằm trong [0, 1]; bản rõ tiếng Anh/ngắn thường gần 1.
    """
    if len(data) == 0:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def _bruteforce_worker(args: Tuple[int, int, int, bytes, float, bool]) -> Dict[str, object]:
    """
    Worker quét một đoạn không gian khóa [start, end).

    Hàm này dùng cho multiprocessing, nên chỉ trả dict đơn giản để gửi
    kết quả về tiến trình chính.
    """
    start, end, key_bits, ciphertext, score_threshold, fast_mode = args
    key_bytes_len = (key_bits + 7) // 8

    for i in range(start, end):
        key_part = i.to_bytes(key_bytes_len, byteorder='big')
        key = key_part.ljust(16, b'\x00')

        try:
            if fast_mode:
                if not _PYCRYPTODOME_AVAILABLE:
                    raise ImportError("pycryptodome chưa cài: pip install pycryptodome")
                cipher = _CryptoAES.new(key, _CryptoAES.MODE_ECB)  # type: ignore[union-attr]
                decrypted_raw = cipher.decrypt(ciphertext)
            else:
                cipher = PureAES(key)
                decrypted_raw = cipher.decrypt(ciphertext)

            try:
                unpadded = unpad(decrypted_raw, 16)
            except ValueError:
                continue

            score = score_plaintext(unpadded)
            if score >= score_threshold:
                try:
                    plaintext = unpadded.decode('utf-8')
                    return {
                        'found': True,
                        'key_int': i,
                        'key_hex': key_part.hex().upper(),
                        'key_full_hex': key.hex().upper(),
                        'plaintext': plaintext,
                        'plaintext_score': score,
                        'keys_tested': (i - start + 1),
                    }
                except UnicodeDecodeError:
                    pass
        except (ValueError, ImportError):
            continue

    return {
        'found': False,
        'keys_tested': (end - start),
    }


def brute_force_aes(
    ciphertext: bytes,
    key_bits: int,
    callback: Optional[CallbackType] = None,
    detail_callback: Optional[DetailCallbackType] = None,
    stop_flag: Optional[object] = None,
    workers: int = 1,
    chunk_size: int = 10000,
    score_threshold: float = 0.9,
    detail_interval: Optional[int] = None,
    fast_mode: bool = False,
) -> Dict[str, object]:
    """
    Thử tất cả khóa từ 0 đến 2^key_bits - 1.

    Đây là vét cạn theo đúng nghĩa: không suy luận khóa, chỉ duyệt hết
    không gian khóa. Trung bình cần thử khoảng 2^(key_bits-1) khóa nếu
    khóa thật phân bố đều trong khoảng.

    Args:
        ciphertext: Dữ liệu đã mã hóa
        key_bits: Độ dài khóa cần tìm
        callback: Hàm callback(current, total, elapsed)
        stop_flag: Object có is_set() để dừng sớm
        fast_mode: Sử dụng thư viện PyCryptodome để tăng tốc

    Returns:
        dict: Kết quả vét cạn
    """
    validate_key_bits(key_bits)

    max_keys = 1 << key_bits  # 2^key_bits
    key_bytes_len = (key_bits + 7) // 8
    start_time = time.time()
    keys_tested = 0
    update_interval = max(1, min(100_000, max_keys // 100))
    if detail_interval is None:
        detail_interval = max(1, min(10_000, max_keys // 200))

    def emit_detail(event: str, **payload: object) -> None:
        if detail_callback is None:
            return
        elapsed = time.time() - start_time
        current = int(payload.get('current', keys_tested) or 0)
        detail_callback({
            'event': event,
            'current': current,
            'total': max_keys,
            'elapsed': elapsed,
            'percent': (current / max_keys) * 100 if max_keys else 0.0,
            **payload,
        })

    if workers > 1:
        emit_detail(
            'start',
            workers=workers,
            key_bits=key_bits,
            keyspace=max_keys,
            mode='multiprocessing',
            fast_mode=fast_mode,
        )
        safe_workers = max(1, min(workers, cpu_count() or 1))
        chunk = max(1, chunk_size)
        ranges = [(i, min(i + chunk, max_keys), key_bits, ciphertext, score_threshold, fast_mode)
                  for i in range(0, max_keys, chunk)]

        with Pool(processes=safe_workers) as pool:
            for result in pool.imap_unordered(_bruteforce_worker, ranges):
                if stop_flag is not None and stop_flag.is_set():
                    pool.terminate()
                    break

                keys_tested += result.get('keys_tested', 0)
                if callback is not None:
                    elapsed = time.time() - start_time
                    callback(keys_tested, max_keys, elapsed)
                emit_detail(
                    'chunk_done',
                    current=keys_tested,
                    keys_tested=keys_tested,
                    workers=safe_workers,
                )

                if result.get('found'):
                    pool.terminate()
                    elapsed = time.time() - start_time
                    kps = keys_tested / elapsed if elapsed > 0 else 0
                    emit_detail(
                        'found',
                        current=keys_tested,
                        key_int=result['key_int'],
                        key_hex=result['key_hex'],
                        key_full_hex=result['key_full_hex'],
                        plaintext=result['plaintext'],
                        plaintext_score=result.get('plaintext_score', 0.0),
                        keys_per_second=kps,
                    )
                    return {
                        'found': True,
                        'key_int': result['key_int'],
                        'key_hex': result['key_hex'],
                        'key_full_hex': result['key_full_hex'],
                        'plaintext': result['plaintext'],
                        'plaintext_score': result.get('plaintext_score', 0.0),
                        'elapsed_seconds': elapsed,
                        'keys_tested': keys_tested,
                        'keys_per_second': kps,
                        'total_keyspace': max_keys,
                        'percent_searched': (keys_tested / max_keys) * 100,
                    }

        elapsed = time.time() - start_time
        kps = keys_tested / elapsed if elapsed > 0 else 0
        emit_detail('exhausted', current=keys_tested, keys_tested=keys_tested)
        return {
            'found': False,
            'key_int': None,
            'key_hex': None,
            'key_full_hex': None,
            'plaintext': None,
            'plaintext_score': 0.0,
            'elapsed_seconds': elapsed,
            'keys_tested': keys_tested,
            'keys_per_second': kps,
            'total_keyspace': max_keys,
            'percent_searched': 100.0,
        }

    emit_detail(
        'start',
        current=0,
        workers=1,
        key_bits=key_bits,
        keyspace=max_keys,
        key_bytes_len=key_bytes_len,
        score_threshold=score_threshold,
        mode='sequential',
        fast_mode=fast_mode,
    )

    for i in range(max_keys):
        if stop_flag is not None and stop_flag.is_set():
            emit_detail('stopped', current=keys_tested, keys_tested=keys_tested)
            break

        current = i + 1
        key_part = i.to_bytes(key_bytes_len, byteorder='big')
        key = key_part.ljust(16, b'\x00')
        key_hex = key_part.hex().upper()

        if detail_callback is not None and (i == 0 or current % detail_interval == 0):
            emit_detail(
                'trying',
                current=current,
                key_int=i,
                key_hex=key_hex,
                key_full_hex=key.hex().upper(),
            )

        try:
            if fast_mode:
                if not _PYCRYPTODOME_AVAILABLE:
                    raise ImportError("pycryptodome chưa cài: pip install pycryptodome")
                cipher = _CryptoAES.new(key, _CryptoAES.MODE_ECB)  # type: ignore[union-attr]
                decrypted_raw = cipher.decrypt(ciphertext)
            else:
                cipher = PureAES(key)
                decrypted_raw = cipher.decrypt(ciphertext)

            # Padding sai là dấu hiệu mạnh cho thấy khóa đang thử không đúng.
            try:
                unpadded = unpad(decrypted_raw, 16)
            except ValueError:
                continue

            # Sau khi padding hợp lệ, kiểm tra xem bản rõ có giống văn bản không.
            score = score_plaintext(unpadded)
            preview = unpadded[:80].decode('utf-8', errors='replace')
            emit_detail(
                'padding_valid',
                current=current,
                key_int=i,
                key_hex=key_hex,
                plaintext_preview=preview,
                plaintext_score=score,
            )
            if score >= score_threshold:
                try:
                    plaintext = unpadded.decode('utf-8')
                    elapsed = time.time() - start_time
                    kps = current / elapsed if elapsed > 0 else 0
                    emit_detail(
                        'found',
                        current=current,
                        key_int=i,
                        key_hex=key_hex,
                        key_full_hex=key.hex().upper(),
                        plaintext=plaintext,
                        plaintext_score=score,
                        keys_per_second=kps,
                    )

                    return {
                        'found': True,
                        'key_int': i,
                        'key_hex': key_hex,
                        'key_full_hex': key.hex().upper(),
                        'plaintext': plaintext,
                        'plaintext_score': score,
                        'elapsed_seconds': elapsed,
                        'keys_tested': current,
                        'keys_per_second': kps,
                        'total_keyspace': max_keys,
                        'percent_searched': (current / max_keys) * 100,
                    }
                except UnicodeDecodeError:
                    pass
        except (ValueError, ImportError):
            continue

        keys_tested = current
        if callback is not None and keys_tested % update_interval == 0:
            elapsed = time.time() - start_time
            callback(keys_tested, max_keys, elapsed)

    elapsed = time.time() - start_time
    kps = keys_tested / elapsed if elapsed > 0 else 0
    emit_detail('exhausted', current=keys_tested, keys_tested=keys_tested)

    return {
        'found': False,
        'key_int': None,
        'key_hex': None,
        'key_full_hex': None,
        'plaintext': None,
        'plaintext_score': 0.0,
        'elapsed_seconds': elapsed,
        'keys_tested': keys_tested,
        'keys_per_second': kps,
        'total_keyspace': max_keys,
        'percent_searched': 100.0,
    }


def estimate_time(key_bits: int, keys_per_second: float = None) -> Dict[str, object]:
    """
    Ước tính thời gian vét cạn dựa trên công thức:

        T_avg = 2^(n-1) / R
        T_worst = 2^n / R

    với n là số bit khóa và R là tốc độ thử khóa mỗi giây.

    Args:
        key_bits: Độ dài khóa (bits)
        keys_per_second: Tốc độ thực tế (nếu đã đo được)

    Returns:
        dict: Thông tin ước tính
    """
    if key_bits <= 0:
        raise ValueError("key_bits phải lớn hơn 0")
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

    print("=== KIỂM TRA VÉT CẠN ===")
    plaintext = "SECRET"
    key_bits = 16

    print(f"Bản rõ: {plaintext}")
    print(f"Độ dài khóa: {key_bits} bit (không gian khóa: 2^{key_bits} = {2**key_bits:,})")

    ciphertext, key, key_int = encrypt_aes(plaintext, key_bits)
    print(f"Giá trị khóa: {key_int} (0x{key_int:04X})")
    print(f"Bản mã: {bytes_to_hex(ciphertext)}")
    print(f"\nBắt đầu vét cạn...")

    def progress_cb(current, total, elapsed):
        pct = current / total * 100
        print(f"  [{pct:.1f}%] {current:,}/{total:,} khóa | {elapsed:.1f}s")

    result = brute_force_aes(ciphertext, key_bits, callback=progress_cb)

    print(f"\n=== KẾT QUẢ ===")
    if result['found']:
        print("Tìm thấy khóa.")
        print(f"   Khóa (số nguyên) : {result['key_int']}")
        print(f"   Khóa (hex)       : 0x{result['key_hex']}")
        print(f"   Bản rõ           : {result['plaintext']}")
        print(f"   Thời gian        : {result['elapsed_seconds']:.2f}s")
        print(f"   Khóa/giây        : {result['keys_per_second']:,.0f}")
    else:
        print("Không tìm thấy khóa.")

    print("\n=== ƯỚC TÍNH THỜI GIAN ===")
    kps = result['keys_per_second']
    for bits in [16, 20, 24, 32, 64, 128]:
        est = estimate_time(bits, kps)
        print(f"  {bits:3d}-bit: {est['keyspace_formatted']:30s} | Trung bình: {est['avg_time_formatted']}")
