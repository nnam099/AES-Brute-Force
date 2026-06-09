"""
main.py - Điểm khởi chạy ứng dụng minh họa vét cạn AES
Chạy: python main.py [--cli] [--text TEXT] [--bits BITS]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Sequence

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from aes_engine import SUPPORTED_KEY_BITS  # noqa: E402


def configure_console() -> None:
    """Chuẩn hóa output console để giảm lỗi Unicode trên Windows."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def check_dependencies() -> None:
    """Kiểm tra thư viện trước khi chạy."""
    missing = []


    try:
        import matplotlib  # noqa: F401
    except ImportError:
        missing.append("matplotlib    (pip install matplotlib)")

    if missing:
        print("[LOI] Thiếu thư viện:")
        for m in missing:
            print(f"   - {m}")
        print("\nCài đặt: pip install matplotlib")
        sys.exit(1)

    print("[ĐẠT] Tất cả thư viện cần thiết đã sẵn sàng")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Minh họa vét cạn AES: chạy giao diện đồ họa hoặc dòng lệnh.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--cli", action="store_true", help="Chạy chế độ dòng lệnh CLI.")
    parser.add_argument("--gui", action="store_true", help="Buộc chạy giao diện Tkinter.")
    parser.add_argument("--no-gui", action="store_true", help="Không chạy GUI, chỉ CLI.")
    parser.add_argument("--fast", action="store_true", help="Sử dụng PyCryptodome (chế độ nhanh).")
    parser.add_argument("--text", default="SECRET", help="Bản rõ cho chế độ dòng lệnh.")
    parser.add_argument(
        "--bits",
        type=int,
        choices=SUPPORTED_KEY_BITS,
        default=16,
        help="Độ dài khóa để mã hóa và vét cạn.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Số tiến trình dùng cho vét cạn (>=1).",
    )
    return parser.parse_args(argv)


def run_gui() -> None:
    """Khởi chạy giao diện đồ họa."""
    import tkinter as tk
    from gui import AESBruteForceApp

    root = tk.Tk()
    app = AESBruteForceApp(root)

    root.update_idletasks()
    w, h = 900, 680
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.mainloop()


def run_cli(plaintext: str, key_bits: int, workers: int, fast_mode: bool = False) -> None:
    """Chạy minh họa dòng lệnh với plaintext và key_bits đã khai báo."""
    from aes_engine import encrypt_aes, bytes_to_hex
    from brute_force import brute_force_aes, estimate_time

    print("=" * 55)
    print("  MINH HỌA VÉT CẠN AES (CHẾ ĐỘ DÒNG LỆNH)")
    print("=" * 55)
    print(f"Bản rõ       : {plaintext}")
    print(f"Độ dài khóa  : {key_bits}-bit")

    ciphertext, key, key_int = encrypt_aes(plaintext, key_bits)
    print(f"\n[Mã hóa] {plaintext!r} -> bản mã")
    print(f"  Khóa (số nguyên) : {key_int}")
    print(f"  Khóa (hex)       : 0x{key_int:0{key_bits//4}X}")
    print(f"  Bản mã           : {bytes_to_hex(ciphertext)}")

    print(f"\n[Vét cạn] Thử {2 ** key_bits:,} khóa...")

    milestone = max(1, (2 ** key_bits) // 20)

    def progress_cb(current: int, total: int, elapsed: float) -> None:
        if current % (milestone * 5) == 0 or current == total:
            pct = current / total * 100
            kps = current / elapsed if elapsed > 0 else 0
            print(
                f"  [{pct:5.1f}%] {current:>8,} / {total:,} | "
                f"{elapsed:.1f}s | {kps:,.0f} khóa/giây"
            )

    result = brute_force_aes(ciphertext, key_bits, callback=progress_cb, workers=workers, fast_mode=fast_mode)

    print("\n" + "=" * 55)
    if result['found']:
        print("[ĐẠT] Đã tìm thấy khóa.")
        print(f"   Khóa (số nguyên) : {result['key_int']}")
        print(f"   Khóa (hex)       : 0x{result['key_hex']}")
        print(f"   Bản rõ           : {result['plaintext']}")
        print(f"   Thời gian        : {result['elapsed_seconds']:.3f}s")
        print(f"   Số khóa đã thử   : {result['keys_tested']:,}")
        print(f"   Tốc độ           : {result['keys_per_second']:,.0f} khóa/giây")
    else:
        print("[LỖI] Không tìm thấy khóa.")

    print("\n[Ước tính thời gian với tốc độ thực tế]")
    measured_kps = result['keys_per_second'] if result['keys_per_second'] > 0 else 50_000
    for b in [16, 20, 24, 32, 64, 128]:
        est = estimate_time(b, measured_kps)
        print(f"  {b:>4}-bit : {est['keyspace_formatted']:32s} | Trung bình: {est['avg_time_formatted']}")


def main(argv: Sequence[str] | None = None) -> None:
    configure_console()
    args = parse_args(argv)
    check_dependencies()

    want_gui = args.gui or (not args.cli and not args.no_gui)
    if want_gui:
        try:
            run_gui()
            return
        except ImportError:
            print("[CẢNH BÁO] Tkinter không khả dụng. Chuyển sang chế độ dòng lệnh...")

    run_cli(args.text, args.bits, args.workers, args.fast)


if __name__ == "__main__":
    main()
