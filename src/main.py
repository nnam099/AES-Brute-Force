"""
main.py - Entry point ứng dụng AES Brute-Force Demo
Chạy: python main.py
"""

import sys
import os

# Đảm bảo import từ thư mục src
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def check_dependencies():
    """Kiểm tra thư viện trước khi chạy."""
    missing = []
    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing.append("pycryptodome  (pip install pycryptodome)")

    try:
        import matplotlib
    except ImportError:
        missing.append("matplotlib    (pip install matplotlib)")

    if missing:
        print("❌ Thiếu thư viện:")
        for m in missing:
            print(f"   - {m}")
        print("\nCài đặt: pip install pycryptodome matplotlib")
        sys.exit(1)

    print("✅ Tất cả thư viện OK")


def run_gui():
    """Khởi chạy giao diện đồ họa."""
    import tkinter as tk
    from gui import AESBruteForceApp

    root = tk.Tk()
    app = AESBruteForceApp(root)

    # Căn giữa cửa sổ
    root.update_idletasks()
    w, h = 900, 680
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")

    root.mainloop()


def run_cli():
    """Chạy demo CLI (không cần GUI)."""
    from aes_engine import encrypt_aes, decrypt_aes, bytes_to_hex, key_int_to_bytes
    from brute_force import brute_force_aes, estimate_time

    print("=" * 55)
    print("  AES BRUTE-FORCE DEMO (CLI Mode)")
    print("=" * 55)

    plaintext = input("Nhập plaintext (Enter = 'SECRET'): ").strip() or "SECRET"
    bits_input = input("Nhập key bits [8/12/16/20] (Enter = 16): ").strip()
    bits = int(bits_input) if bits_input.isdigit() else 16

    print(f"\n[Encrypt] '{plaintext}' với {bits}-bit key...")
    ciphertext, key, key_int = encrypt_aes(plaintext, bits)
    print(f"  Key (int)   : {key_int}")
    print(f"  Key (hex)   : 0x{key_int:0{bits//4}X}")
    print(f"  Ciphertext  : {bytes_to_hex(ciphertext)}")

    print(f"\n[Brute-Force] Thử tất cả {2**bits:,} khóa...")

    milestone_interval = max(1, (2 ** bits) // 20)

    def progress_cb(current, total, elapsed):
        if current % (milestone_interval * 5) == 0:
            pct = current / total * 100
            kps = current / elapsed if elapsed > 0 else 0
            print(f"  [{pct:5.1f}%] {current:>8,} / {total:,} | {elapsed:.1f}s | {kps:,.0f} keys/s")

    result = brute_force_aes(ciphertext, bits, callback=progress_cb)

    print("\n" + "=" * 55)
    if result['found']:
        print(f"✅ TÌM THẤY!")
        print(f"   Key (int)   : {result['key_int']}")
        print(f"   Key (hex)   : 0x{result['key_hex']}")
        print(f"   Plaintext   : {result['plaintext']}")
        print(f"   Thời gian   : {result['elapsed_seconds']:.3f}s")
        print(f"   Keys tested : {result['keys_tested']:,}")
        print(f"   Keys/giây   : {result['keys_per_second']:,.0f}")
    else:
        print("❌ Không tìm thấy!")

    print("\n[Ước tính thời gian cho các key length khác]")
    kps = result['keys_per_second'] if result['keys_per_second'] > 0 else 50_000
    for b in [16, 20, 24, 32, 64, 128]:
        est = estimate_time(b, kps)
        print(f"  {b:>4}-bit : {est['keyspace_formatted']:32s} | Avg: {est['avg_time_formatted']}")


if __name__ == "__main__":
    check_dependencies()

    if "--cli" in sys.argv:
        run_cli()
    else:
        try:
            import tkinter
            run_gui()
        except ImportError:
            print("⚠️  Tkinter không khả dụng. Chạy chế độ CLI...")
            run_cli()
