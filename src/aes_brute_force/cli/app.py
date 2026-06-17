from __future__ import annotations

import argparse
import sys
from typing import Sequence

from aes_brute_force.core.constants import SUPPORTED_KEY_BITS
from aes_brute_force.utils.logging import configure_console, get_logger, setup_logging

logger = get_logger("cli")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AES-128 brute-force educational demo",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI).")
    p.add_argument("--gui", action="store_true", help="Force GUI mode.")
    p.add_argument("--fast", action="store_true", help="Use PyCryptodome backend.")
    p.add_argument("--text", default="SECRET", help="Plaintext for CLI mode.")
    p.add_argument(
        "--bits", type=int, choices=SUPPORTED_KEY_BITS, default=16, help="Key entropy bits."
    )
    p.add_argument("--workers", type=int, default=1, help="Number of processes.")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    return p.parse_args(argv)


def _run_gui() -> None:
    import customtkinter as ctk
    from aes_brute_force.gui.app import AESBruteForceApp

    root = ctk.CTk()
    AESBruteForceApp(root)
    root.update_idletasks()
    w, h = 960, 720
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.mainloop()


def _run_cli(text: str, bits: int, workers: int, fast: bool) -> None:
    from aes_brute_force.core.aes_engine import bytes_to_hex, encrypt_aes
    from aes_brute_force.core.brute_force import brute_force_aes, estimate_time

    print("=" * 55)
    print("  AES BRUTE-FORCE DEMO (CLI)")
    print("=" * 55)
    print(f"Plaintext    : {text}")
    print(f"Key bits     : {bits}")

    ct, key, key_int = encrypt_aes(text, bits)
    print(f"\n[Encrypt] key_int={key_int} (0x{key_int:0{bits // 4}X})")
    print(f"  Ciphertext : {bytes_to_hex(ct)}")
    print(f"\n[Brute-force] Trying {2 ** bits:,} keys ...")

    milestone = max(1, (2**bits) // 20)

    def _cb(cur: int, total: int, elapsed: float) -> None:
        if cur % (milestone * 5) == 0 or cur == total:
            pct = cur / total * 100
            kps = cur / elapsed if elapsed > 0 else 0
            print(f"  [{pct:5.1f}%] {cur:>8,}/{total:,} | {elapsed:.1f}s | {kps:,.0f} keys/s")

    result = brute_force_aes(ct, bits, callback=_cb, workers=workers, fast_mode=fast)

    print("\n" + "=" * 55)
    if result["found"]:
        print(f"[OK] Key found: {result['key_int']} (0x{result['key_hex']})")
        print(f"     Plaintext : {result['plaintext']}")
        print(f"     Time      : {result['elapsed_seconds']:.3f}s")
        print(f"     Speed     : {result['keys_per_second']:,.0f} keys/s")
    else:
        print("[FAIL] Key not found.")

    print("\n[Estimates at measured speed]")
    kps = result["keys_per_second"] if result["keys_per_second"] > 0 else 50_000
    for b in [16, 20, 24, 32, 64, 128]:
        est = estimate_time(b, kps)
        print(f"  {b:>4}-bit : {est['keyspace_formatted']:32s} | avg: {est['avg_time_formatted']}")


def _check_deps() -> None:
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("[ERROR] matplotlib is required: pip install matplotlib")
        sys.exit(1)


def main(argv: Sequence[str] | None = None) -> None:
    import logging

    configure_console()
    args = _parse_args(argv)
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO)
    _check_deps()

    if args.gui or (not args.cli):
        try:
            _run_gui()
            return
        except ImportError:
            logger.warning("Tkinter unavailable — falling back to CLI.")

    _run_cli(args.text, args.bits, args.workers, args.fast)


if __name__ == "__main__":
    main()
