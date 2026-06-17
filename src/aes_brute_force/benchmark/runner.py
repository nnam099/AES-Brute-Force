"""
Benchmark runner — measure brute-force speed across key lengths.

Each run is saved to a timestamped subdirectory under ``results/`` so
that previous measurements are never overwritten.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from aes_brute_force.core.aes_engine import encrypt_aes
from aes_brute_force.core.brute_force import brute_force_aes, estimate_time
from aes_brute_force.core.constants import SUPPORTED_KEY_BITS
from aes_brute_force.utils.logging import configure_console, get_logger

logger = get_logger("benchmark")

DEFAULT_KEY_BITS = [8, 12, 16]
RESULTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "results"
DEFAULT_CHART_NAME = "benchmark_chart.png"
DEFAULT_JSON_NAME = "benchmark_data.json"


def _parse_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid integer: {value!r}") from exc


def make_run_dir(base: Path = RESULTS_DIR, stamp: str | None = None) -> Path:
    stamp = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = base / f"benchmark_{stamp}"
    if not candidate.exists():
        return candidate
    idx = 2
    while True:
        alt = base / f"benchmark_{stamp}_{idx}"
        if not alt.exists():
            return alt
        idx += 1


def resolve_output_paths(
    output: str | None,
    json_path: str | None,
    output_dir: str | None,
    no_plot: bool,
    no_json: bool,
) -> tuple[str | None, str | None]:
    if no_plot and no_json:
        return None, None
    run_dir = Path(output_dir) if output_dir else make_run_dir()
    chart = None if no_plot else (output or str(run_dir / DEFAULT_CHART_NAME))
    data = None if no_json else (json_path or str(run_dir / DEFAULT_JSON_NAME))
    return chart, data


def benchmark_key_length(
    key_bits: int,
    test_text: str = "SECRET",
    verbose: bool = True,
    workers: int = 1,
    key_int: int | None = None,
) -> dict:
    if verbose:
        print(f"\n[Key {key_bits}-bit] keyspace=2^{key_bits}={2**key_bits:,}")

    ct, key, actual_int = encrypt_aes(test_text, key_bits, key_int=key_int)
    if verbose:
        print(f"  key_int={actual_int} — starting brute force ...")

    result = brute_force_aes(ct, key_bits, workers=workers)
    rec = {
        "key_bits": key_bits,
        "keyspace": 1 << key_bits,
        "test_text": test_text,
        "actual_key_int": actual_int,
        "found": result["found"],
        "found_key_int": result.get("key_int"),
        "found_plaintext": result.get("plaintext"),
        "elapsed_seconds": result["elapsed_seconds"],
        "keys_tested": result["keys_tested"],
        "keys_per_second": result["keys_per_second"],
        "percent_searched": result["percent_searched"],
    }
    if verbose and result["found"]:
        print(
            f"  Found key={result['key_int']} in {result['elapsed_seconds']:.3f}s "
            f"({result['keys_per_second']:,.0f} keys/s)"
        )
    return rec


def run_all_benchmarks(
    bits_list: list[int] | None = None,
    test_text: str = "SECRET",
    workers: int = 1,
    key_int: int | None = None,
) -> list[dict]:
    bits_list = bits_list or DEFAULT_KEY_BITS
    print("=" * 55)
    print("  AES BRUTE-FORCE BENCHMARK")
    print("=" * 55)
    results = []
    for bits in bits_list:
        if bits not in SUPPORTED_KEY_BITS:
            raise ValueError(f"Unsupported: {bits}")
        results.append(benchmark_key_length(bits, test_text, workers=workers, key_int=key_int))

    print(f"\n{'Bits':>5} | {'Keyspace':>15} | {'Time':>10} | {'Keys/s':>12} | Result")
    print("-" * 65)
    for r in results:
        print(
            f"{r['key_bits']:>5} | {r['keyspace']:>15,} | "
            f"{r['elapsed_seconds']:>9.3f}s | {r['keys_per_second']:>12,.0f} | "
            f"{'found' if r['found'] else 'not found'}"
        )
    return results


def plot_results(results: list[dict], save_path: str | None = None) -> str:
    save_path = save_path or str(make_run_dir() / DEFAULT_CHART_NAME)
    Path(save_path).parent.mkdir(parents=True, exist_ok=True)

    bits = [r["key_bits"] for r in results]
    times = [r["elapsed_seconds"] for r in results]
    kps_avg = sum(r["keys_per_second"] for r in results) / len(results)

    all_bits = list(range(min(bits), 33))
    base_t, base_b = (times[0] if times else 1.0), (bits[0] if bits else 8)
    theoretical = [base_t * (2 ** (b - base_b)) for b in all_bits]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("AES Brute-Force Time vs Key Length", fontsize=14, fontweight="bold")

    ax1.plot(bits, times, "bo-", lw=2, ms=8, label="Measured", zorder=5)
    ax1.plot(all_bits, theoretical, "r--", lw=1.5, alpha=0.7, label="Theoretical (2^n)")
    ax1.set_yscale("log")
    ax1.set_xlabel("Key bits")
    ax1.set_ylabel("Time (seconds, log)")
    ax1.set_title("Measured vs Exponential Growth")
    ax1.legend()
    ax1.grid(True, which="both", alpha=0.3)
    for b, t in zip(bits, times):
        ax1.annotate(f"{t:.2f}s", (b, t), textcoords="offset points", xytext=(5, 5), fontsize=9)

    ext_bits = list(range(8, 129, 8))
    ext_times = [(1 << b) / (2 * kps_avg) for b in ext_bits]
    colors = ["#2ecc71" if t < 60 else "#f39c12" if t < 3600 else "#e74c3c" for t in ext_times]
    ax2.barh(
        ext_bits, [max(t, 0.001) for t in ext_times], color=colors, edgecolor="white", height=5
    )
    ax2.set_xscale("log")
    ax2.set_xlabel("Average time (seconds, log)")
    ax2.set_ylabel("Key bits")
    ax2.set_title("Estimated Average Time")
    ax2.set_yticks(ext_bits)
    ax2.grid(True, axis="x", alpha=0.3)
    ax2.legend(
        handles=[
            Patch(facecolor="#2ecc71", label="< 1 min"),
            Patch(facecolor="#f39c12", label="< 1 hour"),
            Patch(facecolor="#e74c3c", label="> 1 hour"),
        ],
        fontsize=9,
        loc="lower right",
    )
    ax2.axhline(y=128, color="purple", ls=":", lw=2, alpha=0.7)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Chart saved: %s", save_path)
    return save_path


def save_json(results: list[dict], path: str | None = None) -> str:
    path = path or str(make_run_dir() / DEFAULT_JSON_NAME)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info("Data saved: %s", path)
    return path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Benchmark AES brute-force speed",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--bits", nargs="+", type=int, default=DEFAULT_KEY_BITS, choices=SUPPORTED_KEY_BITS
    )
    p.add_argument("--text", default="SECRET")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--key-int", type=_parse_int, default=None)
    p.add_argument("--output-dir", default=None)
    p.add_argument("--output", default=None)
    p.add_argument("--json", default=None)
    p.add_argument("--no-plot", action="store_true")
    p.add_argument("--no-json", action="store_true")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    configure_console()
    args = parse_args(argv)
    results = run_all_benchmarks(args.bits, args.text, args.workers, args.key_int)
    chart, data = resolve_output_paths(
        args.output, args.json, args.output_dir, args.no_plot, args.no_json
    )
    if chart:
        plot_results(results, chart)
    if data:
        save_json(results, data)


if __name__ == "__main__":
    main()
