"""
benchmark.py - Đo lường và phân tích hiệu năng brute-force.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from typing import List

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

from aes_engine import encrypt_aes
from brute_force import brute_force_aes, estimate_time, SUPPORTED_KEY_BITS

DEFAULT_KEY_BITS = [8, 12, 16]
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def benchmark_key_length(key_bits: int, test_text: str = "SECRET", verbose: bool = True) -> dict:
    """Đo thời gian brute-force cho một độ dài khóa cụ thể."""
    if verbose:
        print(f"\n[Benchmark {key_bits}-bit]")
        print(f"  Keyspace: 2^{key_bits} = {2**key_bits:,} keys")
        print(f"  Encrypting '{test_text}'...")

    ciphertext, key, key_int = encrypt_aes(test_text, key_bits)

    if verbose:
        print(f"  Key value: {key_int} (0x{key_int:0{key_bits//4}X})")
        print("  Running brute-force...")

    result = brute_force_aes(ciphertext, key_bits)

    benchmark_result = {
        'key_bits': key_bits,
        'keyspace': 1 << key_bits,
        'test_text': test_text,
        'actual_key_int': key_int,
        'found': result['found'],
        'found_key_int': result.get('key_int'),
        'found_plaintext': result.get('plaintext'),
        'elapsed_seconds': result['elapsed_seconds'],
        'keys_tested': result['keys_tested'],
        'keys_per_second': result['keys_per_second'],
        'percent_searched': result['percent_searched'],
    }

    if verbose:
        if result['found']:
            print(f"  ✅ Found: key={result['key_int']}, text='{result['plaintext']}'")
        else:
            print("  ❌ Not found (stopped early or exhausted)")
        print(f"  Time    : {result['elapsed_seconds']:.3f}s")
        print(f"  Keys/s  : {result['keys_per_second']:,.0f}")

    return benchmark_result


def run_all_benchmarks(key_bits_list: List[int] = None, test_text: str = "SECRET") -> List[dict]:
    """Chạy benchmark cho một hoặc nhiều độ dài khóa."""
    if key_bits_list is None:
        key_bits_list = DEFAULT_KEY_BITS

    print("=" * 55)
    print("  BENCHMARK AES BRUTE-FORCE")
    print("=" * 55)
    print(f"  Test text: '{test_text}'")
    print(f"  Key lengths: {key_bits_list} bits")

    results = []
    for bits in key_bits_list:
        if bits not in SUPPORTED_KEY_BITS:
            raise ValueError(f"Độ dài khóa không hợp lệ: {bits}. Hỗ trợ: {SUPPORTED_KEY_BITS}")
        results.append(benchmark_key_length(bits, test_text))

    print("\n" + "=" * 55)
    print("  SUMMARY TABLE")
    print("=" * 55)
    print(f"  {'Bits':>5} | {'Keyspace':>15} | {'Time':>10} | {'Keys/s':>12} | Found")
    print("  " + "-" * 53)
    for r in results:
        print(
            f"  {r['key_bits']:>5} | "
            f"{r['keyspace']:>15,} | "
            f"{r['elapsed_seconds']:>9.3f}s | "
            f"{r['keys_per_second']:>12,.0f} | "
            f"{'✅' if r['found'] else '❌'}"
        )

    return results


def plot_results(results: List[dict], save_path: str = None) -> str:
    """Vẽ biểu đồ thời gian theo độ dài khóa và lưu ảnh."""
    if save_path is None:
        save_path = str(RESULTS_DIR / "benchmark_chart.png")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    bits = [r['key_bits'] for r in results]
    times = [r['elapsed_seconds'] for r in results]
    kps_avg = sum(r['keys_per_second'] for r in results) / len(results)

    all_bits = list(range(min(bits), 33))
    base_time = times[0] if times else 1.0
    base_bits = bits[0] if bits else 8
    theoretical = [base_time * (2 ** (b - base_bits)) for b in all_bits]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('AES Brute-Force: Phân tích Thời gian theo Độ dài Khóa', fontsize=14, fontweight='bold')

    ax1 = axes[0]
    ax1.plot(bits, times, 'bo-', linewidth=2, markersize=8, label='Thực nghiệm', zorder=5)
    ax1.plot(all_bits, theoretical, 'r--', linewidth=1.5, alpha=0.7, label='Lý thuyết ($2^n$)')
    ax1.set_yscale('log')
    ax1.set_xlabel('Độ dài khóa (bits)', fontsize=12)
    ax1.set_ylabel('Thời gian (giây, log scale)', fontsize=12)
    ax1.set_title('Thực nghiệm vs Lý thuyết', fontsize=12)
    ax1.legend(fontsize=10)
    ax1.grid(True, which='both', alpha=0.3)
    for b, t in zip(bits, times):
        ax1.annotate(f'{t:.2f}s', (b, t), textcoords='offset points', xytext=(5, 5), fontsize=9)

    ax2 = axes[1]
    extended_bits = list(range(8, 129, 8))
    extended_times_sec = [(1 << b) / (2 * kps_avg) for b in extended_bits]

    colors = [
        '#2ecc71' if t < 60 else '#f39c12' if t < 3600 else '#e74c3c'
        for t in extended_times_sec
    ]
    ax2.barh(extended_bits, [max(t, 0.001) for t in extended_times_sec], color=colors, edgecolor='white', height=5)
    ax2.set_xscale('log')
    ax2.set_xlabel('Thời gian trung bình (giây, log scale)', fontsize=12)
    ax2.set_ylabel('Độ dài khóa (bits)', fontsize=12)
    ax2.set_title('Ước tính thời gian brute-force', fontsize=12)
    ax2.set_yticks(extended_bits)
    ax2.grid(True, axis='x', alpha=0.3)

    legend_elements = [
        Patch(facecolor='#2ecc71', label='< 1 phút (NGUY HIỂM)'),
        Patch(facecolor='#f39c12', label='< 1 giờ (YẾU)'),
        Patch(facecolor='#e74c3c', label='> 1 giờ (an toàn hơn)'),
    ]
    ax2.legend(handles=legend_elements, fontsize=9, loc='lower right')
    ax2.axhline(y=128, color='purple', linestyle=':', linewidth=2, alpha=0.7)
    ax2.text(1e-3, 130, '← AES-128 (chuẩn)', color='purple', fontsize=9, va='bottom')

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"\n✅ Biểu đồ đã lưu: {save_path}")
    return save_path


def save_results_json(results: List[dict], path: str = None) -> str:
    """Lưu kết quả benchmark ra file JSON."""
    if path is None:
        path = str(RESULTS_DIR / "benchmark_data.json")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"✅ Dữ liệu đã lưu: {path}")
    return path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark AES brute-force theo nhiều độ dài khóa.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '--bits',
        nargs='+',
        type=int,
        default=DEFAULT_KEY_BITS,
        choices=SUPPORTED_KEY_BITS,
        help='Danh sách độ dài khóa để benchmark.',
    )
    parser.add_argument('--text', default='SECRET', help='Plaintext dùng cho benchmark.')
    parser.add_argument('--output', default=str(RESULTS_DIR / 'benchmark_chart.png'), help='Đường dẫn lưu biểu đồ.')
    parser.add_argument('--json', default=str(RESULTS_DIR / 'benchmark_data.json'), help='Đường dẫn lưu dữ liệu JSON.')
    parser.add_argument('--no-plot', action='store_true', help='Không vẽ biểu đồ.')
    parser.add_argument('--no-json', action='store_true', help='Không lưu dữ liệu JSON.')
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    results = run_all_benchmarks(key_bits_list=args.bits, test_text=args.text)

    if not args.no_plot:
        plot_results(results, save_path=args.output)

    if not args.no_json:
        save_results_json(results, path=args.json)


if __name__ == "__main__":
    main()
