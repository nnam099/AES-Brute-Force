"""
benchmark.py - Đo thời gian vét cạn với nhiều độ dài khóa.

Mục tiêu của file này là lấy số liệu thực nghiệm để so sánh với công thức
T_avg = 2^(n-1) / R. Mỗi lần chạy nên lưu vào thư mục riêng để không ghi đè
kết quả cũ trong quá trình làm báo cáo.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
import time
from typing import List, Optional, Sequence

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

from aes_engine import encrypt_aes
from brute_force import brute_force_aes, estimate_time, SUPPORTED_KEY_BITS

DEFAULT_KEY_BITS = [8, 12, 16]
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
DEFAULT_CHART_NAME = "benchmark_chart.png"
DEFAULT_JSON_NAME = "benchmark_data.json"


def configure_console() -> None:
    """Chuẩn hóa output console sang UTF-8 khi môi trường hỗ trợ."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def parse_int(value: str) -> int:
    """Đọc số nguyên dạng thập phân hoặc dạng 0x cho tùy chọn CLI."""
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Giá trị số nguyên không hợp lệ: {value!r}"
        ) from exc


def make_run_dir(base_dir: Path = RESULTS_DIR, timestamp: Optional[str] = None) -> Path:
    """Tạo tên thư mục kết quả riêng để tránh ghi đè các lần đo trước."""
    stamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = base_dir / f"benchmark_{stamp}"
    if not candidate.exists():
        return candidate

    index = 2
    while True:
        fallback = base_dir / f"benchmark_{stamp}_{index}"
        if not fallback.exists():
            return fallback
        index += 1


def resolve_output_paths(
    output: Optional[str],
    json_path: Optional[str],
    output_dir: Optional[str],
    no_plot: bool,
    no_json: bool,
) -> tuple[Optional[str], Optional[str]]:
    """Xác định đường dẫn lưu biểu đồ/JSON mà không ghi đè mặc định."""
    if no_plot and no_json:
        return None, None

    run_dir = Path(output_dir) if output_dir is not None else make_run_dir()

    chart_path = None if no_plot else output
    data_path = None if no_json else json_path

    if chart_path is None and not no_plot:
        chart_path = str(run_dir / DEFAULT_CHART_NAME)
    if data_path is None and not no_json:
        data_path = str(run_dir / DEFAULT_JSON_NAME)

    return chart_path, data_path


def benchmark_key_length(
    key_bits: int,
    test_text: str = "SECRET",
    verbose: bool = True,
    workers: int = 1,
    key_int: Optional[int] = None,
) -> dict:
    """Mã hóa một bản rõ mẫu rồi đo thời gian tìm lại khóa bằng vét cạn."""
    if verbose:
        print(f"\n[Khóa {key_bits}-bit]")
        print(f"  Không gian khóa : 2^{key_bits} = {2**key_bits:,} khóa")
        print(f"  Bản rõ mẫu      : {test_text!r}")

    ciphertext, key, actual_key_int = encrypt_aes(test_text, key_bits, key_int=key_int)

    if verbose:
        label = "Giá trị khóa cố định" if key_int is not None else "Giá trị khóa"
        print(f"  {label:<16}: {actual_key_int} (0x{actual_key_int:0{key_bits//4}X})")
        print("  Bắt đầu thử khóa...")

    result = brute_force_aes(ciphertext, key_bits, workers=workers)

    benchmark_result = {
        'key_bits': key_bits,
        'keyspace': 1 << key_bits,
        'test_text': test_text,
        'actual_key_int': actual_key_int,
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
            print(f"  Tìm thấy        : khóa={result['key_int']}, bản rõ={result['plaintext']!r}")
        else:
            print("  Không tìm thấy khóa phù hợp.")
        print(f"  Thời gian       : {result['elapsed_seconds']:.3f}s")
        print(f"  Tốc độ          : {result['keys_per_second']:,.0f} khóa/giây")

    return benchmark_result


def run_all_benchmarks(
    key_bits_list: List[int] = None,
    test_text: str = "SECRET",
    workers: int = 1,
    key_int: Optional[int] = None,
) -> List[dict]:
    """Chạy benchmark cho một hoặc nhiều độ dài khóa."""
    if key_bits_list is None:
        key_bits_list = DEFAULT_KEY_BITS

    print("=" * 55)
    print("  ĐO THỜI GIAN VÉT CẠN AES")
    print("=" * 55)
    print(f"  Bản rõ kiểm thử : {test_text!r}")
    print(f"  Các độ dài khóa : {key_bits_list} bit")
    if key_int is not None:
        print(f"  Khóa cố định    : {key_int} (0x{key_int:X})")

    results = []
    for bits in key_bits_list:
        if bits not in SUPPORTED_KEY_BITS:
            raise ValueError(f"Độ dài khóa không hợp lệ: {bits}. Hỗ trợ: {SUPPORTED_KEY_BITS}")
        results.append(benchmark_key_length(bits, test_text, workers=workers, key_int=key_int))

    print("\n" + "=" * 55)
    print("  BẢNG TÓM TẮT")
    print("=" * 55)
    print(f"  {'Bit':>5} | {'Không gian khóa':>15} | {'Thời gian':>10} | {'Khóa/giây':>12} | Kết quả")
    print("  " + "-" * 53)
    for r in results:
        print(
            f"  {r['key_bits']:>5} | "
            f"{r['keyspace']:>15,} | "
            f"{r['elapsed_seconds']:>9.3f}s | "
            f"{r['keys_per_second']:>12,.0f} | "
            f"{'tìm thấy' if r['found'] else 'không thấy'}"
        )

    return results


def plot_results(results: List[dict], save_path: str = None) -> str:
    """Vẽ biểu đồ thời gian theo độ dài khóa và lưu ảnh."""
    if save_path is None:
        save_path = str(make_run_dir() / DEFAULT_CHART_NAME)

    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    bits = [r['key_bits'] for r in results]
    times = [r['elapsed_seconds'] for r in results]
    kps_avg = sum(r['keys_per_second'] for r in results) / len(results)

    all_bits = list(range(min(bits), 33))
    base_time = times[0] if times else 1.0
    base_bits = bits[0] if bits else 8
    theoretical = [base_time * (2 ** (b - base_bits)) for b in all_bits]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Thời gian vét cạn AES theo độ dài khóa', fontsize=14, fontweight='bold')

    ax1 = axes[0]
    ax1.plot(bits, times, 'bo-', linewidth=2, markersize=8, label='Thực nghiệm', zorder=5)
    ax1.plot(all_bits, theoretical, 'r--', linewidth=1.5, alpha=0.7, label='Lý thuyết ($2^n$)')
    ax1.set_yscale('log')
    ax1.set_xlabel('Độ dài khóa (bits)', fontsize=12)
    ax1.set_ylabel('Thời gian (giây, log scale)', fontsize=12)
    ax1.set_title('Số đo thực nghiệm và đường tăng 2^n', fontsize=12)
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
    ax2.set_title('Ước tính thời gian trung bình', fontsize=12)
    ax2.set_yticks(extended_bits)
    ax2.grid(True, axis='x', alpha=0.3)

    legend_elements = [
        Patch(facecolor='#2ecc71', label='< 1 phút'),
        Patch(facecolor='#f39c12', label='< 1 giờ'),
        Patch(facecolor='#e74c3c', label='> 1 giờ'),
    ]
    ax2.legend(handles=legend_elements, fontsize=9, loc='lower right')
    ax2.axhline(y=128, color='purple', linestyle=':', linewidth=2, alpha=0.7)
    ax2.text(1e-3, 130, 'AES-128 (chuẩn)', color='purple', fontsize=9, va='bottom')

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"\nBiểu đồ đã lưu: {save_path}")
    return save_path


def save_results_json(results: List[dict], path: str = None) -> str:
    """Lưu kết quả benchmark ra file JSON."""
    if path is None:
        path = str(make_run_dir() / DEFAULT_JSON_NAME)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Dữ liệu đã lưu: {path}")
    return path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Đo hiệu năng vét cạn AES theo nhiều độ dài khóa.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '--bits',
        nargs='+',
        type=int,
        default=DEFAULT_KEY_BITS,
        choices=SUPPORTED_KEY_BITS,
        help='Danh sách độ dài khóa để đo hiệu năng.',
    )
    parser.add_argument('--text', default='SECRET', help='Bản rõ dùng để đo hiệu năng.')
    parser.add_argument('--workers', type=int, default=1, help='Số tiến trình dùng cho vét cạn.')
    parser.add_argument('--key-int', type=parse_int, default=None, help='Giá trị khóa cố định để chạy tái lập; chấp nhận số thập phân hoặc dạng 0x...')
    parser.add_argument('--output-dir', default=None, help='Thư mục lưu kết quả. Mặc định tạo thư mục timestamp trong results/.')
    parser.add_argument('--output', default=None, help='Đường dẫn lưu biểu đồ. Nếu bỏ trống, dùng file trong thư mục kết quả riêng.')
    parser.add_argument('--json', default=None, help='Đường dẫn lưu dữ liệu JSON. Nếu bỏ trống, dùng file trong thư mục kết quả riêng.')
    parser.add_argument('--no-plot', action='store_true', help='Không vẽ biểu đồ.')
    parser.add_argument('--no-json', action='store_true', help='Không lưu dữ liệu JSON.')
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    configure_console()
    args = parse_args(argv)
    results = run_all_benchmarks(
        key_bits_list=args.bits,
        test_text=args.text,
        workers=args.workers,
        key_int=args.key_int,
    )

    chart_path, json_path = resolve_output_paths(
        args.output,
        args.json,
        args.output_dir,
        args.no_plot,
        args.no_json,
    )

    if chart_path is not None:
        plot_results(results, save_path=chart_path)

    if json_path is not None:
        save_results_json(results, path=json_path)


if __name__ == "__main__":
    main()
