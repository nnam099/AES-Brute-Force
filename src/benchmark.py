"""
benchmark.py - Đo lường và phân tích hiệu năng brute-force
"""

import time
import os
import json
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

from aes_engine import encrypt_aes
from brute_force import brute_force_aes, estimate_time


def benchmark_key_length(key_bits: int, test_text: str = "SECRET", verbose: bool = True) -> dict:
    """
    Đo thời gian brute-force cho một độ dài khóa cụ thể.
    
    Args:
        key_bits: Độ dài khóa (bits)
        test_text: Văn bản test
        verbose: In kết quả ra terminal
    
    Returns:
        dict: Kết quả benchmark
    """
    if verbose:
        print(f"\n[Benchmark {key_bits}-bit]")
        print(f"  Keyspace: 2^{key_bits} = {2**key_bits:,} keys")
        print(f"  Encrypting '{test_text}'...")

    ciphertext, key, key_int = encrypt_aes(test_text, key_bits)

    if verbose:
        print(f"  Key value: {key_int} (0x{key_int:0{key_bits//4}X})")
        print(f"  Running brute-force...")

    start = time.time()
    result = brute_force_aes(ciphertext, key_bits)
    elapsed = time.time() - start

    benchmark_result = {
        'key_bits': key_bits,
        'keyspace': 2 ** key_bits,
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
            print(f"  ❌ Not found (stopped early or exhausted)")
        print(f"  Time    : {elapsed:.3f}s")
        print(f"  Keys/s  : {result['keys_per_second']:,.0f}")

    return benchmark_result


def run_all_benchmarks(key_bits_list: list = None, test_text: str = "SECRET") -> list:
    """
    Chạy benchmark cho nhiều độ dài khóa.
    
    Args:
        key_bits_list: Danh sách độ dài khóa cần test
        test_text: Văn bản test
    
    Returns:
        list: Danh sách kết quả
    """
    if key_bits_list is None:
        key_bits_list = [8, 12, 16]  # Chỉ chạy các bits nhỏ để demo nhanh

    print("=" * 55)
    print("  BENCHMARK AES BRUTE-FORCE")
    print("=" * 55)
    print(f"  Test text: '{test_text}'")
    print(f"  Key lengths: {key_bits_list} bits")

    results = []
    for bits in key_bits_list:
        result = benchmark_key_length(bits, test_text)
        results.append(result)

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


def plot_results(results: list, save_path: str = "results/benchmark_chart.png"):
    """
    Vẽ biểu đồ thời gian theo độ dài khóa.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    bits = [r['key_bits'] for r in results]
    times = [r['elapsed_seconds'] for r in results]
    kps_avg = sum(r['keys_per_second'] for r in results) / len(results)

    # Dự đoán lý thuyết cho nhiều điểm
    all_bits = list(range(min(bits), 33))
    base_time = times[0] if times else 1.0
    base_bits = bits[0] if bits else 8
    theoretical = [base_time * (2 ** (b - base_bits)) for b in all_bits]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('AES Brute-Force: Phân tích Thời gian theo Độ dài Khóa', fontsize=14, fontweight='bold')

    # --- Chart 1: Thực tế vs Lý thuyết ---
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
        ax1.annotate(f'{t:.2f}s', (b, t), textcoords="offset points", xytext=(5, 5), fontsize=9)

    # --- Chart 2: Ước tính mở rộng ---
    ax2 = axes[1]
    extended_bits = list(range(8, 129, 8))
    extended_times_sec = [(2 ** b) / (2 * kps_avg) for b in extended_bits]  # avg case

    labels = []
    for t in extended_times_sec:
        if t < 60:
            labels.append(f"{t:.1f}s")
        elif t < 3600:
            labels.append(f"{t/60:.1f}m")
        elif t < 86400:
            labels.append(f"{t/3600:.1f}h")
        elif t < 86400*365:
            labels.append(f"{t/86400:.0f}d")
        else:
            labels.append(f"{t/86400/365:.1e}y")

    colors = ['#2ecc71' if t < 60 else '#f39c12' if t < 3600 else '#e74c3c' for t in extended_times_sec]
    bars = ax2.barh(extended_bits, [max(t, 0.001) for t in extended_times_sec], color=colors, edgecolor='white', height=5)
    ax2.set_xscale('log')
    ax2.set_xlabel('Thời gian trung bình (giây, log scale)', fontsize=12)
    ax2.set_ylabel('Độ dài khóa (bits)', fontsize=12)
    ax2.set_title('Ước tính thời gian brute-force', fontsize=12)
    ax2.set_yticks(extended_bits)
    ax2.grid(True, axis='x', alpha=0.3)

    # Thêm legend màu
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#2ecc71', label='< 1 phút (NGUY HIỂM)'),
        Patch(facecolor='#f39c12', label='< 1 giờ (YẾU)'),
        Patch(facecolor='#e74c3c', label='> 1 giờ (an toàn hơn)')
    ]
    ax2.legend(handles=legend_elements, fontsize=9, loc='lower right')

    # Đánh dấu AES thực tế
    ax2.axhline(y=128, color='purple', linestyle=':', linewidth=2, alpha=0.7)
    ax2.text(1e-3, 130, '← AES-128 (chuẩn)', color='purple', fontsize=9, va='bottom')

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    print(f"\n✅ Biểu đồ đã lưu: {save_path}")
    plt.close()

    return save_path


def generate_theoretical_table(kps: float = 50_000) -> None:
    """In bảng ước tính lý thuyết cho mọi độ dài khóa."""
    print("\n" + "=" * 70)
    print("  BẢNG ƯỚC TÍNH THỜI GIAN (Lý thuyết)")
    print(f"  Tốc độ giả định: {kps:,.0f} keys/giây")
    print("=" * 70)
    print(f"  {'Bits':>5} | {'Keyspace':>20} | {'Avg Case':>15} | {'Worst Case':>15}")
    print("  " + "-" * 62)

    for bits in [8, 12, 16, 20, 24, 28, 32, 48, 64, 96, 128]:
        est = estimate_time(bits, kps)
        print(
            f"  {bits:>5} | "
            f"2^{bits} = {est['keyspace']:>15,} | "
            f"{est['avg_time_formatted']:>15} | "
            f"{est['worst_time_formatted']:>15}"
        )


def save_results_json(results: list, path: str = "results/benchmark_data.json"):
    """Lưu kết quả benchmark ra file JSON."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"✅ Dữ liệu đã lưu: {path}")


if __name__ == "__main__":
    # Chạy benchmark cho 8, 12, 16 bits (đủ nhanh để demo)
    results = run_all_benchmarks(key_bits_list=[8, 12, 16], test_text="SECRET")

    # Vẽ biểu đồ
    plot_results(results, save_path="results/benchmark_chart.png")

    # Lưu dữ liệu
    save_results_json(results, path="results/benchmark_data.json")

    # Bảng lý thuyết
    if results:
        kps = sum(r['keys_per_second'] for r in results) / len(results)
        generate_theoretical_table(kps)
