"""
gui.py - Giao diện đồ họa Tkinter
Minh họa tấn công vét cạn AES
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import multiprocessing

class AESBruteForceApp:
    """Ứng dụng GUI chính minh họa vét cạn AES."""

    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Minh Họa Vét Cạn AES - Mật Mã Học")
        self.root.geometry("960x720")
        self.root.configure(bg="#24273A")
        self.root.resizable(True, True)

        # State
        self._bf_thread = None
        self._stop_flag = threading.Event()
        self._ciphertext = None
        self._encrypt_key_int = None
        self._encrypt_key_bits = None
        self.bf_verbose_log = tk.BooleanVar(value=True)
        self._last_log_time = 0.0  # throttle cho detail_callback

        self._build_ui()

    # ─────────────────────────────────────────────
    # BUILD UI
    # ─────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self.root, bg="#1E2030", pady=16)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text="🔐 Tấn Công Vét Cạn AES",
            font=("Segoe UI", 18, "bold"),
            bg="#1E2030", fg="#CAD3F5"
        ).pack()
        tk.Label(
            hdr,
            text="Minh họa phương pháp thám mã khóa ngắn  |  Python thuần",
            font=("Segoe UI", 10),
            bg="#1E2030", fg="#A5ADCB"
        ).pack(pady=(4, 0))

        # ── Notebook (tabs) ──
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook', background='#24273A', borderwidth=0)
        style.configure('TNotebook.Tab', background='#1E2030', foreground='#CAD3F5',
                        padding=[16, 8], font=('Segoe UI', 10, 'bold'), borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', '#8AADF4')],
                  foreground=[('selected', '#1E2030')])

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        self._build_tab_encrypt()
        self._build_tab_bruteforce()
        self._build_tab_theory()

        # ── Statusbar ──
        self.status_var = tk.StringVar(value="✅ Sẵn sàng")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Segoe UI", 9, "bold"), bg="#181825", fg="#A6DA95",
            anchor='w', padx=16, pady=6
        ).pack(fill=tk.X, side=tk.BOTTOM)

    # ── Tab 1: Mã hóa / Giải mã ──────────────────

    def _build_tab_encrypt(self):
        frame = tk.Frame(self.nb, bg="#24273A")
        self.nb.add(frame, text="  🔒 Mã hóa / Giải mã  ")

        # Input Section
        input_frame = tk.Frame(frame, bg="#24273A")
        input_frame.pack(fill=tk.X, padx=20, pady=16)

        self._label(input_frame, "📝 Bản rõ (văn bản gốc):").grid(row=0, column=0, sticky='w', pady=8, padx=(0, 10))
        self.enc_plaintext = self._entry(input_frame, width=54)
        self.enc_plaintext.insert(0, "HELLO WORLD")
        self.enc_plaintext.grid(row=0, column=1, sticky='w', pady=8)

        self._label(input_frame, "🔑 Độ dài khóa:").grid(row=1, column=0, sticky='w', pady=8, padx=(0, 10))
        self.enc_key_bits = tk.IntVar(value=16)
        kf = tk.Frame(input_frame, bg="#363A4F", padx=8, pady=4)
        kf.grid(row=1, column=1, sticky='w', pady=8)
        for v, label in [(8, "8-bit"), (12, "12-bit"), (16, "16-bit"), (20, "20-bit"), (24, "24-bit"), (32, "32-bit")]:
            tk.Radiobutton(
                kf, text=label, variable=self.enc_key_bits, value=v,
                bg="#363A4F", fg="#CAD3F5", selectcolor="#1E2030",
                activebackground="#363A4F", activeforeground="#8AADF4",
                font=("Segoe UI", 10, "bold"), cursor="hand2"
            ).pack(side=tk.LEFT, padx=6)

        self._label(input_frame, "🔢 Khóa cố định (tùy chọn):").grid(row=2, column=0, sticky='w', pady=8, padx=(0, 10))
        fixed_key_frame = tk.Frame(input_frame, bg="#24273A")
        fixed_key_frame.grid(row=2, column=1, sticky='w', pady=8)
        self.enc_use_fixed_key = tk.BooleanVar(value=False)
        tk.Checkbutton(
            fixed_key_frame, text="Dùng khóa cố định", variable=self.enc_use_fixed_key,
            bg="#24273A", fg="#CAD3F5", selectcolor="#1E2030",
            activebackground="#24273A", activeforeground="#8AADF4",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT)
        self.enc_key_int_entry = self._entry(fixed_key_frame, width=18)
        self.enc_key_int_entry.insert(0, "142")
        self.enc_key_int_entry.pack(side=tk.LEFT, padx=10)
        tk.Label(
            fixed_key_frame,
            text="(vd: 142 hoặc 0x8E)",
            font=("Segoe UI", 9), bg="#24273A", fg="#A5ADCB"
        ).pack(side=tk.LEFT)

        # Actions
        act_frame = tk.Frame(frame, bg="#24273A")
        act_frame.pack(fill=tk.X, padx=20, pady=5)
        self._btn(act_frame, "🔒  Mã hóa", self._do_encrypt, "#8AADF4").pack(side=tk.LEFT, padx=(0, 12))
        self._btn(act_frame, "🔓  Giải mã", self._do_decrypt, "#A6DA95").pack(side=tk.LEFT, padx=12)
        self._btn(act_frame, "🗑  Xóa", self._clear_enc, "#ED8796").pack(side=tk.LEFT, padx=12)

        # Output
        out_frame = tk.Frame(frame, bg="#24273A")
        out_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        self._label(out_frame, "📤 Kết quả:").pack(anchor='w', pady=(0, 8))
        self.enc_output = scrolledtext.ScrolledText(
            out_frame, font=("Consolas", 11),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=12, highlightthickness=0
        )
        self.enc_output.pack(fill=tk.BOTH, expand=True)

    # ── Tab 2: Vét cạn ────────────────────────

    def _build_tab_bruteforce(self):
        frame = tk.Frame(self.nb, bg="#24273A")
        self.nb.add(frame, text="  ⚡ Tấn công vét cạn  ")

        # Info
        info_frame = tk.Frame(frame, bg="#363A4F", padx=16, pady=10)
        info_frame.pack(fill=tk.X, padx=20, pady=16)
        tk.Label(
            info_frame,
            text="ℹ️ Bước 1: Mã hóa văn bản trong tab 'Mã hóa / Giải mã' → Bước 2: Sang đây bắt đầu tấn công",
            font=("Segoe UI", 10, "italic"), bg="#363A4F", fg="#EED49F"
        ).pack(anchor='w')

        # Config
        cfg_frame = tk.Frame(frame, bg="#24273A")
        cfg_frame.pack(fill=tk.X, padx=20)

        self._label(cfg_frame, "🔐 Bản mã (hex):").grid(row=0, column=0, sticky='w', pady=8, padx=(0, 10))
        self.bf_cipher_display = scrolledtext.ScrolledText(
            cfg_frame, height=2, width=54,
            font=("Consolas", 10),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=8, highlightthickness=0,
            wrap=tk.WORD
        )
        self.bf_cipher_display.grid(row=0, column=1, sticky='w', pady=8)

        self._label(cfg_frame, "🔑 Độ dài khóa:").grid(row=1, column=0, sticky='w', pady=8, padx=(0, 10))
        self.bf_key_bits = tk.IntVar(value=16)
        kf = tk.Frame(cfg_frame, bg="#363A4F", padx=8, pady=4)
        kf.grid(row=1, column=1, sticky='w', pady=8)
        for v, label in [(8, "8-bit"), (12, "12-bit"), (16, "16-bit"), (20, "20-bit"), (24, "24-bit")]:
            tk.Radiobutton(
                kf, text=label, variable=self.bf_key_bits, value=v,
                bg="#363A4F", fg="#CAD3F5", selectcolor="#1E2030",
                activebackground="#363A4F", activeforeground="#8AADF4",
                font=("Segoe UI", 10, "bold"), cursor="hand2"
            ).pack(side=tk.LEFT, padx=6)
        tk.Label(kf, text="(⚠️ 24-bit ~3 phút)",
                 font=("Segoe UI", 9), bg="#363A4F", fg="#EED49F").pack(side=tk.LEFT, padx=6)

        # Progress
        prog_frame = tk.Frame(frame, bg="#24273A")
        prog_frame.pack(fill=tk.X, padx=20, pady=10)
        self._label(prog_frame, "📊 Tiến trình:").pack(side=tk.LEFT, padx=(0, 10))
        
        style = ttk.Style()
        style.configure("TProgressbar", thickness=14, troughcolor='#363A4F', background='#A6DA95')
        self.bf_progress = ttk.Progressbar(prog_frame, mode='determinate', length=400, style="TProgressbar")
        self.bf_progress.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        
        self.bf_pct_label = tk.Label(prog_frame, text="0%", font=("Segoe UI", 10, "bold"),
                                     bg="#24273A", fg="#CAD3F5", width=5, anchor='e')
        self.bf_pct_label.pack(side=tk.LEFT)

        # Stats
        stat_frame = tk.Frame(frame, bg="#1E2030", padx=16, pady=8)
        stat_frame.pack(fill=tk.X, padx=20, pady=5)
        self.bf_stat_keys = tk.Label(stat_frame, text="Số khóa đã thử: 0", font=("Consolas", 10),
                                     bg="#1E2030", fg="#A6DA95")
        self.bf_stat_keys.pack(side=tk.LEFT, expand=True, anchor='w')
        self.bf_stat_kps = tk.Label(stat_frame, text="Khóa/giây: —", font=("Consolas", 10),
                                    bg="#1E2030", fg="#8AADF4")
        self.bf_stat_kps.pack(side=tk.LEFT, expand=True, anchor='center')
        self.bf_stat_time = tk.Label(stat_frame, text="Thời gian: 0.0s", font=("Consolas", 10),
                                     bg="#1E2030", fg="#F5A97F")
        self.bf_stat_time.pack(side=tk.LEFT, expand=True, anchor='e')

        # Actions
        act_frame = tk.Frame(frame, bg="#24273A")
        act_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Checkbutton(
            act_frame, text="Log chi tiết", variable=self.bf_verbose_log,
            bg="#24273A", fg="#CAD3F5", selectcolor="#1E2030",
            activebackground="#24273A", activeforeground="#8AADF4",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT, padx=(0, 12))
        
        self.bf_fast_mode = tk.BooleanVar(value=False)
        tk.Checkbutton(
            act_frame, text="🚀 Chế độ nhanh", variable=self.bf_fast_mode,
            bg="#24273A", fg="#A6DA95", selectcolor="#1E2030",
            activebackground="#24273A", activeforeground="#8AADF4",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT, padx=(0, 12))
        self.bf_btn_start = self._btn(act_frame, "⚡  Bắt đầu tấn công", self._do_brute_force, "#ED8796")
        self.bf_btn_start.pack(side=tk.LEFT, padx=(0, 12))
        self.bf_btn_stop = self._btn(act_frame, "⏹  Dừng", self._do_stop, "#F5A97F")
        self.bf_btn_stop.pack(side=tk.LEFT, padx=12)
        self.bf_btn_stop.configure(state=tk.DISABLED)
        self._btn(act_frame, "🗑  Xóa log", self._clear_bf, "#5B6078", fg="#CAD3F5").pack(side=tk.RIGHT)

        # Log
        log_frame = tk.Frame(frame, bg="#24273A")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 16))
        self._label(log_frame, "📋 Nhật ký:").pack(anchor='w', pady=(0, 8))
        self.bf_log = scrolledtext.ScrolledText(
            log_frame, font=("Consolas", 11),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=12, highlightthickness=0
        )
        self.bf_log.pack(fill=tk.BOTH, expand=True)

    # ── Tab 3: Theory ────────────────────────────

    def _build_tab_theory(self):
        frame = tk.Frame(self.nb, bg="#24273A")
        self.nb.add(frame, text="  📖 Lý thuyết  ")

        txt = scrolledtext.ScrolledText(
            frame, font=("Consolas", 11),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=16, highlightthickness=0,
            wrap=tk.WORD
        )
        txt.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        content = """══════════════════════════════════════════════════════════
  CƠ SỞ LÝ THUYẾT: AES VÀ TẤN CÔNG BRUTE-FORCE
══════════════════════════════════════════════════════════

1. AES (Tiêu chuẩn Mã hóa Nâng cao)
──────────────────────────────────────
• Tiêu chuẩn mã hóa đối xứng (FIPS-197, 2001)
• Kích thước khối: 128 bit (16 byte)
• Kích thước khóa chuẩn: 128 / 192 / 256 bit
• Số vòng: AES-128→10 vòng, AES-192→12, AES-256→14
• Triển khai trong demo: Python thuần
• Chế độ dùng trong demo: ECB (sổ mã điện tử)

2. Khóa ngắn trong demo này
──────────────────────────────────────
Thay vì dùng khóa 128-bit, chúng ta dùng khóa 8-24 bit
và pad phần còn lại bằng byte 0x00 → vẫn là AES-128
thực sự, nhưng không gian khóa nhỏ → có thể vét cạn.

  Ví dụ (khóa 16-bit = 0xABCD):
  Phần khóa bí mật : AB CD
  Khóa AES đầy đủ  : AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                     └─ 2 byte ─┘└──────────── 14 byte 0 ─────────────┘

3. Điểm yếu của chế độ ECB ⚠️
──────────────────────────────────────
ECB mã hóa mỗi khối 16 byte độc lập, KHÔNG dùng IV.

  NGUY HIỂM: Bản rõ giống nhau → bản mã giống nhau!

  Ví dụ:
  Bản rõ       : [KHỐI A][KHỐI A][KHỐI B]
  Bản mã ECB   : [MÃ(A)] [MÃ(A)] [MÃ(B)]  ← lộ mẫu lặp!
  Bản mã CBC   : [C1]    [C2]    [C3]     ← C1≠C2 dù A=A

  CBC (liên kết khối mã) an toàn hơn vì dùng XOR
  với bản mã trước: Ci = E(Pi XOR C(i-1))
  → Cần dùng CBC/GCM trong thực tế, KHÔNG dùng ECB!

4. Tấn công vét cạn
──────────────────────────────────────
Thử tất cả khóa có thể từ 0 đến 2^n - 1:

  for i in range(2 ** key_bits):
      key = i.to_bytes(key_bits//8, 'big').ljust(16, b'\\x00')
      unpadded = PKCS7_unpad(AES_decrypt(ciphertext, key))
      if is_printable_ascii(unpadded):
          return key  # ← TÌM THẤY!

  Heuristic lọc: PKCS#7 padding hợp lệ + ASCII printable
  → Loại bỏ ~99.97% kết quả giải mã sai.

5. Không gian khóa
──────────────────────────────────────
  n bits → 2^n khóa cần thử (trung bình: 2^(n-1))

  ┌──────────┬──────────────────┬───────────────────┐
  │ Độ dài   │ Không gian khóa  │ TB thời gian       │
  ├──────────┼──────────────────┼───────────────────┤
  │   8-bit  │              256 │ < 0.01 giây        │
  │  12-bit  │            4,096 │ < 0.1 giây         │
  │  16-bit  │           65,536 │ ~0.6 giây          │
  │  20-bit  │        1,048,576 │ ~10 giây           │
  │  24-bit  │       16,777,216 │ ~3 phút            │
  │  32-bit  │    4,294,967,296 │ ~12 giờ            │
  │  64-bit  │   1.8 × 10^19   │ ~11 tỷ năm         │
  │ 128-bit  │   3.4 × 10^38   │ KHÔNG THỂ          │
  └──────────┴──────────────────┴───────────────────┘

6. Kết luận về An toàn
──────────────────────────────────────
  • Khóa < 40 bits  : KHÔNG AN TOÀN (có thể vét cạn)
  • Khóa 64 bits    : CẦN NHIỀU TÀI NGUYÊN
  • Khóa 128 bits+  : AN TOÀN với máy tính thông thường
  • Chế độ ECB      : KHÔNG nên dùng trong thực tế
  • Chế độ CBC/GCM  : Khuyến nghị sử dụng

  → Luôn dùng AES-128 trở lên + chế độ CBC/GCM trong thực tế!

7. Công thức ước tính thời gian
──────────────────────────────────────
  T_avg  = 2^(n-1) / R    (trường hợp trung bình)
  T_worst = 2^n / R       (trường hợp xấu nhất)

  Trong đó:
  • n : độ dài khóa (bits)
  • R : tốc độ thử khóa (khóa/giây)
  • T : thời gian vét cạn (giây)

══════════════════════════════════════════════════════════
  TÀI LIỆU THAM KHẢO
══════════════════════════════════════════════════════════
• FIPS-197: https://csrc.nist.gov/publications/detail/fips/197/final
• Triển khai AES thuần Python, không dùng thư viện mã hóa
• Stallings, W. "Cryptography and Network Security" (8th ed.)
• Paar, C. "Understanding Cryptography"
══════════════════════════════════════════════════════════
"""
        txt.insert(tk.END, content)
        txt.configure(state='disabled')

    # ─────────────────────────────────────────────
    # ACTIONS
    # ─────────────────────────────────────────────

    def _do_encrypt(self):
        """Mã hóa plaintext."""
        try:
            from aes_engine import encrypt_aes, bytes_to_hex
        except ImportError:
            messagebox.showerror("Lỗi", "Không tìm thấy aes_engine.py!\nHãy chạy từ thư mục src/")
            return

        plaintext = self.enc_plaintext.get().strip()
        if not plaintext:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập bản rõ!")
            return

        bits = self.enc_key_bits.get()

        try:
            key_int = None
            if self.enc_use_fixed_key.get():
                key_int = self._parse_key_int(self.enc_key_int_entry.get().strip(), bits)
            ciphertext, key, key_int = encrypt_aes(plaintext, bits, key_int=key_int)
        except Exception as e:
            messagebox.showerror("Lỗi mã hóa", str(e))
            return

        # Lưu để quá trình vét cạn dùng
        self._ciphertext = ciphertext
        self._encrypt_key_int = key_int
        self._encrypt_key_bits = bits

        # Hiển thị trong tab vét cạn
        self._set_bf_ciphertext(bytes_to_hex(ciphertext))
        self.bf_key_bits.set(bits)

        # Output
        self.enc_output.delete('1.0', tk.END)
        self.enc_output.insert(tk.END, "╔══ KẾT QUẢ MÃ HÓA ══════════════════════════════════╗\n")
        self.enc_output.insert(tk.END, f"  Bản rõ             : {plaintext}\n")
        self.enc_output.insert(tk.END, f"  Độ dài khóa        : {bits}-bit (không gian khóa: 2^{bits} = {2**bits:,})\n")
        self.enc_output.insert(tk.END, f"  Khóa (số nguyên)   : {key_int}\n")
        self.enc_output.insert(tk.END, f"  Khóa (hex)         : 0x{key_int:0{bits//4}X}\n")
        self.enc_output.insert(tk.END, f"  Khóa AES đầy đủ    : {bytes_to_hex(key)}\n")
        self.enc_output.insert(tk.END, f"  Bản mã             : {bytes_to_hex(ciphertext)}\n")
        self.enc_output.insert(tk.END, "╚══════════════════════════════════════════════════════╝\n")
        self.enc_output.insert(tk.END, f"\n⚠️  Khóa thực: {key_int} → Brute-force cần tìm đúng số này!\n")
        self.enc_output.insert(tk.END, "✅ Bản mã đã được sao chép sang tab tấn công vét cạn.\n")

        self.status_var.set(f"✅ Đã mã hóa '{plaintext}' với khóa {bits}-bit (khóa={key_int})")

    def _do_decrypt(self):
        """Giải mã bằng key gốc."""
        if self._ciphertext is None:
            messagebox.showwarning("Cảnh báo", "Hãy mã hóa một văn bản trước!")
            return

        try:
            from aes_engine import decrypt_aes, key_int_to_bytes
        except ImportError:
            messagebox.showerror("Lỗi", "Không tìm thấy aes_engine.py!")
            return

        key = key_int_to_bytes(self._encrypt_key_int, self._encrypt_key_bits)
        result = decrypt_aes(self._ciphertext, key)

        self.enc_output.insert(tk.END, "\n╔══ GIẢI MÃ VỚI KEY GỐC ═══════════════════════════╗\n")
        self.enc_output.insert(tk.END, f"  Khóa (số nguyên)   : {self._encrypt_key_int}\n")
        self.enc_output.insert(tk.END, f"  Bản rõ             : {result}\n")
        self.enc_output.insert(tk.END, "╚══════════════════════════════════════════════════════╝\n")
        self.status_var.set(f"✅ Giải mã thành công: {result}")

    def _do_brute_force(self):
        """Bắt đầu vét cạn trong thread riêng."""
        if self._bf_thread and self._bf_thread.is_alive():
            messagebox.showinfo("Thông báo", "Quá trình vét cạn đang chạy!")
            return

        try:
            from brute_force import brute_force_aes
        except ImportError:
            messagebox.showerror("Lỗi", "Không tìm thấy brute_force.py!")
            return

        self._stop_flag.clear()
        bits = self.bf_key_bits.get()
        ciphertext = self._get_ciphertext_from_input()
        if ciphertext is None:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập bản mã hex hợp lệ!")
            return

        self.bf_log.delete('1.0', tk.END)
        self.bf_progress['value'] = 0
        self.bf_pct_label.configure(text="0%")
        self.bf_stat_keys.configure(text="Số khóa đã thử: 0")
        self.bf_stat_kps.configure(text="Khóa/giây: —")
        self.bf_stat_time.configure(text="Thời gian: 0.0s")

        self._log_bf_start_report(bits, ciphertext)
        if self._encrypt_key_int is not None:
            self._log(f"   Khóa demo cần tìm : {self._encrypt_key_int}")
        self._log("=" * 64)

        def run():
            def cb(current, total, elapsed):
                pct = current / total * 100
                kps = current / elapsed if elapsed > 0 else 0
                self.root.after(0, self._update_bf_stats, current, total, pct, kps, elapsed)

            def detail_cb(event):
                if not self.bf_verbose_log.get():
                    return
                # Luôn log các event quan trọng dù throttle
                always_log = event.get('event') in ('found', 'exhausted', 'stopped', 'start')
                now = time.time()
                if always_log or (now - self._last_log_time >= 0.1):
                    self._last_log_time = now
                    self.root.after(0, self._log_bf_detail, event)

            result = brute_force_aes(
                ciphertext,
                bits,
                callback=cb,
                detail_callback=detail_cb,
                stop_flag=self._stop_flag,
                workers=multiprocessing.cpu_count(),
                detail_interval=self._detail_log_interval(bits),
                fast_mode=self.bf_fast_mode.get(),
            )
            self.root.after(0, self._on_bf_done, result, bits)

        self._bf_thread = threading.Thread(target=run, daemon=True)
        self._bf_thread.start()
        self._set_bf_button_state(running=True)
        self.status_var.set(f"⚡ Đang vét cạn khóa {bits}-bit...")

    def _do_stop(self):
        self._stop_flag.set()
        self._set_bf_button_state(running=False)
        self.status_var.set("⏹ Đã yêu cầu dừng...")
        self._log("⏹ Người dùng dừng quá trình vét cạn.")

    def _set_bf_button_state(self, running: bool):
        state_start = tk.DISABLED if running else tk.NORMAL
        state_stop = tk.NORMAL if running else tk.DISABLED
        self.bf_btn_start.configure(state=state_start)
        self.bf_btn_stop.configure(state=state_stop)

    def _clear_enc(self):
        self.enc_output.delete('1.0', tk.END)
        self.enc_plaintext.delete(0, tk.END)
        self.enc_plaintext.insert(0, "HELLO WORLD")
        self.enc_use_fixed_key.set(False)

    def _clear_bf(self):
        self.bf_log.delete('1.0', tk.END)
        self.bf_progress['value'] = 0
        self.bf_pct_label.configure(text="0%")
        self.bf_cipher_display.delete('1.0', tk.END)

    # ─────────────────────────────────────────────
    # UI UPDATE (gọi từ main thread qua after())
    # ─────────────────────────────────────────────

    def _detail_log_interval(self, bits: int) -> int:
        intervals = {
            8: 16,
            12: 256,
            16: 4096,
            20: 65536,
            24: 1048576,
            32: 16777216,
        }
        return intervals.get(bits, 10000)

    def _log_bf_start_report(self, bits: int, ciphertext: bytes) -> None:
        total = 1 << bits
        interval = self._detail_log_interval(bits)
        avg_keys = total // 2
        self._log("=" * 64)
        self._log("BẮT ĐẦU QUÁ TRÌNH VÉT CẠN AES")
        self._log("=" * 64)
        self._log("")
        self._log("[BƯỚC 1] DỮ LIỆU ĐẦU VÀO")
        self._log(f"   Bản mã (hex)        : {ciphertext.hex().upper()}")
        self._log(f"   Kích thước bản mã   : {len(ciphertext)} byte")
        self._log(f"   Độ dài khóa cần tìm : {bits} bit")
        self._log("")
        self._log("[BƯỚC 2] LẬP KẾ HOẠCH TẤN CÔNG")
        self._log(f"   Không gian khóa     : 2^{bits} = {total:,} khóa")
        self._log(f"   Số khóa TB cần thử  : {avg_keys:,} khóa")
        self._log(f"   Ghi log mỗi         : {interval:,} khóa")
        self._log("   Điều kiện hợp lệ    : PKCS#7 đúng + điểm ASCII in được")
        self._log("")
        self._log("[BƯỚC 3] BẮT ĐẦU QUÉT KHÔNG GIAN KHÓA")

    def _log_bf_detail(self, event):
        event_type = event.get('event')
        current = int(event.get('current', 0) or 0)
        total = int(event.get('total', 0) or 0)
        percent = float(event.get('percent', 0.0) or 0.0)

        if event_type == 'start':
            mode = event.get('mode')
            mode_label = "đa tiến trình" if mode == "multiprocessing" else "tuần tự"
            self._log(f"   Chế độ              : {mode_label}")
            self._log(f"   Số tiến trình       : {event.get('workers')}")
            self._log(f"   Ngưỡng điểm         : {event.get('score_threshold', 'không có')}")
        elif event_type == 'trying':
            self._log(
                f"   Thử {current:>8,}/{total:,} ({percent:>6.2f}%)  "
                f"khóa={event.get('key_int')}  hex=0x{event.get('key_hex')}"
            )
        elif event_type == 'padding_valid':
            score = float(event.get('plaintext_score', 0.0) or 0.0)
            if score < 0.85:
                return
            self._log(
                f"   Ứng viên hợp lệ     : khóa={event.get('key_int')} | "
                f"điểm={score:.2f} | bản rõ thử={event.get('plaintext_preview')!r}"
            )
        elif event_type == 'chunk_done':
            self._log(
                f"[CỤM] đã thử={event.get('keys_tested'):,}/{total:,} "
                f"({percent:.2f}%) | tiến trình={event.get('workers')}"
            )
        elif event_type == 'found':
            self._log("   Ứng viên được nhận  : PKCS#7 đúng + ASCII in được")
        elif event_type == 'stopped':
            self._log(f"[CHI TIẾT] Đã dừng sau {current:,}/{total:,} khóa ({percent:.2f}%).")
        elif event_type == 'exhausted':
            self._log(f"[CHI TIẾT] Đã quét hết không gian khóa: {current:,}/{total:,} khóa.")

    def _log_bf_success_report(self, result, bits: int) -> None:
        key_int = int(result['key_int'])
        key_bytes_len = (bits + 7) // 8
        key_bytes = key_int.to_bytes(key_bytes_len, byteorder='big')
        key_binary = format(key_int, f"0{bits}b")
        elapsed = float(result['elapsed_seconds'])
        keys_tested = int(result['keys_tested'])
        total = int(result['total_keyspace'])
        kps = float(result['keys_per_second'])
        avg_theory = (total / 2) / kps if kps > 0 else 0.0
        ratio = (elapsed / avg_theory * 100) if avg_theory > 0 else 0.0
        verdict = "Tìm sớm hơn trung bình" if elapsed <= avg_theory else "Chậm hơn trung bình"
        ciphertext = self._get_ciphertext_from_input()
        ciphertext_hex = ciphertext.hex().upper() if ciphertext is not None else ""

        self._log("TÌM THẤY KHÓA!")
        self._log("=" * 64)
        self._log("")
        self._log("[KẾT QUẢ] THÔNG TIN KHÓA")
        self._log(f"   Khóa (số nguyên)    : {key_int}")
        self._log(f"   Khóa (hex)          : 0x{result['key_hex']}")
        self._log(f"   Khóa (nhị phân)     : {key_binary}")
        self._log(f"   Khóa (byte)         : {key_bytes.hex().upper()}")
        self._log(f"   Khóa AES-128        : {result['key_full_hex']}")
        self._log("")
        self._log("[KẾT QUẢ] GIẢI MÃ THÀNH CÔNG")
        self._log(f"   Bản mã              : {ciphertext_hex}")
        self._log(f"   Bản rõ              : {result['plaintext']}")
        self._log("   Kiểm tra hợp lệ     : PKCS#7 đúng + ASCII in được")
        self._log(f"   Điểm bản rõ         : {result.get('plaintext_score', 0.0):.2f}")
        self._log("")
        self._log("[KẾT QUẢ] THỐNG KÊ HIỆU NĂNG")
        self._log(f"   Thời gian           : {elapsed:.6f} giây")
        self._log(f"   Số khóa đã thử      : {keys_tested:,}")
        self._log(f"   Tổng không gian khóa: {total:,}")
        self._log(f"   % đã quét           : {result['percent_searched']:.2f}%")
        self._log(f"   Tốc độ TB           : {kps:,.0f} khóa/giây")
        self._log("")
        self._log("[PHÂN TÍCH] SO SÁNH LÝ THUYẾT")
        self._log(f"   TB lý thuyết        : {avg_theory:.6f} giây")
        self._log(f"   Thời gian thực      : {elapsed:.6f} giây")
        self._log(f"   Tỉ lệ               : {ratio:.1f}%")
        self._log(f"   Nhận xét            : {verdict}")
        self._log("")
        self._log("=" * 64)

    def _update_bf_stats(self, current, total, pct, kps, elapsed):
        self.bf_progress['value'] = pct
        self.bf_pct_label.configure(text=f"{pct:.1f}%")
        self.bf_stat_keys.configure(text=f"Số khóa đã thử: {current:,}")
        self.bf_stat_kps.configure(text=f"Khóa/giây: {kps:,.0f}")
        self.bf_stat_time.configure(text=f"Thời gian: {elapsed:.1f}s")

    def _on_bf_done(self, result, bits):
        self.bf_progress['value'] = 100 if result['found'] else self.bf_progress['value']
        self._update_bf_stats(
            result['keys_tested'], result['total_keyspace'],
            result['percent_searched'],
            result['keys_per_second'], result['elapsed_seconds']
        )

        self._log("")
        self._log("=" * 64)
        if result['found']:
            self._log_bf_success_report(result, bits)
            self.status_var.set(f"✅ Tìm thấy! Khóa={result['key_int']}, bản rõ='{result['plaintext']}'")
        else:
            self._log("KHÔNG TÌM THẤY KHÓA")
            self._log("=" * 64)
            self._log("")
            self._log("[KẾT QUẢ] THỐNG KÊ")
            self._log(f"   Số khóa đã thử      : {result['keys_tested']:,}")
            self._log(f"   Tổng không gian khóa: {result['total_keyspace']:,}")
            self._log(f"   % đã quét           : {result['percent_searched']:.2f}%")
            self._log(f"   Thời gian           : {result['elapsed_seconds']:.6f} giây")
            self._log(f"   Tốc độ TB           : {result['keys_per_second']:,.0f} khóa/giây")
            self._log("")
            self._log("=" * 64)
            self.status_var.set("❌ Brute-force kết thúc không thành công")

        self._set_bf_button_state(running=False)

    def _log(self, msg: str):
        self.bf_log.insert(tk.END, msg + "\n")
        self.bf_log.see(tk.END)

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _label(self, parent, text):
        return tk.Label(parent, text=text, font=("Segoe UI", 10, "bold"),
                        bg="#24273A", fg="#8AADF4")

    def _entry(self, parent, **kwargs):
        e = tk.Entry(parent, font=("Consolas", 11),
                     bg="#363A4F", fg="#CAD3F5", insertbackground="#CAD3F5",
                     relief=tk.FLAT, bd=8, **kwargs)
        return e

    def _btn(self, parent, text, command, color="#8AADF4", fg="#1E2030"):
        return tk.Button(
            parent, text=text, command=command,
            font=("Segoe UI", 10, "bold"),
            bg=color, fg=fg,
            activebackground="#CAD3F5", activeforeground="#1E2030",
            relief=tk.FLAT, padx=16, pady=8, cursor="hand2", borderwidth=0
        )

    def _set_bf_ciphertext(self, hex_text: str) -> None:
        self.bf_cipher_display.delete('1.0', tk.END)
        self.bf_cipher_display.insert(tk.END, hex_text)

    def _get_ciphertext_from_input(self) -> bytes | None:
        raw = self.bf_cipher_display.get('1.0', tk.END).strip()
        if not raw:
            return None
        cleaned = "".join(raw.split())
        if len(cleaned) % 2 != 0:
            return None
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return None

    def _parse_key_int(self, raw: str, key_bits: int) -> int:
        if raw.lower().startswith("0x"):
            value = int(raw, 16)
        else:
            value = int(raw, 10)

        max_val = (1 << key_bits) - 1
        if value < 0 or value > max_val:
            raise ValueError(f"Khóa phải nằm trong [0, 2^{key_bits} - 1].")
        return value
