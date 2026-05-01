"""
gui.py - Giao diện đồ họa Tkinter
Minh họa AES Brute-Force Attack
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time


class AESBruteForceApp:
    """Ứng dụng GUI chính minh họa AES Brute-Force."""

    def __init__(self, root):
        self.root = root
        self.root.title("🔐 AES Brute-Force Demo - Minh họa Thám Mã")
        self.root.geometry("900x680")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(True, True)

        # State
        self._bf_thread = None
        self._stop_flag = threading.Event()
        self._ciphertext = None
        self._encrypt_key_int = None
        self._encrypt_key_bits = None

        self._build_ui()

    # ─────────────────────────────────────────────
    # BUILD UI
    # ─────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self.root, bg="#313244", pady=12)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr,
            text="🔐  AES Brute-Force Attack  —  Minh họa Phương pháp Thám Mã Khóa Ngắn",
            font=("Consolas", 13, "bold"),
            bg="#313244", fg="#cdd6f4"
        ).pack()
        tk.Label(
            hdr,
            text="Môn: An toàn thông tin  |  Python thuần (From Scratch) + Tkinter",
            font=("Consolas", 9),
            bg="#313244", fg="#6c7086"
        ).pack()

        # ── Notebook (tabs) ──
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook', background='#1e1e2e', borderwidth=0)
        style.configure('TNotebook.Tab', background='#313244', foreground='#cdd6f4',
                        padding=[14, 6], font=('Consolas', 10, 'bold'))
        style.map('TNotebook.Tab',
                  background=[('selected', '#89b4fa')],
                  foreground=[('selected', '#1e1e2e')])

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self._build_tab_encrypt()
        self._build_tab_bruteforce()
        self._build_tab_theory()

        # ── Statusbar ──
        self.status_var = tk.StringVar(value="✅ Sẵn sàng")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Consolas", 9), bg="#181825", fg="#a6e3a1",
            anchor='w', padx=8, pady=4
        ).pack(fill=tk.X, side=tk.BOTTOM)

    # ── Tab 1: Encrypt / Decrypt ──────────────────

    def _build_tab_encrypt(self):
        frame = tk.Frame(self.nb, bg="#1e1e2e")
        self.nb.add(frame, text="  🔒 Mã hóa / Giải mã  ")

        pad = dict(padx=16, pady=6)

        # Plaintext
        self._label(frame, "📝 Plaintext (văn bản gốc):").grid(row=0, column=0, sticky='w', **pad)
        self.enc_plaintext = self._entry(frame, width=52)
        self.enc_plaintext.insert(0, "HELLO WORLD")
        self.enc_plaintext.grid(row=0, column=1, columnspan=2, sticky='ew', **pad)

        # Key length
        self._label(frame, "🔑 Độ dài khóa:").grid(row=1, column=0, sticky='w', **pad)
        self.enc_key_bits = tk.IntVar(value=16)
        kf = tk.Frame(frame, bg="#1e1e2e")
        kf.grid(row=1, column=1, sticky='w', **pad)
        for v, label in [(8, "8-bit"), (12, "12-bit"), (16, "16-bit"), (20, "20-bit"), (24, "24-bit"), (32, "32-bit")]:
            tk.Radiobutton(
                kf, text=label, variable=self.enc_key_bits, value=v,
                bg="#1e1e2e", fg="#cdd6f4", selectcolor="#313244",
                activebackground="#1e1e2e", activeforeground="#89b4fa",
                font=("Consolas", 10)
            ).pack(side=tk.LEFT, padx=4)

        # Buttons
        bf = tk.Frame(frame, bg="#1e1e2e")
        bf.grid(row=2, column=0, columnspan=3, pady=6)
        self._btn(bf, "🔒  Mã hóa (Encrypt)", self._do_encrypt, "#89b4fa").pack(side=tk.LEFT, padx=6)
        self._btn(bf, "🔓  Giải mã (Decrypt)", self._do_decrypt, "#a6e3a1").pack(side=tk.LEFT, padx=6)
        self._btn(bf, "🗑  Xóa", self._clear_enc, "#f38ba8").pack(side=tk.LEFT, padx=6)

        # Output
        self._label(frame, "📤 Kết quả:").grid(row=3, column=0, sticky='nw', pady=(10, 4), padx=16)
        self.enc_output = scrolledtext.ScrolledText(
            frame, height=14, width=75, font=("Consolas", 10),
            bg="#181825", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief=tk.FLAT, borderwidth=0, padx=8, pady=8
        )
        self.enc_output.grid(row=4, column=0, columnspan=3, padx=16, pady=4, sticky='nsew')
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)

    # ── Tab 2: Brute-Force ────────────────────────

    def _build_tab_bruteforce(self):
        frame = tk.Frame(self.nb, bg="#1e1e2e")
        self.nb.add(frame, text="  ⚡ Brute-Force Attack  ")

        pad = dict(padx=16, pady=5)

        # Info
        info = tk.Label(
            frame,
            text="Bước 1: Mã hóa văn bản trong tab 'Mã hóa' → rồi sang đây bắt đầu tấn công",
            font=("Consolas", 9, "italic"), bg="#1e1e2e", fg="#f9e2af"
        )
        info.grid(row=0, column=0, columnspan=3, padx=16, pady=(10, 2), sticky='w')

        # Ciphertext display
        self._label(frame, "🔐 Ciphertext (hex):").grid(row=1, column=0, sticky='w', **pad)
        self.bf_cipher_display = self._entry(frame, width=55)
        self.bf_cipher_display.configure(state='readonly')
        self.bf_cipher_display.grid(row=1, column=1, columnspan=2, sticky='ew', **pad)

        # Key bits
        self._label(frame, "🔑 Độ dài khóa:").grid(row=2, column=0, sticky='w', **pad)
        self.bf_key_bits = tk.IntVar(value=16)
        kf = tk.Frame(frame, bg="#1e1e2e")
        kf.grid(row=2, column=1, sticky='w', **pad)
        for v, label in [(8, "8-bit"), (12, "12-bit"), (16, "16-bit"), (20, "20-bit")]:
            tk.Radiobutton(
                kf, text=label, variable=self.bf_key_bits, value=v,
                bg="#1e1e2e", fg="#cdd6f4", selectcolor="#313244",
                activebackground="#1e1e2e", activeforeground="#89b4fa",
                font=("Consolas", 10)
            ).pack(side=tk.LEFT, padx=4)

        # Progress bar + stats
        self._label(frame, "📊 Tiến trình:").grid(row=3, column=0, sticky='w', **pad)
        self.bf_progress = ttk.Progressbar(frame, mode='determinate', length=400)
        self.bf_progress.grid(row=3, column=1, sticky='ew', padx=(16, 4), pady=5)
        self.bf_pct_label = tk.Label(frame, text="0%", font=("Consolas", 9),
                                     bg="#1e1e2e", fg="#cdd6f4")
        self.bf_pct_label.grid(row=3, column=2, sticky='w')

        # Live stats
        sf = tk.Frame(frame, bg="#1e1e2e")
        sf.grid(row=4, column=0, columnspan=3, padx=16, pady=4, sticky='w')
        self.bf_stat_keys = tk.Label(sf, text="Keys tested: 0", font=("Consolas", 9),
                                     bg="#1e1e2e", fg="#a6e3a1")
        self.bf_stat_keys.pack(side=tk.LEFT, padx=(0, 24))
        self.bf_stat_kps = tk.Label(sf, text="Keys/s: —", font=("Consolas", 9),
                                    bg="#1e1e2e", fg="#a6e3a1")
        self.bf_stat_kps.pack(side=tk.LEFT, padx=(0, 24))
        self.bf_stat_time = tk.Label(sf, text="Elapsed: 0.0s", font=("Consolas", 9),
                                     bg="#1e1e2e", fg="#a6e3a1")
        self.bf_stat_time.pack(side=tk.LEFT)

        # Buttons
        bf = tk.Frame(frame, bg="#1e1e2e")
        bf.grid(row=5, column=0, columnspan=3, pady=6)
        self.bf_btn_start = self._btn(bf, "⚡  Bắt đầu tấn công", self._do_brute_force, "#f38ba8")
        self.bf_btn_start.pack(side=tk.LEFT, padx=6)
        self.bf_btn_stop = self._btn(bf, "⏹  Dừng", self._do_stop, "#fab387")
        self.bf_btn_stop.pack(side=tk.LEFT, padx=6)
        self.bf_btn_stop.configure(state=tk.DISABLED)
        self._btn(bf, "🗑  Xóa log", self._clear_bf, "#6c7086").pack(side=tk.LEFT, padx=6)

        # Log
        self._label(frame, "📋 Log:").grid(row=6, column=0, sticky='nw', padx=16, pady=(8, 2))
        self.bf_log = scrolledtext.ScrolledText(
            frame, height=12, width=75, font=("Consolas", 10),
            bg="#181825", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief=tk.FLAT, borderwidth=0, padx=8, pady=8
        )
        self.bf_log.grid(row=7, column=0, columnspan=3, padx=16, pady=4, sticky='nsew')
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(7, weight=1)

    # ── Tab 3: Theory ────────────────────────────

    def _build_tab_theory(self):
        frame = tk.Frame(self.nb, bg="#1e1e2e")
        self.nb.add(frame, text="  📖 Lý thuyết  ")

        txt = scrolledtext.ScrolledText(
            frame, font=("Consolas", 10),
            bg="#181825", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief=tk.FLAT, borderwidth=0, padx=16, pady=12,
            wrap=tk.WORD
        )
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        content = """══════════════════════════════════════════════════════════
  CƠ SỞ LÝ THUYẾT: AES VÀ TẤN CÔNG BRUTE-FORCE
══════════════════════════════════════════════════════════

1. AES (Advanced Encryption Standard)
──────────────────────────────────────
• Tiêu chuẩn mã hóa đối xứng (FIPS-197, 2001)
• Block size: 128 bits (16 bytes)
• Key size chuẩn: 128 / 192 / 256 bits
• Mode sử dụng trong demo: ECB (Electronic Codebook)

2. Khóa ngắn trong demo này
──────────────────────────────────────
Thay vì dùng khóa 128-bit, chúng ta dùng khóa 16-32 bit
và pad phần còn lại bằng byte 0x00.

  Ví dụ (16-bit key = 0xABCD):
  Key thực   : AB CD
  Key AES    : AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                └─ 2 bytes ─┘└──────────── 14 bytes zeros ─────────────┘

3. Tấn công Brute-Force (Vét Cạn)
──────────────────────────────────────
Thử tất cả khóa có thể từ 0 đến 2^n - 1:

  for i in range(2 ** key_bits):
      key = i.to_bytes(key_bits//8, 'big').ljust(16, b'\\x00')
      try:
          plaintext = AES_decrypt(ciphertext, key)
          if is_printable(plaintext):
              return key  # ← TÌM THẤY!
      except:
          continue

4. Không gian khóa (Keyspace)
──────────────────────────────────────
  n bits → 2^n khóa cần thử (trung bình: 2^(n-1))

  ┌──────────┬──────────────────┬──────────────────┐
  │ Key bits │ Keyspace         │ Avg Time (~50K/s) │
  ├──────────┼──────────────────┼──────────────────┤
  │   8-bit  │            256   │ < 0.01 giây       │
  │  12-bit  │          4,096   │ < 0.1 giây        │
  │  16-bit  │         65,536   │ ~0.6 giây         │
  │  20-bit  │      1,048,576   │ ~10 giây          │
  │  24-bit  │     16,777,216   │ ~3 phút           │
  │  32-bit  │  4,294,967,296   │ ~12 giờ           │
  │  64-bit  │  1.8 × 10^19    │ ~11 tỷ năm        │
  │ 128-bit  │  3.4 × 10^38    │ KHÔNG THỂ         │
  └──────────┴──────────────────┴──────────────────┘

5. Kết luận về An toàn
──────────────────────────────────────
  • Khóa < 40 bits : KHÔNG AN TOÀN (brute-force được)
  • Khóa 64 bits   : CẦN NHIỀU TÀI NGUYÊN
  • Khóa 128 bits+ : AN TOÀN với máy tính thông thường
  
  → Luôn dùng AES-128 (key 128-bit) trở lên trong thực tế!

6. Công thức ước tính thời gian
──────────────────────────────────────
  T_avg  = 2^(n-1) / R    (trường hợp trung bình)
  T_worst = 2^n / R       (trường hợp xấu nhất)
  
  Trong đó:
  • n : độ dài khóa (bits)
  • R : tốc độ thử khóa (keys/giây)
  • T : thời gian brute-force (giây)

══════════════════════════════════════════════════════════
  TÀI LIỆU THAM KHẢO
══════════════════════════════════════════════════════════
• FIPS-197: https://csrc.nist.gov/publications/detail/fips/197/final
• Triển khai thuật toán mã hóa AES từ Scratch (Python thuần)
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
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập plaintext!")
            return

        bits = self.enc_key_bits.get()

        try:
            ciphertext, key, key_int = encrypt_aes(plaintext, bits)
        except Exception as e:
            messagebox.showerror("Lỗi mã hóa", str(e))
            return

        # Lưu để brute-force dùng
        self._ciphertext = ciphertext
        self._encrypt_key_int = key_int
        self._encrypt_key_bits = bits

        # Hiển thị trong tab brute-force
        self.bf_cipher_display.configure(state='normal')
        self.bf_cipher_display.delete(0, tk.END)
        self.bf_cipher_display.insert(0, bytes_to_hex(ciphertext))
        self.bf_cipher_display.configure(state='readonly')
        self.bf_key_bits.set(bits)

        # Output
        self.enc_output.delete('1.0', tk.END)
        self.enc_output.insert(tk.END, "╔══ KẾT QUẢ MÃ HÓA ══════════════════════════════════╗\n")
        self.enc_output.insert(tk.END, f"  Plaintext   : {plaintext}\n")
        self.enc_output.insert(tk.END, f"  Key bits    : {bits}-bit (keyspace: 2^{bits} = {2**bits:,})\n")
        self.enc_output.insert(tk.END, f"  Key (int)   : {key_int}\n")
        self.enc_output.insert(tk.END, f"  Key (hex)   : 0x{key_int:0{bits//4}X}\n")
        self.enc_output.insert(tk.END, f"  Key (full)  : {bytes_to_hex(key)}\n")
        self.enc_output.insert(tk.END, f"  Ciphertext  : {bytes_to_hex(ciphertext)}\n")
        self.enc_output.insert(tk.END, "╚══════════════════════════════════════════════════════╝\n")
        self.enc_output.insert(tk.END, f"\n⚠️  Khóa thực: {key_int} → Brute-force cần tìm đúng số này!\n")
        self.enc_output.insert(tk.END, "✅ Ciphertext đã được copy sang tab Brute-Force.\n")

        self.status_var.set(f"✅ Đã mã hóa '{plaintext}' với {bits}-bit key (key={key_int})")

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
        self.enc_output.insert(tk.END, f"  Key (int)   : {self._encrypt_key_int}\n")
        self.enc_output.insert(tk.END, f"  Plaintext   : {result}\n")
        self.enc_output.insert(tk.END, "╚══════════════════════════════════════════════════════╝\n")
        self.status_var.set(f"✅ Giải mã thành công: {result}")

    def _do_brute_force(self):
        """Bắt đầu brute-force trong thread riêng."""
        if self._ciphertext is None:
            messagebox.showwarning("Cảnh báo", "Hãy mã hóa trước ở tab 'Mã hóa'!")
            return

        if self._bf_thread and self._bf_thread.is_alive():
            messagebox.showinfo("Thông báo", "Brute-force đang chạy!")
            return

        try:
            from brute_force import brute_force_aes
        except ImportError:
            messagebox.showerror("Lỗi", "Không tìm thấy brute_force.py!")
            return

        self._stop_flag.clear()
        bits = self.bf_key_bits.get()
        ciphertext = self._ciphertext

        self.bf_log.delete('1.0', tk.END)
        self.bf_progress['value'] = 0
        self.bf_pct_label.configure(text="0%")
        self.bf_stat_keys.configure(text="Keys tested: 0")
        self.bf_stat_kps.configure(text="Keys/s: —")
        self.bf_stat_time.configure(text="Elapsed: 0.0s")

        self._log(f"⚡ Bắt đầu brute-force {bits}-bit AES...")
        self._log(f"   Keyspace: 2^{bits} = {2**bits:,} keys")
        self._log(f"   Key thực sự cần tìm: {self._encrypt_key_int}")
        self._log("─" * 52)

        def run():
            def cb(current, total, elapsed):
                pct = current / total * 100
                kps = current / elapsed if elapsed > 0 else 0
                self.root.after(0, self._update_bf_stats, current, total, pct, kps, elapsed)

            result = brute_force_aes(ciphertext, bits, callback=cb, stop_flag=self._stop_flag)
            self.root.after(0, self._on_bf_done, result, bits)

        self._bf_thread = threading.Thread(target=run, daemon=True)
        self._bf_thread.start()
        self._set_bf_button_state(running=True)
        self.status_var.set(f"⚡ Đang brute-force {bits}-bit key...")

    def _do_stop(self):
        self._stop_flag.set()
        self._set_bf_button_state(running=False)
        self.status_var.set("⏹ Đã yêu cầu dừng...")
        self._log("⏹ Người dùng dừng brute-force.")

    def _set_bf_button_state(self, running: bool):
        state_start = tk.DISABLED if running else tk.NORMAL
        state_stop = tk.NORMAL if running else tk.DISABLED
        self.bf_btn_start.configure(state=state_start)
        self.bf_btn_stop.configure(state=state_stop)

    def _clear_enc(self):
        self.enc_output.delete('1.0', tk.END)
        self.enc_plaintext.delete(0, tk.END)
        self.enc_plaintext.insert(0, "HELLO WORLD")

    def _clear_bf(self):
        self.bf_log.delete('1.0', tk.END)
        self.bf_progress['value'] = 0
        self.bf_pct_label.configure(text="0%")

    # ─────────────────────────────────────────────
    # UI UPDATE (gọi từ main thread qua after())
    # ─────────────────────────────────────────────

    def _update_bf_stats(self, current, total, pct, kps, elapsed):
        self.bf_progress['value'] = pct
        self.bf_pct_label.configure(text=f"{pct:.1f}%")
        self.bf_stat_keys.configure(text=f"Keys tested: {current:,}")
        self.bf_stat_kps.configure(text=f"Keys/s: {kps:,.0f}")
        self.bf_stat_time.configure(text=f"Elapsed: {elapsed:.1f}s")

    def _on_bf_done(self, result, bits):
        self.bf_progress['value'] = 100 if result['found'] else self.bf_progress['value']
        self._update_bf_stats(
            result['keys_tested'], result['total_keyspace'],
            result['percent_searched'],
            result['keys_per_second'], result['elapsed_seconds']
        )

        self._log("─" * 52)
        if result['found']:
            self._log(f"✅ TÌM THẤY KHÓA!")
            self._log(f"   Key (int) : {result['key_int']}")
            self._log(f"   Key (hex) : 0x{result['key_hex']}")
            self._log(f"   Plaintext : {result['plaintext']}")
            self._log(f"   Thời gian : {result['elapsed_seconds']:.3f}s")
            self._log(f"   Keys test : {result['keys_tested']:,} / {result['total_keyspace']:,}")
            self._log(f"   Keys/giây : {result['keys_per_second']:,.0f}")
            self.status_var.set(f"✅ Tìm thấy! Key={result['key_int']}, plaintext='{result['plaintext']}'")
        else:
            self._log("❌ Không tìm thấy (đã dừng hoặc hết keyspace)")
            self.status_var.set("❌ Brute-force kết thúc không thành công")

        self._set_bf_button_state(running=False)

    def _log(self, msg: str):
        self.bf_log.insert(tk.END, msg + "\n")
        self.bf_log.see(tk.END)

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _label(self, parent, text):
        return tk.Label(parent, text=text, font=("Consolas", 10, "bold"),
                        bg="#1e1e2e", fg="#89b4fa")

    def _entry(self, parent, **kwargs):
        e = tk.Entry(parent, font=("Consolas", 10),
                     bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
                     relief=tk.FLAT, bd=4, **kwargs)
        return e

    def _btn(self, parent, text, command, color="#89b4fa"):
        return tk.Button(
            parent, text=text, command=command,
            font=("Consolas", 10, "bold"),
            bg=color, fg="#1e1e2e",
            activebackground="#cdd6f4", activeforeground="#1e1e2e",
            relief=tk.FLAT, padx=12, pady=6, cursor="hand2"
        )
