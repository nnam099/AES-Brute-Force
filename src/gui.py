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
        self.root.title("Minh họa vét cạn AES - Mật mã học")
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
        self._last_log_time = 0.0  # giảm tần suất ghi log khi callback quá dày

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
            text="Minh họa vét cạn khóa AES",
            font=("Segoe UI", 18, "bold"),
            bg="#1E2030", fg="#CAD3F5"
        ).pack()
        tk.Label(
            hdr,
            text="Thí nghiệm với khóa entropy thấp và không gian khóa 2^n",
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
        self.status_var = tk.StringVar(value="Sẵn sàng")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Segoe UI", 9, "bold"), bg="#181825", fg="#A6DA95",
            anchor='w', padx=16, pady=6
        ).pack(fill=tk.X, side=tk.BOTTOM)

    # ── Tab 1: Mã hóa / Giải mã ──────────────────

    def _build_tab_encrypt(self):
        frame = tk.Frame(self.nb, bg="#24273A")
        self.nb.add(frame, text="  Mã hóa / Giải mã  ")

        # Input Section
        input_frame = tk.Frame(frame, bg="#24273A")
        input_frame.pack(fill=tk.X, padx=20, pady=16)

        self._label(input_frame, "Bản rõ:").grid(row=0, column=0, sticky='w', pady=8, padx=(0, 10))
        self.enc_plaintext = self._entry(input_frame, width=54)
        self.enc_plaintext.insert(0, "HELLO WORLD")
        self.enc_plaintext.grid(row=0, column=1, sticky='w', pady=8)

        self._label(input_frame, "Số bit bí mật:").grid(row=1, column=0, sticky='w', pady=8, padx=(0, 10))
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

        self._label(input_frame, "Khóa thử nghiệm:").grid(row=2, column=0, sticky='w', pady=8, padx=(0, 10))
        fixed_key_frame = tk.Frame(input_frame, bg="#24273A")
        fixed_key_frame.grid(row=2, column=1, sticky='w', pady=8)
        self.enc_use_fixed_key = tk.BooleanVar(value=False)
        tk.Checkbutton(
            fixed_key_frame, text="Nhập khóa cố định", variable=self.enc_use_fixed_key,
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
        self._btn(act_frame, "Mã hóa", self._do_encrypt, "#8AADF4").pack(side=tk.LEFT, padx=(0, 12))
        self._btn(act_frame, "Giải mã lại", self._do_decrypt, "#A6DA95").pack(side=tk.LEFT, padx=12)
        self._btn(act_frame, "Xóa", self._clear_enc, "#ED8796").pack(side=tk.LEFT, padx=12)

        # Output
        out_frame = tk.Frame(frame, bg="#24273A")
        out_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        self._label(out_frame, "Kết quả:").pack(anchor='w', pady=(0, 8))
        self.enc_output = scrolledtext.ScrolledText(
            out_frame, font=("Consolas", 11),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=12, highlightthickness=0
        )
        self.enc_output.pack(fill=tk.BOTH, expand=True)

    # ── Tab 2: Vét cạn ────────────────────────

    def _build_tab_bruteforce(self):
        frame = tk.Frame(self.nb, bg="#24273A")
        self.nb.add(frame, text="  Vét cạn khóa  ")

        # Info
        info_frame = tk.Frame(frame, bg="#363A4F", padx=16, pady=10)
        info_frame.pack(fill=tk.X, padx=20, pady=16)
        tk.Label(
            info_frame,
            text="Mã hóa ở tab đầu, sau đó dùng bản mã hex ở đây để thử lại toàn bộ không gian khóa.",
            font=("Segoe UI", 10, "italic"), bg="#363A4F", fg="#EED49F"
        ).pack(anchor='w')

        # Config
        cfg_frame = tk.Frame(frame, bg="#24273A")
        cfg_frame.pack(fill=tk.X, padx=20)

        self._label(cfg_frame, "Bản mã (hex):").grid(row=0, column=0, sticky='w', pady=8, padx=(0, 10))
        self.bf_cipher_display = scrolledtext.ScrolledText(
            cfg_frame, height=2, width=54,
            font=("Consolas", 10),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=8, highlightthickness=0,
            wrap=tk.WORD
        )
        self.bf_cipher_display.grid(row=0, column=1, sticky='w', pady=8)

        self._label(cfg_frame, "Số bit bí mật:").grid(row=1, column=0, sticky='w', pady=8, padx=(0, 10))
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
        tk.Label(kf, text="(24-bit có thể mất vài phút)",
                 font=("Segoe UI", 9), bg="#363A4F", fg="#EED49F").pack(side=tk.LEFT, padx=6)

        # Progress
        prog_frame = tk.Frame(frame, bg="#24273A")
        prog_frame.pack(fill=tk.X, padx=20, pady=10)
        self._label(prog_frame, "Tiến trình:").pack(side=tk.LEFT, padx=(0, 10))
        
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
        self.bf_stat_kps = tk.Label(stat_frame, text="Khóa/giây: -", font=("Consolas", 10),
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
            act_frame, text="Dùng PyCryptodome", variable=self.bf_fast_mode,
            bg="#24273A", fg="#A6DA95", selectcolor="#1E2030",
            activebackground="#24273A", activeforeground="#8AADF4",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT, padx=(0, 12))
        self.bf_btn_start = self._btn(act_frame, "Bắt đầu vét cạn", self._do_brute_force, "#ED8796")
        self.bf_btn_start.pack(side=tk.LEFT, padx=(0, 12))
        self.bf_btn_stop = self._btn(act_frame, "Dừng", self._do_stop, "#F5A97F")
        self.bf_btn_stop.pack(side=tk.LEFT, padx=12)
        self.bf_btn_stop.configure(state=tk.DISABLED)
        self._btn(act_frame, "Xóa log", self._clear_bf, "#5B6078", fg="#CAD3F5").pack(side=tk.RIGHT)

        # Log
        log_frame = tk.Frame(frame, bg="#24273A")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 16))
        self._label(log_frame, "Nhật ký thử khóa:").pack(anchor='w', pady=(0, 8))
        self.bf_log = scrolledtext.ScrolledText(
            log_frame, font=("Consolas", 11),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=12, highlightthickness=0
        )
        self.bf_log.pack(fill=tk.BOTH, expand=True)

    # ── Tab 3: Theory ────────────────────────────

    def _build_tab_theory(self):
        frame = tk.Frame(self.nb, bg="#24273A")
        self.nb.add(frame, text="  Ghi chú lý thuyết  ")

        txt = scrolledtext.ScrolledText(
            frame, font=("Consolas", 11),
            bg="#1E2030", fg="#CAD3F5", insertbackground="#CAD3F5",
            relief=tk.FLAT, borderwidth=16, highlightthickness=0,
            wrap=tk.WORD
        )
        txt.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        content = """GHI CHÚ LÝ THUYẾT CHO THÍ NGHIỆM AES
==========================================================

1. AES dùng trong chương trình
----------------------------------------------------------
AES là mã khối đối xứng. Trong đồ án này chỉ xét AES-128:

  - kích thước khối: 128 bit = 16 byte
  - kích thước khóa thật của AES-128: 128 bit
  - số vòng biến đổi: 10 vòng
  - chế độ minh họa: ECB

Mỗi khối bản rõ P được mã hóa thành bản mã C theo khóa K:

  C = E_K(P)
  P = D_K(C)

2. Vì sao vẫn vét cạn được trong demo
----------------------------------------------------------
AES-128 đầy đủ có 2^128 khóa, không thể duyệt hết bằng máy
tính thông thường. Để quan sát được quá trình vét cạn, đồ án
chỉ giữ bí mật n bit đầu của khóa, phần còn lại điền 0x00.

Ví dụ với khóa 16 bit:

  phần bí mật      : AB CD
  khóa AES-128     : AB CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  không gian khóa  : |K| = 2^16 = 65,536 khóa

Cách làm này không phải cách sinh khóa an toàn. Nó chỉ dùng
để làm nhỏ bài toán, giúp thấy rõ quan hệ giữa số bit khóa và
thời gian thử khóa.

3. Cách vét cạn
----------------------------------------------------------
Với n bit bí mật, chương trình thử các giá trị:

  0, 1, 2, ..., 2^n - 1

Mỗi giá trị i được đổi thành phần đầu của khóa AES-128:

  key = bytes(i) || 00 ... 00

Sau đó giải mã bản mã và kiểm tra kết quả:

  - PKCS#7 padding phải hợp lệ
  - phần bản rõ sau khi bỏ padding phải chủ yếu là ký tự in được

Hai điều kiện này không chứng minh chắc chắn tuyệt đối, nhưng
đủ tốt cho thí nghiệm với bản rõ dạng văn bản ngắn.

4. Ước tính thời gian
----------------------------------------------------------
Nếu tốc độ thử khóa là R khóa/giây:

  trường hợp trung bình : T_avg   = 2^(n-1) / R
  trường hợp xấu nhất   : T_worst = 2^n / R

Khi tăng n thêm 1 bit, không gian khóa tăng gấp đôi. Vì vậy
thời gian vét cạn cũng tăng xấp xỉ gấp đôi nếu tốc độ R không đổi.

  8 bit   : 256 khóa
  12 bit  : 4,096 khóa
  16 bit  : 65,536 khóa
  20 bit  : 1,048,576 khóa
  24 bit  : 16,777,216 khóa
  32 bit  : 4,294,967,296 khóa
  128 bit : 3.4 x 10^38 khóa

5. Lưu ý về ECB
----------------------------------------------------------
ECB mã hóa từng khối độc lập. Nếu hai khối bản rõ giống nhau
thì hai khối bản mã cũng giống nhau, nên ECB làm lộ mẫu lặp.

Trong thực tế nên dùng chế độ có IV/nonce và xác thực dữ liệu,
ví dụ CBC đúng cách hoặc GCM. Phần ECB ở đây chỉ để giữ demo
đơn giản khi tập trung vào không gian khóa.

Tài liệu tham khảo:
  - NIST FIPS-197, Advanced Encryption Standard
  - Stallings, Cryptography and Network Security
  - Paar, Understanding Cryptography
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
        self.enc_output.insert(tk.END, "KẾT QUẢ MÃ HÓA\n")
        self.enc_output.insert(tk.END, "-" * 56 + "\n")
        self.enc_output.insert(tk.END, f"Bản rõ             : {plaintext}\n")
        self.enc_output.insert(tk.END, f"Số bit bí mật      : {bits}\n")
        self.enc_output.insert(tk.END, f"Không gian khóa    : 2^{bits} = {2**bits:,} khóa\n")
        self.enc_output.insert(tk.END, f"Khóa dạng số       : {key_int}\n")
        self.enc_output.insert(tk.END, f"Khóa dạng hex      : 0x{key_int:0{bits//4}X}\n")
        self.enc_output.insert(tk.END, f"Khóa AES-128       : {bytes_to_hex(key)}\n")
        self.enc_output.insert(tk.END, f"Bản mã             : {bytes_to_hex(ciphertext)}\n")
        self.enc_output.insert(tk.END, "-" * 56 + "\n")
        self.enc_output.insert(tk.END, "\nBản mã đã được chuyển sang tab vét cạn khóa.\n")

        self.status_var.set(f"Đã mã hóa bản rõ với khóa {bits}-bit, key_int={key_int}")

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

        self.enc_output.insert(tk.END, "\nGIẢI MÃ KIỂM TRA\n")
        self.enc_output.insert(tk.END, "-" * 56 + "\n")
        self.enc_output.insert(tk.END, f"Khóa dạng số       : {self._encrypt_key_int}\n")
        self.enc_output.insert(tk.END, f"Bản rõ thu được    : {result}\n")
        self.enc_output.insert(tk.END, "-" * 56 + "\n")
        self.status_var.set(f"Giải mã kiểm tra xong: {result}")

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
        self.bf_stat_kps.configure(text="Khóa/giây: -")
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
        self.status_var.set(f"Đang vét cạn khóa {bits}-bit...")

    def _do_stop(self):
        self._stop_flag.set()
        self._set_bf_button_state(running=False)
        self.status_var.set("Đã yêu cầu dừng.")
        self._log("Người dùng dừng quá trình vét cạn.")

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
        self._log("Bắt đầu vét cạn khóa AES")
        self._log("=" * 64)
        self._log("")
        self._log("[1] Dữ liệu đầu vào")
        self._log(f"   Bản mã (hex)        : {ciphertext.hex().upper()}")
        self._log(f"   Kích thước bản mã   : {len(ciphertext)} byte")
        self._log(f"   Số bit bí mật       : {bits} bit")
        self._log("")
        self._log("[2] Không gian khóa")
        self._log(f"   Không gian khóa     : 2^{bits} = {total:,} khóa")
        self._log(f"   Trung bình cần thử  : {avg_keys:,} khóa")
        self._log(f"   Ghi log mỗi         : {interval:,} khóa")
        self._log("")
        self._log("[3] Quét lần lượt các khóa ứng viên")

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
                f"điểm ASCII={score:.2f} | thử ra={event.get('plaintext_preview')!r}"
            )
        elif event_type == 'chunk_done':
            self._log(
                f"[CỤM] đã thử={event.get('keys_tested'):,}/{total:,} "
                f"({percent:.2f}%) | tiến trình={event.get('workers')}"
            )
        elif event_type == 'found':
            self._log("   Nhận khóa này vì padding đúng và bản rõ đọc được")
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

        self._log("Đã tìm được khóa phù hợp")
        self._log("=" * 64)
        self._log("")
        self._log("[Kết quả] Khóa")
        self._log(f"   Khóa (số nguyên)    : {key_int}")
        self._log(f"   Khóa (hex)          : 0x{result['key_hex']}")
        self._log(f"   Khóa (nhị phân)     : {key_binary}")
        self._log(f"   Khóa (byte)         : {key_bytes.hex().upper()}")
        self._log(f"   Khóa AES-128        : {result['key_full_hex']}")
        self._log("")
        self._log("[Kết quả] Giải mã")
        self._log(f"   Bản mã              : {ciphertext_hex}")
        self._log(f"   Bản rõ              : {result['plaintext']}")
        self._log("")
        self._log("[Kết quả] Thống kê")
        self._log(f"   Thời gian           : {elapsed:.6f} giây")
        self._log(f"   Số khóa đã thử      : {keys_tested:,}")
        self._log(f"   Tổng không gian khóa: {total:,}")
        self._log(f"   % đã quét           : {result['percent_searched']:.2f}%")
        self._log(f"   Tốc độ TB           : {kps:,.0f} khóa/giây")
        self._log("")
        self._log("[Nhận xét] So với trung bình lý thuyết")
        self._log(f"   TB lý thuyết        : {avg_theory:.6f} giây")
        self._log(f"   Thời gian thực      : {elapsed:.6f} giây")
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
            self.status_var.set(f"Tìm thấy khóa={result['key_int']}, bản rõ='{result['plaintext']}'")
        else:
            self._log("Không tìm thấy khóa phù hợp")
            self._log("=" * 64)
            self._log("")
            self._log("[Kết quả] Thống kê")
            self._log(f"   Số khóa đã thử      : {result['keys_tested']:,}")
            self._log(f"   Tổng không gian khóa: {result['total_keyspace']:,}")
            self._log(f"   % đã quét           : {result['percent_searched']:.2f}%")
            self._log(f"   Thời gian           : {result['elapsed_seconds']:.6f} giây")
            self._log(f"   Tốc độ TB           : {result['keys_per_second']:,.0f} khóa/giây")
            self._log("")
            self._log("=" * 64)
            self.status_var.set("Vét cạn kết thúc nhưng chưa tìm thấy khóa.")

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
