"""Brute-force attack tab — extracted from the monolithic gui.py."""

from __future__ import annotations

import multiprocessing
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from aes_brute_force.gui import theme as T


class AttackTab(tk.Frame):
    """Tab 2: brute-force key search with progress visualization."""

    def __init__(self, parent: tk.Widget, app) -> None:
        super().__init__(parent, bg=T.BG_BASE)
        self.app = app
        self._bf_thread: threading.Thread | None = None
        self._stop_flag = threading.Event()
        self.verbose_log = tk.BooleanVar(value=True)
        self.fast_mode = tk.BooleanVar(value=False)
        self._last_log_time = 0.0
        self._build()

    # ── Build UI ────────────────────────────────────

    def _build(self) -> None:
        # Info banner
        info = tk.Frame(self, bg=T.BG_OVERLAY, padx=16, pady=10)
        info.pack(fill=tk.X, padx=20, pady=16)
        tk.Label(info, text="Mã hóa ở tab đầu, sau đó thử vét cạn toàn bộ không gian khóa.",
                 font=("Segoe UI", 10, "italic"), bg=T.BG_OVERLAY, fg=T.ACCENT_YELLOW).pack(anchor="w")

        # Config
        cfg = tk.Frame(self, bg=T.BG_BASE)
        cfg.pack(fill=tk.X, padx=20)

        T.make_label(cfg, "Bản mã (hex):").grid(row=0, column=0, sticky="w", pady=8, padx=(0, 10))
        self.cipher_display = T.make_scrolled_text(cfg, height=2, width=54,
                                                    font=T.FONT_MONO_SM, borderwidth=8, wrap=tk.WORD)
        self.cipher_display.grid(row=0, column=1, sticky="w", pady=8)

        T.make_label(cfg, "Số bit bí mật:").grid(row=1, column=0, sticky="w", pady=8, padx=(0, 10))
        self.key_bits_var = tk.IntVar(value=16)
        kf = tk.Frame(cfg, bg=T.BG_OVERLAY, padx=8, pady=4)
        kf.grid(row=1, column=1, sticky="w", pady=8)
        for v in [8, 12, 16, 20, 24]:
            tk.Radiobutton(
                kf, text=f"{v}-bit", variable=self.key_bits_var, value=v,
                bg=T.BG_OVERLAY, fg=T.FG_TEXT, selectcolor=T.BG_SURFACE,
                activebackground=T.BG_OVERLAY, activeforeground=T.ACCENT_BLUE,
                font=T.FONT_BTN, cursor="hand2",
            ).pack(side=tk.LEFT, padx=6)
        tk.Label(kf, text="(24-bit: ~minutes)", font=T.FONT_SUBHEADING,
                 bg=T.BG_OVERLAY, fg=T.ACCENT_YELLOW).pack(side=tk.LEFT, padx=6)

        # Progress
        pf = tk.Frame(self, bg=T.BG_BASE)
        pf.pack(fill=tk.X, padx=20, pady=10)
        T.make_label(pf, "Tiến trình:").pack(side=tk.LEFT, padx=(0, 10))

        style = ttk.Style()
        style.configure("TProgressbar", thickness=14, troughcolor=T.BG_OVERLAY, background=T.ACCENT_GREEN)
        self.progress = ttk.Progressbar(pf, mode="determinate", length=400, style="TProgressbar")
        self.progress.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        self.pct_label = tk.Label(pf, text="0%", font=T.FONT_BTN, bg=T.BG_BASE, fg=T.FG_TEXT, width=5, anchor="e")
        self.pct_label.pack(side=tk.LEFT)

        # Stats bar
        sf = tk.Frame(self, bg=T.BG_SURFACE, padx=16, pady=8)
        sf.pack(fill=tk.X, padx=20, pady=5)
        self.stat_keys = tk.Label(sf, text="Khóa đã thử: 0", font=T.FONT_MONO_SM, bg=T.BG_SURFACE, fg=T.ACCENT_GREEN)
        self.stat_keys.pack(side=tk.LEFT, expand=True, anchor="w")
        self.stat_kps = tk.Label(sf, text="Khóa/giây: -", font=T.FONT_MONO_SM, bg=T.BG_SURFACE, fg=T.ACCENT_BLUE)
        self.stat_kps.pack(side=tk.LEFT, expand=True, anchor="center")
        self.stat_time = tk.Label(sf, text="Thời gian: 0.0s", font=T.FONT_MONO_SM, bg=T.BG_SURFACE, fg=T.ACCENT_PEACH)
        self.stat_time.pack(side=tk.LEFT, expand=True, anchor="e")

        # Action buttons
        af = tk.Frame(self, bg=T.BG_BASE)
        af.pack(fill=tk.X, padx=20, pady=10)
        tk.Checkbutton(af, text="Log chi tiết", variable=self.verbose_log,
                       bg=T.BG_BASE, fg=T.FG_TEXT, selectcolor=T.BG_SURFACE,
                       activebackground=T.BG_BASE, font=T.FONT_BTN).pack(side=tk.LEFT, padx=(0, 12))
        tk.Checkbutton(af, text="PyCryptodome", variable=self.fast_mode,
                       bg=T.BG_BASE, fg=T.ACCENT_GREEN, selectcolor=T.BG_SURFACE,
                       activebackground=T.BG_BASE, font=T.FONT_BTN).pack(side=tk.LEFT, padx=(0, 12))
        self.btn_start = T.make_button(af, "Bắt đầu vét cạn", self._start, T.ACCENT_RED)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 12))
        self.btn_stop = T.make_button(af, "Dừng", self._stop, T.ACCENT_PEACH)
        self.btn_stop.pack(side=tk.LEFT, padx=12)
        self.btn_stop.configure(state=tk.DISABLED)
        T.make_button(af, "Xóa log", self._clear, T.BG_OVERLAY, fg=T.FG_TEXT).pack(side=tk.RIGHT)

        # Log area
        lf = tk.Frame(self, bg=T.BG_BASE)
        lf.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 16))
        T.make_label(lf, "Nhật ký:").pack(anchor="w", pady=(0, 8))
        self.log = T.make_scrolled_text(lf)
        self.log.pack(fill=tk.BOTH, expand=True)

    # ── Public helpers ──────────────────────────────

    def set_ciphertext(self, hex_text: str) -> None:
        self.cipher_display.delete("1.0", tk.END)
        self.cipher_display.insert(tk.END, hex_text)

    def _get_ciphertext(self) -> bytes | None:
        raw = self.cipher_display.get("1.0", tk.END).strip()
        if not raw:
            return None
        cleaned = "".join(raw.split())
        if len(cleaned) % 2 != 0:
            return None
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return None

    # ── Detail log interval ─────────────────────────

    def _detail_interval(self, bits: int) -> int:
        return {8: 16, 12: 256, 16: 4096, 20: 65536, 24: 1048576, 32: 16777216}.get(bits, 10000)

    # ── Actions ─────────────────────────────────────

    def _start(self) -> None:
        if self._bf_thread and self._bf_thread.is_alive():
            messagebox.showinfo("Thông báo", "Vét cạn đang chạy!")
            return
        from aes_brute_force.core.brute_force import brute_force_aes

        self._stop_flag.clear()
        bits = self.key_bits_var.get()
        ct = self._get_ciphertext()
        if ct is None:
            messagebox.showwarning("Cảnh báo", "Nhập bản mã hex hợp lệ!")
            return

        self.log.delete("1.0", tk.END)
        self.progress["value"] = 0
        self.pct_label.configure(text="0%")
        self._log_start(bits, ct)

        def run():
            def cb(cur, total, elapsed):
                pct = cur / total * 100
                kps = cur / elapsed if elapsed > 0 else 0
                self.winfo_toplevel().after(0, self._update_stats, cur, total, pct, kps, elapsed)

            def detail_cb(ev):
                if not self.verbose_log.get():
                    return
                always = ev.get("event") in ("found", "exhausted", "stopped", "start")
                now = time.time()
                if always or (now - self._last_log_time >= 0.1):
                    self._last_log_time = now
                    self.winfo_toplevel().after(0, self._log_detail, ev)

            result = brute_force_aes(
                ct, bits, callback=cb, detail_callback=detail_cb,
                stop_flag=self._stop_flag, workers=multiprocessing.cpu_count(),
                detail_interval=self._detail_interval(bits), fast_mode=self.fast_mode.get(),
            )
            self.winfo_toplevel().after(0, self._on_done, result, bits)

        self._bf_thread = threading.Thread(target=run, daemon=True)
        self._bf_thread.start()
        self._set_running(True)
        self.app.status_var.set(f"Đang vét cạn khóa {bits}-bit...")

    def _stop(self) -> None:
        self._stop_flag.set()
        self._set_running(False)
        self.app.status_var.set("Đã yêu cầu dừng.")
        self._log("Người dùng dừng quá trình vét cạn.")

    def _clear(self) -> None:
        self.log.delete("1.0", tk.END)
        self.progress["value"] = 0
        self.pct_label.configure(text="0%")

    def _set_running(self, running: bool) -> None:
        self.btn_start.configure(state=tk.DISABLED if running else tk.NORMAL)
        self.btn_stop.configure(state=tk.NORMAL if running else tk.DISABLED)

    # ── UI update helpers ───────────────────────────

    def _update_stats(self, cur, total, pct, kps, elapsed) -> None:
        self.progress["value"] = pct
        self.pct_label.configure(text=f"{pct:.1f}%")
        self.stat_keys.configure(text=f"Khóa đã thử: {cur:,}")
        self.stat_kps.configure(text=f"Khóa/giây: {kps:,.0f}")
        self.stat_time.configure(text=f"Thời gian: {elapsed:.1f}s")

    def _on_done(self, result, bits) -> None:
        self._update_stats(
            result["keys_tested"], result["total_keyspace"],
            result["percent_searched"], result["keys_per_second"], result["elapsed_seconds"],
        )
        if result["found"]:
            self.progress["value"] = 100
            self._log_success(result, bits)
            self.app.status_var.set(f"Khóa={result['key_int']}, bản rõ='{result['plaintext']}'")
        else:
            self._log("\n" + "=" * 64)
            self._log("Không tìm thấy khóa phù hợp")
            self._log(f"  Đã thử {result['keys_tested']:,}/{result['total_keyspace']:,}")
            self._log(f"  Thời gian: {result['elapsed_seconds']:.3f}s")
            self.app.status_var.set("Vét cạn kết thúc — không tìm thấy khóa.")
        self._set_running(False)

    def _log(self, msg: str) -> None:
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    # ── Log formatting ──────────────────────────────

    def _log_start(self, bits, ct) -> None:
        total = 1 << bits
        self._log("=" * 64)
        self._log("BẮT ĐẦU VÉT CẠN KHÓA AES")
        self._log("=" * 64)
        self._log(f"  Bản mã           : {ct.hex().upper()}")
        self._log(f"  Số bit bí mật    : {bits}")
        self._log(f"  Không gian khóa  : 2^{bits} = {total:,}")
        if self.app.shared_key_int is not None:
            self._log(f"  Khóa cần tìm     : {self.app.shared_key_int}")
        self._log("=" * 64)

    def _log_detail(self, ev) -> None:
        etype = ev.get("event")
        cur = int(ev.get("current", 0) or 0)
        total = int(ev.get("total", 0) or 0)
        pct = float(ev.get("percent", 0.0) or 0.0)
        if etype == "start":
            mode = "đa tiến trình" if ev.get("mode") == "multiprocessing" else "tuần tự"
            self._log(f"  Chế độ: {mode}, workers={ev.get('workers')}")
        elif etype == "trying":
            self._log(f"  [{cur:>8,}/{total:,} ({pct:>5.2f}%)] key={ev.get('key_int')} 0x{ev.get('key_hex')}")
        elif etype == "padding_valid":
            score = float(ev.get("plaintext_score", 0) or 0)
            if score >= 0.85:
                self._log(f"  Ứng viên: key={ev.get('key_int')} score={score:.2f} → {ev.get('plaintext_preview')!r}")
        elif etype == "chunk_done":
            self._log(f"  [CỤM] {ev.get('keys_tested'):,}/{total:,} ({pct:.2f}%)")
        elif etype == "found":
            self._log("  → Padding đúng + bản rõ đọc được → CHẤP NHẬN")

    def _log_success(self, result, bits) -> None:
        ki = int(result["key_int"])
        el = float(result["elapsed_seconds"])
        kps = float(result["keys_per_second"])
        total = int(result["total_keyspace"])
        avg_t = (total / 2) / kps if kps > 0 else 0

        self._log("\n" + "=" * 64)
        self._log("ĐÃ TÌM ĐƯỢC KHÓA")
        self._log("=" * 64)
        self._log(f"  Khóa (int)       : {ki}")
        self._log(f"  Khóa (hex)       : 0x{result['key_hex']}")
        self._log(f"  Khóa (binary)    : {format(ki, f'0{bits}b')}")
        self._log(f"  Khóa AES-128     : {result['key_full_hex']}")
        self._log(f"  Bản rõ           : {result['plaintext']}")
        self._log(f"  Thời gian        : {el:.6f}s")
        self._log(f"  Khóa đã thử     : {result['keys_tested']:,}")
        self._log(f"  Tốc độ TB        : {kps:,.0f} khóa/giây")
        self._log(f"  TB lý thuyết     : {avg_t:.6f}s")
        verdict = "sớm hơn" if el <= avg_t else "chậm hơn"
        self._log(f"  Nhận xét         : {verdict} trung bình lý thuyết")
        self._log("=" * 64)
