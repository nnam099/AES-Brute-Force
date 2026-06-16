"""Brute-force attack tab with card-based statistics dashboard."""

from __future__ import annotations

import multiprocessing
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from aes_brute_force.gui import theme as T
from aes_brute_force.gui.widgets.stat_card import StatCard


class AttackTab(tk.Frame):
    """Tab 2: brute-force key search with dashboard-style progress."""

    def __init__(self, parent: tk.Widget, app) -> None:
        super().__init__(parent, bg=T.BG_BASE)
        self.app = app
        self._bf_thread: threading.Thread | None = None
        self._stop_flag = threading.Event()
        self.verbose_log = tk.BooleanVar(value=True)
        self.fast_mode = tk.BooleanVar(value=False)
        self._last_log_time = 0.0
        self._build()

    def _build(self) -> None:
        # ── Top config section ──
        top = tk.Frame(self, bg=T.BG_BASE, padx=20, pady=12)
        top.pack(fill=tk.X)

        # Ciphertext input
        ct_frame = tk.Frame(top, bg=T.BG_BASE)
        ct_frame.pack(fill=tk.X, pady=(0, 12))
        T.make_label(ct_frame, "Dữ liệu cần giải mã (Ciphertext):").pack(side=tk.LEFT, padx=(0, 15))
        self.cipher_display = T.make_scrolled_text(
            ct_frame, height=2, width=60, font=T.FONT_MONO_SM,
            borderwidth=6, wrap=tk.WORD,
        )
        self.cipher_display.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Key bits selector
        bits_frame = tk.Frame(top, bg=T.BG_BASE)
        bits_frame.pack(fill=tk.X, pady=(0, 8))
        T.make_label(bits_frame, "Độ dài khóa bí mật (Entropy):").pack(side=tk.LEFT, padx=(0, 15))
        self.key_bits_var = tk.IntVar(value=16)
        kf = tk.Frame(bits_frame, bg=T.BG_OVERLAY, padx=8, pady=4)
        kf.pack(side=tk.LEFT)
        for v in [8, 12, 16, 20, 24]:
            tk.Radiobutton(
                kf, text=f"{v}", variable=self.key_bits_var, value=v,
                bg=T.BG_OVERLAY, fg=T.FG_TEXT, selectcolor=T.BG_SURFACE,
                activebackground=T.BG_OVERLAY, activeforeground=T.ACCENT_BLUE,
                font=T.FONT_BTN, cursor="hand2",
            ).pack(side=tk.LEFT, padx=4)
        tk.Label(kf, text="bit", font=T.FONT_BODY, bg=T.BG_OVERLAY,
                 fg=T.FG_SUBTEXT).pack(side=tk.LEFT, padx=(2, 6))

        # ── Stats dashboard (card row) ──
        cards_frame = tk.Frame(self, bg=T.BG_BASE, padx=20)
        cards_frame.pack(fill=tk.X, pady=(4, 8))

        self.card_keys = StatCard(cards_frame, "Khóa đã thử", "0", T.ACCENT_GREEN)
        self.card_keys.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.card_kps = StatCard(cards_frame, "Khóa / giây", "—", T.ACCENT_BLUE)
        self.card_kps.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

        self.card_time = StatCard(cards_frame, "Thời gian", "0.0s", T.ACCENT_PEACH)
        self.card_time.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

        self.card_pct = StatCard(cards_frame, "Tiến trình", "0%", T.ACCENT_MAUVE)
        self.card_pct.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        # ── Progress bar ──
        prog = tk.Frame(self, bg=T.BG_BASE, padx=20)
        prog.pack(fill=tk.X, pady=(0, 8))
        style = ttk.Style()
        style.configure("Custom.Horizontal.TProgressbar", thickness=8,
                        troughcolor=T.BG_OVERLAY, background=T.ACCENT_GREEN)
        self.progress = ttk.Progressbar(prog, mode="determinate",
                                         style="Custom.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X)

        # ── Action buttons ──
        actions = tk.Frame(self, bg=T.BG_BASE, padx=20)
        actions.pack(fill=tk.X, pady=(0, 12))

        self.btn_start = T.make_button(actions, "▶ Khởi chạy", self._start, T.ACCENT_GREEN, T.FG_DARK)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))
        self.btn_stop = T.make_button(actions, "■ Dừng lại", self._stop, T.ACCENT_RED, T.FG_DARK)
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 8))
        self.btn_stop.configure(state=tk.DISABLED)

        tk.Checkbutton(
            actions, text="PyCryptodome", variable=self.fast_mode,
            bg=T.BG_BASE, fg=T.ACCENT_GREEN, selectcolor=T.BG_SURFACE,
            activebackground=T.BG_BASE, font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(12, 0))
        tk.Checkbutton(
            actions, text="Log chi tiết", variable=self.verbose_log,
            bg=T.BG_BASE, fg=T.FG_SUBTEXT, selectcolor=T.BG_SURFACE,
            activebackground=T.BG_BASE, font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=(12, 0))
        T.make_button(actions, "Xóa log", self._clear, T.BG_OVERLAY, T.FG_TEXT).pack(side=tk.RIGHT)

        # ── Log ──
        log_frame = tk.Frame(self, bg=T.BG_BASE, padx=20)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        T.make_label(log_frame, "Nhật ký:").pack(anchor="w", pady=(0, 4))
        self.log = T.make_scrolled_text(log_frame, borderwidth=8)
        self.log.pack(fill=tk.BOTH, expand=True)

    # ── Public ──────────────────────────────────────

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

        # Reset UI
        self.log.delete("1.0", tk.END)
        self.progress["value"] = 0
        for card in (self.card_keys, self.card_kps, self.card_time, self.card_pct):
            card.set_value("—" if card is self.card_kps else "0")
        self.card_pct.set_value("0%")
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
        self.app.status_var.set(f"⚡ Đang vét cạn khóa {bits}-bit ...")

    def _stop(self) -> None:
        self._stop_flag.set()
        self._set_running(False)
        self.app.status_var.set("Đã yêu cầu dừng.")
        self._log("⏸ Người dùng dừng quá trình vét cạn.")

    def _clear(self) -> None:
        self.log.delete("1.0", tk.END)
        self.progress["value"] = 0
        self.card_pct.set_value("0%")

    def _set_running(self, running: bool) -> None:
        self.btn_start.configure(state=tk.DISABLED if running else tk.NORMAL)
        self.btn_stop.configure(state=tk.NORMAL if running else tk.DISABLED)

    # ── Stats update ────────────────────────────────

    def _update_stats(self, cur, total, pct, kps, elapsed) -> None:
        self.progress["value"] = pct
        self.card_keys.set_value(f"{cur:,}")
        self.card_kps.set_value(f"{kps:,.0f}")
        self.card_time.set_value(f"{elapsed:.1f}s")
        self.card_pct.set_value(f"{pct:.1f}%")

    def _on_done(self, result, bits) -> None:
        self._update_stats(
            result["keys_tested"], result["total_keyspace"],
            result["percent_searched"], result["keys_per_second"], result["elapsed_seconds"],
        )
        if result["found"]:
            self.progress["value"] = 100
            self.card_pct.set_value("100%")
            self.card_pct.set_accent(T.ACCENT_GREEN)
            self._log_success(result, bits)
            self.app.status_var.set(
                f"✅ Khóa={result['key_int']}, bản rõ='{result['plaintext']}'"
            )
        else:
            self._log(f"\n{'=' * 60}")
            self._log("❌ Không tìm thấy khóa phù hợp")
            self._log(f"   Đã thử: {result['keys_tested']:,} / {result['total_keyspace']:,}")
            self._log(f"   Thời gian: {result['elapsed_seconds']:.3f}s")
            self.card_pct.set_accent(T.ACCENT_RED)
            self.app.status_var.set("Vét cạn kết thúc — không tìm thấy khóa.")
        self._set_running(False)

    # ── Logging ─────────────────────────────────────

    def _log(self, msg: str) -> None:
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def _log_start(self, bits, ct) -> None:
        total = 1 << bits
        self._log(f"{'=' * 60}")
        self._log("BẮT ĐẦU VÉT CẠN KHÓA AES")
        self._log(f"{'=' * 60}")
        self._log(f"  Bản mã        : {ct.hex().upper()}")
        self._log(f"  Key bits      : {bits}")
        self._log(f"  Keyspace      : 2^{bits} = {total:,}")
        if self.app.shared_key_int is not None:
            self._log(f"  Target key    : {self.app.shared_key_int}")
        self._log(f"{'=' * 60}")

    def _log_detail(self, ev) -> None:
        etype = ev.get("event")
        cur = int(ev.get("current", 0) or 0)
        total = int(ev.get("total", 0) or 0)
        pct = float(ev.get("percent", 0.0) or 0.0)
        if etype == "start":
            mode = "multiprocessing" if ev.get("mode") == "multiprocessing" else "sequential"
            self._log(f"  Mode: {mode}, workers={ev.get('workers')}")
        elif etype == "trying":
            self._log(f"  [{cur:>8,}/{total:,} ({pct:>5.2f}%)] "
                       f"key={ev.get('key_int')} 0x{ev.get('key_hex')}")
        elif etype == "padding_valid":
            score = float(ev.get("plaintext_score", 0) or 0)
            if score >= 0.85:
                self._log(f"  ⚠ Candidate: key={ev.get('key_int')} "
                           f"score={score:.2f} → {ev.get('plaintext_preview')!r}")
        elif etype == "chunk_done":
            self._log(f"  [CHUNK] {ev.get('keys_tested'):,}/{total:,} ({pct:.2f}%)")
        elif etype == "found":
            self._log("  → Valid padding + readable plaintext → ACCEPTED")

    def _log_success(self, result, bits) -> None:
        ki = int(result["key_int"])
        el = float(result["elapsed_seconds"])
        kps = float(result["keys_per_second"])
        total = int(result["total_keyspace"])
        avg_t = (total / 2) / kps if kps > 0 else 0

        self._log(f"\n{'=' * 60}")
        self._log("✅ KEY FOUND")
        self._log(f"{'=' * 60}")
        self._log(f"  Key (int)     : {ki}")
        self._log(f"  Key (hex)     : 0x{result['key_hex']}")
        self._log(f"  Key (binary)  : {format(ki, f'0{bits}b')}")
        self._log(f"  AES-128 key   : {result['key_full_hex']}")
        self._log(f"  Plaintext     : {result['plaintext']}")
        self._log(f"{'─' * 60}")
        self._log(f"  Time          : {el:.6f}s")
        self._log(f"  Keys tested   : {result['keys_tested']:,}")
        self._log(f"  Speed (avg)   : {kps:,.0f} keys/s")
        self._log(f"  Theory avg    : {avg_t:.6f}s")
        verdict = "faster" if el <= avg_t else "slower"
        self._log(f"  vs theory     : {verdict} than average")
        self._log(f"{'=' * 60}")
