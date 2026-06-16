"""Brute-force attack tab with card-based statistics dashboard."""

from __future__ import annotations

import multiprocessing
import threading
import time
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

from aes_brute_force.gui import theme as T
from aes_brute_force.gui.widgets.stat_card import StatCard


class AttackTab(ctk.CTkFrame):
    """Tab 2: brute-force key search with dashboard-style progress."""

    def __init__(self, parent: ctk.CTkFrame, app) -> None:
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._bf_thread: threading.Thread | None = None
        self._stop_flag = threading.Event()
        self.verbose_log = tk.BooleanVar(value=True)
        self.fast_mode = tk.BooleanVar(value=False)
        self._last_log_time = 0.0
        self._build()

    def _build(self) -> None:
        # ── Top config section ──
        top = ctk.CTkFrame(self, fg_color=T.BG_SURFACE, corner_radius=12)
        top.pack(fill="x", pady=(0, 20))

        # Inner padding for input section
        top_inner = ctk.CTkFrame(top, fg_color="transparent")
        top_inner.pack(fill="both", expand=True, padx=25, pady=25)

        # Ciphertext input
        ct_frame = ctk.CTkFrame(top_inner, fg_color="transparent")
        ct_frame.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(ct_frame, text="Dữ liệu cần giải mã (Ciphertext):", font=T.FONT_LABEL, text_color=T.FG_TEXT).pack(side="left", padx=(0, 20))
        self.cipher_display = ctk.CTkTextbox(ct_frame, height=50, width=500, font=T.FONT_MONO_SM, fg_color=T.BG_BASE, border_width=0)
        self.cipher_display.pack(side="left", fill="x", expand=True)

        # Key bits selector
        bits_frame = ctk.CTkFrame(top_inner, fg_color="transparent")
        bits_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(bits_frame, text="Độ dài khóa bí mật (Entropy):", font=T.FONT_LABEL, text_color=T.FG_TEXT).pack(side="left", padx=(0, 20))
        self.key_bits_var = tk.IntVar(value=16)
        kf = ctk.CTkFrame(bits_frame, fg_color="transparent")
        kf.pack(side="left")
        for v in [8, 12, 16, 20, 24]:
            ctk.CTkRadioButton(
                kf, text=str(v), variable=self.key_bits_var, value=v,
                font=T.FONT_BODY, text_color=T.FG_SUBTEXT,
                fg_color=T.ACCENT_BLUE, hover_color=T.ACCENT_BLUE
            ).pack(side="left", padx=(0, 15))
        ctk.CTkLabel(kf, text="bit", font=T.FONT_BODY, text_color=T.FG_SUBTEXT).pack(side="left", padx=(2, 6))

        # ── Stats dashboard (card row) ──
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 20))

        self.card_keys = StatCard(cards_frame, "Khóa đã thử", "0", T.ACCENT_GREEN)
        self.card_keys.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.card_kps = StatCard(cards_frame, "Khóa / giây", "—", T.ACCENT_BLUE)
        self.card_kps.pack(side="left", fill="x", expand=True, padx=5)

        self.card_time = StatCard(cards_frame, "Thời gian", "0.0s", T.ACCENT_PEACH)
        self.card_time.pack(side="left", fill="x", expand=True, padx=5)

        self.card_pct = StatCard(cards_frame, "Tiến trình", "0%", T.ACCENT_MAUVE)
        self.card_pct.pack(side="left", fill="x", expand=True, padx=(10, 0))

        # ── Progress bar ──
        prog = ctk.CTkFrame(self, fg_color="transparent")
        prog.pack(fill="x", pady=(0, 15))
        self.progress = ctk.CTkProgressBar(prog, height=10, progress_color=T.ACCENT_GREEN, fg_color=T.BG_SURFACE)
        self.progress.pack(fill="x")
        self.progress.set(0)

        # ── Action buttons ──
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", pady=(0, 20))

        self.btn_start = ctk.CTkButton(actions, text="▶ Khởi chạy", command=self._start, fg_color=T.ACCENT_GREEN, hover_color="#8FCE8A", font=T.FONT_BTN, text_color=T.BG_BASE, height=40)
        self.btn_start.pack(side="left", padx=(0, 15))
        self.btn_stop = ctk.CTkButton(actions, text="■ Dừng lại", command=self._stop, fg_color=T.ACCENT_RED, hover_color="#F07195", font=T.FONT_BTN, text_color=T.BG_BASE, state="disabled", height=40)
        self.btn_stop.pack(side="left", padx=(0, 15))

        ctk.CTkCheckBox(
            actions, text="PyCryptodome", variable=self.fast_mode, font=T.FONT_BODY, text_color=T.FG_SUBTEXT,
            fg_color=T.ACCENT_GREEN, hover_color=T.ACCENT_GREEN
        ).pack(side="left", padx=(15, 0))
        ctk.CTkCheckBox(
            actions, text="Log chi tiết", variable=self.verbose_log, font=T.FONT_BODY, text_color=T.FG_SUBTEXT,
            fg_color=T.ACCENT_BLUE, hover_color=T.ACCENT_BLUE
        ).pack(side="left", padx=(15, 0))
        ctk.CTkButton(actions, text="Xóa log", command=self._clear, fg_color=T.BG_OVERLAY, hover_color=T.BG_SURFACE, font=T.FONT_BTN, text_color=T.FG_TEXT, width=100, height=40).pack(side="right")

        # ── Log ──
        log_frame = ctk.CTkFrame(self, fg_color=T.BG_SURFACE, corner_radius=12)
        log_frame.pack(fill="both", expand=True)
        
        log_inner = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_inner.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(log_inner, text="Nhật ký:", font=T.FONT_LABEL, text_color=T.FG_TEXT).pack(anchor="w", pady=(0, 10))
        self.log = ctk.CTkTextbox(log_inner, font=T.FONT_MONO, fg_color=T.BG_BASE, text_color=T.FG_TEXT, border_width=0)
        self.log.pack(fill="both", expand=True)

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
        self.progress.set(0)
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
        self.progress.set(0)
        self.card_pct.set_value("0%")

    def _set_running(self, running: bool) -> None:
        self.btn_start.configure(state="disabled" if running else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled")

    # ── Stats update ────────────────────────────────

    def _update_stats(self, cur, total, pct, kps, elapsed) -> None:
        self.progress.set(pct / 100.0)
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
            self.progress.set(1.0)
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
