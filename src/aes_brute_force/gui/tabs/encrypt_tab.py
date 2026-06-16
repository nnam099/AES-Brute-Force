"""Encrypt / Decrypt tab — extracted from the monolithic gui.py."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from aes_brute_force.gui import theme as T


class EncryptTab(tk.Frame):
    """Tab 1: encrypt plaintext and display ciphertext."""

    def __init__(self, parent: tk.Widget, app) -> None:
        super().__init__(parent, bg=T.BG_BASE)
        self.app = app  # reference to AESBruteForceApp for shared state
        self._build()

    # ── UI ──────────────────────────────────────────

    def _build(self) -> None:
        inp = tk.Frame(self, bg=T.BG_BASE)
        inp.pack(fill=tk.X, padx=20, pady=16)

        T.make_label(inp, "Bản rõ:").grid(row=0, column=0, sticky="w", pady=8, padx=(0, 10))
        self.plaintext_entry = T.make_entry(inp, width=54)
        self.plaintext_entry.insert(0, "HELLO WORLD")
        self.plaintext_entry.grid(row=0, column=1, sticky="w", pady=8)

        T.make_label(inp, "Số bit bí mật:").grid(row=1, column=0, sticky="w", pady=8, padx=(0, 10))
        self.key_bits_var = tk.IntVar(value=16)
        kf = tk.Frame(inp, bg=T.BG_OVERLAY, padx=8, pady=4)
        kf.grid(row=1, column=1, sticky="w", pady=8)
        for v, label in [(8, "8"), (12, "12"), (16, "16"), (20, "20"), (24, "24"), (32, "32")]:
            tk.Radiobutton(
                kf, text=f"{label}-bit", variable=self.key_bits_var, value=v,
                bg=T.BG_OVERLAY, fg=T.FG_TEXT, selectcolor=T.BG_SURFACE,
                activebackground=T.BG_OVERLAY, activeforeground=T.ACCENT_BLUE,
                font=T.FONT_BTN, cursor="hand2",
            ).pack(side=tk.LEFT, padx=6)

        T.make_label(inp, "Khóa thử nghiệm:").grid(row=2, column=0, sticky="w", pady=8, padx=(0, 10))
        fk = tk.Frame(inp, bg=T.BG_BASE)
        fk.grid(row=2, column=1, sticky="w", pady=8)
        self.use_fixed_key = tk.BooleanVar(value=False)
        tk.Checkbutton(
            fk, text="Nhập khóa cố định", variable=self.use_fixed_key,
            bg=T.BG_BASE, fg=T.FG_TEXT, selectcolor=T.BG_SURFACE,
            activebackground=T.BG_BASE, activeforeground=T.ACCENT_BLUE, font=T.FONT_BTN,
        ).pack(side=tk.LEFT)
        self.key_int_entry = T.make_entry(fk, width=18)
        self.key_int_entry.insert(0, "142")
        self.key_int_entry.pack(side=tk.LEFT, padx=10)
        tk.Label(fk, text="(e.g. 142 or 0x8E)", font=T.FONT_SUBHEADING,
                 bg=T.BG_BASE, fg=T.FG_SUBTEXT).pack(side=tk.LEFT)

        btns = tk.Frame(self, bg=T.BG_BASE)
        btns.pack(fill=tk.X, padx=20, pady=5)
        T.make_button(btns, "Mã hóa", self._encrypt, T.ACCENT_BLUE).pack(side=tk.LEFT, padx=(0, 12))
        T.make_button(btns, "Giải mã lại", self._decrypt, T.ACCENT_GREEN).pack(side=tk.LEFT, padx=12)
        T.make_button(btns, "Xóa", self._clear, T.ACCENT_RED).pack(side=tk.LEFT, padx=12)

        out = tk.Frame(self, bg=T.BG_BASE)
        out.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        T.make_label(out, "Kết quả:").pack(anchor="w", pady=(0, 8))
        self.output = T.make_scrolled_text(out)
        self.output.pack(fill=tk.BOTH, expand=True)

    # ── Actions ─────────────────────────────────────

    def _parse_key_int(self, raw: str, bits: int) -> int:
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
        max_val = (1 << bits) - 1
        if not 0 <= value <= max_val:
            raise ValueError(f"Key must be in [0, 2^{bits} - 1].")
        return value

    def _encrypt(self) -> None:
        from aes_brute_force.core.aes_engine import bytes_to_hex, encrypt_aes

        plaintext = self.plaintext_entry.get().strip()
        if not plaintext:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập bản rõ!")
            return

        bits = self.key_bits_var.get()
        try:
            key_int = None
            if self.use_fixed_key.get():
                key_int = self._parse_key_int(self.key_int_entry.get().strip(), bits)
            ct, key, key_int = encrypt_aes(plaintext, bits, key_int=key_int)
        except Exception as e:
            messagebox.showerror("Lỗi mã hóa", str(e))
            return

        # Share state with attack tab
        self.app.shared_ciphertext = ct
        self.app.shared_key_int = key_int
        self.app.shared_key_bits = bits

        # Update attack tab ciphertext display
        if hasattr(self.app, "attack_tab"):
            self.app.attack_tab.set_ciphertext(bytes_to_hex(ct))
            self.app.attack_tab.key_bits_var.set(bits)

        self.output.delete("1.0", tk.END)
        lines = [
            "KẾT QUẢ MÃ HÓA", "-" * 56,
            f"Bản rõ             : {plaintext}",
            f"Số bit bí mật      : {bits}",
            f"Không gian khóa    : 2^{bits} = {2**bits:,}",
            f"Khóa (số nguyên)   : {key_int}",
            f"Khóa (hex)         : 0x{key_int:0{bits // 4}X}",
            f"Khóa AES-128       : {bytes_to_hex(key)}",
            f"Bản mã             : {bytes_to_hex(ct)}",
            "-" * 56,
            "\nBản mã đã chuyển sang tab vét cạn.",
        ]
        self.output.insert(tk.END, "\n".join(lines))
        self.app.status_var.set(f"Đã mã hóa với khóa {bits}-bit, key_int={key_int}")

    def _decrypt(self) -> None:
        if self.app.shared_ciphertext is None:
            messagebox.showwarning("Cảnh báo", "Hãy mã hóa một văn bản trước!")
            return
        from aes_brute_force.core.aes_engine import decrypt_aes, key_int_to_bytes

        key = key_int_to_bytes(self.app.shared_key_int, self.app.shared_key_bits)
        result = decrypt_aes(self.app.shared_ciphertext, key)
        self.output.insert(tk.END, f"\n\nGIẢI MÃ KIỂM TRA\n{'-' * 56}\n")
        self.output.insert(tk.END, f"Bản rõ thu được    : {result}\n{'-' * 56}\n")
        self.app.status_var.set(f"Giải mã kiểm tra: {result}")

    def _clear(self) -> None:
        self.output.delete("1.0", tk.END)
        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, "HELLO WORLD")
        self.use_fixed_key.set(False)
