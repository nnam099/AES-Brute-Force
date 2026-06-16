"""Encrypt / Decrypt tab with improved card layout."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from aes_brute_force.gui import theme as T
from aes_brute_force.gui.widgets.stat_card import StatCard


class EncryptTab(tk.Frame):
    """Tab 1: encrypt plaintext and display ciphertext."""

    def __init__(self, parent: tk.Widget, app) -> None:
        super().__init__(parent, bg=T.BG_BASE)
        self.app = app
        self._build()

    def _build(self) -> None:
        # ── Input section ──
        inp = tk.Frame(self, bg=T.BG_BASE, padx=20, pady=12)
        inp.pack(fill=tk.X)

        T.make_label(inp, "Bản rõ:").grid(row=0, column=0, sticky="w", pady=6, padx=(0, 10))
        self.plaintext_entry = T.make_entry(inp, width=54)
        self.plaintext_entry.insert(0, "HELLO WORLD")
        self.plaintext_entry.grid(row=0, column=1, sticky="ew", pady=6)
        inp.columnconfigure(1, weight=1)

        T.make_label(inp, "Key bits:").grid(row=1, column=0, sticky="w", pady=6, padx=(0, 10))
        self.key_bits_var = tk.IntVar(value=16)
        kf = tk.Frame(inp, bg=T.BG_OVERLAY, padx=8, pady=4)
        kf.grid(row=1, column=1, sticky="w", pady=6)
        for v in [8, 12, 16, 20, 24, 32]:
            tk.Radiobutton(
                kf, text=str(v), variable=self.key_bits_var, value=v,
                bg=T.BG_OVERLAY, fg=T.FG_TEXT, selectcolor=T.BG_SURFACE,
                activebackground=T.BG_OVERLAY, activeforeground=T.ACCENT_BLUE,
                font=T.FONT_BTN, cursor="hand2",
            ).pack(side=tk.LEFT, padx=4)
        tk.Label(kf, text="bit", font=T.FONT_BODY, bg=T.BG_OVERLAY,
                 fg=T.FG_SUBTEXT).pack(side=tk.LEFT, padx=(2, 6))

        T.make_label(inp, "Khóa cố định:").grid(row=2, column=0, sticky="w", pady=6, padx=(0, 10))
        fk = tk.Frame(inp, bg=T.BG_BASE)
        fk.grid(row=2, column=1, sticky="w", pady=6)
        self.use_fixed_key = tk.BooleanVar(value=False)
        tk.Checkbutton(
            fk, text="Bật", variable=self.use_fixed_key,
            bg=T.BG_BASE, fg=T.FG_TEXT, selectcolor=T.BG_SURFACE,
            activebackground=T.BG_BASE, font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT)
        self.key_int_entry = T.make_entry(fk, width=16)
        self.key_int_entry.insert(0, "142")
        self.key_int_entry.pack(side=tk.LEFT, padx=8)
        tk.Label(fk, text="(e.g. 142 or 0x8E)", font=("Segoe UI", 9),
                 bg=T.BG_BASE, fg=T.FG_SUBTEXT).pack(side=tk.LEFT)

        # ── Info cards ──
        cards = tk.Frame(self, bg=T.BG_BASE, padx=20)
        cards.pack(fill=tk.X, pady=(0, 8))

        self.card_keyspace = StatCard(cards, "Không gian khóa", "2¹⁶ = 65,536", T.ACCENT_BLUE)
        self.card_keyspace.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.card_key_val = StatCard(cards, "Khóa sử dụng", "—", T.ACCENT_GREEN)
        self.card_key_val.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
        self.card_ct_len = StatCard(cards, "Ciphertext", "—", T.ACCENT_PEACH)
        self.card_ct_len.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        # Update keyspace card when bits change
        self.key_bits_var.trace_add("write", self._on_bits_change)

        # ── Buttons ──
        btns = tk.Frame(self, bg=T.BG_BASE, padx=20)
        btns.pack(fill=tk.X, pady=(0, 8))
        T.make_button(btns, "🔒 Mã hóa", self._encrypt, T.ACCENT_BLUE).pack(side=tk.LEFT, padx=(0, 8))
        T.make_button(btns, "🔓 Giải mã", self._decrypt, T.ACCENT_GREEN).pack(side=tk.LEFT, padx=(0, 8))
        T.make_button(btns, "Xóa", self._clear, T.BG_OVERLAY, T.FG_TEXT).pack(side=tk.LEFT)

        # ── Output ──
        out = tk.Frame(self, bg=T.BG_BASE, padx=20)
        out.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        T.make_label(out, "Kết quả:").pack(anchor="w", pady=(0, 4))
        self.output = T.make_scrolled_text(out, borderwidth=8)
        self.output.pack(fill=tk.BOTH, expand=True)

    def _on_bits_change(self, *_args) -> None:
        bits = self.key_bits_var.get()
        ks = 1 << bits
        sup = str(bits).translate(str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹"))
        self.card_keyspace.set_value(f"2{sup} = {ks:,}")

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
            messagebox.showerror("Lỗi", str(e))
            return

        self.app.shared_ciphertext = ct
        self.app.shared_key_int = key_int
        self.app.shared_key_bits = bits

        if hasattr(self.app, "attack_tab"):
            self.app.attack_tab.set_ciphertext(bytes_to_hex(ct))
            self.app.attack_tab.key_bits_var.set(bits)

        # Update cards
        self.card_key_val.set_value(f"0x{key_int:0{bits // 4}X}")
        self.card_ct_len.set_value(f"{len(ct)} bytes")

        self.output.delete("1.0", tk.END)
        lines = [
            "ENCRYPTION RESULT",
            "─" * 50,
            f"Plaintext       : {plaintext}",
            f"Key bits        : {bits}",
            f"Keyspace        : 2^{bits} = {2**bits:,}",
            f"Key (int)       : {key_int}",
            f"Key (hex)       : 0x{key_int:0{bits // 4}X}",
            f"Key (AES-128)   : {bytes_to_hex(key)}",
            f"Ciphertext      : {bytes_to_hex(ct)}",
            "─" * 50,
            "",
            "→ Ciphertext copied to Attack tab.",
        ]
        self.output.insert(tk.END, "\n".join(lines))
        self.app.status_var.set(f"✅ Encrypted with {bits}-bit key (key_int={key_int})")

    def _decrypt(self) -> None:
        if self.app.shared_ciphertext is None:
            messagebox.showwarning("Cảnh báo", "Encrypt something first!")
            return
        from aes_brute_force.core.aes_engine import decrypt_aes, key_int_to_bytes

        key = key_int_to_bytes(self.app.shared_key_int, self.app.shared_key_bits)
        result = decrypt_aes(self.app.shared_ciphertext, key)
        self.output.insert(tk.END, f"\n\nDECRYPTION CHECK\n{'─' * 50}\n")
        self.output.insert(tk.END, f"Recovered       : {result}\n{'─' * 50}\n")
        self.app.status_var.set(f"🔓 Decrypted: {result}")

    def _clear(self) -> None:
        self.output.delete("1.0", tk.END)
        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, "HELLO WORLD")
        self.use_fixed_key.set(False)
        self.card_key_val.set_value("—")
        self.card_ct_len.set_value("—")
