"""Encrypt / Decrypt tab with improved card layout."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

from aes_brute_force.gui import theme as T
from aes_brute_force.gui.widgets.stat_card import StatCard


class EncryptTab(ctk.CTkFrame):
    """Tab 1: encrypt plaintext and display ciphertext."""

    def __init__(self, parent: ctk.CTkFrame, app) -> None:
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self._build()

    def _build(self) -> None:
        inp = ctk.CTkFrame(self, fg_color=T.BG_SURFACE, corner_radius=12)
        inp.pack(fill="x", pady=(0, 20))

        inp_inner = ctk.CTkFrame(inp, fg_color="transparent")
        inp_inner.pack(fill="both", expand=True, padx=25, pady=25)

        ctk.CTkLabel(
            inp_inner, text="Nội dung cần mã hóa:", font=T.FONT_LABEL, text_color=T.FG_TEXT
        ).grid(row=0, column=0, sticky="w", pady=10, padx=(0, 20))
        self.plaintext_entry = ctk.CTkEntry(
            inp_inner, width=500, font=T.FONT_MONO, fg_color=T.BG_BASE, border_width=0, height=35
        )
        self.plaintext_entry.insert(0, "HELLO WORLD")
        self.plaintext_entry.grid(row=0, column=1, sticky="ew", pady=10)
        inp_inner.columnconfigure(1, weight=1)

        ctk.CTkLabel(
            inp_inner, text="Độ dài khóa bí mật:", font=T.FONT_LABEL, text_color=T.FG_TEXT
        ).grid(row=1, column=0, sticky="w", pady=10, padx=(0, 20))
        self.key_bits_var = tk.IntVar(value=16)
        kf = ctk.CTkFrame(inp_inner, fg_color="transparent")
        kf.grid(row=1, column=1, sticky="w", pady=10)
        for v in [8, 12, 16, 20, 24, 32]:
            ctk.CTkRadioButton(
                kf,
                text=f"{v} bit",
                variable=self.key_bits_var,
                value=v,
                font=T.FONT_BODY,
                text_color=T.FG_SUBTEXT,
                fg_color=T.ACCENT_BLUE,
                hover_color=T.ACCENT_BLUE,
            ).pack(side="left", padx=(0, 20))

        ctk.CTkLabel(inp_inner, text="Khóa cố định:", font=T.FONT_LABEL, text_color=T.FG_TEXT).grid(
            row=2, column=0, sticky="w", pady=10, padx=(0, 20)
        )
        fk = ctk.CTkFrame(inp_inner, fg_color="transparent")
        fk.grid(row=2, column=1, sticky="w", pady=10)
        self.use_fixed_key = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            fk,
            text="Bật",
            variable=self.use_fixed_key,
            font=T.FONT_BODY,
            text_color=T.FG_SUBTEXT,
            fg_color=T.ACCENT_BLUE,
            hover_color=T.ACCENT_BLUE,
        ).pack(side="left", padx=(0, 15))
        self.key_int_entry = ctk.CTkEntry(
            fk, width=150, font=T.FONT_MONO, fg_color=T.BG_BASE, border_width=0, height=35
        )
        self.key_int_entry.insert(0, "142")
        self.key_int_entry.pack(side="left", padx=10)
        ctk.CTkLabel(
            fk, text="(e.g. 142 or 0x8E)", font=T.FONT_SUBHEADING, text_color=T.FG_SUBTEXT
        ).pack(side="left")

        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", pady=(0, 20))

        self.card_keyspace = StatCard(cards, "Không gian khóa", "2¹⁶ = 65,536", T.ACCENT_BLUE)
        self.card_keyspace.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.card_key_val = StatCard(cards, "Khóa sử dụng", "—", T.ACCENT_GREEN)
        self.card_key_val.pack(side="left", fill="x", expand=True, padx=5)
        self.card_ct_len = StatCard(cards, "Ciphertext", "—", T.ACCENT_PEACH)
        self.card_ct_len.pack(side="left", fill="x", expand=True, padx=(10, 0))

        self.key_bits_var.trace_add("write", self._on_bits_change)

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", pady=(0, 20))
        ctk.CTkButton(
            btns,
            text="🔒 Bắt đầu mã hóa",
            command=self._encrypt,
            fg_color=T.ACCENT_BLUE,
            hover_color=T.ACCENT_MAUVE,
            font=T.FONT_BTN,
            text_color=T.BG_BASE,
            height=40,
        ).pack(side="left", padx=(0, 15))
        ctk.CTkButton(
            btns,
            text="🔓 Kiểm tra giải mã",
            command=self._decrypt,
            fg_color=T.ACCENT_GREEN,
            hover_color="#8FCE8A",
            font=T.FONT_BTN,
            text_color=T.BG_BASE,
            height=40,
        ).pack(side="left", padx=(0, 15))
        ctk.CTkButton(
            btns,
            text="Xóa toàn bộ",
            command=self._clear,
            fg_color=T.BG_OVERLAY,
            hover_color=T.BG_SURFACE,
            font=T.FONT_BTN,
            text_color=T.FG_TEXT,
            height=40,
        ).pack(side="left")

        out = ctk.CTkFrame(self, fg_color=T.BG_SURFACE, corner_radius=12)
        out.pack(fill="both", expand=True)

        out_inner = ctk.CTkFrame(out, fg_color="transparent")
        out_inner.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(out_inner, text="Kết quả:", font=T.FONT_LABEL, text_color=T.FG_TEXT).pack(
            anchor="w", pady=(0, 10)
        )
        self.output = ctk.CTkTextbox(
            out_inner, font=T.FONT_MONO, fg_color=T.BG_BASE, text_color=T.FG_TEXT, border_width=0
        )
        self.output.pack(fill="both", expand=True)

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
