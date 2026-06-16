"""
Main GUI application — assembles tabs and manages shared state.

This replaces the 715-line monolithic ``gui.py`` with a thin orchestrator
that delegates to focused tab components.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from aes_brute_force.gui import theme as T
from aes_brute_force.gui.tabs.attack_tab import AttackTab
from aes_brute_force.gui.tabs.encrypt_tab import EncryptTab
from aes_brute_force.gui.tabs.theory_tab import TheoryTab


class AESBruteForceApp:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("AES Brute-Force Demo — Mật mã học")
        self.root.geometry("960x720")
        self.root.configure(bg=T.BG_BASE)
        self.root.resizable(True, True)

        # Shared state between tabs
        self.shared_ciphertext: Optional[bytes] = None
        self.shared_key_int: Optional[int] = None
        self.shared_key_bits: Optional[int] = None
        self.status_var = tk.StringVar(value="Sẵn sàng")

        self._build()

    def _build(self) -> None:
        # ── Header ──
        hdr = tk.Frame(self.root, bg=T.BG_SURFACE, pady=16)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Minh họa vét cạn khóa AES",
                 font=T.FONT_HEADING, bg=T.BG_SURFACE, fg=T.FG_TEXT).pack()
        tk.Label(hdr, text="Thí nghiệm với khóa entropy thấp và không gian khóa 2ⁿ",
                 font=T.FONT_SUBHEADING, bg=T.BG_SURFACE, fg=T.FG_SUBTEXT).pack(pady=(4, 0))

        # ── Notebook ──
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=T.BG_BASE, borderwidth=0)
        style.configure("TNotebook.Tab", background=T.BG_SURFACE, foreground=T.FG_TEXT,
                        padding=[16, 8], font=T.FONT_BTN, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", T.ACCENT_BLUE)],
                  foreground=[("selected", T.FG_DARK)])

        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        # Tabs
        self.encrypt_tab = EncryptTab(nb, app=self)
        self.attack_tab = AttackTab(nb, app=self)
        self.theory_tab = TheoryTab(nb, app=self)

        nb.add(self.encrypt_tab, text="  Mã hóa / Giải mã  ")
        nb.add(self.attack_tab, text="  Vét cạn khóa  ")
        nb.add(self.theory_tab, text="  Lý thuyết  ")

        # ── Status bar ──
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Segoe UI", 9, "bold"), bg="#181825", fg=T.ACCENT_GREEN,
            anchor="w", padx=16, pady=6,
        ).pack(fill=tk.X, side=tk.BOTTOM)
