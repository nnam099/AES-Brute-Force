"""
Main GUI application — sidebar navigation + page container.

Replaces the ttk.Notebook tabs with a VS Code-style sidebar that gives
the application a more professional, modern-desktop feel.
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

from aes_brute_force.gui import theme as T
from aes_brute_force.gui.tabs.attack_tab import AttackTab
from aes_brute_force.gui.tabs.encrypt_tab import EncryptTab
from aes_brute_force.gui.tabs.theory_tab import TheoryTab
from aes_brute_force.gui.widgets.stat_card import SidebarButton


class AESBruteForceApp:
    """Main application window with sidebar navigation."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("AES Brute-Force Demo")
        self.root.geometry("1060x740")
        self.root.configure(bg=T.BG_BASE)
        self.root.resizable(True, True)
        self.root.minsize(800, 600)

        # Shared state
        self.shared_ciphertext: Optional[bytes] = None
        self.shared_key_int: Optional[int] = None
        self.shared_key_bits: Optional[int] = None
        self.status_var = tk.StringVar(value="Sẵn sàng — chọn chức năng từ sidebar")

        self._pages: dict[str, tk.Frame] = {}
        self._buttons: dict[str, SidebarButton] = {}
        self._current_page: str = ""

        self._build()

    def _build(self) -> None:
        # ── Sidebar ──
        sidebar = tk.Frame(self.root, bg=T.BG_SURFACE, width=180)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # App title in sidebar
        title_frame = tk.Frame(sidebar, bg=T.BG_SURFACE, pady=16, padx=12)
        title_frame.pack(fill=tk.X)
        tk.Label(title_frame, text="🔐 AES Demo", font=("Segoe UI", 16, "bold"),
                 bg=T.BG_SURFACE, fg=T.ACCENT_BLUE).pack(anchor="w")
        tk.Label(title_frame, text="Minh họa vét cạn khóa", font=("Segoe UI", 9),
                 bg=T.BG_SURFACE, fg=T.FG_SUBTEXT).pack(anchor="w")

        tk.Frame(sidebar, bg=T.BG_OVERLAY, height=1).pack(fill=tk.X, pady=(0, 10))

        # Navigation buttons
        nav_items = [
            ("encrypt", "🔒", "Mã hóa & Giải mã"),
            ("attack", "⚡", "Vét cạn (Brute-force)"),
            ("theory", "📖", "Góc lý thuyết"),
        ]
        for key, icon, label in nav_items:
            btn = SidebarButton(sidebar, icon, label,
                                command=lambda k=key: self._show_page(k),
                                active=(key == "encrypt"))
            btn.pack(fill=tk.X, pady=(2, 2), padx=8)
            self._buttons[key] = btn

        # Version label at bottom of sidebar
        tk.Label(sidebar, text="Phiên bản 2.0.0", font=("Segoe UI", 8),
                 bg=T.BG_SURFACE, fg=T.FG_SUBTEXT).pack(side=tk.BOTTOM, pady=10)
        tk.Label(sidebar, text="Đồ án môn Mật mã học", font=("Segoe UI", 8),
                 bg=T.BG_SURFACE, fg=T.FG_SUBTEXT).pack(side=tk.BOTTOM)

        # ── Right side: header + content + status ──
        right = tk.Frame(self.root, bg=T.BG_BASE)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Header
        hdr = tk.Frame(right, bg=T.BG_BASE, pady=20, padx=30)
        hdr.pack(fill=tk.X)
        self._header_title = tk.Label(hdr, text="Mã hóa / Giải mã",
                                       font=("Segoe UI", 18, "bold"),
                                       bg=T.BG_BASE, fg=T.FG_TEXT)
        self._header_title.pack(side=tk.LEFT)
        self._header_sub = tk.Label(hdr, text="•  Tạo bản mã từ dữ liệu bí mật",
                                     font=("Segoe UI", 10),
                                     bg=T.BG_BASE, fg=T.FG_SUBTEXT)
        self._header_sub.pack(side=tk.LEFT, padx=(16, 0), pady=(6, 0))

        tk.Frame(right, bg=T.BG_OVERLAY, height=1).pack(fill=tk.X, padx=30)

        # Page container
        self._container = tk.Frame(right, bg=T.BG_BASE)
        self._container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create pages
        self.encrypt_tab = EncryptTab(self._container, app=self)
        self.attack_tab = AttackTab(self._container, app=self)
        self.theory_tab = TheoryTab(self._container, app=self)

        self._pages = {
            "encrypt": self.encrypt_tab,
            "attack": self.attack_tab,
            "theory": self.theory_tab,
        }

        # Status bar
        status_bar = tk.Frame(right, bg=T.BG_OVERLAY)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Frame(status_bar, bg=T.ACCENT_GREEN, width=3).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(status_bar, textvariable=self.status_var,
                 font=("Consolas", 9), bg=T.BG_OVERLAY, fg=T.ACCENT_GREEN,
                 anchor="w", padx=12, pady=6).pack(fill=tk.X)

        # Show first page
        self._show_page("encrypt")

    def _show_page(self, key: str) -> None:
        if key == self._current_page:
            return

        # Hide current page
        if self._current_page and self._current_page in self._pages:
            self._pages[self._current_page].pack_forget()

        # Show new page
        self._pages[key].pack(fill=tk.BOTH, expand=True)
        self._current_page = key

        # Update sidebar active state
        for k, btn in self._buttons.items():
            btn.set_active(k == key)

        # Update header
        headers = {
            "encrypt": ("Mã hóa / Giải mã", "•  Tạo bản mã từ dữ liệu bí mật"),
            "attack": ("Vét cạn khóa", "•  Mô phỏng tấn công bằng sức mạnh tính toán"),
            "theory": ("Góc lý thuyết", "•  Tìm hiểu về AES và không gian khóa"),
        }
        title, sub = headers.get(key, ("", ""))
        self._header_title.configure(text=title)
        self._header_sub.configure(text=sub)
