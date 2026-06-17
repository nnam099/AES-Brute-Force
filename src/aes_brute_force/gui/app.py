from __future__ import annotations
import customtkinter as ctk
from typing import Optional

from aes_brute_force.gui import theme as T
from aes_brute_force.gui.tabs.attack_tab import AttackTab
from aes_brute_force.gui.tabs.encrypt_tab import EncryptTab
from aes_brute_force.gui.tabs.theory_tab import TheoryTab
from aes_brute_force.gui.widgets.stat_card import SidebarButton


class AESBruteForceApp:
    def __init__(self, root: ctk.CTk) -> None:
        self.root = root
        self.root.title("AES Brute-Force Demo")
        self.root.geometry("1100x780")
        self.root.minsize(900, 650)
        self.root.configure(fg_color=T.BG_BASE)

        self.shared_ciphertext: Optional[bytes] = None
        self.shared_key_int: Optional[int] = None
        self.shared_key_bits: Optional[int] = None
        self.status_var = ctk.StringVar(value="Sẵn sàng — chọn chức năng từ sidebar")

        self._pages: dict[str, ctk.CTkFrame] = {}
        self._buttons: dict[str, SidebarButton] = {}
        self._current_page: str = ""

        self._build()

    def _build(self) -> None:
        sidebar = ctk.CTkFrame(self.root, width=250, corner_radius=0, fg_color=T.BG_SURFACE)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        title_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        title_frame.pack(fill="x", pady=(30, 20), padx=20)
        ctk.CTkLabel(
            title_frame, text="🔐 AES Demo", font=T.FONT_HEADING, text_color=T.ACCENT_BLUE
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_frame,
            text="Minh họa vét cạn khóa",
            font=T.FONT_SUBHEADING,
            text_color=T.FG_SUBTEXT,
        ).pack(anchor="w")

        nav_items = [
            ("encrypt", "🔒", "Mã hóa & Giải mã"),
            ("attack", "⚡", "Vét cạn (Brute-force)"),
            ("theory", "📖", "Góc lý thuyết"),
        ]

        btn_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        btn_frame.pack(fill="both", expand=True, padx=15, pady=10)

        for key, icon, label in nav_items:
            btn = SidebarButton(
                btn_frame,
                icon,
                label,
                command=lambda k=key: self._show_page(k),
                active=(key == "encrypt"),
            )
            btn.pack(fill="x", pady=(4, 4))
            self._buttons[key] = btn

        ctk.CTkLabel(
            sidebar,
            text="Phiên bản 2.0.0\nĐồ án môn Mật mã học",
            font=("Segoe UI", 12),
            justify="center",
            text_color=T.FG_SUBTEXT,
        ).pack(side="bottom", pady=25)

        right = ctk.CTkFrame(self.root, fg_color="transparent", corner_radius=0)
        right.pack(side="left", fill="both", expand=True)

        hdr = ctk.CTkFrame(right, fg_color="transparent", corner_radius=0)
        hdr.pack(fill="x", pady=(30, 15), padx=40)
        self._header_title = ctk.CTkLabel(
            hdr, text="Mã hóa / Giải mã", font=T.FONT_HEADING, text_color=T.FG_TEXT
        )
        self._header_title.pack(side="left")
        self._header_sub = ctk.CTkLabel(
            hdr,
            text="•  Tạo bản mã từ dữ liệu bí mật",
            font=T.FONT_SUBHEADING,
            text_color=T.FG_SUBTEXT,
        )
        self._header_sub.pack(side="left", padx=(16, 0), pady=(6, 0))

        self._container = ctk.CTkFrame(right, fg_color="transparent")
        self._container.pack(fill="both", expand=True, padx=30, pady=(0, 15))

        self.encrypt_tab = EncryptTab(self._container, app=self)
        self.attack_tab = AttackTab(self._container, app=self)
        self.theory_tab = TheoryTab(self._container, app=self)

        self._pages = {
            "encrypt": self.encrypt_tab,
            "attack": self.attack_tab,
            "theory": self.theory_tab,
        }

        status_bar = ctk.CTkFrame(right, height=35, corner_radius=0, fg_color=T.BG_SURFACE)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        ctk.CTkLabel(
            status_bar, textvariable=self.status_var, font=T.FONT_MONO_SM, text_color=T.ACCENT_GREEN
        ).pack(side="left", padx=20)

        self._show_page("encrypt")

    def _show_page(self, key: str) -> None:
        if key == self._current_page:
            return

        if self._current_page and self._current_page in self._pages:
            self._pages[self._current_page].pack_forget()

        self._pages[key].pack(fill="both", expand=True)
        self._current_page = key

        for k, btn in self._buttons.items():
            btn.set_active(k == key)

        headers = {
            "encrypt": ("Mã hóa / Giải mã", "•  Tạo bản mã từ dữ liệu bí mật"),
            "attack": ("Vét cạn khóa", "•  Mô phỏng tấn công bằng sức mạnh tính toán"),
            "theory": ("Góc lý thuyết", "•  Tìm hiểu về AES và không gian khóa"),
        }
        title, sub = headers.get(key, ("", ""))
        self._header_title.configure(text=title)
        self._header_sub.configure(text=sub)
