from __future__ import annotations
import customtkinter as ctk

from aes_brute_force.gui import theme as T


class StatCard(ctk.CTkFrame):
    def __init__(
        self,
        parent: ctk.CTkFrame,
        title: str,
        value: str = "—",
        accent: str = T.ACCENT_BLUE,
    ) -> None:
        super().__init__(parent, corner_radius=12, fg_color=T.BG_SURFACE)

        self._title = ctk.CTkLabel(
            self,
            text=title.upper(),
            font=("Segoe UI", 12, "bold"),
            text_color=T.FG_SUBTEXT,
            anchor="w",
        )
        self._title.pack(fill="x", padx=20, pady=(15, 0))

        self._value = ctk.CTkLabel(
            self,
            text=value,
            font=("Consolas", 28, "bold"),
            text_color=accent,
            anchor="w",
        )
        self._value.pack(fill="x", padx=20, pady=(0, 15))

    def set_value(self, value: str) -> None:
        self._value.configure(text=value)

    def set_accent(self, color: str) -> None:
        self._value.configure(text_color=color)


class SidebarButton(ctk.CTkFrame):
    def __init__(
        self,
        parent: ctk.CTkFrame,
        icon: str,
        label: str,
        command,
        active: bool = False,
    ) -> None:
        super().__init__(parent, fg_color="transparent", corner_radius=8, cursor="hand2")
        self._command = command
        self._active = active

        self._icon = ctk.CTkLabel(
            self,
            text=icon,
            font=("Segoe UI", 20),
            text_color=T.ACCENT_BLUE if active else T.FG_SUBTEXT,
        )
        self._icon.pack(side="left", padx=(15, 10), pady=10)

        self._label = ctk.CTkLabel(
            self,
            text=label,
            font=("Segoe UI", 14, "bold" if active else "normal"),
            text_color=T.FG_TEXT if active else T.FG_SUBTEXT,
            anchor="w",
        )
        self._label.pack(side="left", fill="x", expand=True)

        for w in (self, self._icon, self._label):
            w.bind("<Button-1>", lambda e: self._command())
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

        self.set_active(active)

    def set_active(self, active: bool) -> None:
        self._active = active
        self.configure(fg_color=T.BG_OVERLAY if active else "transparent")
        self._icon.configure(text_color=T.ACCENT_BLUE if active else T.FG_SUBTEXT)
        self._label.configure(
            text_color=T.FG_TEXT if active else T.FG_SUBTEXT,
            font=("Segoe UI", 14, "bold" if active else "normal"),
        )

    def _on_enter(self, _event) -> None:
        if not self._active:
            self.configure(fg_color=T.BG_OVERLAY)

    def _on_leave(self, _event) -> None:
        if not self._active:
            self.configure(fg_color="transparent")
