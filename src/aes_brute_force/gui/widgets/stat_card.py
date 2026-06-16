"""
Reusable stat-card widget.

Provides a compact, card-styled display for a single metric — inspired
by dashboard UIs in VS Code, Grafana, and Burp Suite Professional.
"""

from __future__ import annotations

import tkinter as tk

from aes_brute_force.gui import theme as T


class StatCard(tk.Frame):
    """A small card showing a title label and a large value label."""

    def __init__(
        self,
        parent: tk.Widget,
        title: str,
        value: str = "—",
        accent: str = T.ACCENT_BLUE,
        width: int = 0,
    ) -> None:
        super().__init__(parent, bg=T.BG_OVERLAY, padx=16, pady=10, highlightthickness=0)
        if width:
            self.configure(width=width)
            self.pack_propagate(False)

        self._title = tk.Label(
            self, text=title.upper(), font=("Segoe UI", 8, "bold"),
            bg=T.BG_OVERLAY, fg=T.FG_SUBTEXT, anchor="w",
        )
        self._title.pack(fill=tk.X)

        self._value = tk.Label(
            self, text=value, font=("Consolas", 16, "bold"),
            bg=T.BG_OVERLAY, fg=accent, anchor="w",
        )
        self._value.pack(fill=tk.X, pady=(4, 0))

    def set_value(self, value: str) -> None:
        self._value.configure(text=value)

    def set_accent(self, color: str) -> None:
        self._value.configure(fg=color)


class SidebarButton(tk.Frame):
    """A sidebar navigation button with icon + label and active state."""

    def __init__(
        self,
        parent: tk.Widget,
        icon: str,
        label: str,
        command,
        active: bool = False,
    ) -> None:
        super().__init__(parent, bg=T.BG_SURFACE, cursor="hand2")
        self._command = command
        self._active = active

        self._icon = tk.Label(
            self, text=icon, font=("Segoe UI", 14),
            bg=T.BG_SURFACE, fg=T.ACCENT_BLUE if active else T.FG_SUBTEXT,
            padx=8, pady=6,
        )
        self._icon.pack(side=tk.LEFT)

        self._label = tk.Label(
            self, text=label, font=("Segoe UI", 10, "bold" if active else ""),
            bg=T.BG_SURFACE, fg=T.FG_TEXT if active else T.FG_SUBTEXT,
            anchor="w",
        )
        self._label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._indicator = tk.Frame(self, bg=T.ACCENT_BLUE if active else T.BG_SURFACE, width=3)
        self._indicator.pack(side=tk.RIGHT, fill=tk.Y)

        for w in (self, self._icon, self._label):
            w.bind("<Button-1>", lambda e: self._command())
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

    def set_active(self, active: bool) -> None:
        self._active = active
        bg = T.BG_OVERLAY if active else T.BG_SURFACE
        fg_icon = T.ACCENT_BLUE if active else T.FG_SUBTEXT
        fg_label = T.FG_TEXT if active else T.FG_SUBTEXT
        font = ("Segoe UI", 10, "bold" if active else "")
        ind_bg = T.ACCENT_BLUE if active else T.BG_SURFACE

        for w in (self, self._icon, self._label):
            w.configure(bg=bg)
        self._icon.configure(fg=fg_icon)
        self._label.configure(fg=fg_label, font=font)
        self._indicator.configure(bg=ind_bg)

    def _on_enter(self, _event) -> None:
        if not self._active:
            for w in (self, self._icon, self._label):
                w.configure(bg="#2E3250")

    def _on_leave(self, _event) -> None:
        bg = T.BG_OVERLAY if self._active else T.BG_SURFACE
        for w in (self, self._icon, self._label):
            w.configure(bg=bg)
