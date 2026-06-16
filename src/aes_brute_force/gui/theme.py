"""
Catppuccin Mocha-inspired theme constants and widget factories.

Centralizes all colors, fonts, and widget styling so that individual
tabs never hard-code hex color values.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext

# ---------------------------------------------------------------------------
# Catppuccin Mocha palette
# ---------------------------------------------------------------------------
BG_BASE = "#24273A"
BG_SURFACE = "#1E2030"
BG_OVERLAY = "#363A4F"
FG_TEXT = "#CAD3F5"
FG_SUBTEXT = "#A5ADCB"
ACCENT_BLUE = "#8AADF4"
ACCENT_GREEN = "#A6DA95"
ACCENT_RED = "#ED8796"
ACCENT_PEACH = "#F5A97F"
ACCENT_YELLOW = "#EED49F"
ACCENT_MAUVE = "#C6A0F6"
FG_DARK = "#1E2030"

# ---------------------------------------------------------------------------
# Fonts
# ---------------------------------------------------------------------------
FONT_HEADING = ("Segoe UI", 18, "bold")
FONT_SUBHEADING = ("Segoe UI", 10)
FONT_LABEL = ("Segoe UI", 10, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 11)
FONT_MONO_SM = ("Consolas", 10)
FONT_BTN = ("Segoe UI", 10, "bold")


# ---------------------------------------------------------------------------
# Widget factories
# ---------------------------------------------------------------------------

def make_label(parent: tk.Widget, text: str, **kw) -> tk.Label:
    return tk.Label(parent, text=text, font=FONT_LABEL, bg=BG_BASE, fg=ACCENT_BLUE, **kw)


def make_entry(parent: tk.Widget, **kw) -> tk.Entry:
    return tk.Entry(
        parent, font=FONT_MONO, bg=BG_OVERLAY, fg=FG_TEXT,
        insertbackground=FG_TEXT, relief=tk.FLAT, bd=8, **kw,
    )


def make_button(
    parent: tk.Widget, text: str, command, color: str = ACCENT_BLUE, fg: str = FG_DARK,
) -> tk.Button:
    return tk.Button(
        parent, text=text, command=command, font=FONT_BTN,
        bg=color, fg=fg, activebackground=FG_TEXT, activeforeground=FG_DARK,
        relief=tk.FLAT, padx=16, pady=8, cursor="hand2", borderwidth=0,
    )


def make_scrolled_text(parent: tk.Widget, **kw) -> scrolledtext.ScrolledText:
    defaults = dict(
        font=FONT_MONO, bg=BG_SURFACE, fg=FG_TEXT, insertbackground=FG_TEXT,
        relief=tk.FLAT, borderwidth=12, highlightthickness=0,
    )
    defaults.update(kw)
    return scrolledtext.ScrolledText(parent, **defaults)
