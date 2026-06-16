"""
Catppuccin Mocha-inspired theme constants and widget factories.

Centralizes all colors, fonts, and widget styling so that individual
tabs never hard-code hex color values.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext

# ---------------------------------------------------------------------------
# Soft Modern Dark Palette (Human-centered, friendly)
# ---------------------------------------------------------------------------
BG_BASE = "#1E1E2E"        # Deep but soft background
BG_SURFACE = "#25253A"     # Slightly lighter for panels/sidebar
BG_OVERLAY = "#313244"     # For cards and inputs
FG_TEXT = "#CDD6F4"        # Soft white for main text
FG_SUBTEXT = "#BAC2DE"     # Muted text for descriptions
ACCENT_BLUE = "#89B4FA"    # Friendly light blue
ACCENT_GREEN = "#A6E3A1"   # Success green, not too harsh
ACCENT_RED = "#F38BA8"     # Soft alert red
ACCENT_PEACH = "#FAB387"   # Warm peach
ACCENT_YELLOW = "#F9E2AF"  # Soft warning yellow
ACCENT_MAUVE = "#CBA6F7"   # Playful purple
FG_DARK = "#11111B"        # Contrast color for button text

# ---------------------------------------------------------------------------
# Fonts (More modern, readable)
# ---------------------------------------------------------------------------
FONT_HEADING = ("Segoe UI", 20, "bold")
FONT_SUBHEADING = ("Segoe UI", 10)
FONT_LABEL = ("Segoe UI", 10, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 10)
FONT_MONO_SM = ("Consolas", 9)
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
