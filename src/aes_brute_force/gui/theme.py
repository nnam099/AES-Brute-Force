"""
Catppuccin Mocha-inspired theme constants and widget factories.

Centralizes all colors, fonts, and widget styling so that individual
tabs never hard-code hex color values.
"""

from __future__ import annotations

"""
CustomTkinter Premium Theme setup (Catppuccin Mocha inspired).
"""

import customtkinter as ctk


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


BG_BASE = "#1E1E2E"
BG_SURFACE = "#181825"
BG_OVERLAY = "#313244"

ACCENT_GREEN = "#A6E3A1"
ACCENT_RED = "#F38BA8"
ACCENT_PEACH = "#FAB387"
ACCENT_BLUE = "#89B4FA"
ACCENT_MAUVE = "#CBA6F7"

FG_TEXT = "#CDD6F4"
FG_SUBTEXT = "#BAC2DE"


FONT_HEADING = ("Segoe UI", 24, "bold")
FONT_SUBHEADING = ("Segoe UI", 12)
FONT_LABEL = ("Segoe UI", 12, "bold")
FONT_BODY = ("Segoe UI", 12)
FONT_MONO = ("Consolas", 13)
FONT_MONO_SM = ("Consolas", 12)
FONT_BTN = ("Segoe UI", 13, "bold")
