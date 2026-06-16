"""
Catppuccin Mocha-inspired theme constants and widget factories.

Centralizes all colors, fonts, and widget styling so that individual
tabs never hard-code hex color values.
"""

from __future__ import annotations

"""
CustomTkinter Theme setup.
"""

import customtkinter as ctk

# Configure global CTk settings
ctk.set_appearance_mode("System")  # Modes: system (default), light, dark
ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

# Standard CTk colors for accents
ACCENT_GREEN = "#2ECC71"
ACCENT_RED = "#E74C3C"
ACCENT_PEACH = "#E67E22"
ACCENT_BLUE = "#3498DB"
ACCENT_MAUVE = "#9B59B6"

# Fonts
FONT_HEADING = ("Segoe UI", 24, "bold")
FONT_SUBHEADING = ("Segoe UI", 12)
FONT_LABEL = ("Segoe UI", 12, "bold")
FONT_BODY = ("Segoe UI", 12)
FONT_MONO = ("Consolas", 12)
FONT_MONO_SM = ("Consolas", 11)
FONT_BTN = ("Segoe UI", 12, "bold")
