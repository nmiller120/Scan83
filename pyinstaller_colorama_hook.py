"""PyInstaller runtime hook for Windows console color support."""

from colorama import just_fix_windows_console


just_fix_windows_console()
