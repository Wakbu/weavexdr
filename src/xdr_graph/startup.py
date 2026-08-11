from __future__ import annotations

import os
import sys


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "WeaveXDR"


def startup_enabled() -> bool:
    if os.name != "nt":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
        return bool(value)
    except FileNotFoundError:
        return False


def set_startup_enabled(enabled: bool) -> bool:
    """Toggle current-user startup without requesting administrator privileges."""
    if os.name != "nt":
        raise RuntimeError("Windows startup registration is only available on Windows")
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        if enabled:
            executable = sys.executable if getattr(sys, "frozen", False) else str(sys.argv[0])
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, f'"{executable}"')
        else:
            try:
                winreg.DeleteValue(key, VALUE_NAME)
            except FileNotFoundError:
                pass
    return startup_enabled()
