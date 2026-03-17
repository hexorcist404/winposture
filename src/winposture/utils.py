"""Shared helper utilities for WinPosture.

All PowerShell, WMI, and registry access goes through this module so that
check modules stay clean and testable (mock these helpers, not subprocess).
"""

from __future__ import annotations

import ctypes
import logging
import subprocess
import sys
from typing import Any

log = logging.getLogger(__name__)


def is_admin() -> bool:
    """Return True if the current process is running with administrator privileges."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_powershell(script: str, timeout: int = 30) -> str:
    """Run a PowerShell snippet and return stdout as a string.

    Args:
        script:  The PowerShell script text to execute.
        timeout: Maximum seconds to wait for the process (default 30).

    Returns:
        The combined stdout output, stripped of leading/trailing whitespace.

    Raises:
        RuntimeError: If the process exits with a non-zero return code.
    """
    log.debug("run_powershell: %s", script[:120])
    result = subprocess.run(
        [
            "powershell.exe",
            "-NonInteractive",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell exited {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def read_registry(hive: str, key: str, value: str) -> Any:
    """Read a single Windows registry value.

    Args:
        hive:  Registry hive abbreviation, e.g. "HKLM" or "HKCU".
        key:   Registry key path, e.g. r"SOFTWARE\\Policies\\Microsoft\\Windows".
        value: Value name to read.

    Returns:
        The registry value data, or None if the key/value does not exist.
    """
    if sys.platform != "win32":
        log.warning("read_registry called on non-Windows platform — returning None")
        return None

    import winreg  # type: ignore[import]

    hive_map: dict[str, int] = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }
    hive_handle = hive_map.get(hive.upper())
    if hive_handle is None:
        raise ValueError(f"Unknown registry hive: {hive!r}")

    try:
        with winreg.OpenKey(hive_handle, key) as reg_key:
            data, _ = winreg.QueryValueEx(reg_key, value)
            return data
    except FileNotFoundError:
        log.debug("Registry key/value not found: %s\\%s\\%s", hive, key, value)
        return None
    except PermissionError:
        log.warning("Permission denied reading registry: %s\\%s\\%s", hive, key, value)
        return None


def ps_bool(script: str) -> bool:
    """Run a PowerShell script that returns 'True' or 'False' and parse the result.

    Args:
        script: PowerShell script whose last output is a boolean string.

    Returns:
        True if output is "True", False otherwise.
    """
    output = run_powershell(script)
    return output.strip().lower() == "true"
