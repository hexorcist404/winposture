"""Custom exceptions for WinPosture."""

from __future__ import annotations


class WinPostureError(Exception):
    """Raised when a WinPosture utility operation fails in an expected way.

    Examples: PowerShell non-zero exit, timeout, JSON parse failure,
    access-denied registry read, or running on a non-Windows platform.
    """
