"""Check: User Account Control (UAC) level."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "UAC"


def run() -> list[CheckResult]:
    """Return UAC configuration checks.

    Returns:
        list[CheckResult]: Result for the current UAC consent behavior level.
    """
    # TODO: implement via registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    return [
        CheckResult(
            category=CATEGORY,
            check_name="UAC Enabled",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether UAC is enabled and at what consent level.",
            details="Not yet implemented.",
            remediation="",
        )
    ]
