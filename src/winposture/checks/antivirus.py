"""Check: Windows Defender / antivirus status."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Antivirus"


def run() -> list[CheckResult]:
    """Return antivirus / Windows Defender status checks.

    Returns:
        list[CheckResult]: Results about AV enablement and definition age.
    """
    # TODO: implement via Get-MpComputerStatus PowerShell cmdlet
    return [
        CheckResult(
            category=CATEGORY,
            check_name="Windows Defender Status",
            status=Status.INFO,
            severity=Severity.CRITICAL,
            description="Checks whether Windows Defender is enabled and definitions are current.",
            details="Not yet implemented.",
            remediation="",
        )
    ]
