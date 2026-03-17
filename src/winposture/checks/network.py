"""Check: Open ports and listening services."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Network"


def run() -> list[CheckResult]:
    """Return network exposure checks.

    Returns:
        list[CheckResult]: Results about listening ports and bound services.
    """
    # TODO: implement via Get-NetTCPConnection / netstat PowerShell
    return [
        CheckResult(
            category=CATEGORY,
            check_name="Open Listening Ports",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Enumerates TCP/UDP ports listening on all interfaces.",
            details="Not yet implemented.",
            remediation="",
        )
    ]
