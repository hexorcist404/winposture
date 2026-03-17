"""Check: Startup programs and scheduled tasks."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Startup"


def run() -> list[CheckResult]:
    """Return startup and scheduled task checks.

    Returns:
        list[CheckResult]: Results about auto-start items.
    """
    # TODO: implement via Get-CimInstance Win32_StartupCommand and Get-ScheduledTask
    return [
        CheckResult(
            category=CATEGORY,
            check_name="Startup Programs",
            status=Status.INFO,
            severity=Severity.LOW,
            description="Enumerates programs configured to run at startup.",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="Scheduled Tasks",
            status=Status.INFO,
            severity=Severity.LOW,
            description="Enumerates non-Microsoft scheduled tasks.",
            details="Not yet implemented.",
            remediation="",
        ),
    ]
