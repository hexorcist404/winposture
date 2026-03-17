"""Check: Remote Desktop Protocol — enabled status and NLA enforcement."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "RDP"


def run() -> list[CheckResult]:
    """Return RDP security configuration checks.

    Returns:
        list[CheckResult]: Results for RDP enablement and NLA requirement.
    """
    # TODO: implement via registry and Get-ItemProperty PowerShell
    return [
        CheckResult(
            category=CATEGORY,
            check_name="RDP Enabled",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether Remote Desktop is enabled.",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="RDP Network Level Authentication",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether NLA is required for RDP connections.",
            details="Not yet implemented.",
            remediation="",
        ),
    ]
