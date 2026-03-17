"""Check: PowerShell execution policy, script block logging, and constrained mode."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "PowerShell"


def run() -> list[CheckResult]:
    """Return PowerShell security configuration checks.

    Returns:
        list[CheckResult]: Results for execution policy, logging, and constrained mode.
    """
    # TODO: implement via Get-ExecutionPolicy and registry checks
    return [
        CheckResult(
            category=CATEGORY,
            check_name="PowerShell Execution Policy",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks the effective PowerShell execution policy.",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="PowerShell Script Block Logging",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks whether PowerShell script block logging is enabled.",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="PowerShell Constrained Language Mode",
            status=Status.INFO,
            severity=Severity.LOW,
            description="Checks whether PowerShell is running in Constrained Language Mode.",
            details="Not yet implemented.",
            remediation="",
        ),
    ]
