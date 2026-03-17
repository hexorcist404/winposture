"""Check: SMB configuration — SMBv1 disabled, message signing enforced."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "SMB"


def run() -> list[CheckResult]:
    """Return SMB security configuration checks.

    Returns:
        list[CheckResult]: Results for SMBv1 status and signing enforcement.
    """
    # TODO: implement via Get-SmbServerConfiguration PowerShell cmdlet
    return [
        CheckResult(
            category=CATEGORY,
            check_name="SMBv1 Disabled",
            status=Status.INFO,
            severity=Severity.CRITICAL,
            description="Checks that SMBv1 is disabled (mitigates EternalBlue/WannaCry).",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="SMB Signing Required",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks that SMB message signing is required (mitigates relay attacks).",
            details="Not yet implemented.",
            remediation="",
        ),
    ]
