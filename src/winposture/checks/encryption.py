"""Check: BitLocker drive encryption status."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Encryption"


def run() -> list[CheckResult]:
    """Return BitLocker encryption status for all drives.

    Returns:
        list[CheckResult]: One result per detected drive volume.
    """
    # TODO: implement via Get-BitLockerVolume PowerShell cmdlet
    return [
        CheckResult(
            category=CATEGORY,
            check_name="BitLocker — System Drive",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether BitLocker encryption is enabled on each drive.",
            details="Not yet implemented.",
            remediation="",
        )
    ]
