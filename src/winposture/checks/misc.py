"""Check: Miscellaneous settings — AutoPlay, Remote Registry."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Misc"


def run() -> list[CheckResult]:
    """Return miscellaneous security configuration checks.

    Returns:
        list[CheckResult]: Results for AutoPlay and Remote Registry.
"""
    # TODO: implement via registry reads and service status checks
    return [
        CheckResult(
            category=CATEGORY,
            check_name="AutoPlay Disabled",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks whether AutoPlay is disabled for all drive types.",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="Remote Registry Service Disabled",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether the Remote Registry service is stopped and disabled.",
            details="Not yet implemented.",
            remediation="",
        ),
    ]
