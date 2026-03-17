"""Check: OS version, build, and patch level."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "OS"


def run() -> list[CheckResult]:
    """Return OS version and build information checks.

    Returns:
        list[CheckResult]: One or more results about OS currency.
    """
    # TODO: implement using platform / WMI / PowerShell
    return [
        CheckResult(
            category=CATEGORY,
            check_name="OS Info",
            status=Status.INFO,
            severity=Severity.INFO,
            description="Collects OS version, build number, and patch level.",
            details="Not yet implemented.",
            remediation="",
        )
    ]
