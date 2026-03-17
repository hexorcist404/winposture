"""Check: Local user accounts, admin group membership, guest account, password policy."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Accounts"


def run() -> list[CheckResult]:
    """Return local account security checks.

    Returns:
        list[CheckResult]: Results for guest account, admin count, and password policy.
    """
    # TODO: implement via Get-LocalUser, Get-LocalGroupMember, net accounts
    return [
        CheckResult(
            category=CATEGORY,
            check_name="Guest Account Status",
            status=Status.INFO,
            severity=Severity.HIGH,
            description="Checks whether the built-in Guest account is disabled.",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="Local Administrator Count",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Counts members of the local Administrators group.",
            details="Not yet implemented.",
            remediation="",
        ),
        CheckResult(
            category=CATEGORY,
            check_name="Password Policy",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks minimum password length and complexity requirements.",
            details="Not yet implemented.",
            remediation="",
        ),
    ]
