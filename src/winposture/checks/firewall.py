"""Check: Windows Firewall status across all profiles."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Firewall"

_PROFILES = ["Domain", "Private", "Public"]


def run() -> list[CheckResult]:
    """Return firewall status for all three Windows Firewall profiles.

    Returns:
        list[CheckResult]: One result per firewall profile.
    """
    # TODO: implement via Get-NetFirewallProfile PowerShell cmdlet
    results = []
    for profile in _PROFILES:
        results.append(
            CheckResult(
                category=CATEGORY,
                check_name=f"Windows Firewall — {profile} Profile",
                status=Status.INFO,
                severity=Severity.HIGH,
                description=f"Checks whether the Windows Firewall {profile} profile is enabled.",
                details="Not yet implemented.",
                remediation="",
            )
        )
    return results
