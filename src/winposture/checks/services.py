"""Check: Running services, with detection of known-risky services."""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

CATEGORY = "Services"

# Services that should generally be disabled on hardened systems
RISKY_SERVICES: dict[str, tuple[Severity, str]] = {
    "RemoteRegistry": (Severity.HIGH, "Remote Registry allows remote modification of the registry."),
    "Telnet": (Severity.CRITICAL, "Telnet transmits credentials in plaintext."),
    "TlntSvr": (Severity.CRITICAL, "Telnet Server — should never be running."),
    "SNMP": (Severity.MEDIUM, "SNMP (v1/v2) uses community strings instead of strong auth."),
    "W3SVC": (Severity.LOW, "IIS web server running — verify this is intentional."),
}


def run() -> list[CheckResult]:
    """Return service security checks.

    Returns:
        list[CheckResult]: One result per risky service detected (or a clean INFO result).
    """
    # TODO: implement via Get-Service PowerShell cmdlet
    return [
        CheckResult(
            category=CATEGORY,
            check_name="Risky Services",
            status=Status.INFO,
            severity=Severity.MEDIUM,
            description="Checks for known-risky services that are running or set to auto-start.",
            details="Not yet implemented.",
            remediation="",
        )
    ]
