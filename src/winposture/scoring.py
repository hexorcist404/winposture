"""Risk scoring logic for WinPosture.

Calculates a 0–100 security score from a list of CheckResult objects.
Scoring model:
  - Start at 100
  - Deduct per failed/warned check, weighted by severity
  - Clamp final score to [0, 100]
"""

from __future__ import annotations

import logging

from winposture.models import CheckResult, Severity, Status

log = logging.getLogger(__name__)

# Deduction points per (status, severity) combination
_DEDUCTIONS: dict[tuple[Status, Severity], int] = {
    (Status.FAIL, Severity.CRITICAL): 20,
    (Status.FAIL, Severity.HIGH): 10,
    (Status.FAIL, Severity.MEDIUM): 5,
    (Status.FAIL, Severity.LOW): 2,
    (Status.FAIL, Severity.INFO): 0,
    (Status.WARN, Severity.CRITICAL): 10,
    (Status.WARN, Severity.HIGH): 5,
    (Status.WARN, Severity.MEDIUM): 3,
    (Status.WARN, Severity.LOW): 2,
    (Status.WARN, Severity.INFO): 1,
}


def calculate_score(results: list[CheckResult]) -> int:
    """Calculate an overall security score from a list of check results.

    Args:
        results: All CheckResult objects from the scan.

    Returns:
        An integer score in the range [0, 100].
    """
    score = 100
    for result in results:
        deduction = _DEDUCTIONS.get((result.status, result.severity), 0)
        if deduction:
            log.debug(
                "  -%d for %s (%s / %s)",
                deduction,
                result.check_name,
                result.status,
                result.severity,
            )
        score -= deduction

    final = max(0, min(100, score))
    log.info("Final security score: %d", final)
    return final


def score_label(score: int) -> str:
    """Return a human-readable grade label for a numeric score.

    Args:
        score: Integer score 0–100.

    Returns:
        One of: "Critical", "Poor", "Fair", "Good", "Excellent".
    """
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Fair"
    if score >= 25:
        return "Poor"
    return "Critical"
