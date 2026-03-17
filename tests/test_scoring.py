"""Unit tests for winposture.scoring."""

from __future__ import annotations

import pytest

from winposture.models import CheckResult, Severity, Status
from winposture.scoring import calculate_score, score_label


def _result(status: Status, severity: Severity) -> CheckResult:
    return CheckResult(
        category="Test",
        check_name="test check",
        status=status,
        severity=severity,
        description="",
        details="",
    )


class TestCalculateScore:
    def test_empty_results_returns_100(self):
        assert calculate_score([]) == 100

    def test_all_pass_returns_100(self):
        results = [_result(Status.PASS, Severity.HIGH) for _ in range(5)]
        assert calculate_score(results) == 100

    def test_critical_fail_deducts_20(self):
        results = [_result(Status.FAIL, Severity.CRITICAL)]
        assert calculate_score(results) == 80

    def test_high_fail_deducts_10(self):
        results = [_result(Status.FAIL, Severity.HIGH)]
        assert calculate_score(results) == 90

    def test_medium_fail_deducts_5(self):
        results = [_result(Status.FAIL, Severity.MEDIUM)]
        assert calculate_score(results) == 95

    def test_low_fail_deducts_2(self):
        results = [_result(Status.FAIL, Severity.LOW)]
        assert calculate_score(results) == 98

    def test_warn_high_deducts_5(self):
        results = [_result(Status.WARN, Severity.HIGH)]
        assert calculate_score(results) == 95

    def test_score_clamps_to_zero(self):
        # 6 critical fails = −120, should clamp to 0
        results = [_result(Status.FAIL, Severity.CRITICAL) for _ in range(6)]
        assert calculate_score(results) == 0

    def test_score_never_exceeds_100(self):
        results = [_result(Status.PASS, Severity.INFO)]
        assert calculate_score(results) <= 100

    def test_info_status_no_deduction(self):
        results = [_result(Status.INFO, Severity.CRITICAL)]
        assert calculate_score(results) == 100

    def test_error_status_no_deduction(self):
        results = [_result(Status.ERROR, Severity.HIGH)]
        assert calculate_score(results) == 100

    def test_mixed_results(self, fail_result, warn_result, pass_result):
        # fail CRITICAL (−20) + warn HIGH (−5) + pass (0) = 75
        results = [fail_result, warn_result, pass_result]
        assert calculate_score(results) == 75


class TestScoreLabel:
    @pytest.mark.parametrize("score,expected", [
        (100, "Excellent"),
        (90, "Excellent"),
        (89, "Good"),
        (75, "Good"),
        (74, "Fair"),
        (50, "Fair"),
        (49, "Poor"),
        (25, "Poor"),
        (24, "Critical"),
        (0, "Critical"),
    ])
    def test_labels(self, score: int, expected: str):
        assert score_label(score) == expected
