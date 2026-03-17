"""Tests for winposture.checks.firewall.

All subprocess/WMI calls will be mocked once the module is implemented.
For now these tests verify the stub contract.
"""

from __future__ import annotations

from winposture.checks import firewall
from winposture.models import CheckResult, Status


class TestFirewallRun:
    def test_returns_list(self):
        results = firewall.run()
        assert isinstance(results, list)

    def test_returns_check_results(self):
        results = firewall.run()
        assert all(isinstance(r, CheckResult) for r in results)

    def test_returns_three_profiles(self):
        """Expects one result per Windows Firewall profile (Domain, Private, Public)."""
        results = firewall.run()
        assert len(results) == 3

    def test_category_is_firewall(self):
        results = firewall.run()
        assert all(r.category == "Firewall" for r in results)

    def test_profile_names_in_check_names(self):
        results = firewall.run()
        names = [r.check_name for r in results]
        for profile in ("Domain", "Private", "Public"):
            assert any(profile in name for name in names)
