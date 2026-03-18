"""Tests for winposture.cli — argument parsing and main() dispatch."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from winposture.cli import build_parser


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

class TestBuildParser:
    def _parse(self, *args: str):
        return build_parser().parse_args(list(args))

    def test_defaults(self):
        ns = self._parse()
        assert ns.html is None
        assert ns.json is None
        assert ns.category is None
        assert ns.verbose is False
        assert ns.no_color is False
        assert ns.log_level == "WARNING"

    def test_html_flag(self):
        ns = self._parse("--html", "report.html")
        assert ns.html == "report.html"

    def test_json_flag(self):
        ns = self._parse("--json", "out.json")
        assert ns.json == "out.json"

    def test_category_flag(self):
        ns = self._parse("--category", "firewall,encryption")
        assert ns.category == "firewall,encryption"

    def test_verbose_flag(self):
        ns = self._parse("--verbose")
        assert ns.verbose is True

    def test_no_color_flag(self):
        ns = self._parse("--no-color")
        assert ns.no_color is True

    def test_log_level_debug(self):
        ns = self._parse("--log-level", "DEBUG")
        assert ns.log_level == "DEBUG"

    def test_log_level_invalid(self):
        with pytest.raises(SystemExit):
            self._parse("--log-level", "VERBOSE")

    def test_all_flags_together(self):
        ns = self._parse(
            "--html", "r.html",
            "--json", "r.json",
            "--category", "firewall",
            "--verbose",
            "--no-color",
            "--log-level", "DEBUG",
        )
        assert ns.html == "r.html"
        assert ns.json == "r.json"
        assert ns.category == "firewall"
        assert ns.verbose is True
        assert ns.no_color is True
        assert ns.log_level == "DEBUG"

    def test_version_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            self._parse("--version")
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------

class TestMain:
    # Scanner/Reporter/is_admin are lazy-imported inside main(), so we patch
    # them in their source modules (not in winposture.cli).
    _SCANNER_PATH  = "winposture.scanner.Scanner"
    _REPORTER_PATH = "winposture.reporter.Reporter"
    _ADMIN_PATH    = "winposture.utils.is_admin"

    def _run_main(self, argv=None, is_admin=False):
        """Run main() with mocked scanner, reporter, and is_admin."""
        mock_report = MagicMock()
        mock_report.fail_count = 0
        mock_report.error_count = 0

        mock_scanner_instance = MagicMock()
        mock_scanner_instance.is_admin = is_admin

        mock_reporter_instance = MagicMock()
        mock_reporter_instance.run_with_progress.return_value = mock_report

        argv = argv or []
        with (
            patch("sys.argv", ["winposture"] + argv),
            patch(self._SCANNER_PATH, return_value=mock_scanner_instance) as MockScanner,
            patch(self._REPORTER_PATH, return_value=mock_reporter_instance) as MockReporter,
            patch(self._ADMIN_PATH, return_value=is_admin),
        ):
            from winposture import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()

        return MockScanner, mock_reporter_instance, mock_report

    def test_scanner_created_with_is_admin_false(self):
        MockScanner, _, _ = self._run_main(is_admin=False)
        assert MockScanner.called

    def test_scanner_created_with_is_admin_true(self):
        MockScanner, _, _ = self._run_main(is_admin=True)
        call_kwargs = MockScanner.call_args[1]
        assert call_kwargs.get("is_admin") is True

    def test_html_report_saved_when_flag_provided(self):
        _, mock_reporter, _ = self._run_main(["--html", "out.html"])
        mock_reporter.generate_html_report.assert_called_once()

    def test_json_report_saved_when_flag_provided(self):
        _, mock_reporter, _ = self._run_main(["--json", "out.json"])
        mock_reporter.generate_json_report.assert_called_once()

    def test_no_html_by_default(self):
        _, mock_reporter, _ = self._run_main()
        mock_reporter.generate_html_report.assert_not_called()

    def test_no_json_by_default(self):
        _, mock_reporter, _ = self._run_main()
        mock_reporter.generate_json_report.assert_not_called()

    def test_print_terminal_always_called(self):
        _, mock_reporter, _ = self._run_main()
        mock_reporter.print_terminal.assert_called_once()

    def test_exit_1_on_failures(self):
        mock_report = MagicMock()
        mock_report.fail_count = 3
        mock_report.error_count = 0
        mock_scanner = MagicMock()
        mock_scanner.is_admin = False
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["winposture"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
            pytest.raises(SystemExit) as exc_info,
        ):
            from winposture import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()

        assert exc_info.value.code == 1

    def test_exit_0_on_clean_scan(self):
        mock_report = MagicMock()
        mock_report.fail_count = 0
        mock_report.error_count = 0
        mock_scanner = MagicMock()
        mock_scanner.is_admin = False
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["winposture"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter),
            patch(self._ADMIN_PATH, return_value=False),
        ):
            from winposture import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()  # Should NOT raise SystemExit

    def test_category_filter_passed_to_scanner(self):
        MockScanner, _, _ = self._run_main(["--category", "firewall,encryption"])
        call_kwargs = MockScanner.call_args[1]
        assert call_kwargs.get("categories") == ["firewall", "encryption"]

    def test_verbose_passed_to_reporter(self):
        mock_report = MagicMock(fail_count=0, error_count=0)
        mock_scanner = MagicMock(is_admin=False)
        mock_reporter = MagicMock()
        mock_reporter.run_with_progress.return_value = mock_report

        with (
            patch("sys.argv", ["winposture", "--verbose"]),
            patch(self._SCANNER_PATH, return_value=mock_scanner),
            patch(self._REPORTER_PATH, return_value=mock_reporter) as MockReporter,
            patch(self._ADMIN_PATH, return_value=False),
        ):
            from winposture import cli as cli_mod
            import importlib
            importlib.reload(cli_mod)
            cli_mod.main()

        MockReporter.assert_called_once_with(verbose=True, no_color=False)
