"""CLI entry point for WinPosture.

Parses arguments and dispatches to the scanner and reporter.
"""

from __future__ import annotations

import argparse
import logging
import sys

from winposture import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="winposture",
        description="WinPosture — Windows Security Posture Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  winposture                          Full audit, terminal output\n"
            "  winposture --html report.html       Also save HTML report\n"
            "  winposture --json report.json       Also save JSON report\n"
            "  winposture --category firewall,encryption  Specific categories only\n"
            "  winposture --verbose                Show details for every check\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save an HTML report to FILE",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save a JSON report to FILE",
    )
    parser.add_argument(
        "--category",
        metavar="CATEGORIES",
        help="Comma-separated list of categories to run (default: all)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output for every check",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable Rich color formatting",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Internal logging verbosity (default: WARNING)",
    )
    return parser


def main() -> None:
    """Parse arguments, run the audit, and produce output."""
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Import here so startup is fast for --version / --help
    from winposture.scanner import Scanner
    from winposture.reporter import Reporter

    categories: list[str] | None = None
    if args.category:
        categories = [c.strip().lower() for c in args.category.split(",")]

    scanner  = Scanner(categories=categories)
    reporter = Reporter(verbose=args.verbose, no_color=args.no_color)

    # Run scan with live progress display, then save outputs, then print results
    report = reporter.run_with_progress(scanner)

    if args.html:
        reporter.save_html(report, args.html)

    if args.json:
        reporter.save_json(report, args.json)

    reporter.print_terminal(report, html_path=args.html, json_path=args.json)

    # Exit with non-zero code if there are any FAIL results
    if report.fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
