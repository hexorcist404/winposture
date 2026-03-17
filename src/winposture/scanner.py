"""Audit scanner — discovers and runs all check modules.

Uses importlib to dynamically load every module inside the checks/ package.
Each module must expose a ``run() -> list[CheckResult]`` function.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import platform
import socket
import time
from datetime import datetime, timezone

from winposture import checks as checks_pkg
from winposture.models import AuditReport, CheckResult, Status, Severity
from winposture.scoring import calculate_score

log = logging.getLogger(__name__)


class Scanner:
    """Discovers check modules and orchestrates an audit run.

    Args:
        categories: If provided, only modules whose ``CATEGORY`` attribute
                    matches one of these strings (case-insensitive) are run.
                    Pass ``None`` (default) to run all modules.
    """

    def __init__(self, categories: list[str] | None = None) -> None:
        self.categories = categories

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> AuditReport:
        """Discover check modules, run them, and return an AuditReport.

        Returns:
            A fully-populated AuditReport including score.
        """
        modules = self._discover_modules()
        log.info("Discovered %d check module(s): %s", len(modules), [m.__name__ for m in modules])

        start = time.monotonic()
        results: list[CheckResult] = []

        for module in modules:
            module_results = self._run_module(module)
            results.extend(module_results)

        duration = time.monotonic() - start
        score = calculate_score(results)

        report = AuditReport(
            hostname=socket.gethostname(),
            os_version=platform.version(),
            scan_timestamp=datetime.now(tz=timezone.utc),
            scan_duration=round(duration, 2),
            results=results,
            score=score,
        )
        log.info(
            "Scan complete: %d results, score=%d, duration=%.2fs",
            len(results),
            score,
            duration,
        )
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_modules(self) -> list:
        """Return a list of check module objects matching the category filter."""
        discovered = []
        for module_info in pkgutil.iter_modules(checks_pkg.__path__):
            if module_info.name.startswith("_"):
                continue  # skip __init__ etc.

            full_name = f"winposture.checks.{module_info.name}"
            try:
                module = importlib.import_module(full_name)
            except Exception as exc:
                log.error("Failed to import %s: %s", full_name, exc)
                continue

            # Category filter
            if self.categories is not None:
                module_category = getattr(module, "CATEGORY", module_info.name).lower()
                if module_category not in self.categories:
                    log.debug("Skipping %s (category %r not in filter)", full_name, module_category)
                    continue

            # Must expose a run() callable
            if not callable(getattr(module, "run", None)):
                log.warning("%s has no run() function — skipping", full_name)
                continue

            discovered.append(module)

        return discovered

    def _run_module(self, module) -> list[CheckResult]:
        """Run a single check module and return its results.

        Wraps execution in a try/except so one broken module cannot crash
        the entire scan.
        """
        log.debug("Running %s", module.__name__)
        try:
            results = module.run()
            if not isinstance(results, list):
                raise TypeError(f"run() must return list[CheckResult], got {type(results)}")
            return results
        except Exception as exc:
            log.error("Error in %s.run(): %s", module.__name__, exc, exc_info=True)
            # Return a synthetic ERROR result so the report reflects the failure
            return [
                CheckResult(
                    category=getattr(module, "CATEGORY", module.__name__),
                    check_name=f"{module.__name__} — module error",
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    description="The check module raised an unhandled exception.",
                    details=str(exc),
                    remediation="",
                )
            ]
