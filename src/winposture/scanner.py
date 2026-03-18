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
        is_admin:   Whether the current process has administrator privileges.
                    Modules with ``REQUIRES_ADMIN = True`` are skipped when
                    this is ``False``, producing an INFO result instead.
    """

    def __init__(
        self,
        categories: list[str] | None = None,
        is_admin: bool = False,
    ) -> None:
        self.categories = categories
        self.is_admin = is_admin

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_modules(self) -> list:
        """Return the list of check modules that would be run (respects category filter)."""
        return self._discover_modules()

    def run(
        self,
        modules: list | None = None,
        on_module_start=None,
    ) -> AuditReport:
        """Discover check modules, run them, and return an AuditReport.

        Args:
            modules:         Pre-discovered module list; if None, auto-discovered.
            on_module_start: Optional callable(module) called before each module runs.

        Returns:
            A fully-populated AuditReport including score.
        """
        if modules is None:
            modules = self._discover_modules()
        log.info("Discovered %d check module(s): %s", len(modules), [m.__name__ for m in modules])

        start = time.monotonic()
        results: list[CheckResult] = []

        for module in modules:
            if on_module_start is not None:
                try:
                    on_module_start(module)
                except Exception:
                    pass
            module_results = self._run_module(module)
            results.extend(module_results)

        duration = time.monotonic() - start
        score = calculate_score(results)

        error_count = sum(1 for r in results if r.status == Status.ERROR)
        if error_count:
            log.warning(
                "%d check(s) could not complete — rerun as Administrator for full results.",
                error_count,
            )

        report = AuditReport(
            hostname=socket.gethostname(),
            os_version=platform.version(),
            scan_timestamp=datetime.now(tz=timezone.utc),
            scan_duration=round(duration, 2),
            results=results,
            score=score,
            is_admin=self.is_admin,
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

        Handles three cases:
        - Module requires admin but we are not elevated → returns INFO result.
        - Module runs successfully → returns its results with timing set.
        - Module raises an unhandled exception → returns a synthetic ERROR result.
        """
        cat = getattr(module, "CATEGORY", module.__name__)

        # Skip modules that require elevation when running without admin
        if getattr(module, "REQUIRES_ADMIN", False) and not self.is_admin:
            log.info(
                "Skipping %s — requires administrator privileges", module.__name__
            )
            return [CheckResult(
                category=cat,
                check_name=f"{cat} — requires administrator",
                status=Status.INFO,
                severity=Severity.INFO,
                description="This check module requires administrator privileges.",
                details=(
                    "Run WinPosture as Administrator to include these checks."
                ),
                remediation="",
            )]

        log.debug("Running %s", module.__name__)
        t_start = time.monotonic()
        try:
            results = module.run()
            if not isinstance(results, list):
                raise TypeError(
                    f"run() must return list[CheckResult], got {type(results)}"
                )
        except Exception as exc:
            log.error("Error in %s.run(): %s", module.__name__, exc, exc_info=True)
            results = [CheckResult(
                category=cat,
                check_name=f"{cat} — module error",
                status=Status.ERROR,
                severity=Severity.INFO,
                description="The check module raised an unhandled exception.",
                details=str(exc),
                remediation="Run with --log-level DEBUG for more detail.",
            )]

        duration = time.monotonic() - t_start
        for r in results:
            r.check_duration = duration
        log.debug("%s finished in %.2fs", module.__name__, duration)
        return results
