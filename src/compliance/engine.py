"""Compliance assessment engine.

Orchestrates the execution of compliance checks across registered
frameworks and produces structured compliance reports.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from compliance.cis_aws import ALL_CIS_AWS_CHECKS
from compliance.models import (
    CheckResult,
    CheckStatus,
    ComplianceCheck,
    ComplianceReport,
    Framework,
)

__all__ = ["ComplianceEngine"]

logger = logging.getLogger(__name__)


class ComplianceEngine:
    """Central engine that registers checks and runs compliance assessments.

    On initialisation the engine auto-registers all built-in CIS AWS
    Foundations Benchmark checks.  Additional frameworks and custom checks
    can be registered at runtime.

    Example::

        engine = ComplianceEngine()
        report = engine.run_assessment(config, Framework.CIS_AWS)
        print(f"Score: {report.score:.1f}%")
    """

    def __init__(self) -> None:
        self._registry: dict[Framework, list[ComplianceCheck]] = {}
        self._auto_register()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_framework(
        self,
        framework: Framework,
        checks: list[ComplianceCheck],
    ) -> None:
        """Register (or extend) the check list for a given framework.

        Args:
            framework: The compliance framework to register checks under.
            checks: List of ComplianceCheck instances to add.

        Raises:
            ValueError: If *checks* is empty.
        """
        if not checks:
            raise ValueError("Cannot register an empty check list.")
        existing = self._registry.setdefault(framework, [])
        existing.extend(checks)
        logger.info(
            "Registered %d check(s) for %s (total: %d)",
            len(checks),
            framework.value,
            len(existing),
        )

    @property
    def registered_frameworks(self) -> list[Framework]:
        """Return frameworks that have at least one registered check."""
        return list(self._registry.keys())

    def get_checks(self, framework: Framework) -> list[ComplianceCheck]:
        """Return a copy of the registered checks for a framework."""
        return list(self._registry.get(framework, []))

    def run_assessment(
        self,
        config: dict[str, Any],
        framework: Framework,
    ) -> ComplianceReport:
        """Execute all registered checks for *framework* against *config*.

        Args:
            config: Environment configuration dictionary consumed by checks.
            framework: The framework whose checks should be executed.

        Returns:
            A ComplianceReport with individual results and aggregate score.

        Raises:
            ValueError: If no checks are registered for the given framework.
        """
        checks = self._registry.get(framework)
        if not checks:
            raise ValueError(f"No checks registered for framework: {framework.value}")

        report = ComplianceReport(
            framework=framework,
            timestamp=datetime.now(UTC),
        )

        for check in checks:
            result = self._execute_check(check, config)
            report.results.append(result)

        report.calculate_stats()
        return report

    def run_all(self, config: dict[str, Any]) -> list[ComplianceReport]:
        """Run assessments for every registered framework.

        Args:
            config: Environment configuration dictionary consumed by checks.

        Returns:
            List of ComplianceReport instances, one per registered framework.
        """
        reports: list[ComplianceReport] = []
        for framework in self._registry:
            report = self.run_assessment(config, framework)
            reports.append(report)
        return reports

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auto_register(self) -> None:
        """Register built-in check suites on engine creation."""
        if ALL_CIS_AWS_CHECKS:
            self.register_framework(Framework.CIS_AWS, list(ALL_CIS_AWS_CHECKS))

    @staticmethod
    def _execute_check(
        check: ComplianceCheck,
        config: dict[str, Any],
    ) -> CheckResult:
        """Safely execute a single check, catching unexpected errors.

        Args:
            check: The ComplianceCheck to execute.
            config: Environment configuration dictionary.

        Returns:
            CheckResult — on unexpected exceptions returns an ERROR status.
        """
        try:
            return check.check_function(config)
        except Exception as exc:
            logger.exception("Check %s raised an exception", check.id)
            return CheckResult(
                check=check,
                status=CheckStatus.ERROR,
                details=f"Check raised an unexpected error: {exc}",
                evidence={"exception": str(exc)},
                recommendation="Investigate the check implementation or input config.",
            )
