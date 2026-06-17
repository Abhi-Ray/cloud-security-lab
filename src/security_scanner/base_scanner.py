"""Abstract base class for all security scanners.

Every concrete scanner (IAM, S3, CloudTrail, …) inherits from
:class:`BaseScanner` and implements :meth:`scan` to evaluate a
:class:`ScanConfig` and return a :class:`ScanResult`.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from security_scanner.models import (
    Finding,
    ScanConfig,
    ScanResult,
    Severity,
    generate_finding_id,
)

__all__ = ["BaseScanner"]


class BaseScanner(ABC):
    """Base class that all security scanners must extend.

    Subclasses must implement:
        * :pyattr:`name` — a human-readable scanner name.
        * :meth:`scan` — the scanning logic.

    The helper :meth:`_create_finding` simplifies building :class:`Finding`
    instances with auto-generated IDs.
    """

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this scanner (e.g. ``'IAM Scanner'``)."""
        ...

    @abstractmethod
    def _run_checks(self, config: ScanConfig) -> list[Finding]:
        """Execute all checks and return findings.

        This is the primary extension point for subclasses.

        Args:
            config: The account/resource configuration to evaluate.

        Returns:
            A list of :class:`Finding` instances (may be empty).
        """
        ...

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, config: ScanConfig) -> ScanResult:
        """Run the scanner against *config* and return aggregated results.

        Handles timing, exception safety, and result construction so that
        subclasses only need to focus on the check logic.

        Args:
            config: The account configuration to scan.

        Returns:
            A :class:`ScanResult` containing all findings.
        """
        start = time.perf_counter()
        try:
            findings = self._run_checks(config)
        except Exception as exc:
            # Surface scanner crashes as a CRITICAL finding so they are
            # never silently swallowed.
            findings = [
                self._create_finding(
                    title=f"{self.name} encountered an internal error",
                    severity=Severity.CRITICAL,
                    resource_type="Scanner",
                    resource_id=self.name,
                    description=f"An unhandled exception occurred: {exc}",
                    recommendation="Review the scanner implementation and input config.",
                    details={"error_type": type(exc).__name__, "error": str(exc)},
                )
            ]
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ScanResult(
            scanner_name=self.name,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            scan_duration_ms=round(elapsed_ms, 2),
        )

    # ------------------------------------------------------------------
    # Helpers for subclasses
    # ------------------------------------------------------------------

    def _create_finding(
        self,
        *,
        title: str,
        severity: Severity,
        resource_type: str,
        resource_id: str,
        description: str,
        recommendation: str,
        details: dict[str, Any] | None = None,
    ) -> Finding:
        """Build a :class:`Finding` with an auto-generated ID.

        All parameters are keyword-only to improve call-site readability.

        Args:
            title: Short title of the finding.
            severity: Risk severity.
            resource_type: AWS resource type affected.
            resource_id: Specific resource identifier.
            description: Detailed explanation.
            recommendation: Remediation guidance.
            details: Optional extra metadata dict.

        Returns:
            A new :class:`Finding` instance.
        """
        prefix = self.name.split()[0].upper()[:5]
        return Finding(
            id=generate_finding_id(prefix),
            title=title,
            severity=severity,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            recommendation=recommendation,
            details=details or {},
        )
