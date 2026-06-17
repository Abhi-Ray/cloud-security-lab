"""Compliance Engine data models.

Defines the core types used across the compliance framework including
enumerations for frameworks, check statuses, severity levels, and
dataclasses for checks, results, and reports.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol


__all__ = [
    "Framework",
    "CheckStatus",
    "Severity",
    "ComplianceCheck",
    "CheckResult",
    "ComplianceReport",
    "CheckFunction",
]


class Framework(enum.Enum):
    """Supported compliance frameworks."""

    CIS_AWS = "CIS AWS Foundations Benchmark"
    ISO_27001 = "ISO/IEC 27001:2022"
    NIST_CSF = "NIST Cybersecurity Framework"
    SOC2 = "SOC 2 Type II"


class CheckStatus(enum.Enum):
    """Outcome status for an individual compliance check."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(enum.Enum):
    """Severity level for a compliance check or finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckFunction(Protocol):
    """Protocol describing the signature every check function must follow."""

    def __call__(self, config: dict[str, Any]) -> CheckResult: ...


@dataclass(frozen=True, slots=True)
class ComplianceCheck:
    """Definition of a single compliance check.

    Attributes:
        id: Unique identifier for the check (e.g. "cis-aws-1.1").
        title: Short human-readable title.
        description: Detailed description of what the check validates.
        framework: The compliance framework this check belongs to.
        section: Section reference within the framework (e.g. "1.1").
        severity: Severity level of the control.
        check_function: Callable that executes the check against a config dict.
    """

    id: str
    title: str
    description: str
    framework: Framework
    section: str
    severity: Severity
    check_function: Callable[[dict[str, Any]], CheckResult]


@dataclass(slots=True)
class CheckResult:
    """Result produced by executing a single compliance check.

    Attributes:
        check: The ComplianceCheck that was executed.
        status: Outcome status (PASS, FAIL, ERROR, NOT_APPLICABLE).
        details: Human-readable explanation of the result.
        evidence: Structured evidence data supporting the result.
        recommendation: Remediation guidance when the check fails.
    """

    check: ComplianceCheck
    status: CheckStatus
    details: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    @property
    def passed(self) -> bool:
        """Return True when the check passed or is not applicable."""
        return self.status in (CheckStatus.PASS, CheckStatus.NOT_APPLICABLE)


@dataclass(slots=True)
class ComplianceReport:
    """Aggregated compliance report for a single framework assessment.

    Attributes:
        framework: The compliance framework that was assessed.
        timestamp: When the assessment was executed (UTC).
        results: Ordered list of individual check results.
        pass_count: Number of checks that passed.
        fail_count: Number of checks that failed.
        error_count: Number of checks that encountered errors.
        not_applicable_count: Number of checks marked not applicable.
        score: Compliance score as a percentage (0.0–100.0).
    """

    framework: Framework
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    results: list[CheckResult] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    error_count: int = 0
    not_applicable_count: int = 0
    score: float = 0.0

    def calculate_stats(self) -> None:
        """Recompute counts and score from the current results list."""
        self.pass_count = sum(
            1 for r in self.results if r.status == CheckStatus.PASS
        )
        self.fail_count = sum(
            1 for r in self.results if r.status == CheckStatus.FAIL
        )
        self.error_count = sum(
            1 for r in self.results if r.status == CheckStatus.ERROR
        )
        self.not_applicable_count = sum(
            1 for r in self.results if r.status == CheckStatus.NOT_APPLICABLE
        )
        applicable = self.pass_count + self.fail_count
        self.score = (self.pass_count / applicable * 100.0) if applicable > 0 else 0.0
