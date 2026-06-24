"""Data models for the Cloud Security Scanner.

Defines the core types used across all scanners:
- Severity levels for categorizing findings
- Finding records for individual security issues
- ScanResult containers aggregating findings from a scanner run
- ScanConfig wrappers for account configuration data
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

__all__ = [
    "Finding",
    "ScanConfig",
    "ScanResult",
    "Severity",
]


class Severity(Enum):
    """Severity levels for security findings, ordered from most to least severe.

    Attributes:
        CRITICAL: Immediate risk of exploitation or data breach.
        HIGH: Significant security weakness requiring prompt remediation.
        MEDIUM: Moderate risk that should be addressed in the near term.
        LOW: Minor issue with limited security impact.
        INFO: Informational observation, no direct security impact.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def numeric_weight(self) -> int:
        """Return a numeric weight for sorting (higher = more severe)."""
        weights = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_weight < other.numeric_weight

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_weight <= other.numeric_weight

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_weight > other.numeric_weight

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric_weight >= other.numeric_weight


@dataclass(frozen=True)
class Finding:
    """Represents a single security finding discovered during a scan.

    Attributes:
        id: Unique identifier for this finding.
        title: Short, human-readable title of the finding.
        severity: Severity level indicating the risk.
        resource_type: Type of the resource affected (e.g., 'IAM User', 'S3 Bucket').
        resource_id: Identifier of the specific resource (e.g., username, bucket name).
        description: Detailed explanation of the finding.
        recommendation: Actionable guidance for remediation.
        details: Arbitrary metadata providing additional context.
    """

    id: str
    title: str
    severity: Severity
    resource_type: str
    resource_id: str
    description: str
    recommendation: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "description": self.description,
            "recommendation": self.recommendation,
            "details": self.details,
        }


@dataclass
class ScanResult:
    """Aggregated results from a single scanner run.

    Attributes:
        scanner_name: Name of the scanner that produced these results.
        timestamp: UTC datetime when the scan was executed.
        findings: List of findings discovered during the scan.
        scan_duration_ms: Wall-clock duration of the scan in milliseconds.
    """

    scanner_name: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    findings: list[Finding] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    # --- Summary statistics ---------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL-severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of HIGH-severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of MEDIUM-severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count of LOW-severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Count of INFO-severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def summary(self) -> dict[str, int]:
        """Return a severity → count mapping."""
        return {
            "CRITICAL": self.critical_count,
            "HIGH": self.high_count,
            "MEDIUM": self.medium_count,
            "LOW": self.low_count,
            "INFO": self.info_count,
            "TOTAL": self.total_findings,
        }

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Filter findings to those matching a specific severity level."""
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the scan result to a JSON-compatible dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "timestamp": self.timestamp.isoformat(),
            "scan_duration_ms": self.scan_duration_ms,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanConfig:
    """Wrapper around the configuration data to be scanned.

    The config dict mirrors the structure of an AWS account's resource
    configuration, organised by service (iam, s3, cloudtrail, …).

    Attributes:
        config: Nested dictionary of service configurations.
        account_id: Optional AWS account identifier for labelling.
        account_alias: Optional human-friendly account name.
    """

    config: dict[str, Any]
    account_id: str = "000000000000"
    account_alias: str = "cloud-security-lab"

    def get_service_config(self, service: str) -> dict[str, Any]:
        """Return the sub-config for a given service, or empty dict.

        Args:
            service: Service key, e.g. ``'iam'``, ``'s3'``, ``'cloudtrail'``.

        Returns:
            The nested dict for that service, or ``{}`` if not present.
        """
        return self.config.get(service, {})


def generate_finding_id(scanner_prefix: str) -> str:
    """Generate a deterministic-looking finding ID.

    Args:
        scanner_prefix: Short prefix identifying the scanner (e.g. ``'IAM'``).

    Returns:
        A string of the form ``IAM-a1b2c3d4``.
    """
    short_uuid = uuid.uuid4().hex[:8]
    return f"{scanner_prefix}-{short_uuid}"
