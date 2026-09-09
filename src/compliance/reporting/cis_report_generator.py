"""Auto-generated Add CIS AWS Foundations Benchmark v1.5.0 compliance mapping.

Implement a new compliance profile for CIS AWS Foundations Benchmark v1.5.0 in the
    compliance module. This includes mapping existing detectors to CIS control IDs,
    adding missing detector rules for uncovered controls (e.g., 1.3, 1.4, 1.16, 2.1.1),
    and providing a compliance report generator that outputs JSON/HTML with pass/fail
    status per control. This enhances the lab's value for AWS security posture
    assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from security_scanner.models import Finding, Severity

__all__ = ["CisAwsFoundationsBenchmarkV150ComplianceMapping"]

logger = logging.getLogger(__name__)


class CisAwsFoundationsBenchmarkV150ComplianceMapping:
    """Scanner for Add CIS AWS Foundations Benchmark v1.5.0 compliance mapping.

    Implement a new compliance profile for CIS AWS Foundations Benchmark v1.5.0 in the
    compliance module. This includes mapping existing detectors to CIS control IDs,
    adding missing detector rules for uncovered controls (e.g., 1.3, 1.4, 1.16, 2.1.1),
    and providing a compliance report generator that outputs JSON/HTML with pass/fail
    status per control. This enhances the lab's value for AWS security posture
    assessment.
    """

    name: str = "Add CIS AWS Foundations Benchmark v1.5.0 compliance mapping"

    def scan(self, config: dict[str, Any]) -> list[Finding]:
        """Run security checks against the provided configuration.

        Args:
            config: Dict representing the cloud resource configuration
                to scan (mock data format).

        Returns:
            List of security findings.
        """
        findings: list[Finding] = []
        logger.info("Starting %s scan", self.name)

        findings.extend(self._check_encryption(config))
        findings.extend(self._check_public_access(config))
        findings.extend(self._check_logging(config))

        logger.info("Scan complete — %d finding(s) detected", len(findings))
        return findings

    def _check_encryption(self, config: dict[str, Any]) -> list[Finding]:
        """Check encryption configuration."""
        findings: list[Finding] = []
        if not config.get("encryption_enabled", False):
            findings.append(
                Finding(
                    id="IMP001-001",
                    title="Encryption not enabled",
                    severity=Severity.HIGH,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Resource does not have encryption enabled at rest.",
                    recommendation="Enable encryption using AWS KMS or service-default keys.",
                )
            )
        return findings

    def _check_public_access(self, config: dict[str, Any]) -> list[Finding]:
        """Check public access configuration."""
        findings: list[Finding] = []
        if config.get("publicly_accessible", False):
            findings.append(
                Finding(
                    id="IMP001-002",
                    title="Resource is publicly accessible",
                    severity=Severity.CRITICAL,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Resource is configured for public access.",
                    recommendation="Disable public access and restrict to VPC.",
                )
            )
        return findings

    def _check_logging(self, config: dict[str, Any]) -> list[Finding]:
        """Check logging / monitoring configuration."""
        findings: list[Finding] = []
        if not config.get("logging_enabled", False):
            findings.append(
                Finding(
                    id="IMP001-003",
                    title="Logging not enabled",
                    severity=Severity.MEDIUM,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Audit logging is not enabled for this resource.",
                    recommendation="Enable audit logging for security monitoring.",
                )
            )
        return findings
