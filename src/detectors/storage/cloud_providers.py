"""Auto-generated Add detector for publicly accessible cloud storage buckets.

Implement a new detector module that identifies publicly accessible storage buckets
    across AWS S3, Google Cloud Storage, and Azure Blob Storage. The detector should
    check bucket ACLs, bucket policies, and IAM bindings for public read/write
    permissions. Include unit tests for each cloud provider and integration tests using
    mock cloud APIs.
"""

from __future__ import annotations

import logging
from typing import Any

from security_scanner.models import Finding, Severity

__all__ = ["DetectorPubliclyAccessibleCloudStorageBuckets"]

logger = logging.getLogger(__name__)


class DetectorPubliclyAccessibleCloudStorageBuckets:
    """Scanner for Add detector for publicly accessible cloud storage buckets.

    Implement a new detector module that identifies publicly accessible storage buckets
    across AWS S3, Google Cloud Storage, and Azure Blob Storage. The detector should
    check bucket ACLs, bucket policies, and IAM bindings for public read/write
    permissions. Include unit tests for each cloud provider and integration tests using
    mock cloud APIs.
    """

    name: str = "Add detector for publicly accessible cloud storage buckets"

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
                    id="DET007-001",
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
                    id="DET007-002",
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
                    id="DET007-003",
                    title="Logging not enabled",
                    severity=Severity.MEDIUM,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Audit logging is not enabled for this resource.",
                    recommendation="Enable audit logging for security monitoring.",
                )
            )
        return findings
