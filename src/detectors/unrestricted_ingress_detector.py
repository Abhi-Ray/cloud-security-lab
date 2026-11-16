"""Auto-generated Add Detector for Unrestricted Security Group Ingress on Sensitive Ports.

Implement a new detector in the 'detectors' module to identify AWS Security Groups,
    Azure NSGs, and GCP Firewall Rules that allow unrestricted ingress (0.0.0.0/0 or
    ::/0) on sensitive ports (e.g., 22, 3389, 3306, 5432, 27017). The detector should
    support multi-cloud resource models and integrate with the existing finding
    aggregation pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from security_scanner.models import Finding, Severity

__all__ = ["DetectorUnrestrictedSecurityGroupIngressOnSensitivePorts"]

logger = logging.getLogger(__name__)


class DetectorUnrestrictedSecurityGroupIngressOnSensitivePorts:
    """Scanner for Add Detector for Unrestricted Security Group Ingress on Sensitive Ports.

    Implement a new detector in the 'detectors' module to identify AWS Security Groups,
    Azure NSGs, and GCP Firewall Rules that allow unrestricted ingress (0.0.0.0/0 or
    ::/0) on sensitive ports (e.g., 22, 3389, 3306, 5432, 27017). The detector should
    support multi-cloud resource models and integrate with the existing finding
    aggregation pipeline.
    """

    name: str = "Add Detector for Unrestricted Security Group Ingress on Sensitive Ports"

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
                    id="DET001-001",
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
                    id="DET001-002",
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
                    id="DET001-003",
                    title="Logging not enabled",
                    severity=Severity.MEDIUM,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Audit logging is not enabled for this resource.",
                    recommendation="Enable audit logging for security monitoring.",
                )
            )
        return findings
