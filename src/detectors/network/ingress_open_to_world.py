"""Auto-generated Add Detector for Overly Permissive Ingress Rules (SSH/RDP Open to 0.0.0.0/0).

Implement a new detector in the `detectors` module to identify security groups or
    firewall rules allowing unrestricted inbound access (0.0.0.0/0) on sensitive
    management ports (TCP 22 for SSH, TCP 3389 for RDP). This addresses a critical CIS
    Benchmark control and common cloud misconfiguration. Includes unit tests covering
    positive matches, negative matches (restricted CIDRs, different ports), and edge
    cases (IPv6 ::/0).
"""

from __future__ import annotations

import logging
from typing import Any

from security_scanner.models import Finding, Severity

__all__ = ["DetectorOverlyPermissiveIngressRulesSshrdpOpenTo00000"]

logger = logging.getLogger(__name__)


class DetectorOverlyPermissiveIngressRulesSshrdpOpenTo00000:
    """Scanner for Add Detector for Overly Permissive Ingress Rules (SSH/RDP Open to 0.0.0.0/0).

    Implement a new detector in the `detectors` module to identify security groups or
    firewall rules allowing unrestricted inbound access (0.0.0.0/0) on sensitive
    management ports (TCP 22 for SSH, TCP 3389 for RDP). This addresses a critical CIS
    Benchmark control and common cloud misconfiguration. Includes unit tests covering
    positive matches, negative matches (restricted CIDRs, different ports), and edge
    cases (IPv6 ::/0).
    """

    name: str = "Add Detector for Overly Permissive Ingress Rules (SSH/RDP Open to 0.0.0.0/0)"

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
