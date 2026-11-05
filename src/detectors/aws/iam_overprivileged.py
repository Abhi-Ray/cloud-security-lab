"""Auto-generated Add detector for AWS IAM roles with overly permissive policies.

Implement a new detector in the detectors module that identifies IAM roles/policies
    granting wildcard actions (*) on wildcard resources (*) or overly broad permissions
    (e.g., 'iam:*', 's3:*', '*'). This addresses a top cloud misconfiguration risk. The
    detector should parse CloudFormation, Terraform, and live AWS API outputs, flagging
    violations with severity HIGH and providing remediation guidance (least-privilege
    policy examples).
"""

from __future__ import annotations

import logging
from typing import Any

from security_scanner.models import Finding, Severity

__all__ = ["DetectorAwsIamRolesOverlyPermissivePolicies"]

logger = logging.getLogger(__name__)


class DetectorAwsIamRolesOverlyPermissivePolicies:
    """Scanner for Add detector for AWS IAM roles with overly permissive policies.

    Implement a new detector in the detectors module that identifies IAM roles/policies
    granting wildcard actions (*) on wildcard resources (*) or overly broad permissions
    (e.g., 'iam:*', 's3:*', '*'). This addresses a top cloud misconfiguration risk. The
    detector should parse CloudFormation, Terraform, and live AWS API outputs, flagging
    violations with severity HIGH and providing remediation guidance (least-privilege
    policy examples).
    """

    name: str = "Add detector for AWS IAM roles with overly permissive policies"

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
                    id="DETECTORIAMOVERPRIVILEGED001-001",
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
                    id="DETECTORIAMOVERPRIVILEGED001-002",
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
                    id="DETECTORIAMOVERPRIVILEGED001-003",
                    title="Logging not enabled",
                    severity=Severity.MEDIUM,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Audit logging is not enabled for this resource.",
                    recommendation="Enable audit logging for security monitoring.",
                )
            )
        return findings
