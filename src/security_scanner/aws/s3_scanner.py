"""S3 Bucket Security Scanner.

Analyses mock S3 bucket configuration for common security misconfigurations
aligned with CIS AWS Foundations Benchmark and AWS Security Best Practices.

Checks performed
----------------
1. Public access block not fully enabled (CRITICAL)
2. Server-side encryption not enabled (HIGH)
3. Versioning not enabled (MEDIUM)
4. Access logging not enabled (MEDIUM)
5. Bucket policy allows public access (CRITICAL)
"""

from __future__ import annotations

from typing import Any

from security_scanner.base_scanner import BaseScanner
from security_scanner.models import Finding, ScanConfig, Severity

__all__ = ["S3Scanner"]

_PUBLIC_ACCESS_BLOCK_KEYS = [
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
]


class S3Scanner(BaseScanner):
    """Scanner for AWS S3 bucket configuration issues.

    Expected config structure under ``config['s3']``::

        {
            "buckets": [
                {
                    "name": str,
                    "public_access_block": {
                        "block_public_acls": bool,
                        "ignore_public_acls": bool,
                        "block_public_policy": bool,
                        "restrict_public_buckets": bool,
                    },
                    "encryption": {
                        "enabled": bool,
                        "algorithm": "AES256" | "aws:kms",
                    },
                    "versioning": bool,
                    "logging": bool,
                    "policy": {
                        "effect": "Allow" | "Deny",
                        "principal": str,
                        "actions": list[str],
                    } | None,
                }
            ]
        }
    """

    @property
    def name(self) -> str:
        return "S3 Scanner"

    # ------------------------------------------------------------------
    # Internal check dispatcher
    # ------------------------------------------------------------------

    def _run_checks(self, config: ScanConfig) -> list[Finding]:
        """Execute all S3 checks against *config*."""
        s3: dict[str, Any] = config.get_service_config("s3")
        if not s3:
            return [
                self._create_finding(
                    title="S3 configuration data missing",
                    severity=Severity.INFO,
                    resource_type="S3",
                    resource_id="N/A",
                    description="No S3 configuration was provided for scanning.",
                    recommendation="Supply S3 data in the config under the 's3' key.",
                )
            ]

        findings: list[Finding] = []
        for bucket in s3.get("buckets", []):
            bucket_name: str = bucket.get("name", "unknown-bucket")
            findings.extend(self._check_public_access_block(bucket_name, bucket))
            findings.extend(self._check_encryption(bucket_name, bucket))
            findings.extend(self._check_versioning(bucket_name, bucket))
            findings.extend(self._check_logging(bucket_name, bucket))
            findings.extend(self._check_bucket_policy(bucket_name, bucket))
        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_public_access_block(
        self, bucket_name: str, bucket: dict[str, Any]
    ) -> list[Finding]:
        """Verify that all four S3 public access block settings are enabled."""
        findings: list[Finding] = []
        pab: dict[str, bool] = bucket.get("public_access_block", {})

        disabled_settings: list[str] = [
            key for key in _PUBLIC_ACCESS_BLOCK_KEYS if not pab.get(key, False)
        ]

        if disabled_settings:
            readable = ", ".join(s.replace("_", " ").title() for s in disabled_settings)
            findings.append(
                self._create_finding(
                    title=f"S3 bucket '{bucket_name}' has public access block settings disabled",
                    severity=Severity.CRITICAL,
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    description=(
                        f"Bucket '{bucket_name}' does not have all public access block "
                        f"settings enabled. Disabled: {readable}. This may allow "
                        "objects to be made publicly accessible."
                    ),
                    recommendation=(
                        f"Enable all four public access block settings on bucket "
                        f"'{bucket_name}': BlockPublicAcls, IgnorePublicAcls, "
                        "BlockPublicPolicy, RestrictPublicBuckets."
                    ),
                    details={
                        "disabled_settings": disabled_settings,
                        "current_config": pab,
                        "cis_benchmark": "2.1.5",
                    },
                )
            )

        return findings

    def _check_encryption(
        self, bucket_name: str, bucket: dict[str, Any]
    ) -> list[Finding]:
        """Check that server-side encryption is enabled."""
        findings: list[Finding] = []
        encryption: dict[str, Any] = bucket.get("encryption", {})

        if not encryption.get("enabled", False):
            findings.append(
                self._create_finding(
                    title=f"S3 bucket '{bucket_name}' does not have encryption enabled",
                    severity=Severity.HIGH,
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    description=(
                        f"Server-side encryption is not enabled on bucket "
                        f"'{bucket_name}'. Data at rest is not protected."
                    ),
                    recommendation=(
                        f"Enable default server-side encryption on bucket "
                        f"'{bucket_name}' using SSE-S3 (AES256) or SSE-KMS."
                    ),
                    details={
                        "current_config": encryption,
                        "cis_benchmark": "2.1.1",
                    },
                )
            )

        return findings

    def _check_versioning(
        self, bucket_name: str, bucket: dict[str, Any]
    ) -> list[Finding]:
        """Check that versioning is enabled for data protection."""
        findings: list[Finding] = []

        if not bucket.get("versioning", False):
            findings.append(
                self._create_finding(
                    title=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                    severity=Severity.MEDIUM,
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    description=(
                        f"Versioning is not enabled on bucket '{bucket_name}'. "
                        "Without versioning, accidental or malicious deletions "
                        "cannot be recovered."
                    ),
                    recommendation=(
                        f"Enable versioning on bucket '{bucket_name}' to protect "
                        "against data loss and support MFA Delete."
                    ),
                    details={"cis_benchmark": "2.1.3"},
                )
            )

        return findings

    def _check_logging(
        self, bucket_name: str, bucket: dict[str, Any]
    ) -> list[Finding]:
        """Check that server access logging is enabled."""
        findings: list[Finding] = []

        if not bucket.get("logging", False):
            findings.append(
                self._create_finding(
                    title=f"S3 bucket '{bucket_name}' does not have access logging enabled",
                    severity=Severity.MEDIUM,
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    description=(
                        f"Server access logging is not enabled on bucket "
                        f"'{bucket_name}'. Without logging, access patterns and "
                        "potential data exfiltration cannot be audited."
                    ),
                    recommendation=(
                        f"Enable server access logging on bucket '{bucket_name}' "
                        "and deliver logs to a separate, secured logging bucket."
                    ),
                    details={"cis_benchmark": "2.1.2"},
                )
            )

        return findings

    def _check_bucket_policy(
        self, bucket_name: str, bucket: dict[str, Any]
    ) -> list[Finding]:
        """Check whether the bucket policy allows public access."""
        findings: list[Finding] = []
        policy: dict[str, Any] | None = bucket.get("policy")

        if policy is None:
            return findings

        effect: str = policy.get("effect", "").lower()
        principal: str = str(policy.get("principal", ""))

        if effect == "allow" and principal in ("*", "AWS: *"):
            findings.append(
                self._create_finding(
                    title=f"S3 bucket '{bucket_name}' policy allows public access",
                    severity=Severity.CRITICAL,
                    resource_type="S3 Bucket Policy",
                    resource_id=bucket_name,
                    description=(
                        f"The bucket policy on '{bucket_name}' contains a statement "
                        "that allows access to any principal ('*'). This effectively "
                        "makes the bucket publicly accessible."
                    ),
                    recommendation=(
                        f"Review and restrict the bucket policy on '{bucket_name}'. "
                        "Remove statements that grant access to '*' and specify "
                        "explicit principal ARNs instead."
                    ),
                    details={
                        "policy": policy,
                        "cis_benchmark": "2.1.5",
                    },
                )
            )

        return findings
