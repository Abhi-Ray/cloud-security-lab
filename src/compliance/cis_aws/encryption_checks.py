"""CIS AWS Foundations Benchmark — Section 3: Encryption.

Implements automated checks for encryption-at-rest configuration
including EBS default encryption, S3 bucket encryption, and RDS
instance encryption.
"""

from __future__ import annotations

from typing import Any

from compliance.models import (
    CheckResult,
    CheckStatus,
    ComplianceCheck,
    Framework,
    Severity,
)

__all__ = [
    "CIS_ENCRYPTION_CHECKS",
    "check_3_1_ebs_encryption_default",
    "check_3_2_s3_bucket_encryption",
    "check_3_3_rds_encryption",
]


# ---------------------------------------------------------------------------
# Check 3.1 – EBS encryption by default
# ---------------------------------------------------------------------------


def check_3_1_ebs_encryption_default(config: dict[str, Any]) -> CheckResult:
    """Ensure EBS encryption by default is enabled.

    When enabled, all new EBS volumes and snapshots are encrypted
    automatically, removing the risk of unencrypted data at rest.

    Args:
        config: Environment configuration dict with an ``encryption`` section.

    Returns:
        CheckResult indicating PASS if EBS default encryption is on.
    """
    check = _CHECKS["3.1"]
    encryption = config.get("encryption", {})
    ebs_default: bool = encryption.get("ebs_default_encryption", False)

    if ebs_default:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="EBS encryption by default is enabled.",
            evidence={"ebs_default_encryption": True},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details="EBS encryption by default is NOT enabled.",
        evidence={"ebs_default_encryption": False},
        recommendation=(
            "Enable EBS encryption by default in each region using "
            "`aws ec2 enable-ebs-encryption-by-default`."
        ),
    )


# ---------------------------------------------------------------------------
# Check 3.2 – S3 bucket encryption
# ---------------------------------------------------------------------------


def check_3_2_s3_bucket_encryption(config: dict[str, Any]) -> CheckResult:
    """Ensure all S3 buckets have encryption enabled.

    S3 bucket default encryption ensures that all objects stored in a
    bucket are encrypted at rest using SSE-S3 or SSE-KMS.

    Args:
        config: Environment configuration dict with an ``encryption`` section.

    Returns:
        CheckResult indicating PASS if every bucket is encrypted.
    """
    check = _CHECKS["3.2"]
    encryption = config.get("encryption", {})
    buckets: list[dict[str, Any]] = encryption.get("s3_buckets", [])

    if not buckets:
        return CheckResult(
            check=check,
            status=CheckStatus.NOT_APPLICABLE,
            details="No S3 buckets found in configuration.",
            evidence={"s3_buckets": []},
        )

    unencrypted: list[str] = [
        b.get("name", "<unknown>") for b in buckets if not b.get("encryption_enabled", False)
    ]

    if not unencrypted:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details=f"All {len(buckets)} S3 bucket(s) have encryption enabled.",
            evidence={"buckets_checked": len(buckets)},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(unencrypted)} S3 bucket(s) do not have encryption enabled: "
            f"{', '.join(unencrypted)}."
        ),
        evidence={"unencrypted_buckets": unencrypted},
        recommendation=(
            "Enable default encryption on all S3 buckets using SSE-S3 or SSE-KMS. "
            "Use `aws s3api put-bucket-encryption`."
        ),
    )


# ---------------------------------------------------------------------------
# Check 3.3 – RDS encryption
# ---------------------------------------------------------------------------


def check_3_3_rds_encryption(config: dict[str, Any]) -> CheckResult:
    """Ensure all RDS instances are encrypted at rest.

    RDS encryption at rest protects the underlying storage, automated
    backups, read replicas, and snapshots.

    Args:
        config: Environment configuration dict with an ``encryption`` section.

    Returns:
        CheckResult indicating PASS if all RDS instances are encrypted.
    """
    check = _CHECKS["3.3"]
    encryption = config.get("encryption", {})
    instances: list[dict[str, Any]] = encryption.get("rds_instances", [])

    if not instances:
        return CheckResult(
            check=check,
            status=CheckStatus.NOT_APPLICABLE,
            details="No RDS instances found in configuration.",
            evidence={"rds_instances": []},
        )

    unencrypted: list[str] = [
        inst.get("id", "<unknown>") for inst in instances if not inst.get("encrypted", False)
    ]

    if not unencrypted:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details=f"All {len(instances)} RDS instance(s) are encrypted at rest.",
            evidence={"instances_checked": len(instances)},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(unencrypted)} RDS instance(s) are NOT encrypted: {', '.join(unencrypted)}."
        ),
        evidence={"unencrypted_instances": unencrypted},
        recommendation=(
            "Enable encryption on RDS instances. Note: existing unencrypted "
            "instances must be migrated — create an encrypted snapshot, then "
            "restore from it."
        ),
    )


# ---------------------------------------------------------------------------
# ComplianceCheck definitions
# ---------------------------------------------------------------------------

_CHECKS: dict[str, ComplianceCheck] = {
    "3.1": ComplianceCheck(
        id="cis-aws-3.1",
        title="Ensure EBS encryption by default is enabled",
        description=(
            "Enabling EBS encryption by default ensures all new volumes "
            "are automatically encrypted at rest."
        ),
        framework=Framework.CIS_AWS,
        section="3.1",
        severity=Severity.HIGH,
        check_function=check_3_1_ebs_encryption_default,
    ),
    "3.2": ComplianceCheck(
        id="cis-aws-3.2",
        title="Ensure all S3 buckets have encryption enabled",
        description=(
            "S3 bucket default encryption provides an additional layer "
            "of data protection by encrypting objects at rest."
        ),
        framework=Framework.CIS_AWS,
        section="3.2",
        severity=Severity.HIGH,
        check_function=check_3_2_s3_bucket_encryption,
    ),
    "3.3": ComplianceCheck(
        id="cis-aws-3.3",
        title="Ensure RDS instances are encrypted at rest",
        description=(
            "RDS encryption protects database storage, backups, replicas, "
            "and snapshots from unauthorized physical access."
        ),
        framework=Framework.CIS_AWS,
        section="3.3",
        severity=Severity.HIGH,
        check_function=check_3_3_rds_encryption,
    ),
}

CIS_ENCRYPTION_CHECKS: list[ComplianceCheck] = list(_CHECKS.values())
