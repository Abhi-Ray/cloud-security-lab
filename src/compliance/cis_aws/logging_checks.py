"""CIS AWS Foundations Benchmark — Section 2: Logging.

Implements automated checks for CloudTrail configuration including
trail enablement, log file validation, and encryption at rest.
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
    "CIS_LOGGING_CHECKS",
    "check_2_1_cloudtrail_enabled",
    "check_2_2_cloudtrail_log_validation",
    "check_2_3_cloudtrail_encrypted",
]


# ---------------------------------------------------------------------------
# Check 2.1 – CloudTrail enabled
# ---------------------------------------------------------------------------


def check_2_1_cloudtrail_enabled(config: dict[str, Any]) -> CheckResult:
    """Ensure CloudTrail is enabled in all regions.

    CloudTrail provides a record of actions taken by a user, role, or
    service in the AWS account. At least one multi-region trail must
    be configured and active.

    Args:
        config: Environment configuration dict with a ``logging`` section.

    Returns:
        CheckResult indicating PASS if at least one active trail exists.
    """
    check = _CHECKS["2.1"]
    logging_cfg = config.get("logging", {})
    trails: list[dict[str, Any]] = logging_cfg.get("cloudtrail", {}).get("trails", [])

    active_trails = [
        t for t in trails if t.get("is_logging", False) and t.get("is_multi_region", False)
    ]

    if active_trails:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details=f"{len(active_trails)} active multi-region trail(s) found.",
            evidence={"active_trails": [t.get("name") for t in active_trails]},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details="No active multi-region CloudTrail trail found.",
        evidence={"trails": trails},
        recommendation=(
            "Create a multi-region CloudTrail trail and enable logging. "
            "Use `aws cloudtrail create-trail --is-multi-region-trail`."
        ),
    )


# ---------------------------------------------------------------------------
# Check 2.2 – CloudTrail log validation
# ---------------------------------------------------------------------------


def check_2_2_cloudtrail_log_validation(config: dict[str, Any]) -> CheckResult:
    """Ensure CloudTrail log file validation is enabled.

    Log file validation creates a digest file that can be used to
    determine whether log files have been modified or deleted after
    delivery.

    Args:
        config: Environment configuration dict with a ``logging`` section.

    Returns:
        CheckResult indicating PASS if all trails have validation enabled.
    """
    check = _CHECKS["2.2"]
    logging_cfg = config.get("logging", {})
    trails: list[dict[str, Any]] = logging_cfg.get("cloudtrail", {}).get("trails", [])

    if not trails:
        return CheckResult(
            check=check,
            status=CheckStatus.FAIL,
            details="No CloudTrail trails configured.",
            evidence={"trails": []},
            recommendation="Configure CloudTrail with log file validation enabled.",
        )

    invalid_trails = [
        t.get("name", "<unknown>")
        for t in trails
        if not t.get("log_file_validation_enabled", False)
    ]

    if not invalid_trails:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="All CloudTrail trails have log file validation enabled.",
            evidence={"trails_checked": len(trails)},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(invalid_trails)} trail(s) do not have log file validation: "
            f"{', '.join(invalid_trails)}."
        ),
        evidence={"invalid_trails": invalid_trails},
        recommendation=(
            "Enable log file validation on all trails with "
            "`aws cloudtrail update-trail --enable-log-file-validation`."
        ),
    )


# ---------------------------------------------------------------------------
# Check 2.3 – CloudTrail encrypted
# ---------------------------------------------------------------------------


def check_2_3_cloudtrail_encrypted(config: dict[str, Any]) -> CheckResult:
    """Ensure CloudTrail logs are encrypted at rest using KMS.

    Server-side encryption with KMS (SSE-KMS) ensures that CloudTrail
    log files are encrypted at rest for confidentiality.

    Args:
        config: Environment configuration dict with a ``logging`` section.

    Returns:
        CheckResult indicating PASS if all trails are KMS-encrypted.
    """
    check = _CHECKS["2.3"]
    logging_cfg = config.get("logging", {})
    trails: list[dict[str, Any]] = logging_cfg.get("cloudtrail", {}).get("trails", [])

    if not trails:
        return CheckResult(
            check=check,
            status=CheckStatus.FAIL,
            details="No CloudTrail trails configured.",
            evidence={"trails": []},
            recommendation="Configure CloudTrail with KMS encryption.",
        )

    unencrypted = [t.get("name", "<unknown>") for t in trails if not t.get("kms_key_id")]

    if not unencrypted:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="All CloudTrail trails are encrypted with KMS.",
            evidence={"trails_checked": len(trails)},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(unencrypted)} trail(s) are not encrypted with KMS: {', '.join(unencrypted)}."
        ),
        evidence={"unencrypted_trails": unencrypted},
        recommendation=(
            "Enable SSE-KMS encryption on CloudTrail trails using "
            "`aws cloudtrail update-trail --kms-key-id <key-arn>`."
        ),
    )


# ---------------------------------------------------------------------------
# ComplianceCheck definitions
# ---------------------------------------------------------------------------

_CHECKS: dict[str, ComplianceCheck] = {
    "2.1": ComplianceCheck(
        id="cis-aws-2.1",
        title="Ensure CloudTrail is enabled in all regions",
        description=(
            "CloudTrail must be enabled with at least one multi-region "
            "trail to log API activity across the entire account."
        ),
        framework=Framework.CIS_AWS,
        section="2.1",
        severity=Severity.HIGH,
        check_function=check_2_1_cloudtrail_enabled,
    ),
    "2.2": ComplianceCheck(
        id="cis-aws-2.2",
        title="Ensure CloudTrail log file validation is enabled",
        description=(
            "Log file validation ensures integrity of delivered log files "
            "and enables detection of modification or deletion."
        ),
        framework=Framework.CIS_AWS,
        section="2.2",
        severity=Severity.MEDIUM,
        check_function=check_2_2_cloudtrail_log_validation,
    ),
    "2.3": ComplianceCheck(
        id="cis-aws-2.3",
        title="Ensure CloudTrail logs are encrypted at rest with KMS",
        description=(
            "Encrypting CloudTrail logs with KMS provides confidentiality "
            "for the recorded API activity data."
        ),
        framework=Framework.CIS_AWS,
        section="2.3",
        severity=Severity.MEDIUM,
        check_function=check_2_3_cloudtrail_encrypted,
    ),
}

CIS_LOGGING_CHECKS: list[ComplianceCheck] = list(_CHECKS.values())
