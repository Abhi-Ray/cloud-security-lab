"""CIS AWS Foundations Benchmark — Section 1: Identity and Access Management.

Implements automated checks for IAM best practices including root account
security, credential rotation, password policies, and least-privilege access.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from compliance.models import (
    CheckResult,
    CheckStatus,
    ComplianceCheck,
    Framework,
    Severity,
)


__all__ = [
    "check_1_1_root_account_no_access_keys",
    "check_1_2_root_mfa_enabled",
    "check_1_3_unused_credentials_disabled",
    "check_1_4_access_keys_rotated",
    "check_1_5_password_policy",
    "check_1_6_no_full_admin_policies",
    "CIS_IAM_CHECKS",
]


# ---------------------------------------------------------------------------
# Check 1.1 – Root account access keys
# ---------------------------------------------------------------------------

def check_1_1_root_account_no_access_keys(config: dict[str, Any]) -> CheckResult:
    """Ensure no root account access keys exist.

    Root account access keys provide unrestricted access to all resources.
    They should be deleted so that the root account can only be used via
    the AWS Management Console with MFA.

    Args:
        config: Environment configuration dict with an ``iam`` section.

    Returns:
        CheckResult indicating PASS if no root keys exist, FAIL otherwise.
    """
    check = _CHECKS["1.1"]
    iam = config.get("iam", {})
    root_access_keys: list[dict[str, Any]] = iam.get("root_access_keys", [])

    if not root_access_keys:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="No root account access keys found.",
            evidence={"root_access_keys": []},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=f"Found {len(root_access_keys)} root account access key(s).",
        evidence={"root_access_keys": root_access_keys},
        recommendation=(
            "Delete all root account access keys via the IAM console. "
            "Use IAM users or roles with least-privilege policies instead."
        ),
    )


# ---------------------------------------------------------------------------
# Check 1.2 – Root MFA enabled
# ---------------------------------------------------------------------------

def check_1_2_root_mfa_enabled(config: dict[str, Any]) -> CheckResult:
    """Ensure MFA is enabled for the root account.

    Enabling MFA on the root account adds a critical second factor that
    protects against password compromise.

    Args:
        config: Environment configuration dict with an ``iam`` section.

    Returns:
        CheckResult indicating PASS if MFA is enabled, FAIL otherwise.
    """
    check = _CHECKS["1.2"]
    iam = config.get("iam", {})
    root_mfa: bool = iam.get("root_mfa_enabled", False)

    if root_mfa:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="MFA is enabled for the root account.",
            evidence={"root_mfa_enabled": True},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details="MFA is NOT enabled for the root account.",
        evidence={"root_mfa_enabled": False},
        recommendation=(
            "Enable a hardware or virtual MFA device for the root account "
            "via the IAM console under 'Security credentials'."
        ),
    )


# ---------------------------------------------------------------------------
# Check 1.3 – Unused credentials disabled
# ---------------------------------------------------------------------------

_UNUSED_THRESHOLD_DAYS = 90


def check_1_3_unused_credentials_disabled(config: dict[str, Any]) -> CheckResult:
    """Ensure credentials unused for 90+ days are disabled.

    Stale credentials increase the blast radius of a compromise. Any user
    whose password or access keys have not been used in 90 days should have
    those credentials disabled.

    Args:
        config: Environment configuration dict with an ``iam`` section.

    Returns:
        CheckResult with status PASS if all stale credentials are disabled.
    """
    check = _CHECKS["1.3"]
    iam = config.get("iam", {})
    users: list[dict[str, Any]] = iam.get("users", [])
    now = datetime.now(timezone.utc)
    stale_users: list[str] = []

    for user in users:
        last_used_str: str | None = user.get("last_activity")
        enabled: bool = user.get("enabled", True)
        if not enabled:
            continue  # already disabled — fine
        if last_used_str is not None:
            last_used = datetime.fromisoformat(last_used_str)
            if last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=timezone.utc)
            age_days = (now - last_used).days
            if age_days >= _UNUSED_THRESHOLD_DAYS:
                stale_users.append(user.get("username", "<unknown>"))

    if not stale_users:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="No enabled credentials unused for 90+ days.",
            evidence={"stale_users": []},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(stale_users)} user(s) have enabled credentials unused "
            f"for {_UNUSED_THRESHOLD_DAYS}+ days: {', '.join(stale_users)}."
        ),
        evidence={"stale_users": stale_users},
        recommendation=(
            "Disable or delete credentials for users that have not been active "
            "in the last 90 days. Use `aws iam update-login-profile` or "
            "`aws iam update-access-key` to disable them."
        ),
    )


# ---------------------------------------------------------------------------
# Check 1.4 – Access key rotation
# ---------------------------------------------------------------------------

_ROTATION_THRESHOLD_DAYS = 90


def check_1_4_access_keys_rotated(config: dict[str, Any]) -> CheckResult:
    """Ensure access keys are rotated within 90 days.

    Regularly rotating access keys limits the window of exposure if a key
    is leaked.

    Args:
        config: Environment configuration dict with an ``iam`` section.

    Returns:
        CheckResult with status PASS if all active keys are < 90 days old.
    """
    check = _CHECKS["1.4"]
    iam = config.get("iam", {})
    users: list[dict[str, Any]] = iam.get("users", [])
    now = datetime.now(timezone.utc)
    stale_keys: list[dict[str, Any]] = []

    for user in users:
        for key in user.get("access_keys", []):
            if key.get("status") != "Active":
                continue
            created_str: str | None = key.get("created_date")
            if created_str is None:
                continue
            created = datetime.fromisoformat(created_str)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (now - created).days
            if age_days >= _ROTATION_THRESHOLD_DAYS:
                stale_keys.append({
                    "username": user.get("username", "<unknown>"),
                    "key_id": key.get("key_id", "<unknown>"),
                    "age_days": age_days,
                })

    if not stale_keys:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="All active access keys have been rotated within 90 days.",
            evidence={"stale_keys": []},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(stale_keys)} access key(s) have not been rotated in "
            f"{_ROTATION_THRESHOLD_DAYS}+ days."
        ),
        evidence={"stale_keys": stale_keys},
        recommendation=(
            "Rotate access keys that are older than 90 days. Create a new "
            "key, update applications, then deactivate/delete the old key."
        ),
    )


# ---------------------------------------------------------------------------
# Check 1.5 – Password policy
# ---------------------------------------------------------------------------

_REQUIRED_PASSWORD_POLICY: dict[str, Any] = {
    "minimum_length": 14,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_symbols": True,
}


def check_1_5_password_policy(config: dict[str, Any]) -> CheckResult:
    """Ensure the IAM password policy meets minimum requirements.

    The password policy must enforce: minimum 14 characters, uppercase,
    lowercase, numbers, and symbols.

    Args:
        config: Environment configuration dict with an ``iam`` section.

    Returns:
        CheckResult with status PASS if the policy meets all requirements.
    """
    check = _CHECKS["1.5"]
    iam = config.get("iam", {})
    policy: dict[str, Any] = iam.get("password_policy", {})
    violations: list[str] = []

    actual_min = policy.get("minimum_length", 0)
    required_min = _REQUIRED_PASSWORD_POLICY["minimum_length"]
    if actual_min < required_min:
        violations.append(
            f"minimum_length is {actual_min}, required >= {required_min}"
        )

    for flag in ("require_uppercase", "require_lowercase", "require_numbers", "require_symbols"):
        if not policy.get(flag, False):
            violations.append(f"{flag} is not enabled")

    if not violations:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="Password policy meets all CIS requirements.",
            evidence={"password_policy": policy},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=f"Password policy violations: {'; '.join(violations)}.",
        evidence={"password_policy": policy, "violations": violations},
        recommendation=(
            "Update the IAM password policy to enforce at least 14 characters, "
            "uppercase, lowercase, numbers, and symbols via "
            "`aws iam update-account-password-policy`."
        ),
    )


# ---------------------------------------------------------------------------
# Check 1.6 – No full admin policies
# ---------------------------------------------------------------------------

def check_1_6_no_full_admin_policies(config: dict[str, Any]) -> CheckResult:
    """Ensure no IAM policies allow full *:* administrator access.

    Policies with ``Effect: Allow, Action: *, Resource: *`` grant
    unrestricted access and violate the principle of least privilege.

    Args:
        config: Environment configuration dict with an ``iam`` section.

    Returns:
        CheckResult with status PASS if no such policies exist.
    """
    check = _CHECKS["1.6"]
    iam = config.get("iam", {})
    policies: list[dict[str, Any]] = iam.get("policies", [])
    admin_policies: list[str] = []

    for pol in policies:
        for stmt in pol.get("statements", []):
            effect = stmt.get("effect", "").lower()
            action = stmt.get("action", "")
            resource = stmt.get("resource", "")
            if effect == "allow" and action == "*" and resource == "*":
                admin_policies.append(pol.get("name", pol.get("arn", "<unknown>")))
                break  # one match is enough per policy

    if not admin_policies:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="No IAM policies grant full *:* administrator access.",
            evidence={"admin_policies": []},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(admin_policies)} policy(ies) grant full admin access: "
            f"{', '.join(admin_policies)}."
        ),
        evidence={"admin_policies": admin_policies},
        recommendation=(
            "Replace overly permissive *:* policies with fine-grained "
            "policies that follow the principle of least privilege."
        ),
    )


# ---------------------------------------------------------------------------
# ComplianceCheck definitions — used by the engine registry
# ---------------------------------------------------------------------------

_CHECKS: dict[str, ComplianceCheck] = {
    "1.1": ComplianceCheck(
        id="cis-aws-1.1",
        title="Ensure no root account access keys exist",
        description=(
            "The root account has full, unrestricted access. Access keys "
            "for root must not exist to prevent programmatic abuse."
        ),
        framework=Framework.CIS_AWS,
        section="1.1",
        severity=Severity.CRITICAL,
        check_function=check_1_1_root_account_no_access_keys,
    ),
    "1.2": ComplianceCheck(
        id="cis-aws-1.2",
        title="Ensure MFA is enabled for the root account",
        description=(
            "Enabling MFA provides an additional authentication factor "
            "that protects the root account from password compromise."
        ),
        framework=Framework.CIS_AWS,
        section="1.2",
        severity=Severity.CRITICAL,
        check_function=check_1_2_root_mfa_enabled,
    ),
    "1.3": ComplianceCheck(
        id="cis-aws-1.3",
        title="Ensure credentials unused for 90+ days are disabled",
        description=(
            "Disabling stale credentials reduces the attack surface by "
            "eliminating dormant access vectors."
        ),
        framework=Framework.CIS_AWS,
        section="1.3",
        severity=Severity.MEDIUM,
        check_function=check_1_3_unused_credentials_disabled,
    ),
    "1.4": ComplianceCheck(
        id="cis-aws-1.4",
        title="Ensure access keys are rotated within 90 days",
        description=(
            "Regular key rotation limits the window of exposure when a "
            "key is compromised."
        ),
        framework=Framework.CIS_AWS,
        section="1.4",
        severity=Severity.MEDIUM,
        check_function=check_1_4_access_keys_rotated,
    ),
    "1.5": ComplianceCheck(
        id="cis-aws-1.5",
        title="Ensure IAM password policy meets requirements",
        description=(
            "A strong password policy enforces complexity requirements "
            "to resist brute-force and dictionary attacks."
        ),
        framework=Framework.CIS_AWS,
        section="1.5",
        severity=Severity.MEDIUM,
        check_function=check_1_5_password_policy,
    ),
    "1.6": ComplianceCheck(
        id="cis-aws-1.6",
        title="Ensure no IAM policies allow full *:* admin access",
        description=(
            "Policies granting unrestricted admin access violate the "
            "principle of least privilege."
        ),
        framework=Framework.CIS_AWS,
        section="1.6",
        severity=Severity.HIGH,
        check_function=check_1_6_no_full_admin_policies,
    ),
}

CIS_IAM_CHECKS: list[ComplianceCheck] = list(_CHECKS.values())
