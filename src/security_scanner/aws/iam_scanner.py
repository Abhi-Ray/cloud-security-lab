"""IAM Security Scanner.

Analyses mock IAM configuration data for common security misconfigurations
aligned with CIS AWS Foundations Benchmark v1.4+ and AWS Security Best
Practices.

Checks performed
----------------
1. Root account access keys present (CRITICAL)
2. Root account MFA not enabled (CRITICAL)
3. Users without MFA enabled (HIGH)
4. Unused credentials (> 90 days since last activity) (HIGH)
5. Overly permissive IAM policies (``*:*``) (CRITICAL)
6. Weak password policy (MEDIUM)
7. Access key age > 90 days without rotation (MEDIUM)
"""

from __future__ import annotations

from typing import Any

from security_scanner.base_scanner import BaseScanner
from security_scanner.models import Finding, ScanConfig, Severity

__all__ = ["IAMScanner"]

# Thresholds (days)
_UNUSED_CREDENTIAL_THRESHOLD = 90
_KEY_ROTATION_THRESHOLD = 90

# Minimum password-policy requirements
_MIN_PASSWORD_LENGTH = 14
_REQUIRED_PASSWORD_POLICY_FLAGS = {
    "require_uppercase": True,
    "require_numbers": True,
    "require_symbols": True,
}
_MAX_PASSWORD_AGE = 90  # days; 0 means "never expires"


class IAMScanner(BaseScanner):
    """Scanner for AWS IAM configuration issues.

    Expected config structure under ``config['iam']``::

        {
            "root_account": {
                "has_access_keys": bool,
                "mfa_enabled": bool,
            },
            "users": [
                {
                    "username": str,
                    "has_mfa": bool,
                    "has_console_access": bool,
                    "last_activity_days": int,
                    "access_keys": [
                        {"age_days": int, "last_used_days": int}
                    ],
                }
            ],
            "policies": [
                {
                    "name": str,
                    "effect": "Allow" | "Deny",
                    "actions": list[str],
                    "resources": list[str],
                }
            ],
            "password_policy": {
                "min_length": int,
                "require_uppercase": bool,
                "require_numbers": bool,
                "require_symbols": bool,
                "max_age_days": int,
            },
        }
    """

    @property
    def name(self) -> str:
        return "IAM Scanner"

    # ------------------------------------------------------------------
    # Internal check dispatcher
    # ------------------------------------------------------------------

    def _run_checks(self, config: ScanConfig) -> list[Finding]:
        """Execute all IAM checks against *config*."""
        iam: dict[str, Any] = config.get_service_config("iam")
        if not iam:
            return [
                self._create_finding(
                    title="IAM configuration data missing",
                    severity=Severity.INFO,
                    resource_type="IAM",
                    resource_id="N/A",
                    description="No IAM configuration was provided for scanning.",
                    recommendation="Supply IAM data in the config under the 'iam' key.",
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._check_root_account(iam.get("root_account", {})))
        findings.extend(self._check_users(iam.get("users", [])))
        findings.extend(self._check_policies(iam.get("policies", [])))
        findings.extend(self._check_password_policy(iam.get("password_policy", {})))
        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_root_account(self, root: dict[str, Any]) -> list[Finding]:
        """Check root account for access keys and MFA."""
        findings: list[Finding] = []
        if not root:
            return findings

        if root.get("has_access_keys", False):
            findings.append(
                self._create_finding(
                    title="Root account has active access keys",
                    severity=Severity.CRITICAL,
                    resource_type="IAM Root Account",
                    resource_id="root",
                    description=(
                        "The AWS root account has active access keys. Root access keys "
                        "provide unrestricted access to all resources and cannot be "
                        "constrained by IAM policies."
                    ),
                    recommendation=(
                        "Delete root access keys immediately. Use IAM users or roles "
                        "with least-privilege policies for programmatic access."
                    ),
                    details={"cis_benchmark": "1.4"},
                )
            )

        if not root.get("mfa_enabled", True):
            findings.append(
                self._create_finding(
                    title="Root account MFA not enabled",
                    severity=Severity.CRITICAL,
                    resource_type="IAM Root Account",
                    resource_id="root",
                    description=(
                        "Multi-Factor Authentication is not enabled on the root account. "
                        "This significantly increases the risk of account takeover."
                    ),
                    recommendation=(
                        "Enable a hardware MFA device on the root account. "
                        "Prefer a FIDO2 security key for the strongest protection."
                    ),
                    details={"cis_benchmark": "1.5"},
                )
            )

        return findings

    def _check_users(self, users: list[dict[str, Any]]) -> list[Finding]:
        """Check individual IAM users for MFA, unused creds, and key rotation."""
        findings: list[Finding] = []

        for user in users:
            username: str = user.get("username", "unknown")

            # --- MFA check ---------------------------------------------------
            if user.get("has_console_access", False) and not user.get("has_mfa", False):
                findings.append(
                    self._create_finding(
                        title=f"IAM user '{username}' does not have MFA enabled",
                        severity=Severity.HIGH,
                        resource_type="IAM User",
                        resource_id=username,
                        description=(
                            f"User '{username}' has console access but MFA is not "
                            "enabled. This allows password-only authentication."
                        ),
                        recommendation=(
                            f"Enable MFA for user '{username}'. Virtual MFA apps or "
                            "hardware tokens are recommended."
                        ),
                        details={"cis_benchmark": "1.10"},
                    )
                )

            # --- Unused credentials -------------------------------------------
            last_activity = user.get("last_activity_days", 0)
            if last_activity > _UNUSED_CREDENTIAL_THRESHOLD:
                findings.append(
                    self._create_finding(
                        title=f"IAM user '{username}' has unused credentials",
                        severity=Severity.HIGH,
                        resource_type="IAM User",
                        resource_id=username,
                        description=(
                            f"User '{username}' has not been active for "
                            f"{last_activity} days (threshold: "
                            f"{_UNUSED_CREDENTIAL_THRESHOLD} days). Dormant accounts "
                            "increase the attack surface."
                        ),
                        recommendation=(
                            f"Disable or remove credentials for user '{username}' "
                            "if they are no longer needed."
                        ),
                        details={
                            "last_activity_days": last_activity,
                            "threshold_days": _UNUSED_CREDENTIAL_THRESHOLD,
                            "cis_benchmark": "1.12",
                        },
                    )
                )

            # --- Access key rotation ------------------------------------------
            for idx, key in enumerate(user.get("access_keys", [])):
                age = key.get("age_days", 0)
                if age > _KEY_ROTATION_THRESHOLD:
                    findings.append(
                        self._create_finding(
                            title=(
                                f"Access key for '{username}' has not been rotated"
                            ),
                            severity=Severity.MEDIUM,
                            resource_type="IAM Access Key",
                            resource_id=f"{username}/key-{idx + 1}",
                            description=(
                                f"Access key #{idx + 1} for user '{username}' is "
                                f"{age} days old (threshold: "
                                f"{_KEY_ROTATION_THRESHOLD} days)."
                            ),
                            recommendation=(
                                f"Rotate the access key for user '{username}'. "
                                "Automate key rotation where possible."
                            ),
                            details={
                                "key_age_days": age,
                                "threshold_days": _KEY_ROTATION_THRESHOLD,
                                "last_used_days": key.get("last_used_days"),
                                "cis_benchmark": "1.14",
                            },
                        )
                    )

        return findings

    def _check_policies(self, policies: list[dict[str, Any]]) -> list[Finding]:
        """Check IAM policies for overly permissive permissions."""
        findings: list[Finding] = []

        for policy in policies:
            name: str = policy.get("name", "unknown")
            effect: str = policy.get("effect", "").lower()
            actions: list[str] = policy.get("actions", [])
            resources: list[str] = policy.get("resources", [])

            if effect != "allow":
                continue

            is_wildcard_action = "*" in actions or "*:*" in actions
            is_wildcard_resource = "*" in resources

            if is_wildcard_action and is_wildcard_resource:
                findings.append(
                    self._create_finding(
                        title=f"IAM policy '{name}' grants full administrative access",
                        severity=Severity.CRITICAL,
                        resource_type="IAM Policy",
                        resource_id=name,
                        description=(
                            f"Policy '{name}' allows all actions ('*') on all "
                            "resources ('*'). This is equivalent to root-level "
                            "access and violates the principle of least privilege."
                        ),
                        recommendation=(
                            f"Scope down policy '{name}' to only the specific "
                            "actions and resources required."
                        ),
                        details={
                            "actions": actions,
                            "resources": resources,
                            "cis_benchmark": "1.16",
                        },
                    )
                )
            elif is_wildcard_action:
                findings.append(
                    self._create_finding(
                        title=f"IAM policy '{name}' allows all actions",
                        severity=Severity.HIGH,
                        resource_type="IAM Policy",
                        resource_id=name,
                        description=(
                            f"Policy '{name}' allows all actions ('*') on scoped "
                            "resources. While resources are constrained, wildcard "
                            "actions still pose significant risk."
                        ),
                        recommendation=(
                            f"Replace the wildcard action in policy '{name}' with "
                            "specific service actions."
                        ),
                        details={"actions": actions, "resources": resources},
                    )
                )
            elif is_wildcard_resource:
                for action in actions:
                    if ":" in action and action.split(":")[1] == "*":
                        findings.append(
                            self._create_finding(
                                title=(
                                    f"IAM policy '{name}' grants broad service access"
                                ),
                                severity=Severity.HIGH,
                                resource_type="IAM Policy",
                                resource_id=name,
                                description=(
                                    f"Policy '{name}' grants all actions for service "
                                    f"'{action.split(':')[0]}' on all resources."
                                ),
                                recommendation=(
                                    "Restrict both the actions and resource ARNs."
                                ),
                                details={"actions": actions, "resources": resources},
                            )
                        )
                        break  # One finding per policy is sufficient

        return findings

    def _check_password_policy(self, policy: dict[str, Any]) -> list[Finding]:
        """Check the account password policy against best practices."""
        findings: list[Finding] = []
        if not policy:
            findings.append(
                self._create_finding(
                    title="No IAM password policy configured",
                    severity=Severity.MEDIUM,
                    resource_type="IAM Password Policy",
                    resource_id="password-policy",
                    description="No custom password policy is configured for the account.",
                    recommendation=(
                        "Configure a password policy that enforces minimum length, "
                        "complexity, and rotation requirements."
                    ),
                )
            )
            return findings

        issues: list[str] = []

        min_length = policy.get("min_length", 0)
        if min_length < _MIN_PASSWORD_LENGTH:
            issues.append(
                f"Minimum length is {min_length} (recommended: {_MIN_PASSWORD_LENGTH})"
            )

        for flag, required in _REQUIRED_PASSWORD_POLICY_FLAGS.items():
            if required and not policy.get(flag, False):
                readable = flag.replace("_", " ").title()
                issues.append(f"'{readable}' is not enforced")

        max_age = policy.get("max_age_days", 0)
        if max_age == 0 or max_age > _MAX_PASSWORD_AGE:
            age_str = "never" if max_age == 0 else f"{max_age} days"
            issues.append(
                f"Password expiration is set to {age_str} "
                f"(recommended: {_MAX_PASSWORD_AGE} days or less)"
            )

        if issues:
            findings.append(
                self._create_finding(
                    title="IAM password policy does not meet best practices",
                    severity=Severity.MEDIUM,
                    resource_type="IAM Password Policy",
                    resource_id="password-policy",
                    description=(
                        "The account password policy has the following gaps:\n• "
                        + "\n• ".join(issues)
                    ),
                    recommendation=(
                        "Update the password policy to enforce: minimum "
                        f"{_MIN_PASSWORD_LENGTH} characters, uppercase letters, numbers, "
                        f"symbols, and a maximum age of {_MAX_PASSWORD_AGE} days."
                    ),
                    details={"policy": policy, "issues": issues},
                )
            )

        return findings
