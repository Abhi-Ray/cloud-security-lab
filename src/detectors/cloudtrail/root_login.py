"""Root console login detection.

Detects when the AWS root account is used to sign into the
management console, which is a critical security event in any
production environment.
"""

from __future__ import annotations

from typing import Any

from detectors.models import (
    DetectionMatch,
    DetectionRule,
    MitreTactic,
    RuleSeverity,
)


def detect_root_console_login(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect root account console logins.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` if the event represents a successful
        or failed root console login, otherwise ``None``.
    """
    if event.get("eventName") != "ConsoleLogin":
        return None

    user_identity = event.get("userIdentity", {})
    if user_identity.get("type") != "Root":
        return None

    # Determine success/failure for detail string.
    response = event.get("responseElements", {})
    login_result = response.get("ConsoleLogin", "Unknown")
    source_ip = event.get("sourceIPAddress", "unknown")

    details = (
        f"Root account console login detected (result={login_result}) "
        f"from IP {source_ip}. The root account should not be used for "
        f"day-to-day operations."
    )

    return DetectionMatch(
        rule=ROOT_CONSOLE_LOGIN_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Immediately verify this login was authorized. Enable MFA on the "
            "root account if not already enabled. Remove root access keys. "
            "Consider using AWS Organizations SCPs to restrict root usage."
        ),
    )


ROOT_CONSOLE_LOGIN_RULE = DetectionRule(
    id="CT-ROOT-001",
    name="Root Console Login",
    description=(
        "Detects AWS root account console logins. Root account usage should "
        "be extremely rare and limited to account-level operations that "
        "cannot be performed by IAM users or roles."
    ),
    severity=RuleSeverity.CRITICAL,
    mitre_tactics=[MitreTactic.INITIAL_ACCESS],
    data_source="aws:cloudtrail",
    detect_function=detect_root_console_login,
)
