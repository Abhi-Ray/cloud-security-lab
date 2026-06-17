"""IAM change detection rules.

Detects privilege-escalation and persistence activities through IAM,
including:

* Attachment of administrator-level managed policies
* Creation of new IAM users
* Inline policy modifications that grant dangerous permissions
"""

from __future__ import annotations

from typing import Any

from detectors.models import (
    DetectionMatch,
    DetectionRule,
    MitreTactic,
    RuleSeverity,
)

# ---------------------------------------------------------------------------
# Dangerous policy / permission patterns
# ---------------------------------------------------------------------------

_ADMIN_POLICY_ARNS: frozenset[str] = frozenset({
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
})

_DANGEROUS_ACTIONS: frozenset[str] = frozenset({
    "*",
    "iam:*",
    "sts:AssumeRole",
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "lambda:*",
    "s3:*",
    "ec2:*",
})


# ---------------------------------------------------------------------------
# detect_admin_policy_attachment
# ---------------------------------------------------------------------------

def detect_admin_policy_attachment(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect attachment of admin-level managed policies.

    Fires on ``AttachUserPolicy``, ``AttachGroupPolicy``, or
    ``AttachRolePolicy`` when the policy ARN is in the known
    administrator-level set.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    attach_events = {"AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy"}
    event_name = event.get("eventName", "")
    if event_name not in attach_events:
        return None

    params = event.get("requestParameters", {})
    policy_arn: str = params.get("policyArn", "")

    if not any(policy_arn.endswith(admin.split(":")[-1]) for admin in _ADMIN_POLICY_ARNS):
        # Also check exact match.
        if policy_arn not in _ADMIN_POLICY_ARNS:
            return None

    actor = _get_actor(event)
    target = params.get("userName") or params.get("groupName") or params.get("roleName", "unknown")

    details = (
        f"Admin-level policy '{policy_arn}' attached to {target} "
        f"by {actor} via {event_name}."
    )

    return DetectionMatch(
        rule=ADMIN_POLICY_ATTACHMENT_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Verify the policy attachment was authorized. If unexpected, "
            "immediately detach the policy and investigate the actor's "
            "recent activity. Consider enforcing least-privilege policies "
            "and using IAM Access Analyzer."
        ),
    )


ADMIN_POLICY_ATTACHMENT_RULE = DetectionRule(
    id="CT-IAM-001",
    name="Admin Policy Attachment",
    description=(
        "Detects when administrator-level managed policies "
        "(AdministratorAccess, IAMFullAccess, PowerUserAccess) are attached "
        "to IAM users, groups, or roles."
    ),
    severity=RuleSeverity.CRITICAL,
    mitre_tactics=[MitreTactic.PRIVILEGE_ESCALATION, MitreTactic.PERSISTENCE],
    data_source="aws:cloudtrail",
    detect_function=detect_admin_policy_attachment,
)


# ---------------------------------------------------------------------------
# detect_new_user_creation
# ---------------------------------------------------------------------------

def detect_new_user_creation(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect creation of new IAM users.

    New user creation can be a persistence mechanism for an attacker
    who has gained access to an environment.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    if event.get("eventName") != "CreateUser":
        return None

    params = event.get("requestParameters", {})
    new_user = params.get("userName", "unknown")
    actor = _get_actor(event)

    details = f"New IAM user '{new_user}' created by {actor}."

    return DetectionMatch(
        rule=NEW_USER_CREATION_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Confirm the new user creation was part of an approved change "
            "request. If unexpected, disable the user immediately and "
            "investigate whether access keys or a login profile were "
            "created for this user."
        ),
    )


NEW_USER_CREATION_RULE = DetectionRule(
    id="CT-IAM-002",
    name="New IAM User Creation",
    description=(
        "Detects creation of new IAM users, which may indicate an "
        "attacker establishing persistence in the account."
    ),
    severity=RuleSeverity.HIGH,
    mitre_tactics=[MitreTactic.PERSISTENCE],
    data_source="aws:cloudtrail",
    detect_function=detect_new_user_creation,
)


# ---------------------------------------------------------------------------
# detect_policy_modification
# ---------------------------------------------------------------------------

def detect_policy_modification(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect creation or modification of policies with dangerous permissions.

    Looks at ``CreatePolicy``, ``PutUserPolicy``, and ``PutGroupPolicy``
    events and inspects the policy document for overly permissive
    actions (e.g. ``*``, ``iam:*``).

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    policy_events = {"CreatePolicy", "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy"}
    event_name = event.get("eventName", "")
    if event_name not in policy_events:
        return None

    params = event.get("requestParameters", {})
    policy_document: str | dict[str, Any] = params.get("policyDocument", "")

    # Attempt to detect dangerous actions in the policy document.
    # The document can be a JSON string or already-parsed dict.
    dangerous_found = _extract_dangerous_actions(policy_document)
    if not dangerous_found:
        return None

    actor = _get_actor(event)
    target = (
        params.get("policyName")
        or params.get("userName")
        or params.get("groupName")
        or params.get("roleName")
        or "unknown"
    )

    details = (
        f"Policy modification '{event_name}' on '{target}' by {actor} "
        f"includes dangerous permissions: {', '.join(sorted(dangerous_found))}."
    )

    return DetectionMatch(
        rule=POLICY_MODIFICATION_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Review the policy document for least-privilege compliance. "
            "If the broad permissions are not justified, scope them down "
            "immediately. Use IAM Access Analyzer to validate the policy."
        ),
    )


POLICY_MODIFICATION_RULE = DetectionRule(
    id="CT-IAM-003",
    name="Dangerous Policy Modification",
    description=(
        "Detects creation or modification of IAM policies that contain "
        "overly permissive actions such as '*', 'iam:*', or other "
        "dangerous permission grants."
    ),
    severity=RuleSeverity.HIGH,
    mitre_tactics=[MitreTactic.PRIVILEGE_ESCALATION, MitreTactic.PERSISTENCE],
    data_source="aws:cloudtrail",
    detect_function=detect_policy_modification,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_actor(event: dict[str, Any]) -> str:
    """Extract a human-readable actor identifier from a CloudTrail event."""
    identity = event.get("userIdentity", {})
    return (
        identity.get("arn")
        or identity.get("userName")
        or identity.get("type", "unknown")
    )


def _extract_dangerous_actions(
    policy_doc: str | dict[str, Any],
) -> set[str]:
    """Return the set of dangerous actions found in *policy_doc*.

    The policy document is inspected as a raw string (not fully
    parsed) for simplicity — this keeps the module dependency-free
    while still providing useful detection.
    """
    import json

    found: set[str] = set()

    # Normalise to string for pattern matching.
    if isinstance(policy_doc, dict):
        doc_str = json.dumps(policy_doc)
    else:
        doc_str = str(policy_doc)

    for action in _DANGEROUS_ACTIONS:
        # Check for the action surrounded by quotes (as it would appear in JSON).
        if f'"{action}"' in doc_str:
            found.add(action)

    return found
