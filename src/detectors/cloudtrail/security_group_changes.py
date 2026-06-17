"""Security group change detection rules.

Detects:

* Ingress rules opened to the entire internet (``0.0.0.0/0`` or ``::/0``)
* Deletion of security groups (potential defense-evasion)
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
# detect_sg_ingress_modification
# ---------------------------------------------------------------------------

def detect_sg_ingress_modification(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect security group ingress rules that allow traffic from anywhere.

    Fires when ``AuthorizeSecurityGroupIngress`` includes a CIDR of
    ``0.0.0.0/0`` or ``::/0``, meaning the rule is open to the entire
    internet.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    if event.get("eventName") != "AuthorizeSecurityGroupIngress":
        return None

    params = event.get("requestParameters", {})

    # Check for open CIDR in ipPermissions list.
    open_cidrs = _find_open_cidrs(params)
    if not open_cidrs:
        return None

    group_id = params.get("groupId", "unknown")
    actor = _get_actor(event)

    details = (
        f"Security group '{group_id}' modified by {actor} to allow "
        f"ingress from {', '.join(open_cidrs)}. "
        f"This exposes resources to the entire internet."
    )

    return DetectionMatch(
        rule=SG_INGRESS_MODIFICATION_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Immediately review whether the security group rule is "
            "intentional. Restrict the CIDR to specific IP ranges. "
            "Enable VPC Flow Logs to monitor traffic to affected resources."
        ),
    )


SG_INGRESS_MODIFICATION_RULE = DetectionRule(
    id="CT-NET-001",
    name="Security Group Opened to Internet",
    description=(
        "Detects when a security group ingress rule is modified to "
        "allow traffic from 0.0.0.0/0 or ::/0, exposing resources "
        "to the entire internet."
    ),
    severity=RuleSeverity.HIGH,
    mitre_tactics=[MitreTactic.DEFENSE_EVASION, MitreTactic.PERSISTENCE],
    data_source="aws:cloudtrail",
    detect_function=detect_sg_ingress_modification,
)


# ---------------------------------------------------------------------------
# detect_sg_deletion
# ---------------------------------------------------------------------------

def detect_sg_deletion(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect deletion of security groups.

    Deletion of security groups may indicate an attacker removing
    network-level controls as part of defense evasion.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    if event.get("eventName") != "DeleteSecurityGroup":
        return None

    params = event.get("requestParameters", {})
    group_id = params.get("groupId", "unknown")
    actor = _get_actor(event)

    details = (
        f"Security group '{group_id}' deleted by {actor}. "
        f"This may remove network-level protections from resources."
    )

    return DetectionMatch(
        rule=SG_DELETION_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Verify the security group deletion was part of an approved "
            "change. Check if any resources were left without adequate "
            "network protection. Review CloudTrail for other related "
            "changes by the same actor."
        ),
    )


SG_DELETION_RULE = DetectionRule(
    id="CT-NET-002",
    name="Security Group Deleted",
    description=(
        "Detects deletion of VPC security groups, which may indicate "
        "removal of network-level controls as a defense-evasion technique."
    ),
    severity=RuleSeverity.HIGH,
    mitre_tactics=[MitreTactic.DEFENSE_EVASION],
    data_source="aws:cloudtrail",
    detect_function=detect_sg_deletion,
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


def _find_open_cidrs(params: dict[str, Any]) -> list[str]:
    """Return a list of open-to-internet CIDRs found in request parameters.

    Checks both ``ipPermissions`` (modern format) and top-level
    ``cidrIp`` (legacy format).
    """
    open_cidrs: list[str] = []
    open_values = {"0.0.0.0/0", "::/0"}

    # Modern format: ipPermissions → items → ipRanges / ipv6Ranges.
    ip_permissions = params.get("ipPermissions", {})
    items = ip_permissions.get("items", [])
    for permission in items:
        for ip_range in permission.get("ipRanges", {}).get("items", []):
            cidr = ip_range.get("cidrIp", "")
            if cidr in open_values:
                open_cidrs.append(cidr)
        for ipv6_range in permission.get("ipv6Ranges", {}).get("items", []):
            cidr = ipv6_range.get("cidrIpv6", "")
            if cidr in open_values:
                open_cidrs.append(cidr)

    # Legacy format: top-level cidrIp.
    top_cidr = params.get("cidrIp", "")
    if top_cidr in open_values:
        open_cidrs.append(top_cidr)

    return open_cidrs
