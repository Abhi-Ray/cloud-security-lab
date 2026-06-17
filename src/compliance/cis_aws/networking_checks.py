"""CIS AWS Foundations Benchmark — Section 4: Networking.

Implements automated checks for VPC and Security Group configurations
including default security group restrictions, SSH access controls,
and VPC Flow Logs enablement.
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
    "check_4_1_default_sg_restricts_all",
    "check_4_2_no_unrestricted_ssh",
    "check_4_3_vpc_flow_logs_enabled",
    "CIS_NETWORKING_CHECKS",
]


# ---------------------------------------------------------------------------
# Check 4.1 – Default security group restricts all traffic
# ---------------------------------------------------------------------------

def check_4_1_default_sg_restricts_all(config: dict[str, Any]) -> CheckResult:
    """Ensure the default security group of every VPC restricts all traffic.

    The default security group should have no inbound or outbound rules so
    that resources are not inadvertently exposed when placed in the default
    group.

    Args:
        config: Environment configuration dict with a ``networking`` section.

    Returns:
        CheckResult indicating PASS if all default SGs have no rules.
    """
    check = _CHECKS["4.1"]
    networking = config.get("networking", {})
    security_groups: list[dict[str, Any]] = networking.get("security_groups", [])

    permissive_defaults: list[str] = []
    for sg in security_groups:
        if not sg.get("is_default", False):
            continue
        inbound: list[dict[str, Any]] = sg.get("inbound_rules", [])
        outbound: list[dict[str, Any]] = sg.get("outbound_rules", [])
        if inbound or outbound:
            permissive_defaults.append(sg.get("id", "<unknown>"))

    if not permissive_defaults:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="All default security groups restrict inbound and outbound traffic.",
            evidence={"permissive_defaults": []},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(permissive_defaults)} default security group(s) allow traffic: "
            f"{', '.join(permissive_defaults)}."
        ),
        evidence={"permissive_defaults": permissive_defaults},
        recommendation=(
            "Remove all inbound and outbound rules from default security groups. "
            "Use custom security groups with explicit least-privilege rules instead."
        ),
    )


# ---------------------------------------------------------------------------
# Check 4.2 – No unrestricted SSH
# ---------------------------------------------------------------------------

_SSH_PORT = 22
_UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}


def check_4_2_no_unrestricted_ssh(config: dict[str, Any]) -> CheckResult:
    """Ensure no security groups allow unrestricted ingress to port 22.

    SSH access should be limited to known IP ranges. Allowing 0.0.0.0/0
    or ::/0 on port 22 exposes instances to brute-force attacks from the
    entire internet.

    Args:
        config: Environment configuration dict with a ``networking`` section.

    Returns:
        CheckResult indicating PASS if no SG allows unrestricted SSH.
    """
    check = _CHECKS["4.2"]
    networking = config.get("networking", {})
    security_groups: list[dict[str, Any]] = networking.get("security_groups", [])

    violating_sgs: list[dict[str, Any]] = []
    for sg in security_groups:
        for rule in sg.get("inbound_rules", []):
            port = rule.get("port")
            cidr = rule.get("cidr", "")
            protocol = rule.get("protocol", "").lower()
            # Check for port 22 or port-range covering 22
            from_port = rule.get("from_port", port)
            to_port = rule.get("to_port", port)
            port_match = (
                (port is not None and port == _SSH_PORT)
                or (
                    from_port is not None
                    and to_port is not None
                    and from_port <= _SSH_PORT <= to_port
                )
            )
            if port_match and cidr in _UNRESTRICTED_CIDRS and protocol in ("tcp", "-1", "all"):
                violating_sgs.append({
                    "sg_id": sg.get("id", "<unknown>"),
                    "sg_name": sg.get("name", "<unknown>"),
                    "cidr": cidr,
                })
                break  # one match per SG is enough

    if not violating_sgs:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="No security groups allow unrestricted SSH access.",
            evidence={"violating_sgs": []},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(violating_sgs)} security group(s) allow unrestricted SSH (0.0.0.0/0)."
        ),
        evidence={"violating_sgs": violating_sgs},
        recommendation=(
            "Restrict SSH ingress rules to specific trusted CIDR ranges. "
            "Consider using AWS Systems Manager Session Manager as an alternative."
        ),
    )


# ---------------------------------------------------------------------------
# Check 4.3 – VPC Flow Logs enabled
# ---------------------------------------------------------------------------

def check_4_3_vpc_flow_logs_enabled(config: dict[str, Any]) -> CheckResult:
    """Ensure VPC Flow Logs are enabled for all VPCs.

    Flow Logs capture IP traffic information for network interfaces in a
    VPC, enabling security analysis and troubleshooting.

    Args:
        config: Environment configuration dict with a ``networking`` section.

    Returns:
        CheckResult indicating PASS if all VPCs have flow logs enabled.
    """
    check = _CHECKS["4.3"]
    networking = config.get("networking", {})
    vpcs: list[dict[str, Any]] = networking.get("vpcs", [])

    if not vpcs:
        return CheckResult(
            check=check,
            status=CheckStatus.NOT_APPLICABLE,
            details="No VPCs found in configuration.",
            evidence={"vpcs": []},
        )

    no_flow_logs: list[str] = [
        vpc.get("id", "<unknown>")
        for vpc in vpcs
        if not vpc.get("flow_logs_enabled", False)
    ]

    if not no_flow_logs:
        return CheckResult(
            check=check,
            status=CheckStatus.PASS,
            details="VPC Flow Logs are enabled on all VPCs.",
            evidence={"vpcs_checked": len(vpcs)},
        )

    return CheckResult(
        check=check,
        status=CheckStatus.FAIL,
        details=(
            f"{len(no_flow_logs)} VPC(s) do not have Flow Logs enabled: "
            f"{', '.join(no_flow_logs)}."
        ),
        evidence={"vpcs_without_flow_logs": no_flow_logs},
        recommendation=(
            "Enable VPC Flow Logs for all VPCs and send them to CloudWatch "
            "Logs or S3 for analysis."
        ),
    )


# ---------------------------------------------------------------------------
# ComplianceCheck definitions
# ---------------------------------------------------------------------------

_CHECKS: dict[str, ComplianceCheck] = {
    "4.1": ComplianceCheck(
        id="cis-aws-4.1",
        title="Ensure default security group restricts all traffic",
        description=(
            "Default security groups should have no rules to prevent "
            "inadvertent exposure of resources."
        ),
        framework=Framework.CIS_AWS,
        section="4.1",
        severity=Severity.HIGH,
        check_function=check_4_1_default_sg_restricts_all,
    ),
    "4.2": ComplianceCheck(
        id="cis-aws-4.2",
        title="Ensure no security groups allow unrestricted SSH",
        description=(
            "Security groups should not allow ingress from 0.0.0.0/0 "
            "to port 22 to prevent unauthorized SSH access."
        ),
        framework=Framework.CIS_AWS,
        section="4.2",
        severity=Severity.HIGH,
        check_function=check_4_2_no_unrestricted_ssh,
    ),
    "4.3": ComplianceCheck(
        id="cis-aws-4.3",
        title="Ensure VPC Flow Logs are enabled",
        description=(
            "VPC Flow Logs capture network traffic metadata and are "
            "essential for security monitoring and incident response."
        ),
        framework=Framework.CIS_AWS,
        section="4.3",
        severity=Severity.MEDIUM,
        check_function=check_4_3_vpc_flow_logs_enabled,
    ),
}

CIS_NETWORKING_CHECKS: list[ComplianceCheck] = list(_CHECKS.values())
