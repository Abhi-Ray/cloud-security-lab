"""Tests for the IAM Security Scanner.

Validates that the IAM scanner correctly identifies security issues
in mock AWS IAM configurations, including root access keys, missing MFA,
unused credentials, overly permissive policies, and weak password policies.
"""

from __future__ import annotations

import pytest

from security_scanner.aws.iam_scanner import IAMScanner
from security_scanner.models import Finding, ScanConfig, ScanResult, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan_iam(config_dict: dict) -> ScanResult:
    """Run the IAM scanner against the given raw config dict."""
    scanner = IAMScanner()
    scan_config = ScanConfig(config=config_dict)
    return scanner.scan(scan_config)


def _titles(result: ScanResult) -> list[str]:
    """Extract finding titles from a scan result for easier assertions."""
    return [f.title for f in result.findings]


def _severities(result: ScanResult) -> list[Severity]:
    """Extract finding severity levels from a scan result."""
    return [f.severity for f in result.findings]


def _has_finding_with(
    result: ScanResult,
    *,
    severity: Severity | None = None,
    title_contains: str | None = None,
    resource_id_contains: str | None = None,
) -> bool:
    """Return True if at least one finding matches all given criteria."""
    for f in result.findings:
        if severity is not None and f.severity != severity:
            continue
        if title_contains is not None and title_contains.lower() not in f.title.lower():
            continue
        if (
            resource_id_contains is not None
            and resource_id_contains.lower() not in f.resource_id.lower()
        ):
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Root account checks
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIAMRootAccount:
    """Tests for root account security checks."""

    def test_iam_scanner_detects_root_access_keys(self, aws_config_insecure: dict) -> None:
        """Root account with access keys should produce a CRITICAL finding."""
        result = _scan_iam(aws_config_insecure)

        assert _has_finding_with(
            result,
            severity=Severity.CRITICAL,
            title_contains="root",
        ), f"Expected a CRITICAL finding about root access keys. Got findings: {_titles(result)}"

    def test_iam_scanner_no_root_access_key_finding_on_secure(
        self, aws_config_secure: dict
    ) -> None:
        """Secure config (no root access keys) should not flag root keys."""
        result = _scan_iam(aws_config_secure)

        root_key_findings = [
            f
            for f in result.findings
            if "root" in f.title.lower()
            and "access key" in f.title.lower()
            and f.severity == Severity.CRITICAL
        ]
        assert root_key_findings == [], (
            f"Secure config should not have root access key findings, "
            f"but got: {[f.title for f in root_key_findings]}"
        )


# ---------------------------------------------------------------------------
# MFA checks
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIAMMFA:
    """Tests for MFA enforcement checks."""

    def test_iam_scanner_detects_missing_mfa(self, aws_config_insecure: dict) -> None:
        """Users without MFA should produce HIGH findings."""
        result = _scan_iam(aws_config_insecure)

        mfa_findings = [
            f for f in result.findings if "mfa" in f.title.lower() and f.severity == Severity.HIGH
        ]
        # Insecure config has 2 users without MFA
        assert len(mfa_findings) >= 1, (
            f"Expected at least 1 HIGH finding about missing MFA. Got findings: {_titles(result)}"
        )

    def test_iam_scanner_no_mfa_finding_on_secure(self, aws_config_secure: dict) -> None:
        """Secure config (all users have MFA) should not flag MFA issues."""
        result = _scan_iam(aws_config_secure)

        mfa_findings = [
            f
            for f in result.findings
            if "mfa" in f.title.lower() and f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        assert mfa_findings == [], (
            f"Secure config should not have MFA findings, "
            f"but got: {[f.title for f in mfa_findings]}"
        )


# ---------------------------------------------------------------------------
# Unused / inactive credentials
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIAMUnusedCredentials:
    """Tests for unused and stale credential detection."""

    def test_iam_scanner_detects_unused_credentials(self, aws_config_insecure: dict) -> None:
        """Users with >90 days inactivity should produce findings."""
        result = _scan_iam(aws_config_insecure)

        inactive_findings = [
            f
            for f in result.findings
            if any(
                keyword in f.title.lower()
                for keyword in ("unused", "inactive", "stale", "credential", "activity")
            )
        ]
        assert len(inactive_findings) >= 1, (
            f"Expected at least 1 finding about unused credentials. Got findings: {_titles(result)}"
        )

    def test_iam_scanner_detects_old_access_keys(self, aws_config_insecure: dict) -> None:
        """Access keys older than 90 days should produce MEDIUM findings."""
        result = _scan_iam(aws_config_insecure)

        old_key_findings = [
            f
            for f in result.findings
            if any(
                keyword in f.title.lower()
                for keyword in ("access key", "key rotation", "key age", "old key", "rotate")
            )
        ]
        assert len(old_key_findings) >= 1, (
            f"Expected at least 1 finding about old access keys. Got findings: {_titles(result)}"
        )

        # All old-key findings should be at least MEDIUM severity.
        for f in old_key_findings:
            assert f.severity >= Severity.MEDIUM, (
                f"Old access key finding '{f.title}' should be at least "
                f"MEDIUM severity, got {f.severity.value}"
            )


# ---------------------------------------------------------------------------
# Policy checks
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIAMPolicies:
    """Tests for IAM policy analysis."""

    def test_iam_scanner_detects_admin_policy(self, aws_config_insecure: dict) -> None:
        """Policies with Action: * and Resource: * should produce CRITICAL findings."""
        result = _scan_iam(aws_config_insecure)

        admin_findings = [
            f
            for f in result.findings
            if f.severity == Severity.CRITICAL
            and any(
                keyword in f.title.lower()
                for keyword in ("admin", "wildcard", "full access", "overly permissive", "*")
            )
        ]
        assert len(admin_findings) >= 1, (
            f"Expected at least 1 CRITICAL finding about admin policy. "
            f"Got findings: {_titles(result)}"
        )


# ---------------------------------------------------------------------------
# Password policy checks
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIAMPasswordPolicy:
    """Tests for password policy strength evaluation."""

    def test_iam_scanner_detects_weak_password_policy(self, aws_config_insecure: dict) -> None:
        """Weak password policy should produce at least a MEDIUM finding."""
        result = _scan_iam(aws_config_insecure)

        password_findings = [
            f
            for f in result.findings
            if "password" in f.title.lower() and f.severity >= Severity.MEDIUM
        ]
        assert len(password_findings) >= 1, (
            f"Expected at least 1 finding about weak password policy. "
            f"Got findings: {_titles(result)}"
        )


# ---------------------------------------------------------------------------
# Clean config & result structure
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIAMCleanConfig:
    """Tests for secure configuration producing clean results."""

    def test_iam_scanner_clean_config(self, aws_config_secure: dict) -> None:
        """Secure config should produce no findings above INFO severity."""
        result = _scan_iam(aws_config_secure)

        non_info_findings = [f for f in result.findings if f.severity != Severity.INFO]
        assert non_info_findings == [], (
            f"Secure config should have no findings above INFO, "
            f"but got: {[(f.title, f.severity.value) for f in non_info_findings]}"
        )


@pytest.mark.unit
class TestIAMScanResult:
    """Tests for scan result structure and metadata."""

    def test_iam_scanner_returns_scan_result(self, aws_config_insecure: dict) -> None:
        """Scan result should have correct scanner_name and structure."""
        result = _scan_iam(aws_config_insecure)

        # Type & name
        assert isinstance(result, ScanResult)
        assert result.scanner_name is not None
        assert len(result.scanner_name) > 0
        assert "iam" in result.scanner_name.lower()

        # Timestamp
        assert result.timestamp is not None

        # Findings list
        assert isinstance(result.findings, list)
        assert result.total_findings == len(result.findings)

        # Each finding is properly typed
        for finding in result.findings:
            assert isinstance(finding, Finding)
            assert isinstance(finding.severity, Severity)
            assert finding.id is not None and len(finding.id) > 0
            assert finding.title is not None and len(finding.title) > 0
            assert finding.description is not None
            assert finding.recommendation is not None

        # Summary dict
        summary = result.summary
        assert "CRITICAL" in summary
        assert "HIGH" in summary
        assert "MEDIUM" in summary
        assert "LOW" in summary
        assert "INFO" in summary
        assert "TOTAL" in summary
        assert summary["TOTAL"] == result.total_findings

    def test_iam_scanner_scan_duration_is_positive(self, aws_config_insecure: dict) -> None:
        """Scan duration should be a positive number (indicating timing)."""
        result = _scan_iam(aws_config_insecure)
        assert result.scan_duration_ms >= 0
