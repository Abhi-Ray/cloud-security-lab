"""Tests for Implement CIS AWS Foundations Benchmark v1.5.0 compliance checks."""

from __future__ import annotations

import pytest


class TestCisAwsFoundationsBenchmarkV1.5.0ComplianceChecks:
    """Unit tests for CisAwsFoundationsBenchmarkV1.5.0ComplianceChecks."""

    def test_compliant_config_passes(self) -> None:
        """Fully compliant configuration should pass all checks."""
        from compliance.checks.cis_aws_1_5_0.cloudtrail_checks import CisAwsFoundationsBenchmarkV1.5.0ComplianceChecks

        checker = CisAwsFoundationsBenchmarkV1.5.0ComplianceChecks()
        config = {
            "resource_id": "test-001",
            "encryption_enabled": True,
            "mfa_enabled": True,
            "logging_enabled": True,
        }
        results = checker.check(config)
        assert all(r.status.value == "PASS" for r in results)

    def test_non_compliant_encryption(self) -> None:
        """Missing encryption should fail the encryption check."""
        from compliance.checks.cis_aws_1_5_0.cloudtrail_checks import CisAwsFoundationsBenchmarkV1.5.0ComplianceChecks

        checker = CisAwsFoundationsBenchmarkV1.5.0ComplianceChecks()
        config = {
            "resource_id": "test-002",
            "encryption_enabled": False,
            "mfa_enabled": True,
            "logging_enabled": True,
        }
        results = checker.check(config)
        enc_results = [r for r in results if "enc" in r.check_id]
        assert any(r.status.value == "FAIL" for r in enc_results)

    def test_non_compliant_access(self) -> None:
        """Missing MFA should fail the access control check."""
        from compliance.checks.cis_aws_1_5_0.cloudtrail_checks import CisAwsFoundationsBenchmarkV1.5.0ComplianceChecks

        checker = CisAwsFoundationsBenchmarkV1.5.0ComplianceChecks()
        config = {
            "resource_id": "test-003",
            "encryption_enabled": True,
            "mfa_enabled": False,
            "logging_enabled": True,
        }
        results = checker.check(config)
        ac_results = [r for r in results if "ac" in r.check_id]
        assert any(r.status.value == "FAIL" for r in ac_results)
