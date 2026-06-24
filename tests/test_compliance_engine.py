"""Tests for the Compliance Assessment Engine."""

import pytest

from compliance.engine import ComplianceEngine
from compliance.models import CheckStatus, Framework


@pytest.fixture
def engine():
    """Create a ComplianceEngine instance with CIS AWS checks registered."""
    return ComplianceEngine()


@pytest.fixture
def secure_config():
    """Fully compliant AWS configuration."""
    return {
        "iam": {
            "root_access_keys": False,
            "root_mfa_enabled": True,
            "users": [
                {
                    "username": "developer",
                    "has_mfa": True,
                    "last_activity_days": 5,
                    "has_console_access": True,
                    "access_keys": [{"age_days": 30, "last_used_days": 1}],
                },
            ],
            "policies": [
                {
                    "name": "ReadOnly",
                    "statements": [
                        {
                            "effect": "Allow",
                            "action": "s3:GetObject",
                            "resource": "arn:aws:s3:::my-bucket/*",
                        }
                    ],
                }
            ],
            "password_policy": {
                "minimum_length": 14,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_symbols": True,
                "max_age_days": 90,
                "prevent_reuse": 24,
            },
        },
        "logging": {
            "cloudtrail": {
                "trails": [
                    {
                        "name": "main-trail",
                        "is_multi_region": True,
                        "log_file_validation": True,
                        "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc",
                        "s3_bucket_logging": True,
                        "is_logging": True,
                    }
                ]
            }
        },
        "networking": {
            "security_groups": [
                {
                    "id": "sg-secure",
                    "name": "default",
                    "is_default": True,
                    "inbound_rules": [],
                }
            ],
            "vpcs": [{"id": "vpc-123", "flow_logs_enabled": True}],
        },
        "encryption": {
            "ebs_default_encryption": True,
            "s3_buckets": [{"name": "secure-bucket", "encryption_enabled": True}],
            "rds_instances": [{"id": "db-1", "encrypted": True}],
        },
    }


@pytest.fixture
def insecure_config():
    """Non-compliant AWS configuration."""
    return {
        "iam": {
            "root_access_keys": True,
            "root_mfa_enabled": False,
            "users": [
                {
                    "username": "admin",
                    "has_mfa": False,
                    "last_activity_days": 120,
                    "has_console_access": True,
                    "access_keys": [{"age_days": 200, "last_used_days": 100}],
                },
            ],
            "policies": [
                {
                    "name": "SuperAdmin",
                    "statements": [{"effect": "Allow", "action": "*", "resource": "*"}],
                }
            ],
            "password_policy": {
                "minimum_length": 8,
                "require_uppercase": False,
                "require_lowercase": True,
                "require_numbers": True,
                "require_symbols": False,
                "max_age_days": 0,
                "prevent_reuse": 0,
            },
        },
        "logging": {
            "cloudtrail": {
                "trails": [
                    {
                        "name": "basic-trail",
                        "is_multi_region": False,
                        "log_file_validation": False,
                        "kms_key_id": None,
                        "s3_bucket_logging": False,
                        "is_logging": True,
                    }
                ]
            }
        },
        "networking": {
            "security_groups": [
                {
                    "id": "sg-open",
                    "name": "default",
                    "is_default": True,
                    "inbound_rules": [
                        {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
                    ],
                }
            ],
            "vpcs": [{"id": "vpc-456", "flow_logs_enabled": False}],
        },
        "encryption": {
            "ebs_default_encryption": False,
            "s3_buckets": [{"name": "public-bucket", "encryption_enabled": False}],
            "rds_instances": [{"id": "db-2", "encrypted": False}],
        },
    }


@pytest.mark.unit
class TestComplianceEngine:
    """Tests for the ComplianceEngine."""

    def test_engine_has_cis_aws_framework(self, engine):
        """Engine should have CIS AWS checks registered by default."""
        frameworks = engine.registered_frameworks
        assert Framework.CIS_AWS in frameworks

    def test_run_cis_assessment(self, engine, secure_config):
        """Should run a full CIS AWS assessment."""
        report = engine.run_assessment(secure_config, Framework.CIS_AWS)
        assert report is not None
        assert report.framework == Framework.CIS_AWS
        assert len(report.results) > 0

    def test_secure_config_high_score(self, engine, secure_config):
        """Secure configuration should score above 80%."""
        report = engine.run_assessment(secure_config, Framework.CIS_AWS)
        failed = [r.check.title for r in report.results if r.status == CheckStatus.FAIL]
        assert report.score >= 80.0, (
            f"Secure config should score >=80%, got {report.score}%. Failed checks: {failed}"
        )

    def test_insecure_config_low_score(self, engine, insecure_config):
        """Insecure configuration should score below 50%."""
        report = engine.run_assessment(insecure_config, Framework.CIS_AWS)
        passed = [r.check.title for r in report.results if r.status == CheckStatus.PASS]
        assert report.score <= 50.0, (
            f"Insecure config should score <=50%, got {report.score}%. Passed checks: {passed}"
        )

    def test_report_has_correct_structure(self, engine, secure_config):
        """Compliance report should have all required fields."""
        report = engine.run_assessment(secure_config, Framework.CIS_AWS)
        assert report.framework == Framework.CIS_AWS
        assert report.timestamp is not None
        assert isinstance(report.results, list)
        assert report.pass_count >= 0
        assert report.fail_count >= 0
        assert 0 <= report.score <= 100

    def test_report_counts_are_consistent(self, engine, insecure_config):
        """Pass + Fail counts should equal total results."""
        report = engine.run_assessment(insecure_config, Framework.CIS_AWS)
        counted_pass = sum(1 for r in report.results if r.status == CheckStatus.PASS)
        counted_fail = sum(1 for r in report.results if r.status == CheckStatus.FAIL)
        assert report.pass_count == counted_pass
        assert report.fail_count == counted_fail

    def test_each_result_has_check_info(self, engine, insecure_config):
        """Each result should reference the check that produced it."""
        report = engine.run_assessment(insecure_config, Framework.CIS_AWS)
        for result in report.results:
            assert result.check is not None
            assert result.check.title is not None
            assert result.check.id is not None
            assert result.status in (
                CheckStatus.PASS,
                CheckStatus.FAIL,
                CheckStatus.ERROR,
                CheckStatus.NOT_APPLICABLE,
            )
