"""Tests for AWS S3 Security Scanner."""

import pytest

from security_scanner.aws.s3_scanner import S3Scanner
from security_scanner.models import ScanConfig, Severity


@pytest.fixture
def scanner():
    """Create an S3Scanner instance."""
    return S3Scanner()


@pytest.fixture
def insecure_s3_config():
    """S3 configuration with multiple security issues."""
    return ScanConfig(
        config={
            "s3": {
                "buckets": [
                    {
                        "name": "public-data-bucket",
                        "public_access_block": {
                            "block_public_acls": False,
                            "block_public_policy": False,
                            "ignore_public_acls": False,
                            "restrict_public_buckets": False,
                        },
                        "encryption": {"enabled": False},
                        "versioning": False,
                        "logging": False,
                        "policy": {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                        },
                    },
                ]
            }
        }
    )


@pytest.fixture
def secure_s3_config():
    """Fully secure S3 configuration."""
    return ScanConfig(
        config={
            "s3": {
                "buckets": [
                    {
                        "name": "secure-bucket",
                        "public_access_block": {
                            "block_public_acls": True,
                            "block_public_policy": True,
                            "ignore_public_acls": True,
                            "restrict_public_buckets": True,
                        },
                        "encryption": {"enabled": True, "type": "AES256"},
                        "versioning": True,
                        "logging": True,
                        "policy": None,
                    },
                ]
            }
        }
    )


@pytest.mark.unit
class TestS3Scanner:
    """Tests for S3Scanner."""

    def test_scanner_name(self, scanner):
        """Scanner should have correct name."""
        assert "s3" in scanner.name.lower()

    def test_detects_public_access_block_disabled(self, scanner, insecure_s3_config):
        """Should detect when public access block is disabled."""
        result = scanner.scan(insecure_s3_config)
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        public_access_findings = [
            f
            for f in critical_findings
            if "public" in f.title.lower() and "access" in f.title.lower()
        ]
        assert len(public_access_findings) > 0, "Should detect disabled public access block"

    def test_detects_no_encryption(self, scanner, insecure_s3_config):
        """Should detect missing encryption."""
        result = scanner.scan(insecure_s3_config)
        encryption_findings = [f for f in result.findings if "encrypt" in f.title.lower()]
        assert len(encryption_findings) > 0, "Should detect missing encryption"

    def test_detects_no_versioning(self, scanner, insecure_s3_config):
        """Should detect disabled versioning."""
        result = scanner.scan(insecure_s3_config)
        versioning_findings = [f for f in result.findings if "version" in f.title.lower()]
        assert len(versioning_findings) > 0, "Should detect disabled versioning"

    def test_detects_no_logging(self, scanner, insecure_s3_config):
        """Should detect disabled access logging."""
        result = scanner.scan(insecure_s3_config)
        logging_findings = [f for f in result.findings if "log" in f.title.lower()]
        assert len(logging_findings) > 0, "Should detect disabled access logging"

    def test_detects_public_bucket_policy(self, scanner, insecure_s3_config):
        """Should detect bucket policy with Principal: *."""
        result = scanner.scan(insecure_s3_config)
        policy_findings = [
            f for f in result.findings if "policy" in f.title.lower() or "public" in f.title.lower()
        ]
        assert len(policy_findings) > 0, "Should detect public bucket policy"

    def test_clean_config_no_critical_findings(self, scanner, secure_s3_config):
        """Secure S3 config should produce no critical/high findings."""
        result = scanner.scan(secure_s3_config)
        serious_findings = [
            f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(serious_findings) == 0, (
            f"Secure config should have no critical/high findings, got: "
            f"{[f.title for f in serious_findings]}"
        )

    def test_scan_result_structure(self, scanner, insecure_s3_config):
        """Scan result should have proper structure."""
        result = scanner.scan(insecure_s3_config)
        assert result.scanner_name is not None
        assert result.timestamp is not None
        assert isinstance(result.findings, list)
        assert len(result.findings) > 0
