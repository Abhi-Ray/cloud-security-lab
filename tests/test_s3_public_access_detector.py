"""Tests for Add AWS S3 Bucket Public Access Detector."""

from __future__ import annotations


class TestAwsS3BucketPublicAccessDetector:
    """Unit tests for AwsS3BucketPublicAccessDetector."""

    def test_scan_detects_missing_encryption(self) -> None:
        """Encryption check should flag unencrypted resources."""
        from detectors.s3_public_access_detector import AwsS3BucketPublicAccessDetector

        scanner = AwsS3BucketPublicAccessDetector()
        config = {
            "resource_id": "test-resource-001",
            "encryption_enabled": False,
            "publicly_accessible": False,
            "logging_enabled": True,
        }
        findings = scanner.scan(config)
        assert any(f.id.endswith("-001") for f in findings)

    def test_scan_detects_public_access(self) -> None:
        """Public access check should flag exposed resources."""
        from detectors.s3_public_access_detector import AwsS3BucketPublicAccessDetector

        scanner = AwsS3BucketPublicAccessDetector()
        config = {
            "resource_id": "test-resource-002",
            "encryption_enabled": True,
            "publicly_accessible": True,
            "logging_enabled": True,
        }
        findings = scanner.scan(config)
        assert any(f.id.endswith("-002") for f in findings)

    def test_scan_clean_config(self) -> None:
        """A fully-compliant config should produce no findings."""
        from detectors.s3_public_access_detector import AwsS3BucketPublicAccessDetector

        scanner = AwsS3BucketPublicAccessDetector()
        config = {
            "resource_id": "test-resource-003",
            "encryption_enabled": True,
            "publicly_accessible": False,
            "logging_enabled": True,
        }
        findings = scanner.scan(config)
        assert len(findings) == 0

    def test_scan_detects_missing_logging(self) -> None:
        """Logging check should flag resources without audit logs."""
        from detectors.s3_public_access_detector import AwsS3BucketPublicAccessDetector

        scanner = AwsS3BucketPublicAccessDetector()
        config = {
            "resource_id": "test-resource-004",
            "encryption_enabled": True,
            "publicly_accessible": False,
            "logging_enabled": False,
        }
        findings = scanner.scan(config)
        assert any(f.id.endswith("-003") for f in findings)
