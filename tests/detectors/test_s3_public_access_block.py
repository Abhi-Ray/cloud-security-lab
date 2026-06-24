"""Tests for S3 Public Access Block Detector."""

from __future__ import annotations

from detectors.s3_public_access_block import S3PublicAccessBlockDetector


class TestS3PublicAccessBlockDetector:
    """Unit tests for S3PublicAccessBlockDetector."""

    def test_scan_detects_missing_encryption(self) -> None:
        """Encryption check should flag unencrypted resources."""
        scanner = S3PublicAccessBlockDetector()
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
        scanner = S3PublicAccessBlockDetector()
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
        scanner = S3PublicAccessBlockDetector()
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
        scanner = S3PublicAccessBlockDetector()
        config = {
            "resource_id": "test-resource-004",
            "encryption_enabled": True,
            "publicly_accessible": False,
            "logging_enabled": False,
        }
        findings = scanner.scan(config)
        assert any(f.id.endswith("-003") for f in findings)
