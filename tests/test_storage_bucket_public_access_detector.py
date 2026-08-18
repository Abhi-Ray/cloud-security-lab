"""Tests for Add multi-cloud storage bucket public access detector."""

from __future__ import annotations


class TestMultiCloudStorageBucketPublicAccessDetector:
    """Unit tests for MultiCloudStorageBucketPublicAccessDetector."""

    def test_scan_detects_missing_encryption(self) -> None:
        """Encryption check should flag unencrypted resources."""
        from detectors.storage_bucket_public_access_detector import (
            MultiCloudStorageBucketPublicAccessDetector,
        )

        scanner = MultiCloudStorageBucketPublicAccessDetector()
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
        from detectors.storage_bucket_public_access_detector import (
            MultiCloudStorageBucketPublicAccessDetector,
        )

        scanner = MultiCloudStorageBucketPublicAccessDetector()
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
        from detectors.storage_bucket_public_access_detector import (
            MultiCloudStorageBucketPublicAccessDetector,
        )

        scanner = MultiCloudStorageBucketPublicAccessDetector()
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
        from detectors.storage_bucket_public_access_detector import (
            MultiCloudStorageBucketPublicAccessDetector,
        )

        scanner = MultiCloudStorageBucketPublicAccessDetector()
        config = {
            "resource_id": "test-resource-004",
            "encryption_enabled": True,
            "publicly_accessible": False,
            "logging_enabled": False,
        }
        findings = scanner.scan(config)
        assert any(f.id.endswith("-003") for f in findings)
