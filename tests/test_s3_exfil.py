"""Tests for Add S3 data exfiltration detector."""

from __future__ import annotations


class TestS3DataExfiltrationDetector:
    """Unit tests for S3DataExfiltrationDetector."""

    def test_detects_high_risk_action(self) -> None:
        """High-risk API call should generate an alert."""
        from detectors.rules.s3_exfil import S3DataExfiltrationDetector

        detector = S3DataExfiltrationDetector()
        events = [
            {
                "action": "AttachUserPolicy",
                "principal": "evil-user",
                "source_ip": "203.0.113.50",
            }
        ]
        alerts = detector.analyse(events)
        assert len(alerts) >= 1
        assert alerts[0].severity.value == "HIGH"

    def test_no_alert_for_normal_events(self) -> None:
        """Normal events should not trigger alerts."""
        from detectors.rules.s3_exfil import S3DataExfiltrationDetector

        detector = S3DataExfiltrationDetector()
        events = [
            {
                "action": "DescribeInstances",
                "principal": "normal-user",
                "source_ip": "10.0.1.50",
            }
        ]
        alerts = detector.analyse(events)
        assert len(alerts) == 0

    def test_detects_external_console_login(self) -> None:
        """Console login from external IP should alert."""
        from detectors.rules.s3_exfil import S3DataExfiltrationDetector

        detector = S3DataExfiltrationDetector()
        events = [
            {
                "action": "ConsoleLogin",
                "principal": "admin-user",
                "source_ip": "198.51.100.25",
                "is_console_login": True,
            }
        ]
        alerts = detector.analyse(events)
        titles = [a.title.lower() for a in alerts]
        assert any("external ip" in t or "console" in t for t in titles)
