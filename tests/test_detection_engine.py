"""Tests for the Detection Engine."""

import pytest

from detectors.engine import DetectionEngine
from detectors.models import RuleSeverity


@pytest.fixture
def engine():
    """Create a DetectionEngine with all rules registered."""
    return DetectionEngine()


@pytest.fixture
def root_login_event():
    """CloudTrail event: Root console login."""
    return {
        "eventTime": "2024-01-15T10:30:00Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {
            "type": "Root",
            "arn": "arn:aws:iam::123456789012:root",
        },
        "sourceIPAddress": "198.51.100.1",
        "responseElements": {"ConsoleLogin": "Success"},
    }


@pytest.fixture
def normal_user_login_event():
    """CloudTrail event: Normal IAM user login."""
    return {
        "eventTime": "2024-01-15T10:35:00Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/developer",
            "userName": "developer",
        },
        "sourceIPAddress": "203.0.113.5",
        "responseElements": {"ConsoleLogin": "Success"},
    }


@pytest.fixture
def admin_policy_event():
    """CloudTrail event: Admin policy attached to user."""
    return {
        "eventTime": "2024-01-15T11:00:00Z",
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/admin",
        },
        "requestParameters": {
            "userName": "new-user",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    }


@pytest.fixture
def cloudtrail_stop_event():
    """CloudTrail event: CloudTrail logging stopped."""
    return {
        "eventTime": "2024-01-15T12:00:00Z",
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/attacker",
        },
        "requestParameters": {"name": "main-trail"},
    }


@pytest.fixture
def normal_api_event():
    """CloudTrail event: Normal API call (should not trigger)."""
    return {
        "eventTime": "2024-01-15T12:30:00Z",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/developer",
        },
    }


@pytest.fixture
def sg_open_event():
    """CloudTrail event: Security group opened to 0.0.0.0/0."""
    return {
        "eventTime": "2024-01-15T13:00:00Z",
        "eventName": "AuthorizeSecurityGroupIngress",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/admin",
        },
        "requestParameters": {
            "groupId": "sg-123",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }
                ]
            },
        },
    }


@pytest.mark.unit
class TestDetectionEngine:
    """Tests for the DetectionEngine."""

    def test_engine_has_rules(self, engine):
        """Engine should have detection rules registered."""
        rules = engine.get_rules()
        assert len(rules) > 0, "Engine should have rules registered"

    def test_detects_root_login(self, engine, root_login_event):
        """Should detect root console login."""
        matches = engine.process_event(root_login_event)
        assert len(matches) > 0, "Should detect root console login"
        assert any(
            m.rule.severity == RuleSeverity.CRITICAL for m in matches
        ), "Root login should be CRITICAL"

    def test_ignores_normal_user_login(self, engine, normal_user_login_event):
        """Should NOT trigger on normal IAM user login."""
        matches = engine.process_event(normal_user_login_event)
        # Filter for login-specific rules only
        login_matches = [
            m for m in matches if "root" in m.rule.name.lower() or "login" in m.rule.name.lower()
        ]
        assert len(login_matches) == 0, "Normal user login should not trigger root login detection"

    def test_detects_admin_policy_attachment(self, engine, admin_policy_event):
        """Should detect admin policy being attached."""
        matches = engine.process_event(admin_policy_event)
        assert len(matches) > 0, "Should detect admin policy attachment"

    def test_detects_cloudtrail_stop(self, engine, cloudtrail_stop_event):
        """Should detect CloudTrail being stopped."""
        matches = engine.process_event(cloudtrail_stop_event)
        assert len(matches) > 0, "Should detect CloudTrail StopLogging"
        assert any(
            m.rule.severity == RuleSeverity.CRITICAL for m in matches
        ), "StopLogging should be CRITICAL"

    def test_ignores_normal_api_calls(self, engine, normal_api_event):
        """Should NOT trigger on normal API calls like DescribeInstances."""
        matches = engine.process_event(normal_api_event)
        assert len(matches) == 0, (
            f"Normal API calls should not trigger detections, got: "
            f"{[m.rule.name for m in matches]}"
        )

    def test_detects_sg_open(self, engine, sg_open_event):
        """Should detect security group being opened to 0.0.0.0/0."""
        matches = engine.process_event(sg_open_event)
        assert len(matches) > 0, "Should detect SG opened to 0.0.0.0/0"

    def test_process_multiple_events(self, engine, root_login_event, normal_api_event, cloudtrail_stop_event):
        """Should process multiple events and return summary."""
        events = [root_login_event, normal_api_event, cloudtrail_stop_event]
        summary = engine.process_events(events)
        assert summary.events_processed == 3
        assert summary.rules_evaluated > 0
        assert len(summary.matches) >= 2  # root login + cloudtrail stop

    def test_all_rules_have_mitre_mapping(self, engine):
        """All detection rules should have MITRE ATT&CK tactics."""
        for rule in engine.get_rules():
            assert len(rule.mitre_tactics) > 0, (
                f"Rule '{rule.name}' should have MITRE ATT&CK tactics mapped"
            )

    def test_all_rules_have_severity(self, engine):
        """All detection rules should have a severity level."""
        for rule in engine.get_rules():
            assert rule.severity is not None, (
                f"Rule '{rule.name}' should have a severity"
            )
            assert isinstance(rule.severity, RuleSeverity)
