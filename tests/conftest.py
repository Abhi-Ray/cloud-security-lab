"""Shared pytest fixtures for the Cloud Security Lab test suite.

Provides mock AWS configuration dictionaries (secure and insecure) and
sample CloudTrail events that are reused across multiple test modules.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# AWS configuration fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def aws_config_secure() -> dict:
    """A fully secure AWS configuration (all checks should pass)."""
    return {
        "iam": {
            "root_account": {"has_access_keys": False, "mfa_enabled": True},
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
                    "effect": "Allow",
                    "actions": ["s3:GetObject", "s3:ListBucket"],
                    "resources": ["arn:aws:s3:::my-bucket/*"],
                },
            ],
            "password_policy": {
                "min_length": 14,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_symbols": True,
                "max_age_days": 90,
                "prevent_reuse": 24,
            },
        },
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
            ],
        },
        "cloudtrail": {
            "trails": [
                {
                    "name": "main-trail",
                    "is_multi_region": True,
                    "log_file_validation": True,
                    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc",
                    "s3_bucket_logging": True,
                    "is_logging": True,
                },
            ],
        },
        "networking": {
            "security_groups": [
                {
                    "id": "sg-secure",
                    "name": "default",
                    "is_default": True,
                    "inbound_rules": [],
                },
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
def aws_config_insecure() -> dict:
    """An insecure AWS configuration (many checks should fail)."""
    return {
        "iam": {
            "root_account": {"has_access_keys": True, "mfa_enabled": False},
            "users": [
                {
                    "username": "admin",
                    "has_mfa": False,
                    "last_activity_days": 120,
                    "has_console_access": True,
                    "access_keys": [{"age_days": 200, "last_used_days": 100}],
                },
                {
                    "username": "old-contractor",
                    "has_mfa": False,
                    "last_activity_days": 180,
                    "has_console_access": True,
                    "access_keys": [{"age_days": 365, "last_used_days": 180}],
                },
            ],
            "policies": [
                {
                    "name": "SuperAdmin",
                    "effect": "Allow",
                    "actions": ["*"],
                    "resources": ["*"],
                },
            ],
            "password_policy": {
                "min_length": 8,
                "require_uppercase": False,
                "require_lowercase": True,
                "require_numbers": True,
                "require_symbols": False,
                "max_age_days": 0,
                "prevent_reuse": 0,
            },
        },
        "s3": {
            "buckets": [
                {
                    "name": "public-bucket",
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
            ],
        },
        "cloudtrail": {
            "trails": [
                {
                    "name": "basic-trail",
                    "is_multi_region": False,
                    "log_file_validation": False,
                    "kms_key_id": None,
                    "s3_bucket_logging": False,
                    "is_logging": True,
                },
            ],
        },
        "networking": {
            "security_groups": [
                {
                    "id": "sg-open",
                    "name": "default",
                    "is_default": True,
                    "inbound_rules": [
                        {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
                        {"port": 3389, "cidr": "0.0.0.0/0", "protocol": "tcp"},
                    ],
                },
            ],
            "vpcs": [{"id": "vpc-456", "flow_logs_enabled": False}],
        },
        "encryption": {
            "ebs_default_encryption": False,
            "s3_buckets": [{"name": "public-bucket", "encryption_enabled": False}],
            "rds_instances": [{"id": "db-2", "encrypted": False}],
        },
    }


# ---------------------------------------------------------------------------
# CloudTrail event fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_cloudtrail_events() -> list[dict]:
    """Sample CloudTrail events for detection testing.

    Includes events that should and should not trigger detection rules:
    - Root console login (should trigger)
    - Normal user login (should NOT trigger)
    - Admin policy attached (should trigger)
    - CloudTrail stopped (should trigger)
    - Normal API call (should NOT trigger)
    - Security group opened (should trigger)
    """
    return [
        # Root console login — should trigger
        {
            "eventTime": "2024-01-15T10:30:00Z",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {
                "type": "Root",
                "arn": "arn:aws:iam::123456789012:root",
            },
            "sourceIPAddress": "198.51.100.1",
            "responseElements": {"ConsoleLogin": "Success"},
        },
        # Normal user login — should NOT trigger root-login rule
        {
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
        },
        # Admin policy attached — should trigger
        {
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
        },
        # CloudTrail stopped — should trigger
        {
            "eventTime": "2024-01-15T12:00:00Z",
            "eventName": "StopLogging",
            "eventSource": "cloudtrail.amazonaws.com",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/attacker",
            },
            "requestParameters": {"name": "main-trail"},
        },
        # Normal API call — should NOT trigger
        {
            "eventTime": "2024-01-15T12:30:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/developer",
            },
        },
        # Security group opened — should trigger
        {
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
                            "ipRanges": {
                                "items": [{"cidrIp": "0.0.0.0/0"}],
                            },
                        },
                    ],
                },
            },
        },
    ]
