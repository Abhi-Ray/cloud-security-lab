"""CIS AWS Foundations Benchmark checks.

Implements automated compliance checks based on the CIS Amazon Web Services
Foundations Benchmark covering IAM, logging, encryption, and networking.
"""

from __future__ import annotations

from compliance.cis_aws.encryption_checks import (
    CIS_ENCRYPTION_CHECKS,
    check_3_1_ebs_encryption_default,
    check_3_2_s3_bucket_encryption,
    check_3_3_rds_encryption,
)
from compliance.cis_aws.iam_checks import (
    CIS_IAM_CHECKS,
    check_1_1_root_account_no_access_keys,
    check_1_2_root_mfa_enabled,
    check_1_3_unused_credentials_disabled,
    check_1_4_access_keys_rotated,
    check_1_5_password_policy,
    check_1_6_no_full_admin_policies,
)
from compliance.cis_aws.logging_checks import (
    CIS_LOGGING_CHECKS,
    check_2_1_cloudtrail_enabled,
    check_2_2_cloudtrail_log_validation,
    check_2_3_cloudtrail_encrypted,
)
from compliance.cis_aws.networking_checks import (
    CIS_NETWORKING_CHECKS,
    check_4_1_default_sg_restricts_all,
    check_4_2_no_unrestricted_ssh,
    check_4_3_vpc_flow_logs_enabled,
)
from compliance.models import ComplianceCheck


__all__ = [
    # IAM checks
    "check_1_1_root_account_no_access_keys",
    "check_1_2_root_mfa_enabled",
    "check_1_3_unused_credentials_disabled",
    "check_1_4_access_keys_rotated",
    "check_1_5_password_policy",
    "check_1_6_no_full_admin_policies",
    # Logging checks
    "check_2_1_cloudtrail_enabled",
    "check_2_2_cloudtrail_log_validation",
    "check_2_3_cloudtrail_encrypted",
    # Encryption checks
    "check_3_1_ebs_encryption_default",
    "check_3_2_s3_bucket_encryption",
    "check_3_3_rds_encryption",
    # Networking checks
    "check_4_1_default_sg_restricts_all",
    "check_4_2_no_unrestricted_ssh",
    "check_4_3_vpc_flow_logs_enabled",
    # Pre-built check lists
    "CIS_IAM_CHECKS",
    "CIS_LOGGING_CHECKS",
    "CIS_ENCRYPTION_CHECKS",
    "CIS_NETWORKING_CHECKS",
    "ALL_CIS_AWS_CHECKS",
]


def _collect_all_checks() -> list[ComplianceCheck]:
    """Aggregate every CIS AWS check definition into a single list."""
    return [
        *CIS_IAM_CHECKS,
        *CIS_LOGGING_CHECKS,
        *CIS_ENCRYPTION_CHECKS,
        *CIS_NETWORKING_CHECKS,
    ]


ALL_CIS_AWS_CHECKS: list[ComplianceCheck] = _collect_all_checks()
