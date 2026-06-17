"""CloudTrail Security Scanner.

Analyses mock CloudTrail configuration data for common security
misconfigurations aligned with CIS AWS Foundations Benchmark and AWS
Security Best Practices.

Checks performed
----------------
1. CloudTrail not enabled / no trails configured (CRITICAL)
2. Trail is not multi-region (HIGH)
3. Log file validation not enabled (HIGH)
4. Trail does not use KMS encryption (MEDIUM)
5. S3 bucket access logging not enabled for the trail bucket (MEDIUM)
"""

from __future__ import annotations

from typing import Any

from security_scanner.base_scanner import BaseScanner
from security_scanner.models import Finding, ScanConfig, Severity

__all__ = ["CloudTrailScanner"]


class CloudTrailScanner(BaseScanner):
    """Scanner for AWS CloudTrail configuration issues.

    Expected config structure under ``config['cloudtrail']``::

        {
            "trails": [
                {
                    "name": str,
                    "is_enabled": bool,
                    "is_multi_region": bool,
                    "log_file_validation": bool,
                    "kms_encryption": bool,
                    "s3_bucket_logging": bool,
                    "s3_bucket_name": str,
                }
            ]
        }

    If the ``trails`` list is empty or missing, a CRITICAL finding is
    generated indicating that CloudTrail is not configured at all.
    """

    @property
    def name(self) -> str:
        return "CloudTrail Scanner"

    # ------------------------------------------------------------------
    # Internal check dispatcher
    # ------------------------------------------------------------------

    def _run_checks(self, config: ScanConfig) -> list[Finding]:
        """Execute all CloudTrail checks against *config*."""
        ct: dict[str, Any] = config.get_service_config("cloudtrail")
        if not ct:
            return [
                self._create_finding(
                    title="CloudTrail configuration data missing",
                    severity=Severity.INFO,
                    resource_type="CloudTrail",
                    resource_id="N/A",
                    description=(
                        "No CloudTrail configuration was provided for scanning."
                    ),
                    recommendation=(
                        "Supply CloudTrail data in the config under the "
                        "'cloudtrail' key."
                    ),
                )
            ]

        trails: list[dict[str, Any]] = ct.get("trails", [])
        if not trails:
            return [
                self._create_finding(
                    title="No CloudTrail trails are configured",
                    severity=Severity.CRITICAL,
                    resource_type="CloudTrail",
                    resource_id="account",
                    description=(
                        "No CloudTrail trails are configured in the account. "
                        "Without CloudTrail, API activity is not logged, making "
                        "incident investigation and compliance auditing impossible."
                    ),
                    recommendation=(
                        "Create a multi-region CloudTrail trail with log file "
                        "validation and KMS encryption enabled."
                    ),
                    details={"cis_benchmark": "3.1"},
                )
            ]

        findings: list[Finding] = []
        for trail in trails:
            trail_name: str = trail.get("name", "unknown-trail")
            findings.extend(self._check_trail(trail_name, trail))
        return findings

    # ------------------------------------------------------------------
    # Per-trail checks
    # ------------------------------------------------------------------

    def _check_trail(
        self, trail_name: str, trail: dict[str, Any]
    ) -> list[Finding]:
        """Run all checks against a single trail."""
        findings: list[Finding] = []

        # 1. Trail enabled
        if not trail.get("is_enabled", False):
            findings.append(
                self._create_finding(
                    title=f"CloudTrail trail '{trail_name}' is not enabled",
                    severity=Severity.CRITICAL,
                    resource_type="CloudTrail Trail",
                    resource_id=trail_name,
                    description=(
                        f"Trail '{trail_name}' exists but is not enabled. "
                        "API events are not being recorded."
                    ),
                    recommendation=(
                        f"Enable trail '{trail_name}' to resume logging of "
                        "management and data events."
                    ),
                    details={"cis_benchmark": "3.1"},
                )
            )

        # 2. Multi-region
        if not trail.get("is_multi_region", False):
            findings.append(
                self._create_finding(
                    title=f"CloudTrail trail '{trail_name}' is not multi-region",
                    severity=Severity.HIGH,
                    resource_type="CloudTrail Trail",
                    resource_id=trail_name,
                    description=(
                        f"Trail '{trail_name}' only captures events in a single "
                        "region. Activity in other regions will be missed."
                    ),
                    recommendation=(
                        f"Enable multi-region logging on trail '{trail_name}' to "
                        "capture API activity across all AWS regions."
                    ),
                    details={"cis_benchmark": "3.1"},
                )
            )

        # 3. Log file validation
        if not trail.get("log_file_validation", False):
            findings.append(
                self._create_finding(
                    title=f"CloudTrail trail '{trail_name}' has log file validation disabled",
                    severity=Severity.HIGH,
                    resource_type="CloudTrail Trail",
                    resource_id=trail_name,
                    description=(
                        f"Log file validation is not enabled on trail "
                        f"'{trail_name}'. Without validation, tampered or deleted "
                        "log files may go undetected."
                    ),
                    recommendation=(
                        f"Enable log file validation on trail '{trail_name}' to "
                        "ensure integrity of CloudTrail logs."
                    ),
                    details={"cis_benchmark": "3.2"},
                )
            )

        # 4. KMS encryption
        if not trail.get("kms_encryption", False):
            findings.append(
                self._create_finding(
                    title=f"CloudTrail trail '{trail_name}' is not using KMS encryption",
                    severity=Severity.MEDIUM,
                    resource_type="CloudTrail Trail",
                    resource_id=trail_name,
                    description=(
                        f"Trail '{trail_name}' is not configured to encrypt log "
                        "files with a KMS CMK. SSE-S3 provides basic encryption "
                        "but KMS offers additional access controls."
                    ),
                    recommendation=(
                        f"Configure trail '{trail_name}' to use a KMS Customer "
                        "Managed Key (CMK) for server-side encryption."
                    ),
                    details={"cis_benchmark": "3.7"},
                )
            )

        # 5. S3 bucket logging
        if not trail.get("s3_bucket_logging", False):
            s3_bucket = trail.get("s3_bucket_name", "unknown")
            findings.append(
                self._create_finding(
                    title=(
                        f"S3 bucket for trail '{trail_name}' does not have "
                        "access logging enabled"
                    ),
                    severity=Severity.MEDIUM,
                    resource_type="CloudTrail Trail",
                    resource_id=trail_name,
                    description=(
                        f"The S3 bucket '{s3_bucket}' used by trail "
                        f"'{trail_name}' does not have server access logging "
                        "enabled. This limits the ability to audit who accessed "
                        "the CloudTrail logs themselves."
                    ),
                    recommendation=(
                        f"Enable server access logging on the S3 bucket "
                        f"'{s3_bucket}' used by trail '{trail_name}'."
                    ),
                    details={
                        "s3_bucket_name": s3_bucket,
                        "cis_benchmark": "3.6",
                    },
                )
            )

        return findings
