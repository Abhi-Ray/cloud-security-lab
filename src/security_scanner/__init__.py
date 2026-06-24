"""Cloud Security Scanner — autonomous security scanning for AWS configurations.

Quick start::

    from security_scanner import (
        IAMScanner, S3Scanner, CloudTrailScanner,
        ScanConfig, ScanResult, Finding, Severity,
        SecurityReportGenerator,
    )

    config = ScanConfig(config={...})
    results = [IAMScanner().scan(config)]
    SecurityReportGenerator().print_report(results)
"""

__version__ = "0.1.0"

from security_scanner.aws.cloudtrail_scanner import CloudTrailScanner
from security_scanner.aws.iam_scanner import IAMScanner
from security_scanner.aws.s3_scanner import S3Scanner
from security_scanner.base_scanner import BaseScanner
from security_scanner.models import Finding, ScanConfig, ScanResult, Severity
from security_scanner.report import SecurityReportGenerator

__all__ = [
    # Scanners
    "BaseScanner",
    "CloudTrailScanner",
    # Models
    "Finding",
    "IAMScanner",
    "S3Scanner",
    "ScanConfig",
    "ScanResult",
    # Reporting
    "SecurityReportGenerator",
    "Severity",
    # Version
    "__version__",
]
