"""AWS-specific security scanners.

Re-exports the concrete scanner classes for convenient access::

    from security_scanner.aws import IAMScanner, S3Scanner, CloudTrailScanner
"""

from security_scanner.aws.cloudtrail_scanner import CloudTrailScanner
from security_scanner.aws.iam_scanner import IAMScanner
from security_scanner.aws.s3_scanner import S3Scanner

__all__ = [
    "CloudTrailScanner",
    "IAMScanner",
    "S3Scanner",
]
