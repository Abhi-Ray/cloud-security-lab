"""Command-line interface for the Cloud Security Scanner.

Entry point registered as ``cloudsec`` via *pyproject.toml*::

    cloudsec scan --demo            # run against built-in demo data
    cloudsec scan --config env.yaml # run against a YAML config file
    cloudsec scan --demo --output report.json  # write JSON report
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from security_scanner.aws.cloudtrail_scanner import CloudTrailScanner
from security_scanner.aws.iam_scanner import IAMScanner
from security_scanner.aws.s3_scanner import S3Scanner
from security_scanner.models import ScanConfig, ScanResult
from security_scanner.report import SecurityReportGenerator

__all__ = ["main"]

# ======================================================================
# Built-in demo configuration with deliberate security issues
# ======================================================================

DEMO_CONFIG: dict[str, Any] = {
    "iam": {
        "root_account": {
            "has_access_keys": True,
            "mfa_enabled": False,
        },
        "users": [
            {
                "username": "admin-alice",
                "has_mfa": False,
                "has_console_access": True,
                "last_activity_days": 2,
                "access_keys": [
                    {"age_days": 200, "last_used_days": 1},
                ],
            },
            {
                "username": "dev-bob",
                "has_mfa": True,
                "has_console_access": True,
                "last_activity_days": 5,
                "access_keys": [
                    {"age_days": 45, "last_used_days": 3},
                ],
            },
            {
                "username": "cicd-service",
                "has_mfa": False,
                "has_console_access": False,
                "last_activity_days": 150,
                "access_keys": [
                    {"age_days": 365, "last_used_days": 150},
                ],
            },
            {
                "username": "intern-charlie",
                "has_mfa": False,
                "has_console_access": True,
                "last_activity_days": 95,
                "access_keys": [],
            },
        ],
        "policies": [
            {
                "name": "FullAdminAccess",
                "effect": "Allow",
                "actions": ["*"],
                "resources": ["*"],
            },
            {
                "name": "S3ReadOnly",
                "effect": "Allow",
                "actions": ["s3:GetObject", "s3:ListBucket"],
                "resources": ["arn:aws:s3:::data-bucket/*"],
            },
            {
                "name": "EC2FullAccess",
                "effect": "Allow",
                "actions": ["ec2:*"],
                "resources": ["*"],
            },
        ],
        "password_policy": {
            "min_length": 8,
            "require_uppercase": False,
            "require_numbers": True,
            "require_symbols": False,
            "max_age_days": 0,
        },
    },
    "s3": {
        "buckets": [
            {
                "name": "prod-data-lake",
                "public_access_block": {
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                },
                "encryption": {"enabled": True, "algorithm": "aws:kms"},
                "versioning": True,
                "logging": False,
                "policy": None,
            },
            {
                "name": "marketing-assets",
                "public_access_block": {
                    "block_public_acls": False,
                    "ignore_public_acls": False,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                },
                "encryption": {"enabled": False},
                "versioning": False,
                "logging": False,
                "policy": {
                    "effect": "Allow",
                    "principal": "*",
                    "actions": ["s3:GetObject"],
                },
            },
            {
                "name": "cloudtrail-logs-bucket",
                "public_access_block": {
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True,
                },
                "encryption": {"enabled": True, "algorithm": "AES256"},
                "versioning": True,
                "logging": True,
                "policy": None,
            },
            {
                "name": "dev-scratch-bucket",
                "public_access_block": {
                    "block_public_acls": False,
                    "ignore_public_acls": False,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                },
                "encryption": {"enabled": False},
                "versioning": False,
                "logging": False,
                "policy": None,
            },
        ],
    },
    "cloudtrail": {
        "trails": [
            {
                "name": "main-trail",
                "is_enabled": True,
                "is_multi_region": False,
                "log_file_validation": False,
                "kms_encryption": False,
                "s3_bucket_logging": False,
                "s3_bucket_name": "cloudtrail-logs-bucket",
            },
            {
                "name": "legacy-trail",
                "is_enabled": False,
                "is_multi_region": False,
                "log_file_validation": False,
                "kms_encryption": False,
                "s3_bucket_logging": False,
                "s3_bucket_name": "old-ct-bucket",
            },
        ],
    },
}


# ======================================================================
# Scanner registry
# ======================================================================


def _get_all_scanners() -> list[IAMScanner | S3Scanner | CloudTrailScanner]:
    """Instantiate all available scanners."""
    return [
        IAMScanner(),
        S3Scanner(),
        CloudTrailScanner(),
    ]


def _run_scan(config: ScanConfig) -> list[ScanResult]:
    """Run every registered scanner against *config*."""
    scanners = _get_all_scanners()
    return [scanner.scan(config) for scanner in scanners]


# ======================================================================
# CLI definition
# ======================================================================


@click.group()
@click.version_option(version="0.1.0", prog_name="cloudsec")
def main() -> None:
    """☁️  Cloud Security Lab — Autonomous Security Scanner.

    Run security checks against AWS account configurations (mock data)
    and generate actionable reports.
    """


@main.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML configuration file to scan.",
)
@click.option(
    "--demo",
    is_flag=True,
    default=False,
    help="Run against the built-in demo configuration with known issues.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write a JSON report to this file instead of printing to terminal.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "text", "json"], case_sensitive=False),
    default="rich",
    help="Report output format (ignored when --output is set).",
)
def scan(
    config_path: Path | None,
    demo: bool,
    output_path: Path | None,
    output_format: str,
) -> None:
    """Run security scanners against AWS account configuration.

    Either --config or --demo must be specified.

    \b
    Examples:
        cloudsec scan --demo
        cloudsec scan --config my_env.yaml
        cloudsec scan --demo --output report.json
        cloudsec scan --demo --format text
    """
    if not demo and config_path is None:
        raise click.UsageError(
            "Either --demo or --config must be specified. "
            "Use 'cloudsec scan --demo' to try with sample data."
        )

    # Load configuration
    if demo:
        click.echo("🔍 Running scan against built-in demo configuration …")
        raw_config = DEMO_CONFIG
    else:
        assert config_path is not None
        click.echo(f"🔍 Loading configuration from {config_path} …")
        try:
            raw_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise click.ClickException(f"Failed to load config: {exc}") from exc

        if not isinstance(raw_config, dict):
            raise click.ClickException(
                "Configuration file must contain a YAML mapping at the top level."
            )

    scan_config = ScanConfig(config=raw_config)
    results = _run_scan(scan_config)
    reporter = SecurityReportGenerator()

    # Output
    if output_path is not None:
        json_data = reporter.generate_json_report(results)
        output_path.write_text(
            json.dumps(json_data, indent=2) + "\n",
            encoding="utf-8",
        )
        total = sum(r.total_findings for r in results)
        click.echo(f"✅ JSON report written to {output_path} ({total} findings)")
    elif output_format == "json":
        click.echo(reporter.generate_json_string(results))
    elif output_format == "text":
        click.echo(reporter.generate_text_report(results))
    else:
        reporter.print_report(results)

    # Exit code: non-zero if any CRITICAL or HIGH findings
    critical_high = sum(r.critical_count + r.high_count for r in results)
    if critical_high > 0:
        sys.exit(1)
