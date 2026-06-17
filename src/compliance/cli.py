"""Compliance Engine CLI.

Provides a ``cloudsec-comply`` command-line interface for running
compliance assessments against a configuration file or a built-in
demo configuration.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from compliance.engine import ComplianceEngine
from compliance.models import CheckStatus, ComplianceReport, Framework, Severity


__all__ = ["main"]

console = Console()


# ---------------------------------------------------------------------------
# Built-in demo configuration
# ---------------------------------------------------------------------------

DEMO_CONFIG: dict[str, Any] = {
    # ── IAM ────────────────────────────────────────────────────────
    "iam": {
        "root_access_keys": [
            {"key_id": "AKIAIOSFODNN7EXAMPLE", "status": "Active"},
        ],
        "root_mfa_enabled": False,
        "users": [
            {
                "username": "alice",
                "enabled": True,
                "last_activity": "2026-01-15T10:00:00+00:00",
                "access_keys": [
                    {
                        "key_id": "AKIAI44QH8DHBEXAMPLE",
                        "status": "Active",
                        "created_date": "2025-11-01T00:00:00+00:00",
                    },
                ],
            },
            {
                "username": "bob",
                "enabled": True,
                "last_activity": "2026-06-10T08:30:00+00:00",
                "access_keys": [
                    {
                        "key_id": "AKIAI44QH8DHBEX2MPLE",
                        "status": "Active",
                        "created_date": "2026-05-20T00:00:00+00:00",
                    },
                ],
            },
            {
                "username": "charlie",
                "enabled": True,
                "last_activity": "2025-12-01T00:00:00+00:00",
                "access_keys": [],
            },
        ],
        "password_policy": {
            "minimum_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_symbols": False,
        },
        "policies": [
            {
                "name": "AdminAccess",
                "arn": "arn:aws:iam::123456789012:policy/AdminAccess",
                "statements": [
                    {"effect": "Allow", "action": "*", "resource": "*"},
                ],
            },
            {
                "name": "ReadOnlyAccess",
                "arn": "arn:aws:iam::123456789012:policy/ReadOnlyAccess",
                "statements": [
                    {"effect": "Allow", "action": "s3:Get*", "resource": "*"},
                ],
            },
        ],
    },
    # ── Logging ────────────────────────────────────────────────────
    "logging": {
        "cloudtrail": {
            "trails": [
                {
                    "name": "management-trail",
                    "is_logging": True,
                    "is_multi_region": True,
                    "log_file_validation_enabled": True,
                    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd1234",
                },
                {
                    "name": "data-trail",
                    "is_logging": True,
                    "is_multi_region": False,
                    "log_file_validation_enabled": False,
                    "kms_key_id": None,
                },
            ],
        },
    },
    # ── Encryption ─────────────────────────────────────────────────
    "encryption": {
        "ebs_default_encryption": False,
        "s3_buckets": [
            {"name": "prod-data-bucket", "encryption_enabled": True},
            {"name": "dev-logs-bucket", "encryption_enabled": True},
            {"name": "temp-upload-bucket", "encryption_enabled": False},
        ],
        "rds_instances": [
            {"id": "prod-db-1", "encrypted": True},
            {"id": "dev-db-1", "encrypted": False},
        ],
    },
    # ── Networking ─────────────────────────────────────────────────
    "networking": {
        "security_groups": [
            {
                "id": "sg-default-001",
                "name": "default",
                "is_default": True,
                "inbound_rules": [
                    {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
                ],
                "outbound_rules": [
                    {"port": 0, "cidr": "0.0.0.0/0", "protocol": "-1"},
                ],
            },
            {
                "id": "sg-web-001",
                "name": "web-servers",
                "is_default": False,
                "inbound_rules": [
                    {"port": 443, "cidr": "0.0.0.0/0", "protocol": "tcp"},
                    {"port": 80, "cidr": "0.0.0.0/0", "protocol": "tcp"},
                ],
                "outbound_rules": [],
            },
            {
                "id": "sg-ssh-open",
                "name": "ssh-open",
                "is_default": False,
                "inbound_rules": [
                    {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
                ],
                "outbound_rules": [],
            },
        ],
        "vpcs": [
            {"id": "vpc-prod-001", "flow_logs_enabled": True},
            {"id": "vpc-dev-001", "flow_logs_enabled": False},
        ],
    },
}


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

_FRAMEWORK_MAP: dict[str, Framework] = {
    "cis-aws": Framework.CIS_AWS,
    "iso-27001": Framework.ISO_27001,
    "nist-csf": Framework.NIST_CSF,
    "soc2": Framework.SOC2,
}


@click.group()
@click.version_option(version="0.1.0", prog_name="cloudsec-comply")
def main() -> None:
    """Cloud Security Lab — Compliance Assessment Engine."""


@main.command()
@click.option(
    "--framework",
    "framework_name",
    type=click.Choice(list(_FRAMEWORK_MAP.keys()), case_sensitive=False),
    default="cis-aws",
    show_default=True,
    help="Compliance framework to assess against.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a JSON configuration file.",
)
@click.option(
    "--demo",
    is_flag=True,
    default=False,
    help="Run against the built-in demo configuration.",
)
def assess(
    framework_name: str,
    config_path: Path | None,
    demo: bool,
) -> None:
    """Run a compliance assessment."""
    if not demo and config_path is None:
        console.print(
            "[red]Error:[/red] Provide --config <path> or --demo.",
        )
        sys.exit(1)

    # Load configuration
    if demo:
        config = DEMO_CONFIG
        console.print(
            "[dim]Using built-in demo configuration.[/dim]\n",
        )
    else:
        assert config_path is not None  # guaranteed by guard above
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Error reading config:[/red] {exc}")
            sys.exit(1)

    framework = _FRAMEWORK_MAP[framework_name.lower()]
    engine = ComplianceEngine()

    try:
        report = engine.run_assessment(config, framework)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    _print_report(report)


@main.command(name="list-frameworks")
def list_frameworks() -> None:
    """List available compliance frameworks."""
    engine = ComplianceEngine()
    table = Table(title="Registered Compliance Frameworks")
    table.add_column("Key", style="cyan")
    table.add_column("Framework", style="bold")
    table.add_column("Checks", justify="right")

    for key, fw in _FRAMEWORK_MAP.items():
        checks = engine.get_checks(fw)
        count = str(len(checks)) if checks else "[dim]0[/dim]"
        table.add_row(key, fw.value, count)

    console.print(table)


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

_STATUS_STYLE: dict[CheckStatus, str] = {
    CheckStatus.PASS: "[green]✓ PASS[/green]",
    CheckStatus.FAIL: "[red]✗ FAIL[/red]",
    CheckStatus.ERROR: "[yellow]⚠ ERROR[/yellow]",
    CheckStatus.NOT_APPLICABLE: "[dim]— N/A[/dim]",
}

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
    Severity.HIGH: "[red]HIGH[/red]",
    Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
    Severity.LOW: "[blue]LOW[/blue]",
    Severity.INFO: "[dim]INFO[/dim]",
}


def _print_report(report: ComplianceReport) -> None:
    """Render a compliance report to the terminal using Rich."""
    # Header panel
    score_color = "green" if report.score >= 80 else ("yellow" if report.score >= 50 else "red")
    header = (
        f"[bold]{report.framework.value}[/bold]\n"
        f"Assessed: {report.timestamp:%Y-%m-%d %H:%M:%S UTC}\n"
        f"Score: [{score_color}]{report.score:.1f}%[/{score_color}]  "
        f"({report.pass_count} passed · {report.fail_count} failed · "
        f"{report.error_count} errors · {report.not_applicable_count} N/A)"
    )
    console.print(Panel(header, title="Compliance Assessment Report", expand=False))
    console.print()

    # Results table
    table = Table(show_lines=True, expand=True)
    table.add_column("Section", style="cyan", width=8)
    table.add_column("Status", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Check", ratio=2)
    table.add_column("Details", ratio=3)

    for result in report.results:
        status_str = _STATUS_STYLE.get(result.status, str(result.status.value))
        severity_str = _SEVERITY_STYLE.get(
            result.check.severity, str(result.check.severity.value)
        )

        details = result.details
        if result.recommendation and result.status == CheckStatus.FAIL:
            details += f"\n[dim]→ {result.recommendation}[/dim]"

        table.add_row(
            result.check.section,
            status_str,
            severity_str,
            result.check.title,
            details,
        )

    console.print(table)
    console.print()

    # Summary bar
    total = len(report.results)
    if total > 0:
        bar_width = 40
        pass_bar = int(bar_width * report.pass_count / total)
        fail_bar = int(bar_width * report.fail_count / total)
        other_bar = bar_width - pass_bar - fail_bar
        bar = (
            f"[green]{'█' * pass_bar}[/green]"
            f"[red]{'█' * fail_bar}[/red]"
            f"[dim]{'░' * other_bar}[/dim]"
        )
        console.print(f"  {bar}  {report.pass_count}/{total} checks passed")
    console.print()


if __name__ == "__main__":
    main()
