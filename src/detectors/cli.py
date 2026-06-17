"""CLI for the Detection Engineering module.

Provides the ``cloudsec-detect`` command with two sub-commands:

* ``analyze`` — process CloudTrail events from a JSON file or built-in
  demo data.
* ``rules`` — list all registered detection rules with severity and
  MITRE ATT&CK mapping.

Usage::

    cloudsec-detect analyze --demo
    cloudsec-detect analyze --events trail.json
    cloudsec-detect rules
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from detectors.engine import DetectionEngine
from detectors.models import DetectionMatch, DetectionSummary

# ---------------------------------------------------------------------------
# Built-in demo CloudTrail events
# ---------------------------------------------------------------------------

DEMO_EVENTS: list[dict[str, Any]] = [
    # 1 — Root console login (SHOULD trigger CT-ROOT-001)
    {
        "eventTime": "2024-01-15T10:30:00Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {
            "type": "Root",
            "arn": "arn:aws:iam::123456789012:root",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "198.51.100.1",
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success"},
    },
    # 2 — Normal IAM user console login (should NOT trigger)
    {
        "eventTime": "2024-01-15T10:35:00Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "userName": "alice",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "203.0.113.50",
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success"},
    },
    # 3 — Admin policy attached to user (SHOULD trigger CT-IAM-001)
    {
        "eventTime": "2024-01-15T11:00:00Z",
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/mallory",
            "userName": "mallory",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "198.51.100.42",
        "requestParameters": {
            "userName": "backdoor-user",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        "responseElements": None,
    },
    # 4 — New IAM user creation (SHOULD trigger CT-IAM-002)
    {
        "eventTime": "2024-01-15T11:05:00Z",
        "eventName": "CreateUser",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/mallory",
            "userName": "mallory",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "198.51.100.42",
        "requestParameters": {"userName": "backdoor-user"},
        "responseElements": {
            "user": {
                "userName": "backdoor-user",
                "userId": "AIDAEXAMPLE123456",
                "arn": "arn:aws:iam::123456789012:user/backdoor-user",
            }
        },
    },
    # 5 — Dangerous inline policy creation (SHOULD trigger CT-IAM-003)
    {
        "eventTime": "2024-01-15T11:10:00Z",
        "eventName": "PutUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/mallory",
            "userName": "mallory",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "198.51.100.42",
        "requestParameters": {
            "userName": "backdoor-user",
            "policyName": "full-access",
            "policyDocument": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
            ),
        },
        "responseElements": None,
    },
    # 6 — Security group opened to 0.0.0.0/0 (SHOULD trigger CT-NET-001)
    {
        "eventTime": "2024-01-15T12:00:00Z",
        "eventName": "AuthorizeSecurityGroupIngress",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/bob",
            "userName": "bob",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "203.0.113.10",
        "requestParameters": {
            "groupId": "sg-0abc123def456",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {
                            "items": [{"cidrIp": "0.0.0.0/0"}],
                        },
                    }
                ]
            },
        },
        "responseElements": {"_return": True},
    },
    # 7 — CloudTrail stopped (SHOULD trigger CT-LOG-001)
    {
        "eventTime": "2024-01-15T13:00:00Z",
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/mallory",
            "userName": "mallory",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "198.51.100.42",
        "requestParameters": {"name": "management-trail"},
        "responseElements": None,
    },
    # 8 — DescribeInstances (should NOT trigger)
    {
        "eventTime": "2024-01-15T14:00:00Z",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "userName": "alice",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "203.0.113.50",
        "requestParameters": {"instancesSet": {"items": []}},
        "responseElements": None,
    },
    # 9 — ListBuckets (should NOT trigger)
    {
        "eventTime": "2024-01-15T14:05:00Z",
        "eventName": "ListBuckets",
        "eventSource": "s3.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "userName": "alice",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "203.0.113.50",
        "requestParameters": None,
        "responseElements": None,
    },
    # 10 — DeleteTrail (SHOULD trigger CT-LOG-002)
    {
        "eventTime": "2024-01-15T15:00:00Z",
        "eventName": "DeleteTrail",
        "eventSource": "cloudtrail.amazonaws.com",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/mallory",
            "userName": "mallory",
            "accountId": "123456789012",
        },
        "sourceIPAddress": "198.51.100.42",
        "requestParameters": {"name": "management-trail"},
        "responseElements": None,
    },
]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "red",
    "HIGH": "bright_red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFORMATIONAL": "white",
}


def _print_match(match: DetectionMatch, index: int) -> None:
    """Pretty-print a single detection match."""
    sev = str(match.rule.severity)
    colour = _SEVERITY_COLOURS.get(sev, "white")
    tactics = ", ".join(str(t) for t in match.rule.mitre_tactics)

    click.echo()
    click.secho(f"  ┌─ Match #{index}", bold=True)
    click.echo(f"  │ Rule       : {match.rule.id} — {match.rule.name}")
    click.echo(f"  │ Severity   : ", nl=False)
    click.secho(sev, fg=colour, bold=True)
    click.echo(f"  │ MITRE      : {tactics}")
    click.echo(f"  │ Timestamp  : {match.timestamp}")
    click.echo(f"  │ Event      : {match.event.get('eventName', 'N/A')}")
    click.echo(f"  │ Details    : {match.details}")
    click.echo(f"  │ Action     : {match.recommended_action}")
    click.secho("  └─", bold=True)


def _print_summary(summary: DetectionSummary) -> None:
    """Pretty-print the detection summary."""
    click.echo()
    click.secho("═" * 72, fg="blue", bold=True)
    click.secho("  DETECTION SUMMARY", fg="blue", bold=True)
    click.secho("═" * 72, fg="blue", bold=True)
    click.echo(f"  Rules evaluated   : {summary.rules_evaluated}")
    click.echo(f"  Events processed  : {summary.events_processed}")

    if summary.matches:
        click.echo(f"  Matches found     : ", nl=False)
        click.secho(str(len(summary.matches)), fg="red", bold=True)
    else:
        click.echo(f"  Matches found     : ", nl=False)
        click.secho("0", fg="green", bold=True)

    click.echo(f"  Generated at      : {summary.timestamp}")
    click.secho("═" * 72, fg="blue", bold=True)

    if summary.matches:
        # Group by severity for a quick breakdown.
        severity_counts: dict[str, int] = {}
        for m in summary.matches:
            sev = str(m.rule.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        click.echo()
        click.secho("  Breakdown by severity:", bold=True)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            count = severity_counts.get(sev, 0)
            if count:
                colour = _SEVERITY_COLOURS.get(sev, "white")
                click.echo(f"    {sev:15s} : ", nl=False)
                click.secho(str(count), fg=colour, bold=True)


# ---------------------------------------------------------------------------
# Click CLI
# ---------------------------------------------------------------------------

@click.group()
def main() -> None:
    """Cloud Security Detection Engineering — analyse CloudTrail events."""


@main.command()
@click.option(
    "--events",
    "events_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a JSON file containing a list of CloudTrail events.",
)
@click.option(
    "--demo",
    is_flag=True,
    default=False,
    help="Run analysis against built-in demo events.",
)
def analyze(events_file: Path | None, demo: bool) -> None:
    """Analyse CloudTrail events against detection rules."""
    if not events_file and not demo:
        click.secho(
            "Error: Provide --events <file> or --demo.",
            fg="red",
            err=True,
        )
        sys.exit(1)

    if demo:
        events = DEMO_EVENTS
        click.secho(
            f"\n  Running demo analysis with {len(events)} built-in events…\n",
            fg="cyan",
            bold=True,
        )
    else:
        assert events_file is not None  # guaranteed by the guard above
        try:
            raw = events_file.read_text(encoding="utf-8")
            events = json.loads(raw)
            if not isinstance(events, list):
                click.secho(
                    "Error: JSON file must contain a top-level array of events.",
                    fg="red",
                    err=True,
                )
                sys.exit(1)
        except (json.JSONDecodeError, OSError) as exc:
            click.secho(f"Error reading events file: {exc}", fg="red", err=True)
            sys.exit(1)
        click.secho(
            f"\n  Loaded {len(events)} events from {events_file}\n",
            fg="cyan",
            bold=True,
        )

    engine = DetectionEngine()
    summary = engine.process_events(events)

    # Print individual matches.
    for idx, match in enumerate(summary.matches, start=1):
        _print_match(match, idx)

    # Print summary.
    _print_summary(summary)
    click.echo()


@main.command(name="rules")
def list_rules() -> None:
    """List all registered detection rules."""
    engine = DetectionEngine()
    rules = engine.get_rules()

    click.echo()
    click.secho("═" * 72, fg="blue", bold=True)
    click.secho("  REGISTERED DETECTION RULES", fg="blue", bold=True)
    click.secho("═" * 72, fg="blue", bold=True)
    click.echo()

    for rule in rules:
        sev = str(rule.severity)
        colour = _SEVERITY_COLOURS.get(sev, "white")
        tactics = ", ".join(str(t) for t in rule.mitre_tactics)

        click.echo(f"  {rule.id}  ", nl=False)
        click.secho(f"[{sev}]", fg=colour, bold=True, nl=False)
        click.echo(f"  {rule.name}")
        click.echo(f"           {rule.description}")
        click.echo(f"           MITRE: {tactics}")
        click.echo(f"           Source: {rule.data_source}")
        click.echo()

    click.secho(f"  Total: {len(rules)} rules registered.", fg="blue", bold=True)
    click.echo()


if __name__ == "__main__":
    main()
