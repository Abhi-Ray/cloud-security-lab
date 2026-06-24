"""Security scan report generation.

Provides :class:`SecurityReportGenerator` with three output modes:

* **Text** — plain-text report suitable for files or piping.
* **JSON** — machine-readable dictionary for downstream tooling.
* **Rich terminal** — colourised table output using the *rich* library.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from security_scanner.models import Finding, ScanResult, Severity

__all__ = ["SecurityReportGenerator"]

# Severity → (rich colour tag, ANSI-safe label)
_SEVERITY_STYLES: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("bold red", "🔴 CRITICAL"),
    Severity.HIGH: ("bold orange1", "🟠 HIGH"),
    Severity.MEDIUM: ("bold yellow", "🟡 MEDIUM"),
    Severity.LOW: ("bold blue", "🔵 LOW"),
    Severity.INFO: ("bold dim", "ℹ️  INFO"),
}


class SecurityReportGenerator:
    """Generate human- and machine-readable reports from scan results.

    Usage::

        gen = SecurityReportGenerator()
        text = gen.generate_text_report(results)
        data = gen.generate_json_report(results)
        gen.print_report(results)  # colourised terminal output
    """

    # ------------------------------------------------------------------
    # Text report
    # ------------------------------------------------------------------

    def generate_text_report(self, results: list[ScanResult]) -> str:
        """Produce a plain-text report from one or more scan results.

        Args:
            results: List of :class:`ScanResult` objects.

        Returns:
            A multi-line string containing the formatted report.
        """
        lines: list[str] = []
        width = 80

        lines.append("=" * width)
        lines.append("CLOUD SECURITY SCAN REPORT".center(width))
        lines.append(
            f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}".center(width)
        )
        lines.append("=" * width)
        lines.append("")

        # Aggregate summary
        all_findings = self._collect_findings(results)
        lines.append(self._text_summary(all_findings, results))

        # Per-scanner sections
        for result in results:
            lines.append("")
            lines.append("-" * width)
            lines.append(f"Scanner: {result.scanner_name}")
            lines.append(
                f"  Scan time: {result.scan_duration_ms:.1f} ms  |  "
                f"Findings: {result.total_findings}"
            )
            lines.append("-" * width)

            if not result.findings:
                lines.append("  ✅ No findings — all checks passed.")
                continue

            for severity in Severity:
                sev_findings = result.findings_by_severity(severity)
                if not sev_findings:
                    continue
                _, label = _SEVERITY_STYLES[severity]
                lines.append(f"\n  [{label}]")
                for f in sev_findings:
                    lines.append(f"    • {f.title}")
                    lines.append(f"      Resource: {f.resource_type} / {f.resource_id}")
                    lines.append(f"      {f.description}")
                    lines.append(f"      ➜ {f.recommendation}")
                    lines.append("")

        lines.append("=" * width)
        lines.append("END OF REPORT".center(width))
        lines.append("=" * width)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON report
    # ------------------------------------------------------------------

    def generate_json_report(self, results: list[ScanResult]) -> dict[str, Any]:
        """Produce a JSON-serialisable dictionary from scan results.

        Args:
            results: List of :class:`ScanResult` objects.

        Returns:
            A nested dict suitable for ``json.dumps()``.
        """
        all_findings = self._collect_findings(results)
        return {
            "report": {
                "generated_at": datetime.now(UTC).isoformat(),
                "total_findings": len(all_findings),
                "severity_summary": self._severity_counts(all_findings),
                "scanners": [r.to_dict() for r in results],
            }
        }

    def generate_json_string(self, results: list[ScanResult]) -> str:
        """Convenience wrapper returning an indented JSON string."""
        return json.dumps(self.generate_json_report(results), indent=2)

    # ------------------------------------------------------------------
    # Rich terminal report
    # ------------------------------------------------------------------

    def print_report(self, results: list[ScanResult]) -> None:
        """Print a colourised report to the terminal using *rich*.

        Args:
            results: List of :class:`ScanResult` objects.
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
        except ImportError:  # pragma: no cover
            # Graceful degradation — fall back to plain text.
            print(self.generate_text_report(results))
            return

        console = Console()

        # Title
        console.print()
        console.print(
            Panel.fit(
                "[bold white]☁️  Cloud Security Scan Report[/bold white]",
                border_style="bright_cyan",
            )
        )

        # Summary table
        all_findings = self._collect_findings(results)
        summary_table = Table(
            title="Summary",
            show_header=True,
            header_style="bold white",
            border_style="dim",
        )
        summary_table.add_column("Severity", style="bold", min_width=12)
        summary_table.add_column("Count", justify="right", min_width=8)

        counts = self._severity_counts(all_findings)
        for sev in Severity:
            style, _ = _SEVERITY_STYLES[sev]
            summary_table.add_row(
                Text(sev.value, style=style),
                str(counts[sev.value]),
            )
        summary_table.add_row(
            Text("TOTAL", style="bold white"),
            Text(str(len(all_findings)), style="bold white"),
        )
        console.print(summary_table)

        # Per-scanner findings
        for result in results:
            console.print()
            scanner_table = Table(
                title=f"{result.scanner_name}  ({result.total_findings} findings, "
                f"{result.scan_duration_ms:.1f} ms)",
                show_header=True,
                header_style="bold white",
                border_style="dim",
                show_lines=True,
                expand=True,
            )
            scanner_table.add_column("Severity", style="bold", width=10)
            scanner_table.add_column("Title", min_width=30, ratio=2)
            scanner_table.add_column("Resource", min_width=15, ratio=1)
            scanner_table.add_column("Recommendation", min_width=25, ratio=2)

            if not result.findings:
                scanner_table.add_row("✅", "All checks passed", "", "")
            else:
                # Sort by severity descending
                sorted_findings = sorted(
                    result.findings,
                    key=lambda f: f.severity.numeric_weight,
                    reverse=True,
                )
                for f in sorted_findings:
                    style, _ = _SEVERITY_STYLES[f.severity]
                    scanner_table.add_row(
                        Text(f.severity.value, style=style),
                        f.title,
                        f"{f.resource_type}\n{f.resource_id}",
                        f.recommendation,
                    )

            console.print(scanner_table)

        console.print()
        console.print(
            f"[dim]Report generated at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]"
        )
        console.print()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_findings(results: list[ScanResult]) -> list[Finding]:
        """Flatten findings from all scan results."""
        findings: list[Finding] = []
        for r in results:
            findings.extend(r.findings)
        return findings

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> dict[str, int]:
        """Count findings per severity level."""
        counts = {sev.value: 0 for sev in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        return counts

    @staticmethod
    def _text_summary(findings: list[Finding], results: list[ScanResult]) -> str:
        """Build the summary block for the text report."""
        counts = SecurityReportGenerator._severity_counts(findings)
        total_duration = sum(r.scan_duration_ms for r in results)
        lines = [
            "SUMMARY",
            f"  Scanners run : {len(results)}",
            f"  Total time   : {total_duration:.1f} ms",
            f"  Total findings: {len(findings)}",
            "",
        ]
        for sev in Severity:
            _, label = _SEVERITY_STYLES[sev]
            lines.append(f"    {label:<16s}: {counts[sev.value]}")
        return "\n".join(lines)
