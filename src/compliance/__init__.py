"""Compliance Engine — automated compliance assessment framework.

Provides a pluggable engine for running security and compliance checks
against cloud environment configurations.  Ships with built-in support
for the CIS AWS Foundations Benchmark.

Quick start::

    from compliance.engine import ComplianceEngine
    from compliance.models import Framework

    engine = ComplianceEngine()
    report = engine.run_assessment(config, Framework.CIS_AWS)
    print(f"Score: {report.score:.1f}%")
"""

from __future__ import annotations

from compliance.engine import ComplianceEngine
from compliance.models import (
    CheckResult,
    CheckStatus,
    ComplianceCheck,
    ComplianceReport,
    Framework,
    Severity,
)

__all__ = [
    "CheckResult",
    "CheckStatus",
    "ComplianceCheck",
    "ComplianceEngine",
    "ComplianceReport",
    "Framework",
    "Severity",
]
