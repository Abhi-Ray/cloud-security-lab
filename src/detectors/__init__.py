"""Detection Engineering module for Cloud Security Lab.

This package provides a rule-based detection engine that evaluates
CloudTrail-style events against a library of security detection
rules, producing structured match results with MITRE ATT&CK mapping
and remediation guidance.

Quick start::

    from detectors.engine import DetectionEngine

    engine = DetectionEngine()
    summary = engine.process_events(my_cloudtrail_events)
    for match in summary.matches:
        print(match.rule.name, match.details)
"""

from detectors.models import (
    DetectionMatch,
    DetectionRule,
    DetectionSummary,
    MitreTactic,
    RuleSeverity,
)
from detectors.engine import DetectionEngine

__all__ = [
    "DetectionEngine",
    "DetectionMatch",
    "DetectionRule",
    "DetectionSummary",
    "MitreTactic",
    "RuleSeverity",
]
