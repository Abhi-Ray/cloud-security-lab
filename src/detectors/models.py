"""Detection Engineering data models.

Defines the core types used throughout the detection module:
severity levels, MITRE ATT&CK tactics, detection rules, match
results, and batch-processing summaries.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


class RuleSeverity(enum.Enum):
    """Severity levels for detection rules, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    def __str__(self) -> str:
        return self.value


class MitreTactic(enum.Enum):
    """MITRE ATT&CK Enterprise tactics.

    Each value maps to the official tactic identifier used in the
    MITRE ATT&CK framework.
    """

    INITIAL_ACCESS = "Initial Access"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """A single detection rule that can evaluate CloudTrail-style events.

    Attributes:
        id: Unique rule identifier (e.g. ``CT-ROOT-001``).
        name: Short human-readable rule name.
        description: Detailed explanation of what the rule detects.
        severity: Severity level assigned to matches produced by this rule.
        mitre_tactics: MITRE ATT&CK tactics this rule maps to.
        data_source: Origin data source the rule is designed for
            (e.g. ``aws:cloudtrail``).
        detect_function: Callable that accepts an event dict and returns
            a :class:`DetectionMatch` or ``None``.
    """

    id: str
    name: str
    description: str
    severity: RuleSeverity
    mitre_tactics: list[MitreTactic]
    data_source: str
    detect_function: Callable[[dict[str, Any]], DetectionMatch | None]

    # Frozen dataclass with a mutable field needs an explicit hash override.
    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DetectionRule):
            return NotImplemented
        return self.id == other.id


@dataclass(slots=True)
class DetectionMatch:
    """A confirmed match produced when a detection rule fires on an event.

    Attributes:
        rule: The :class:`DetectionRule` that triggered.
        timestamp: ISO-8601 timestamp of the matching event.
        event: The raw event dictionary that triggered the match.
        details: Human-readable explanation of why the rule fired.
        recommended_action: Suggested remediation or investigation step.
    """

    rule: DetectionRule
    timestamp: str
    event: dict[str, Any]
    details: str
    recommended_action: str


@dataclass(slots=True)
class DetectionSummary:
    """Aggregated results from processing a batch of events.

    Attributes:
        rules_evaluated: Number of rules that were applied.
        events_processed: Number of events that were analysed.
        matches: List of all :class:`DetectionMatch` instances produced.
        timestamp: ISO-8601 time at which the summary was generated.
    """

    rules_evaluated: int
    events_processed: int
    matches: list[DetectionMatch] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
