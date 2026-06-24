"""Detection engine — orchestrates rule evaluation against event streams.

The :class:`DetectionEngine` is the central coordinator: it holds a
registry of :class:`DetectionRule` instances and exposes methods to
process individual events or batches, producing structured
:class:`DetectionMatch` and :class:`DetectionSummary` results.
"""

from __future__ import annotations

import logging
from typing import Any

from detectors.models import (
    DetectionMatch,
    DetectionRule,
    DetectionSummary,
)

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Event processing engine for cloud security detection rules.

    On instantiation the engine automatically registers every built-in
    CloudTrail detection rule.  Additional rules can be registered via
    :meth:`register_rule`.

    Example::

        engine = DetectionEngine()
        summary = engine.process_events(cloudtrail_events)
        for match in summary.matches:
            print(match.details)
    """

    def __init__(self, *, auto_register: bool = True) -> None:
        """Initialise the engine.

        Args:
            auto_register: If ``True`` (default), all built-in
                CloudTrail detection rules are registered
                automatically.
        """
        self._rules: dict[str, DetectionRule] = {}
        if auto_register:
            self._auto_register_cloudtrail_rules()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_rule(self, rule: DetectionRule) -> None:
        """Register a detection rule.

        Args:
            rule: The :class:`DetectionRule` to add.

        Raises:
            ValueError: If a rule with the same ``id`` is already
                registered.
        """
        if rule.id in self._rules:
            raise ValueError(
                f"A rule with id '{rule.id}' is already registered "
                f"(name='{self._rules[rule.id].name}')."
            )
        self._rules[rule.id] = rule
        logger.debug("Registered rule %s: %s", rule.id, rule.name)

    def get_rules(self) -> list[DetectionRule]:
        """Return all currently registered detection rules.

        Rules are returned in registration order.
        """
        return list(self._rules.values())

    def process_event(self, event: dict[str, Any]) -> list[DetectionMatch]:
        """Evaluate all registered rules against a single event.

        Args:
            event: A CloudTrail-style event dictionary.

        Returns:
            A list of :class:`DetectionMatch` instances (may be empty).
        """
        matches: list[DetectionMatch] = []
        for rule in self._rules.values():
            try:
                result = rule.detect_function(event)
                if result is not None:
                    matches.append(result)
            except Exception:
                logger.exception(
                    "Rule %s (%s) raised an exception while processing event '%s'",
                    rule.id,
                    rule.name,
                    event.get("eventName", "<unknown>"),
                )
        return matches

    def process_events(
        self,
        events: list[dict[str, Any]],
    ) -> DetectionSummary:
        """Evaluate all rules against a batch of events.

        Args:
            events: List of CloudTrail-style event dictionaries.

        Returns:
            A :class:`DetectionSummary` with aggregate statistics and
            all matches.
        """
        all_matches: list[DetectionMatch] = []
        for event in events:
            all_matches.extend(self.process_event(event))

        return DetectionSummary(
            rules_evaluated=len(self._rules),
            events_processed=len(events),
            matches=all_matches,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _auto_register_cloudtrail_rules(self) -> None:
        """Register every built-in CloudTrail detection rule."""
        from detectors.cloudtrail import get_all_cloudtrail_rules

        for rule in get_all_cloudtrail_rules():
            self.register_rule(rule)
        logger.info(
            "Auto-registered %d CloudTrail detection rules.",
            len(self._rules),
        )
