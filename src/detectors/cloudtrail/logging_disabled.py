"""Logging-disabled detection rules.

Detects attempts to disable AWS audit and monitoring services:

* CloudTrail ``StopLogging`` — disables trail log delivery
* CloudTrail ``DeleteTrail`` — removes a trail entirely
* AWS Config ``StopConfigurationRecorder`` — disables config recording

These are hallmark defence-evasion techniques: an attacker disables
logging to cover subsequent actions.
"""

from __future__ import annotations

from typing import Any

from detectors.models import (
    DetectionMatch,
    DetectionRule,
    MitreTactic,
    RuleSeverity,
)

# ---------------------------------------------------------------------------
# detect_cloudtrail_stopped
# ---------------------------------------------------------------------------


def detect_cloudtrail_stopped(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect CloudTrail ``StopLogging`` API calls.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    if event.get("eventName") != "StopLogging":
        return None

    params = event.get("requestParameters", {})
    trail_name = params.get("name", "unknown")
    actor = _get_actor(event)

    details = (
        f"CloudTrail logging stopped for trail '{trail_name}' by {actor}. "
        f"This is a critical defence-evasion indicator — subsequent API "
        f"activity will NOT be recorded."
    )

    return DetectionMatch(
        rule=CLOUDTRAIL_STOPPED_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Immediately re-enable logging on the affected trail. "
            "Investigate the actor's activity BEFORE the StopLogging event "
            "and treat this as a potential incident until proven otherwise."
        ),
    )


CLOUDTRAIL_STOPPED_RULE = DetectionRule(
    id="CT-LOG-001",
    name="CloudTrail Logging Stopped",
    description=(
        "Detects the StopLogging API call which disables CloudTrail "
        "log delivery. Attackers disable logging to hide their "
        "subsequent activity."
    ),
    severity=RuleSeverity.CRITICAL,
    mitre_tactics=[MitreTactic.DEFENSE_EVASION],
    data_source="aws:cloudtrail",
    detect_function=detect_cloudtrail_stopped,
)


# ---------------------------------------------------------------------------
# detect_cloudtrail_deleted
# ---------------------------------------------------------------------------


def detect_cloudtrail_deleted(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect CloudTrail ``DeleteTrail`` API calls.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    if event.get("eventName") != "DeleteTrail":
        return None

    params = event.get("requestParameters", {})
    trail_name = params.get("name", "unknown")
    actor = _get_actor(event)

    details = (
        f"CloudTrail trail '{trail_name}' deleted by {actor}. "
        f"Deleting a trail removes historical log configuration and "
        f"is a strong indicator of defence evasion."
    )

    return DetectionMatch(
        rule=CLOUDTRAIL_DELETED_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Recreate the CloudTrail trail immediately. Investigate the "
            "actor's full session activity. Check S3 bucket policies "
            "for the trail's log bucket to ensure logs were not also deleted."
        ),
    )


CLOUDTRAIL_DELETED_RULE = DetectionRule(
    id="CT-LOG-002",
    name="CloudTrail Trail Deleted",
    description=(
        "Detects the DeleteTrail API call which permanently removes "
        "a CloudTrail trail configuration."
    ),
    severity=RuleSeverity.CRITICAL,
    mitre_tactics=[MitreTactic.DEFENSE_EVASION],
    data_source="aws:cloudtrail",
    detect_function=detect_cloudtrail_deleted,
)


# ---------------------------------------------------------------------------
# detect_config_stopped
# ---------------------------------------------------------------------------


def detect_config_stopped(event: dict[str, Any]) -> DetectionMatch | None:
    """Detect AWS Config ``StopConfigurationRecorder`` API calls.

    Args:
        event: A CloudTrail event dictionary.

    Returns:
        A :class:`DetectionMatch` or ``None``.
    """
    if event.get("eventName") != "StopConfigurationRecorder":
        return None

    params = event.get("requestParameters", {})
    recorder_name = params.get("configurationRecorderName", "unknown")
    actor = _get_actor(event)

    details = (
        f"AWS Config recorder '{recorder_name}' stopped by {actor}. "
        f"Disabling Config prevents resource configuration changes from "
        f"being recorded."
    )

    return DetectionMatch(
        rule=CONFIG_STOPPED_RULE,
        timestamp=event.get("eventTime", "unknown"),
        event=event,
        details=details,
        recommended_action=(
            "Re-start the configuration recorder immediately. "
            "Investigate what changes the actor may have made while "
            "recording was disabled."
        ),
    )


CONFIG_STOPPED_RULE = DetectionRule(
    id="CT-LOG-003",
    name="AWS Config Recorder Stopped",
    description=(
        "Detects the StopConfigurationRecorder API call which disables "
        "AWS Config resource change recording."
    ),
    severity=RuleSeverity.CRITICAL,
    mitre_tactics=[MitreTactic.DEFENSE_EVASION],
    data_source="aws:cloudtrail",
    detect_function=detect_cloudtrail_stopped,  # will be re-bound below
)

# Re-bind the detect_function to the correct callable (frozen dataclass
# workaround: we redefine the rule after the function is available).
CONFIG_STOPPED_RULE = DetectionRule(
    id="CT-LOG-003",
    name="AWS Config Recorder Stopped",
    description=(
        "Detects the StopConfigurationRecorder API call which disables "
        "AWS Config resource change recording."
    ),
    severity=RuleSeverity.CRITICAL,
    mitre_tactics=[MitreTactic.DEFENSE_EVASION],
    data_source="aws:cloudtrail",
    detect_function=detect_config_stopped,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_actor(event: dict[str, Any]) -> str:
    """Extract a human-readable actor identifier from a CloudTrail event."""
    identity = event.get("userIdentity", {})
    return identity.get("arn") or identity.get("userName") or identity.get("type", "unknown")
