"""CloudTrail detection rules package.

Exposes individual detection functions and a convenience helper
:func:`get_all_cloudtrail_rules` that returns every built-in
CloudTrail detection rule.
"""

from __future__ import annotations

from detectors.models import DetectionRule

from detectors.cloudtrail.iam_changes import (
    ADMIN_POLICY_ATTACHMENT_RULE,
    NEW_USER_CREATION_RULE,
    POLICY_MODIFICATION_RULE,
)
from detectors.cloudtrail.logging_disabled import (
    CLOUDTRAIL_DELETED_RULE,
    CLOUDTRAIL_STOPPED_RULE,
    CONFIG_STOPPED_RULE,
)
from detectors.cloudtrail.root_login import ROOT_CONSOLE_LOGIN_RULE
from detectors.cloudtrail.security_group_changes import (
    SG_DELETION_RULE,
    SG_INGRESS_MODIFICATION_RULE,
)

__all__ = [
    "get_all_cloudtrail_rules",
    "ADMIN_POLICY_ATTACHMENT_RULE",
    "NEW_USER_CREATION_RULE",
    "POLICY_MODIFICATION_RULE",
    "CLOUDTRAIL_DELETED_RULE",
    "CLOUDTRAIL_STOPPED_RULE",
    "CONFIG_STOPPED_RULE",
    "ROOT_CONSOLE_LOGIN_RULE",
    "SG_DELETION_RULE",
    "SG_INGRESS_MODIFICATION_RULE",
]


def get_all_cloudtrail_rules() -> list[DetectionRule]:
    """Return all built-in CloudTrail detection rules."""
    return [
        ROOT_CONSOLE_LOGIN_RULE,
        ADMIN_POLICY_ATTACHMENT_RULE,
        NEW_USER_CREATION_RULE,
        POLICY_MODIFICATION_RULE,
        SG_INGRESS_MODIFICATION_RULE,
        SG_DELETION_RULE,
        CLOUDTRAIL_STOPPED_RULE,
        CLOUDTRAIL_DELETED_RULE,
        CONFIG_STOPPED_RULE,
    ]
