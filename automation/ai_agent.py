"""Security Lab AI Agent — orchestrates automated improvements.

The agent assesses the current project state, selects a relevant task,
generates implementation code (via OpenRouter or local templates),
validates the result, and commits with a conventional-commit message.

It degrades gracefully when no API key is configured by falling back to
the :class:`TaskGenerator` and built-in code templates.
"""

from __future__ import annotations

import logging
import subprocess
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from automation.config import AgentConfig
from automation.github_manager import GitManager
from automation.openrouter_client import APINotConfigured, OpenRouterClient, RateLimitExceeded
from automation.task_generator import TaskGenerator

__all__ = ["SecurityLabAgent"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in code templates used when the AI API is unavailable
# ---------------------------------------------------------------------------

_PYTHON_SCANNER_TEMPLATE = textwrap.dedent('''\
    """Auto-generated {title}.

    {description}
    """

    from __future__ import annotations

    import logging
    from typing import Any

    from security_scanner.models import Finding, Severity

    __all__ = ["{class_name}"]

    logger = logging.getLogger(__name__)


    class {class_name}:
        """Scanner for {title}.

        {description}
        """

        name: str = "{title}"

        def scan(self, config: dict[str, Any]) -> list[Finding]:
            """Run security checks against the provided configuration.

            Args:
                config: Dict representing the cloud resource configuration
                    to scan (mock data format).

            Returns:
                List of security findings.
            """
            findings: list[Finding] = []
            logger.info("Starting %s scan", self.name)

            findings.extend(self._check_encryption(config))
            findings.extend(self._check_public_access(config))
            findings.extend(self._check_logging(config))

            logger.info(
                "Scan complete — %d finding(s) detected", len(findings)
            )
            return findings

        def _check_encryption(self, config: dict[str, Any]) -> list[Finding]:
            """Check encryption configuration."""
            findings: list[Finding] = []
            if not config.get("encryption_enabled", False):
                findings.append(Finding(
                    id="{rule_prefix}-001",
                    title="Encryption not enabled",
                    severity=Severity.HIGH,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Resource does not have encryption enabled at rest.",
                    recommendation="Enable encryption using AWS KMS or service-default keys.",
                ))
            return findings

        def _check_public_access(self, config: dict[str, Any]) -> list[Finding]:
            """Check public access configuration."""
            findings: list[Finding] = []
            if config.get("publicly_accessible", False):
                findings.append(Finding(
                    id="{rule_prefix}-002",
                    title="Resource is publicly accessible",
                    severity=Severity.CRITICAL,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Resource is configured for public access.",
                    recommendation="Disable public access and restrict to VPC.",
                ))
            return findings

        def _check_logging(self, config: dict[str, Any]) -> list[Finding]:
            """Check logging / monitoring configuration."""
            findings: list[Finding] = []
            if not config.get("logging_enabled", False):
                findings.append(Finding(
                    id="{rule_prefix}-003",
                    title="Logging not enabled",
                    severity=Severity.MEDIUM,
                    resource_type="Cloud Resource",
                    resource_id=config.get("resource_id", "unknown"),
                    description="Audit logging is not enabled for this resource.",
                    recommendation="Enable audit logging for security monitoring.",
                ))
            return findings
''')

_PYTHON_TEST_TEMPLATE = textwrap.dedent('''\
    """Tests for {title}."""

    from __future__ import annotations

    import pytest

    from security_scanner.models import Finding


    class Test{class_name}:
        """Unit tests for {class_name}."""

        def test_scan_detects_missing_encryption(self) -> None:
            """Encryption check should flag unencrypted resources."""
            from {module_path} import {class_name}

            scanner = {class_name}()
            config = {{
                "resource_id": "test-resource-001",
                "encryption_enabled": False,
                "publicly_accessible": False,
                "logging_enabled": True,
            }}
            findings = scanner.scan(config)
            assert any(f.id.endswith("-001") for f in findings)

        def test_scan_detects_public_access(self) -> None:
            """Public access check should flag exposed resources."""
            from {module_path} import {class_name}

            scanner = {class_name}()
            config = {{
                "resource_id": "test-resource-002",
                "encryption_enabled": True,
                "publicly_accessible": True,
                "logging_enabled": True,
            }}
            findings = scanner.scan(config)
            assert any(f.id.endswith("-002") for f in findings)

        def test_scan_clean_config(self) -> None:
            """A fully-compliant config should produce no findings."""
            from {module_path} import {class_name}

            scanner = {class_name}()
            config = {{
                "resource_id": "test-resource-003",
                "encryption_enabled": True,
                "publicly_accessible": False,
                "logging_enabled": True,
            }}
            findings = scanner.scan(config)
            assert len(findings) == 0

        def test_scan_detects_missing_logging(self) -> None:
            """Logging check should flag resources without audit logs."""
            from {module_path} import {class_name}

            scanner = {class_name}()
            config = {{
                "resource_id": "test-resource-004",
                "encryption_enabled": True,
                "publicly_accessible": False,
                "logging_enabled": False,
            }}
            findings = scanner.scan(config)
            assert any(f.id.endswith("-003") for f in findings)
''')

_COMPLIANCE_CHECK_TEMPLATE = textwrap.dedent('''\
    """Auto-generated {title}.

    {description}
    """

    from __future__ import annotations

    import logging
    from dataclasses import dataclass, field
    from enum import Enum
    from typing import Any

    __all__ = ["{class_name}"]

    logger = logging.getLogger(__name__)


    class ComplianceStatus(Enum):
        """Result status for a compliance check."""
        PASS = "PASS"
        FAIL = "FAIL"
        NOT_APPLICABLE = "NOT_APPLICABLE"
        ERROR = "ERROR"


    @dataclass
    class CheckResult:
        """Result of a single compliance check.

        Attributes:
            check_id: Unique check identifier.
            title: Human-readable title.
            status: Pass/fail/N-A/error status.
            resource: Affected resource identifier.
            details: Additional context.
            remediation: How to fix failures.
        """
        check_id: str
        title: str
        status: ComplianceStatus
        resource: str
        details: str
        remediation: str = ""


    @dataclass
    class {class_name}:
        """Compliance checker for {title}.

        {description}

        Attributes:
            results: Results from the last run.
        """
        results: list[CheckResult] = field(default_factory=list)

        def check(self, config: dict[str, Any]) -> list[CheckResult]:
            """Evaluate compliance against the provided configuration.

            Args:
                config: Dict representing the cloud environment
                    configuration (mock data format).

            Returns:
                List of compliance check results.
            """
            self.results.clear()
            logger.info("Running %s compliance checks", self.__class__.__name__)

            self._check_encryption_requirements(config)
            self._check_access_controls(config)
            self._check_monitoring(config)

            passed = sum(1 for r in self.results if r.status == ComplianceStatus.PASS)
            total = len(self.results)
            logger.info("Compliance checks complete — %d/%d passed", passed, total)
            return list(self.results)

        def _check_encryption_requirements(self, config: dict[str, Any]) -> None:
            """Verify encryption requirements are met."""
            encrypted = config.get("encryption_enabled", False)
            self.results.append(CheckResult(
                check_id="{rule_prefix}-enc-01",
                title="Encryption at rest",
                status=ComplianceStatus.PASS if encrypted else ComplianceStatus.FAIL,
                resource=config.get("resource_id", "unknown"),
                details="Encryption at rest is " + ("enabled" if encrypted else "disabled"),
                remediation="" if encrypted else "Enable encryption at rest with KMS.",
            ))

        def _check_access_controls(self, config: dict[str, Any]) -> None:
            """Verify access control requirements."""
            mfa = config.get("mfa_enabled", False)
            self.results.append(CheckResult(
                check_id="{rule_prefix}-ac-01",
                title="MFA enforcement",
                status=ComplianceStatus.PASS if mfa else ComplianceStatus.FAIL,
                resource=config.get("resource_id", "unknown"),
                details="MFA is " + ("enabled" if mfa else "not enabled"),
                remediation="" if mfa else "Enable MFA for all privileged users.",
            ))

        def _check_monitoring(self, config: dict[str, Any]) -> None:
            """Verify monitoring and logging requirements."""
            logging_on = config.get("logging_enabled", False)
            self.results.append(CheckResult(
                check_id="{rule_prefix}-mon-01",
                title="Audit logging",
                status=ComplianceStatus.PASS if logging_on else ComplianceStatus.FAIL,
                resource=config.get("resource_id", "unknown"),
                details="Audit logging is " + ("active" if logging_on else "inactive"),
                remediation="" if logging_on else "Enable CloudTrail and access logging.",
            ))
''')

_COMPLIANCE_TEST_TEMPLATE = textwrap.dedent('''\
    """Tests for {title}."""

    from __future__ import annotations

    import pytest


    class Test{class_name}:
        """Unit tests for {class_name}."""

        def test_compliant_config_passes(self) -> None:
            """Fully compliant configuration should pass all checks."""
            from {module_path} import {class_name}

            checker = {class_name}()
            config = {{
                "resource_id": "test-001",
                "encryption_enabled": True,
                "mfa_enabled": True,
                "logging_enabled": True,
            }}
            results = checker.check(config)
            assert all(r.status.value == "PASS" for r in results)

        def test_non_compliant_encryption(self) -> None:
            """Missing encryption should fail the encryption check."""
            from {module_path} import {class_name}

            checker = {class_name}()
            config = {{
                "resource_id": "test-002",
                "encryption_enabled": False,
                "mfa_enabled": True,
                "logging_enabled": True,
            }}
            results = checker.check(config)
            enc_results = [r for r in results if "enc" in r.check_id]
            assert any(r.status.value == "FAIL" for r in enc_results)

        def test_non_compliant_access(self) -> None:
            """Missing MFA should fail the access control check."""
            from {module_path} import {class_name}

            checker = {class_name}()
            config = {{
                "resource_id": "test-003",
                "encryption_enabled": True,
                "mfa_enabled": False,
                "logging_enabled": True,
            }}
            results = checker.check(config)
            ac_results = [r for r in results if "ac" in r.check_id]
            assert any(r.status.value == "FAIL" for r in ac_results)
''')

_DETECTION_RULE_TEMPLATE = textwrap.dedent('''\
    """Auto-generated {title}.

    {description}
    """

    from __future__ import annotations

    import logging
    from dataclasses import dataclass, field
    from enum import Enum
    from typing import Any

    __all__ = ["{class_name}"]

    logger = logging.getLogger(__name__)


    class AlertSeverity(Enum):
        """Alert severity levels."""
        CRITICAL = "CRITICAL"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
        INFO = "INFO"


    @dataclass
    class Alert:
        """A security alert generated by a detection rule.

        Attributes:
            rule_id: Detection rule identifier.
            title: Alert title.
            severity: Alert severity.
            source: Source of the event.
            details: Detailed description.
            mitre_tactic: MITRE ATT&CK tactic.
            mitre_technique: MITRE ATT&CK technique ID.
        """
        rule_id: str
        title: str
        severity: AlertSeverity
        source: str
        details: str
        mitre_tactic: str = ""
        mitre_technique: str = ""


    @dataclass
    class {class_name}:
        """Detection rule for {title}.

        {description}

        Attributes:
            alerts: Alerts generated during the last analysis.
        """
        alerts: list[Alert] = field(default_factory=list)

        def analyse(self, events: list[dict[str, Any]]) -> list[Alert]:
            """Analyse events for suspicious patterns.

            Args:
                events: List of cloud event dicts (mock CloudTrail format).

            Returns:
                List of generated alerts.
            """
            self.alerts.clear()
            logger.info("Running %s detection", self.__class__.__name__)

            for event in events:
                self._evaluate_event(event)

            logger.info("Detection complete — %d alert(s)", len(self.alerts))
            return list(self.alerts)

        def _evaluate_event(self, event: dict[str, Any]) -> None:
            """Evaluate a single event against detection logic."""
            # Check for high-risk API calls
            action = event.get("action", "")
            principal = event.get("principal", "unknown")
            source_ip = event.get("source_ip", "")

            high_risk_actions = {{
                "CreatePolicyVersion", "AttachUserPolicy",
                "AttachRolePolicy", "PutBucketPolicy",
                "CreateAccessKey", "AssumeRole",
            }}

            if action in high_risk_actions:
                self.alerts.append(Alert(
                    rule_id="{rule_prefix}-001",
                    title=f"High-risk API call: {{action}}",
                    severity=AlertSeverity.HIGH,
                    source=principal,
                    details=(
                        f"Principal '{{principal}}' invoked high-risk action "
                        f"'{{action}}' from {{source_ip}}"
                    ),
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1078",
                ))

            # Check for unusual source IPs
            if source_ip and not source_ip.startswith(("10.", "172.16.", "192.168.")):
                if event.get("is_console_login", False):
                    self.alerts.append(Alert(
                        rule_id="{rule_prefix}-002",
                        title="Console login from external IP",
                        severity=AlertSeverity.MEDIUM,
                        source=principal,
                        details=(
                            f"Console login by '{{principal}}' from external "
                            f"IP {{source_ip}}"
                        ),
                        mitre_tactic="Initial Access",
                        mitre_technique="T1078",
                    ))
''')

_DETECTION_TEST_TEMPLATE = textwrap.dedent('''\
    """Tests for {title}."""

    from __future__ import annotations

    import pytest


    class Test{class_name}:
        """Unit tests for {class_name}."""

        def test_detects_high_risk_action(self) -> None:
            """High-risk API call should generate an alert."""
            from {module_path} import {class_name}

            detector = {class_name}()
            events = [{{
                "action": "AttachUserPolicy",
                "principal": "evil-user",
                "source_ip": "203.0.113.50",
            }}]
            alerts = detector.analyse(events)
            assert len(alerts) >= 1
            assert alerts[0].severity.value == "HIGH"

        def test_no_alert_for_normal_events(self) -> None:
            """Normal events should not trigger alerts."""
            from {module_path} import {class_name}

            detector = {class_name}()
            events = [{{
                "action": "DescribeInstances",
                "principal": "normal-user",
                "source_ip": "10.0.1.50",
            }}]
            alerts = detector.analyse(events)
            assert len(alerts) == 0

        def test_detects_external_console_login(self) -> None:
            """Console login from external IP should alert."""
            from {module_path} import {class_name}

            detector = {class_name}()
            events = [{{
                "action": "ConsoleLogin",
                "principal": "admin-user",
                "source_ip": "198.51.100.25",
                "is_console_login": True,
            }}]
            alerts = detector.analyse(events)
            titles = [a.title.lower() for a in alerts]
            assert any("external ip" in t or "console" in t for t in titles)
''')

_MARKDOWN_TEMPLATE = textwrap.dedent("""\
    # {title}

    > Auto-generated by Cloud Security Lab Agent

    ## Overview

    {description}

    ## Key Points

    - Security best practices should be followed at all times
    - Regular audits and reviews are essential
    - Automation reduces human error in security configurations
    - Defence in depth provides layered protection

    ## Details

    This document covers the essential aspects of {title_lower}.
    It is intended as a living reference that will be expanded as the
    project evolves.

    ### Scope

    - Cloud provider: AWS / Azure (multi-cloud)
    - Environment: Development, Staging, Production
    - Compliance frameworks: CIS, SOC 2, HIPAA, PCI-DSS

    ### Recommendations

    1. Enable encryption at rest and in transit for all data stores
    2. Implement least-privilege IAM policies
    3. Enable comprehensive audit logging (CloudTrail, VPC Flow Logs)
    4. Regularly rotate credentials and access keys
    5. Use infrastructure as code for reproducible, auditable deployments

    ## References

    - [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
    - [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
    - [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

    ---

    *Last updated: {date}*
""")

_TERRAFORM_MAIN_TEMPLATE = textwrap.dedent("""\
    # {title}
    #
    # {description}
    #
    # Auto-generated by Cloud Security Lab Agent

    terraform {{
      required_version = ">= 1.5.0"

      required_providers {{
        aws = {{
          source  = "hashicorp/aws"
          version = "~> 5.0"
        }}
      }}
    }}

    # --- Main Resource ---

    resource "aws_example" "this" {{
      # TODO: Replace with actual resource configuration

      tags = merge(var.tags, {{
        ManagedBy   = "terraform"
        SecurityLab = "true"
        Module      = "{module_name}"
      }})
    }}
""")

_TERRAFORM_VARS_TEMPLATE = textwrap.dedent("""\
    # Variables for {title}

    variable "name" {{
      description = "Name for the resource"
      type        = string
    }}

    variable "environment" {{
      description = "Environment (dev, staging, prod)"
      type        = string
      default     = "dev"

      validation {{
        condition     = contains(["dev", "staging", "prod"], var.environment)
        error_message = "Environment must be dev, staging, or prod."
      }}
    }}

    variable "tags" {{
      description = "Additional tags to apply"
      type        = map(string)
      default     = {{}}
    }}
""")

_TERRAFORM_OUTPUTS_TEMPLATE = textwrap.dedent("""\
    # Outputs for {title}

    output "id" {{
      description = "Resource ID"
      value       = aws_example.this.id
    }}

    output "arn" {{
      description = "Resource ARN"
      value       = aws_example.this.arn
    }}
""")

_TEST_FIXTURE_TEMPLATE = textwrap.dedent('''\
    """Auto-generated {title}.

    {description}
    """

    from __future__ import annotations

    from typing import Any

    __all__ = ["COMPLIANT_CONFIGS", "NON_COMPLIANT_CONFIGS"]


    COMPLIANT_CONFIGS: list[dict[str, Any]] = [
        {{
            "resource_id": "compliant-001",
            "encryption_enabled": True,
            "publicly_accessible": False,
            "logging_enabled": True,
            "mfa_enabled": True,
            "backup_enabled": True,
            "tags": {{"Environment": "prod", "Owner": "security-team"}},
        }},
        {{
            "resource_id": "compliant-002",
            "encryption_enabled": True,
            "publicly_accessible": False,
            "logging_enabled": True,
            "mfa_enabled": True,
            "backup_enabled": True,
            "tags": {{"Environment": "staging", "Owner": "dev-team"}},
        }},
    ]

    NON_COMPLIANT_CONFIGS: list[dict[str, Any]] = [
        {{
            "resource_id": "non-compliant-001",
            "encryption_enabled": False,
            "publicly_accessible": True,
            "logging_enabled": False,
            "mfa_enabled": False,
            "backup_enabled": False,
            "tags": {{}},
        }},
        {{
            "resource_id": "non-compliant-002",
            "encryption_enabled": True,
            "publicly_accessible": True,
            "logging_enabled": False,
            "mfa_enabled": False,
            "backup_enabled": True,
            "tags": {{"Environment": "dev"}},
        }},
    ]
''')


class SecurityLabAgent:
    """Autonomous agent that drives continuous security lab improvements.

    The agent follows a simple loop:

    1. **Assess** — scan the repository for existing modules and gaps.
    2. **Plan** — select or generate a task (AI or local catalogue).
    3. **Execute** — create the files using templates or AI output.
    4. **Validate** — run linting / tests.
    5. **Commit** — stage and commit with a conventional message.

    Args:
        config: Agent configuration.
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._task_gen = TaskGenerator()
        self._ai_client = OpenRouterClient(config)
        self._git = GitManager(config.repo_path)
        self._repo = Path(config.repo_path)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self) -> bool:
        """Execute a single improvement cycle.

        Returns:
            *True* if the cycle completed successfully, *False* on error.
        """
        logger.info("=" * 60)
        logger.info("Cloud Security Lab Agent — starting improvement cycle")
        logger.info("=" * 60)

        try:
            # Step 1: Assess
            state = self.assess_project_state()
            logger.info(
                "Project state: %d source files, %d test files, %d modules",
                state["source_file_count"],
                state["test_file_count"],
                len(state["modules"]),
            )

            # Step 2: Plan
            task = self.generate_improvement(state)
            logger.info("Selected task: [%s] %s", task["id"], task["title"])

            # Step 3: Execute
            success = self.execute_task(task)
            if not success:
                logger.error("Task execution failed — aborting cycle")
                return False

            # Step 4: Validate
            valid = self.validate()
            if not valid:
                logger.warning("Validation failed — aborting cycle, no commit (normal no-op)")
                return True

            # Step 5: Commit
            self.create_commit(task)

            logger.info("✓ Improvement cycle completed successfully")
            return True

        except Exception:
            logger.exception("Improvement cycle failed with an unexpected error")
            return False

    # ------------------------------------------------------------------
    # Step 1: Assess
    # ------------------------------------------------------------------

    def assess_project_state(self) -> dict[str, Any]:
        """Scan the repository to understand its current state.

        Returns:
            Dict with keys: ``source_file_count``, ``test_file_count``,
            ``modules`` (list of package names), ``existing_files``
            (list of relative paths), ``git_status``.
        """
        logger.info("Assessing project state …")

        src_dir = self._repo / "src"
        test_dir = self._repo / "tests"

        source_files = list(src_dir.rglob("*.py")) if src_dir.is_dir() else []
        test_files = list(test_dir.rglob("*.py")) if test_dir.is_dir() else []

        # Discover top-level packages under src/
        modules: list[str] = []
        if src_dir.is_dir():
            for child in sorted(src_dir.iterdir()):
                if child.is_dir() and (child / "__init__.py").exists():
                    modules.append(child.name)

        # Collect all existing file paths relative to repo
        existing: list[str] = []
        for pattern in ("src/**/*.py", "tests/**/*.py", "infra/**/*.tf", "docs/**/*.md"):
            existing.extend(str(p.relative_to(self._repo)) for p in self._repo.glob(pattern))

        git_status = self._git.get_status()

        state = {
            "source_file_count": len(source_files),
            "test_file_count": len(test_files),
            "modules": modules,
            "existing_files": sorted(set(existing)),
            "git_status": git_status,
        }

        logger.debug("Existing files: %s", existing[:20])
        return state

    # ------------------------------------------------------------------
    # Step 2: Plan
    # ------------------------------------------------------------------

    def generate_improvement(self, state: dict[str, Any]) -> dict[str, Any]:
        """Select or generate the next improvement task.

        If the OpenRouter API is configured and within rate limits, the
        agent asks the AI to suggest a task based on the project state.
        Otherwise it falls back to :class:`TaskGenerator`.

        Args:
            state: Current project state from :meth:`assess_project_state`.

        Returns:
            Task dict.
        """
        existing = set(state.get("existing_files", []))

        # Try AI-assisted planning first
        if self.config.is_configured():
            task = self._try_ai_planning(state)
            if task is not None:
                # Skip if all target files already exist (avoid duplicates)
                target_files = set(task.get("files_to_create", []))
                if not target_files or not existing.intersection(target_files):
                    return task
                logger.info("AI task targets existing files — skipping to avoid duplicate")

        # Fallback: pick from catalogue, preferring tasks whose files
        # don't already exist
        logger.info("Using local task catalogue (AI unavailable or not configured)")
        for _ in range(self._task_gen.total_tasks):
            candidate = self._task_gen.get_next_task()
            # Prefer tasks that create new files
            if not existing.intersection(candidate.get("files_to_create", [])):
                return candidate

        # All tasks overlap — just return the next one
        return self._task_gen.get_next_task()

    def _try_ai_planning(self, state: dict[str, Any]) -> dict[str, Any] | None:
        """Attempt to get a task suggestion from OpenRouter.

        Args:
            state: Project state dict.

        Returns:
            A task dict, or *None* if the API call fails.
        """
        prompt = (
            "You are a cloud security engineer working on an open-source "
            "security lab project.  The project currently has these modules: "
            f"{state['modules']}.  There are {state['source_file_count']} "
            f"source files and {state['test_file_count']} test files.\n\n"
            "Suggest ONE specific, actionable improvement task.  Reply with "
            'ONLY a JSON object: {"id": "...", "title": "...", '
            '"description": "...", "category": "...", '
            '"files_to_create": [...], "commit_message": "..."}'
        )

        try:
            reply = self._ai_client.chat(
                [
                    {"role": "system", "content": "You are a senior cloud security engineer."},
                    {"role": "user", "content": prompt},
                ]
            )

            import json

            # Try to extract JSON from the reply
            # Handle case where reply includes markdown code fences
            cleaned = reply.strip()
            if cleaned.startswith("```"):
                lines = cleaned.splitlines()
                # Remove first and last lines (code fences)
                json_lines = [line for line in lines if not line.strip().startswith("```")]
                cleaned = "\n".join(json_lines)

            task = json.loads(cleaned)
            # Validate required keys
            required = {
                "id",
                "title",
                "description",
                "category",
                "files_to_create",
                "commit_message",
            }
            if required.issubset(task.keys()):
                logger.info("AI suggested task: %s", task["title"])
                return task
            logger.warning("AI response missing required keys — falling back")
            return None

        except (APINotConfigured, RateLimitExceeded) as exc:
            logger.info("AI planning unavailable: %s", exc)
            return None
        except Exception:
            logger.warning("AI planning failed — falling back to local catalogue", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Step 3: Execute
    # ------------------------------------------------------------------

    def execute_task(self, task: dict[str, Any]) -> bool:
        """Create files for the given task.

        Uses built-in templates to generate production-quality code
        appropriate to the task category.

        Args:
            task: Task dict with ``files_to_create``, ``title``,
                ``description``, and ``category``.

        Returns:
            *True* if all files were created successfully.
        """
        logger.info("Executing task: %s", task["title"])
        files = task.get("files_to_create", [])

        if not files:
            logger.warning("Task has no files to create")
            return False

        # Normalize Python file paths so they live under src/ or tests/
        normalized_files: list[str] = []
        for rel_path in files:
            normalized = rel_path
            if rel_path.endswith(".py") and not (
                rel_path.startswith("src/") or rel_path.startswith("tests/")
            ):
                if "test" in rel_path.lower():
                    normalized = f"tests/{rel_path}"
                else:
                    normalized = f"src/{rel_path}"
                logger.info("Normalized %s -> %s", rel_path, normalized)
            normalized_files.append(normalized)

        # Update task dict so templates see normalized paths
        task["files_to_create"] = normalized_files

        created: list[str] = []
        for rel_path in normalized_files:
            try:
                full = self._repo / rel_path
                full.parent.mkdir(parents=True, exist_ok=True)

                content = self._render_template(rel_path, task)
                full.write_text(content, encoding="utf-8")
                created.append(rel_path)
                logger.info("Created %s", rel_path)

                # Ensure __init__.py exists in Python package dirs
                if rel_path.endswith(".py") and "src/" in rel_path:
                    self._ensure_init_py(full.parent)

            except Exception:
                logger.exception("Failed to create %s", rel_path)

        logger.info("Created %d/%d files", len(created), len(normalized_files))
        return len(created) > 0

    def _render_template(self, rel_path: str, task: dict[str, Any]) -> str:
        """Select and render the appropriate template for a file.

        Args:
            rel_path: Relative file path.
            task: Task dict.

        Returns:
            Rendered file content.
        """
        title = task.get("title", "Security Module")
        description = task.get("description", "")
        category = task.get("category", "")
        task_id = task.get("id", "task")

        # Derive class name from title (sanitized to valid Python identifier)
        _skip = {"add", "implement", "create", "write", "a", "an", "the", "for", "with"}
        import re

        _clean = re.sub(r"[^a-zA-Z0-9 _-]", "", title)
        class_name = "".join(
            word.capitalize()
            for word in _clean.replace("-", " ").replace("_", " ").split()
            if word.lower() not in _skip
        )
        if not class_name:
            class_name = "SecurityModule"

        # Derive rule prefix from task id
        rule_prefix = task_id.replace("-", "").upper()

        # Derive module import path from file path
        module_path = ""
        if rel_path.startswith("src/") and rel_path.endswith(".py"):
            module_path = rel_path[4:].replace("/", ".").removesuffix(".py")

        # For test files, try to infer module path from the corresponding source file
        if not module_path and "test" in rel_path.lower() and rel_path.endswith(".py"):
            test_name = Path(rel_path).stem.replace("test_", "")
            source_files = [
                f
                for f in task.get("files_to_create", [])
                if f.startswith("src/") and f.endswith(".py") and "__init__" not in f
            ]
            # 1. Direct match: test_name == source file stem
            for other in source_files:
                other_name = Path(other).stem
                if test_name == other_name or other_name in test_name:
                    module_path = other[4:].replace("/", ".").removesuffix(".py")
                    break
            # 2. Package match: test_name matches a package directory
            if not module_path:
                for other in source_files:
                    parts = other[4:].split("/")
                    if len(parts) > 1 and test_name in parts:
                        module_path = other[4:].replace("/", ".").removesuffix(".py")
                        break
            # 3. Fallback: use the first non-init source file
            if not module_path and source_files:
                module_path = source_files[0][4:].replace("/", ".").removesuffix(".py")

        context = {
            "title": title,
            "title_lower": title.lower(),
            "description": description,
            "class_name": class_name,
            "rule_prefix": rule_prefix,
            "module_path": module_path,
            "module_name": task_id,
            "date": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"),  # noqa: UP017
        }

        # Select template based on path and category
        if rel_path.endswith(".tf"):
            if "variables" in rel_path:
                return _TERRAFORM_VARS_TEMPLATE.format(**context)
            elif "outputs" in rel_path:
                return _TERRAFORM_OUTPUTS_TEMPLATE.format(**context)
            else:
                return _TERRAFORM_MAIN_TEMPLATE.format(**context)

        if rel_path.endswith(".md"):
            return _MARKDOWN_TEMPLATE.format(**context)

        # Python files — never overwrite an existing __init__.py with template code
        if rel_path.endswith("__init__.py") and (self._repo / rel_path).exists():
            return (self._repo / rel_path).read_text(encoding="utf-8")

        if "test" in rel_path.lower():
            if category == "scanner":
                return _PYTHON_TEST_TEMPLATE.format(**context)
            elif category == "compliance":
                return _COMPLIANCE_TEST_TEMPLATE.format(**context)
            elif category == "detection":
                return _DETECTION_TEST_TEMPLATE.format(**context)
            else:
                return _PYTHON_TEST_TEMPLATE.format(**context)

        if rel_path.startswith("tests/fixtures/") and rel_path.endswith(".py"):
            if "__init__" in rel_path:
                return '"""Test fixtures package."""\n'
            return _TEST_FIXTURE_TEMPLATE.format(**context)

        if category == "scanner":
            return _PYTHON_SCANNER_TEMPLATE.format(**context)
        elif category == "compliance":
            return _COMPLIANCE_CHECK_TEMPLATE.format(**context)
        elif category == "detection":
            return _DETECTION_RULE_TEMPLATE.format(**context)
        elif category == "refactor":
            return _PYTHON_SCANNER_TEMPLATE.format(**context)
        else:
            return _PYTHON_SCANNER_TEMPLATE.format(**context)

    def _ensure_init_py(self, directory: Path) -> None:
        """Create ``__init__.py`` in *directory* and ancestors up to ``src/``.

        Args:
            directory: The directory to ensure has an ``__init__.py``.
        """
        src_root = self._repo / "src"
        current = directory
        while current != self._repo and str(current).startswith(str(src_root)):
            init = current / "__init__.py"
            if not init.exists():
                pkg_name = current.name
                init.write_text(
                    f'"""{pkg_name} package."""\n',
                    encoding="utf-8",
                )
                logger.debug("Created %s", init.relative_to(self._repo))
            current = current.parent

    # ------------------------------------------------------------------
    # Step 4: Validate
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """Run linting and tests to verify the changes.

        Returns:
            *True* if validation passes, *False* otherwise.
        """
        logger.info("Running validation …")
        passed = True
        import sys

        # Ruff check (auto-fix) + format
        passed &= self._run_tool([sys.executable, "-m", "ruff", "check", ".", "--fix"], "ruff")
        passed &= self._run_tool([sys.executable, "-m", "ruff", "format", "."], "ruff-format")

        # Pytest (only unit tests, fast)
        passed &= self._run_tool(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/",
                "-x",
                "-q",
                "--tb=short",
                "--no-header",
            ],
            "pytest",
        )

        return passed

    def _run_tool(self, cmd: list[str], name: str) -> bool:
        """Run an external tool and report success.

        Args:
            cmd: Command-line arguments.
            name: Human-readable tool name for logging.

        Returns:
            *True* if the tool exits successfully.
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=self._repo,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("✓ %s passed", name)
                return True
            else:
                logger.warning(
                    "✗ %s failed (exit %d):\n%s",
                    name,
                    result.returncode,
                    (result.stdout + result.stderr)[:1000],
                )
                return False
        except FileNotFoundError:
            logger.warning("Tool '%s' not found — treating as failure", name)
            return False
        except subprocess.TimeoutExpired:
            logger.warning("Tool '%s' timed out — treating as failure", name)
            return False

    # ------------------------------------------------------------------
    # Step 5: Commit
    # ------------------------------------------------------------------

    def create_commit(self, task: dict[str, Any]) -> str | None:
        """Stage created files and commit.

        Args:
            task: Task dict (must contain ``files_to_create`` and
                ``commit_message``).

        Returns:
            The short SHA of the new commit, or *None* on failure.
        """
        files = task.get("files_to_create", [])
        message = task.get("commit_message", "chore: automated improvement")

        if not files:
            logger.warning("No files to commit")
            return None

        try:
            self._git.stage_files(files)
            sha = self._git.commit(message)
            logger.info("Committed as %s", sha)
            return sha
        except Exception:
            logger.exception("Commit failed")
            return None


# ------------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------------


def main() -> int:
    """Run a single improvement cycle from the command line.

    Returns:
        0 on success, 1 on failure.
    """
    config = AgentConfig.from_env()
    agent = SecurityLabAgent(config)
    success = agent.run()
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
