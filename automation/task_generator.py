"""Security engineering task generator.

Provides a curated catalogue of realistic cloud-security tasks and a
scheduler that produces human-like commit patterns (not every day,
clustered in some weeks, with quiet periods).
"""

from __future__ import annotations

import hashlib
import logging
import random
from typing import Any

__all__ = ["TaskGenerator"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Task catalogue (30+ diverse tasks)
# ---------------------------------------------------------------------------

_TASKS: list[dict[str, Any]] = [
    # ── Scanner tasks ─────────────────────────────────────────────────
    {
        "id": "scanner-001",
        "title": "Add AWS RDS security scanner",
        "description": (
            "Implement scanner for RDS instances checking encryption at rest, "
            "public accessibility, automated backups, and IAM authentication."
        ),
        "category": "scanner",
        "files_to_create": [
            "src/security_scanner/scanners/rds_scanner.py",
            "tests/test_rds_scanner.py",
        ],
        "commit_message": "feat(scanner): add AWS RDS security configuration scanner",
    },
    {
        "id": "scanner-002",
        "title": "Add S3 bucket policy scanner",
        "description": (
            "Scan S3 bucket policies for overly permissive access, public "
            "ACLs, missing encryption defaults, and versioning status."
        ),
        "category": "scanner",
        "files_to_create": [
            "src/security_scanner/scanners/s3_scanner.py",
            "tests/test_s3_scanner.py",
        ],
        "commit_message": "feat(scanner): add S3 bucket policy security scanner",
    },
    {
        "id": "scanner-003",
        "title": "Add EC2 security group scanner",
        "description": (
            "Check security groups for unrestricted ingress rules "
            "(0.0.0.0/0), unused groups, and overly broad port ranges."
        ),
        "category": "scanner",
        "files_to_create": [
            "src/security_scanner/scanners/sg_scanner.py",
            "tests/test_sg_scanner.py",
        ],
        "commit_message": "feat(scanner): add EC2 security group misconfiguration scanner",
    },
    {
        "id": "scanner-004",
        "title": "Add Lambda function security scanner",
        "description": (
            "Scan Lambda functions for overly permissive IAM roles, public "
            "URLs, environment variable secrets, and runtime EOL versions."
        ),
        "category": "scanner",
        "files_to_create": [
            "src/security_scanner/scanners/lambda_scanner.py",
            "tests/test_lambda_scanner.py",
        ],
        "commit_message": "feat(scanner): add Lambda function security scanner",
    },
    {
        "id": "scanner-005",
        "title": "Add EKS cluster security scanner",
        "description": (
            "Audit EKS clusters for public endpoint access, logging "
            "configuration, secrets encryption, and RBAC settings."
        ),
        "category": "scanner",
        "files_to_create": [
            "src/security_scanner/scanners/eks_scanner.py",
            "tests/test_eks_scanner.py",
        ],
        "commit_message": "feat(scanner): add EKS cluster security audit scanner",
    },
    # ── Compliance tasks ──────────────────────────────────────────────
    {
        "id": "compliance-001",
        "title": "Implement CIS AWS 1.4 password policy checks",
        "description": (
            "Add compliance checks for CIS AWS Foundations 1.4 — password "
            "minimum length, complexity requirements, and rotation policy."
        ),
        "category": "compliance",
        "files_to_create": [
            "src/compliance/checks/cis_password_policy.py",
            "tests/test_cis_password_policy.py",
        ],
        "commit_message": "feat(compliance): add CIS 1.4 password policy checks",
    },
    {
        "id": "compliance-002",
        "title": "Add SOC 2 logging compliance checker",
        "description": (
            "Verify CloudTrail is enabled in all regions, S3 access logging "
            "is on, and VPC Flow Logs are active — SOC 2 CC6.1 / CC7.2."
        ),
        "category": "compliance",
        "files_to_create": [
            "src/compliance/checks/soc2_logging.py",
            "tests/test_soc2_logging.py",
        ],
        "commit_message": "feat(compliance): add SOC 2 logging compliance checker",
    },
    {
        "id": "compliance-003",
        "title": "Implement HIPAA encryption-at-rest checks",
        "description": (
            "Check EBS, RDS, S3, and DynamoDB for encryption at rest to "
            "satisfy HIPAA §164.312(a)(2)(iv)."
        ),
        "category": "compliance",
        "files_to_create": [
            "src/compliance/checks/hipaa_encryption.py",
            "tests/test_hipaa_encryption.py",
        ],
        "commit_message": "feat(compliance): add HIPAA encryption-at-rest checks",
    },
    {
        "id": "compliance-004",
        "title": "Add PCI-DSS network segmentation checks",
        "description": (
            "Validate VPC segmentation, NACLs, and security group rules "
            "align with PCI-DSS Requirement 1 network controls."
        ),
        "category": "compliance",
        "files_to_create": [
            "src/compliance/checks/pci_network.py",
            "tests/test_pci_network.py",
        ],
        "commit_message": "feat(compliance): add PCI-DSS network segmentation checks",
    },
    # ── Detection tasks ───────────────────────────────────────────────
    {
        "id": "detection-001",
        "title": "Add IAM privilege escalation detector",
        "description": (
            "Detect dangerous IAM policy combinations that allow privilege "
            "escalation (iam:CreatePolicyVersion, iam:AttachUserPolicy, etc.)."
        ),
        "category": "detection",
        "files_to_create": [
            "src/detectors/rules/iam_privesc.py",
            "tests/test_iam_privesc.py",
        ],
        "commit_message": "feat(detection): add IAM privilege escalation path detector",
    },
    {
        "id": "detection-002",
        "title": "Add CloudTrail anomaly detector",
        "description": (
            "Analyse CloudTrail mock events for unusual API call patterns, "
            "off-hours access, and impossible travel scenarios."
        ),
        "category": "detection",
        "files_to_create": [
            "src/detectors/rules/cloudtrail_anomaly.py",
            "tests/test_cloudtrail_anomaly.py",
        ],
        "commit_message": "feat(detection): add CloudTrail anomaly detection rules",
    },
    {
        "id": "detection-003",
        "title": "Add S3 data exfiltration detector",
        "description": (
            "Detect suspicious S3 access patterns: bulk downloads, cross-"
            "account access, and public object creation."
        ),
        "category": "detection",
        "files_to_create": [
            "src/detectors/rules/s3_exfil.py",
            "tests/test_s3_exfil.py",
        ],
        "commit_message": "feat(detection): add S3 data exfiltration detector",
    },
    {
        "id": "detection-004",
        "title": "Add crypto-mining activity detector",
        "description": (
            "Detect EC2 instance types and utilisation patterns that indicate "
            "cryptocurrency mining abuse."
        ),
        "category": "detection",
        "files_to_create": [
            "src/detectors/rules/cryptomining.py",
            "tests/test_cryptomining.py",
        ],
        "commit_message": "feat(detection): add crypto-mining activity detector",
    },
    # ── Terraform / IaC tasks ─────────────────────────────────────────
    {
        "id": "terraform-001",
        "title": "Add Terraform S3 bucket module with security defaults",
        "description": (
            "Create a reusable Terraform module for S3 buckets with SSE-KMS, "
            "versioning, public access blocks, and lifecycle rules."
        ),
        "category": "terraform",
        "files_to_create": [
            "infra/modules/s3_bucket/main.tf",
            "infra/modules/s3_bucket/variables.tf",
            "infra/modules/s3_bucket/outputs.tf",
        ],
        "commit_message": "feat(terraform): add hardened S3 bucket module",
    },
    {
        "id": "terraform-002",
        "title": "Add Terraform VPC module with security baselines",
        "description": (
            "Create VPC module with private/public subnets, NACLs, flow log "
            "enablement, and no default route to internet for private subnets."
        ),
        "category": "terraform",
        "files_to_create": [
            "infra/modules/vpc/main.tf",
            "infra/modules/vpc/variables.tf",
            "infra/modules/vpc/outputs.tf",
        ],
        "commit_message": "feat(terraform): add secure VPC module with flow logs",
    },
    {
        "id": "terraform-003",
        "title": "Add Terraform IAM role module with least-privilege template",
        "description": (
            "Create IAM role module enforcing MFA conditions, session "
            "duration limits, and permission boundary attachment."
        ),
        "category": "terraform",
        "files_to_create": [
            "infra/modules/iam_role/main.tf",
            "infra/modules/iam_role/variables.tf",
            "infra/modules/iam_role/outputs.tf",
        ],
        "commit_message": "feat(terraform): add least-privilege IAM role module",
    },
    {
        "id": "terraform-004",
        "title": "Add Terraform security-group module with CIS presets",
        "description": (
            "Create reusable security-group module with named rule presets "
            "for web, database, and management tiers following CIS benchmarks."
        ),
        "category": "terraform",
        "files_to_create": [
            "infra/modules/security_group/main.tf",
            "infra/modules/security_group/variables.tf",
            "infra/modules/security_group/outputs.tf",
        ],
        "commit_message": "feat(terraform): add CIS-aligned security-group module",
    },
    # ── Documentation tasks ───────────────────────────────────────────
    {
        "id": "docs-001",
        "title": "Write AWS IAM security best-practices guide",
        "description": (
            "Document IAM best practices: least privilege, MFA enforcement, "
            "access key rotation, service-linked roles, and permission boundaries."
        ),
        "category": "documentation",
        "files_to_create": [
            "docs/guides/aws_iam_best_practices.md",
        ],
        "commit_message": "docs: add AWS IAM security best-practices guide",
    },
    {
        "id": "docs-002",
        "title": "Write incident response playbook for compromised credentials",
        "description": (
            "Step-by-step playbook for handling compromised AWS access keys: "
            "containment, investigation, remediation, and lessons learned."
        ),
        "category": "documentation",
        "files_to_create": [
            "docs/playbooks/compromised_credentials.md",
        ],
        "commit_message": "docs: add incident response playbook for compromised credentials",
    },
    {
        "id": "docs-003",
        "title": "Document security scanner architecture",
        "description": (
            "Create an architecture document explaining the security scanner "
            "pipeline: data flow, plugin system, findings model, and output formats."
        ),
        "category": "documentation",
        "files_to_create": [
            "docs/architecture/scanner_architecture.md",
        ],
        "commit_message": "docs: add security scanner architecture documentation",
    },
    {
        "id": "docs-004",
        "title": "Write cloud security threat model",
        "description": (
            "STRIDE-based threat model for a typical AWS workload covering "
            "compute, storage, network, and identity attack surfaces."
        ),
        "category": "documentation",
        "files_to_create": [
            "docs/threat_models/aws_workload_threat_model.md",
        ],
        "commit_message": "docs: add STRIDE threat model for AWS workloads",
    },
    # ── Research tasks ────────────────────────────────────────────────
    {
        "id": "research-001",
        "title": "Research AWS GuardDuty finding types",
        "description": (
            "Catalogue GuardDuty finding types, map them to MITRE ATT&CK, "
            "and note recommended automated response actions."
        ),
        "category": "research",
        "files_to_create": [
            "research/guardduty_findings_analysis.md",
        ],
        "commit_message": "docs(research): add GuardDuty findings analysis with MITRE mapping",
    },
    {
        "id": "research-002",
        "title": "Analyse OWASP Top 10 for cloud-native applications",
        "description": (
            "Map OWASP Top 10 2021 to cloud-specific mitigations using AWS "
            "and Azure native services."
        ),
        "category": "research",
        "files_to_create": [
            "research/owasp_top10_cloud_mapping.md",
        ],
        "commit_message": "docs(research): add OWASP Top 10 cloud-native mapping",
    },
    {
        "id": "research-003",
        "title": "Compare cloud CSPM tools",
        "description": (
            "Evaluate Prowler, ScoutSuite, CloudSploit, and Steampipe for "
            "CSPM coverage, extensibility, and CI/CD integration."
        ),
        "category": "research",
        "files_to_create": [
            "research/cspm_tool_comparison.md",
        ],
        "commit_message": "docs(research): add CSPM tool comparison analysis",
    },
    # ── Testing tasks ─────────────────────────────────────────────────
    {
        "id": "testing-001",
        "title": "Add integration test suite for scanner pipeline",
        "description": (
            "Create end-to-end tests that run the full scanner pipeline "
            "against mock AWS configurations and validate finding output."
        ),
        "category": "testing",
        "files_to_create": [
            "tests/integration/test_scanner_pipeline.py",
            "tests/integration/conftest.py",
        ],
        "commit_message": "test: add integration test suite for scanner pipeline",
    },
    {
        "id": "testing-002",
        "title": "Add property-based tests for IAM policy parser",
        "description": (
            "Use Hypothesis to generate randomised IAM policy documents and "
            "verify the parser never crashes and produces valid output."
        ),
        "category": "testing",
        "files_to_create": [
            "tests/test_iam_policy_property.py",
        ],
        "commit_message": "test: add property-based tests for IAM policy parser",
    },
    {
        "id": "testing-003",
        "title": "Add compliance framework test fixtures",
        "description": (
            "Build a library of mock AWS configurations (compliant and "
            "non-compliant) for CIS, SOC 2, and HIPAA test scenarios."
        ),
        "category": "testing",
        "files_to_create": [
            "tests/fixtures/aws_configs.py",
            "tests/fixtures/__init__.py",
        ],
        "commit_message": "test: add compliance framework test fixtures",
    },
    # ── Refactor tasks ────────────────────────────────────────────────
    {
        "id": "refactor-001",
        "title": "Extract shared finding model to common package",
        "description": (
            "Create a shared `Finding` dataclass with severity enum, resource "
            "reference, remediation text, and SARIF-compatible serialisation."
        ),
        "category": "refactor",
        "files_to_create": [
            "src/security_scanner/models.py",
        ],
        "commit_message": "refactor: extract shared Finding model with SARIF support",
    },
    {
        "id": "refactor-002",
        "title": "Add plugin registry for scanner modules",
        "description": (
            "Implement an entry-point-based plugin registry so scanner "
            "modules are discovered and loaded dynamically."
        ),
        "category": "refactor",
        "files_to_create": [
            "src/security_scanner/registry.py",
            "tests/test_scanner_registry.py",
        ],
        "commit_message": "refactor: add plugin registry for scanner module discovery",
    },
    {
        "id": "refactor-003",
        "title": "Add structured JSON logging adapter",
        "description": (
            "Create a logging adapter that outputs structured JSON for "
            "production environments and human-readable text for development."
        ),
        "category": "refactor",
        "files_to_create": [
            "src/security_scanner/logging_adapter.py",
            "tests/test_logging_adapter.py",
        ],
        "commit_message": "refactor: add structured JSON logging adapter",
    },
    {
        "id": "refactor-004",
        "title": "Add severity enum and risk-scoring utility",
        "description": (
            "Create a shared severity enum (CRITICAL, HIGH, MEDIUM, LOW, INFO) "
            "with CVSS-like risk scoring and sorting utilities."
        ),
        "category": "refactor",
        "files_to_create": [
            "src/security_scanner/severity.py",
            "tests/test_severity.py",
        ],
        "commit_message": "refactor: add severity enum and risk-scoring utility",
    },
]


class TaskGenerator:
    """Generates realistic security-engineering tasks.

    The generator maintains an internal index into the task catalogue so
    successive calls to :meth:`get_next_task` return different tasks.  A
    deterministic *seed* can be provided for reproducibility.

    Args:
        seed: Optional random seed for reproducible scheduling and
            task ordering.
    """

    def __init__(self, seed: int | None = None) -> None:
        self._tasks = list(_TASKS)
        self._index = 0
        self._rng = random.Random(seed)  # noqa: S311 — not used for crypto
        self._rng.shuffle(self._tasks)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def total_tasks(self) -> int:
        """Total number of tasks in the catalogue."""
        return len(self._tasks)

    @property
    def categories(self) -> list[str]:
        """Sorted unique category names."""
        return sorted({t["category"] for t in self._tasks})

    def get_next_task(self) -> dict[str, Any]:
        """Return the next task in the shuffled queue.

        The queue wraps around and reshuffles when exhausted.

        Returns:
            Task dict with keys: ``id``, ``title``, ``description``,
            ``category``, ``files_to_create``, ``commit_message``.
        """
        if self._index >= len(self._tasks):
            self._rng.shuffle(self._tasks)
            self._index = 0
            logger.info("Task catalogue exhausted — reshuffled for next cycle")

        task = self._tasks[self._index]
        self._index += 1
        logger.info("Selected task %s: %s", task["id"], task["title"])
        return dict(task)  # return a copy

    def get_task_by_id(self, task_id: str) -> dict[str, Any] | None:
        """Look up a task by its identifier.

        Args:
            task_id: The unique task ID (e.g. ``"scanner-001"``).

        Returns:
            The task dict, or *None* if not found.
        """
        for task in self._tasks:
            if task["id"] == task_id:
                return dict(task)
        return None

    def get_tasks_by_category(self, category: str) -> list[dict[str, Any]]:
        """Return all tasks in the given category.

        Args:
            category: Category name (e.g. ``"scanner"``).

        Returns:
            List of task dicts.
        """
        return [dict(t) for t in self._tasks if t["category"] == category]

    def get_random_schedule(self, month_days: int = 30) -> list[int]:
        """Generate a human-like activity schedule for a month.

        The schedule clusters activity in "productive weeks" with some
        quiet days, mimicking a real engineer's commit pattern.

        Args:
            month_days: Number of days in the target month (default 30).

        Returns:
            Sorted list of 1-indexed day numbers (12–18 days typically).
        """
        # Decide how many active days (12–18 for realism)
        num_active = self._rng.randint(12, 18)

        # Generate "weight" per day — higher weight = more likely to be
        # active.  Weekdays (Mon–Fri mapped roughly) get higher weight.
        weights: list[float] = []
        for day in range(1, month_days + 1):
            # Approximate weekday (day 1 = Monday)
            weekday = (day - 1) % 7
            if weekday < 5:
                # Weekday: base weight 3–5
                w = self._rng.uniform(3.0, 5.0)
            else:
                # Weekend: lower weight
                w = self._rng.uniform(0.5, 1.5)

            # Create "productive burst" clusters
            week_num = (day - 1) // 7
            if week_num in self._productive_weeks(month_days):
                w *= self._rng.uniform(1.3, 1.8)

            weights.append(w)

        # Normalise and sample
        total = sum(weights)
        probs = [w / total for w in weights]
        all_days = list(range(1, month_days + 1))

        chosen: set[int] = set()
        attempts = 0
        while len(chosen) < num_active and attempts < 500:
            pick = self._rng.choices(all_days, weights=probs, k=1)[0]
            chosen.add(pick)
            attempts += 1

        schedule = sorted(chosen)
        logger.debug("Generated schedule with %d active days: %s", len(schedule), schedule)
        return schedule

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _productive_weeks(self, month_days: int) -> set[int]:
        """Pick 2–3 'productive weeks' in the month.

        Args:
            month_days: Days in the month.

        Returns:
            Set of 0-indexed week numbers.
        """
        total_weeks = (month_days + 6) // 7
        n = self._rng.randint(2, min(3, total_weeks))
        return set(self._rng.sample(range(total_weeks), k=n))

    def get_digest(self) -> str:
        """Return a SHA-256 hex-digest of the full task catalogue.

        Useful for detecting when the task set has changed.
        """
        blob = json.dumps(_TASKS, sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()[:16]


# Needed for get_digest
import json  # noqa: E402 — intentionally at bottom to keep _TASKS readable
