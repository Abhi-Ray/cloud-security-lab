# Cloud Security Lab — Architecture

## Overview

The Cloud Security Autonomous Lab is a modular security engineering platform designed to continuously scan, assess, and improve cloud security posture across AWS and Azure environments.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cloud Security Lab                           │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Security    │  │  Compliance  │  │  Detection Engine    │  │
│  │   Scanner     │  │  Engine      │  │                      │  │
│  │              │  │              │  │  CloudTrail Rules     │  │
│  │  IAM Scanner │  │  CIS AWS     │  │  Root Login          │  │
│  │  S3 Scanner  │  │  ISO 27001   │  │  IAM Changes         │  │
│  │  CT Scanner  │  │  NIST CSF    │  │  SG Changes          │  │
│  └──────┬───────┘  └──────┬───────┘  │  Logging Disabled    │  │
│         │                 │          └──────────┬───────────┘  │
│         ▼                 ▼                     ▼              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Report Generator                      │   │
│  │         Text Reports │ JSON Export │ Rich Terminal        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 AI Automation System                      │   │
│  │  OpenRouter Client → Task Generator → Git Manager         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────┐  ┌───────────────────────────────┐   │
│  │  Terraform Modules    │  │  CI/CD Pipelines              │   │
│  │  AWS: S3, IAM, CT    │  │  GitHub Actions: CI, Agent,   │   │
│  │  Azure: NSG           │  │  Terraform Validate           │   │
│  └──────────────────────┘  └───────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Security Scanner (`src/security_scanner/`)

Modular scanning engine that analyzes cloud configurations for security misconfigurations.

**Design decisions:**
- **Abstract base class pattern** — All scanners extend `BaseScanner`, ensuring consistent interface
- **Config-driven** — Scanners work against configuration dictionaries, not live APIs. This enables:
  - Testing without cloud credentials
  - CI/CD pipeline integration
  - Reproducible scans
- **Severity-based findings** — CRITICAL, HIGH, MEDIUM, LOW, INFO

**Scanners:**
| Scanner | Checks | Target |
|---------|--------|--------|
| `IAMScanner` | Root keys, MFA, unused creds, admin policies, password policy | AWS IAM |
| `S3Scanner` | Public access, encryption, versioning, logging, bucket policy | AWS S3 |
| `CloudTrailScanner` | Enabled, multi-region, log validation, KMS encryption | AWS CloudTrail |

### 2. Compliance Engine (`src/compliance/`)

Automated compliance assessment against industry frameworks.

**Supported frameworks:**
- CIS AWS Foundations Benchmark (15 controls implemented)
- ISO 27001 (mapped, not yet implemented)
- NIST CSF (mapped, not yet implemented)
- SOC 2 (mapped, not yet implemented)

**Check categories:**
- IAM (6 checks) — Root access, MFA, password policy, credentials
- Logging (3 checks) — CloudTrail configuration
- Networking (3 checks) — Security groups, VPC flow logs
- Encryption (3 checks) — EBS, S3, RDS encryption

### 3. Detection Engine (`src/detectors/`)

Rule-based detection system for identifying suspicious activity in cloud audit logs.

**Design decisions:**
- **Pure function detectors** — Each detection is a stateless function: `event → match | None`
- **MITRE ATT&CK mapping** — Every rule maps to ATT&CK tactics
- **CloudTrail native** — Detections parse standard CloudTrail event format

**Detection rules:**
| Rule | Event | MITRE Tactic | Severity |
|------|-------|-------------|----------|
| Root Console Login | ConsoleLogin (Root) | Initial Access | CRITICAL |
| Admin Policy Attachment | AttachUserPolicy | Privilege Escalation | CRITICAL |
| New User Creation | CreateUser | Persistence | HIGH |
| Policy Modification | CreatePolicy/PutUserPolicy | Persistence | HIGH |
| SG Ingress Open | AuthorizeSecurityGroupIngress (0.0.0.0/0) | Defense Evasion | HIGH |
| SG Deletion | DeleteSecurityGroup | Defense Evasion | MEDIUM |
| CloudTrail Stopped | StopLogging | Defense Evasion | CRITICAL |
| CloudTrail Deleted | DeleteTrail | Defense Evasion | CRITICAL |
| Config Stopped | StopConfigurationRecorder | Defense Evasion | CRITICAL |

### 4. AI Automation System (`automation/`)

Autonomous agent that evolves the project through AI-assisted engineering.

**Components:**
- `OpenRouterClient` — Rate-limited API client (5 calls/day free tier)
- `TaskGenerator` — 30+ realistic security engineering tasks
- `GitManager` — Conventional commit automation
- `SecurityLabAgent` — Orchestrator: assess → generate → implement → validate → commit

**Fallback behavior:** Works without API key using the built-in task generator.

### 5. Infrastructure as Code (`infra/`)

Terraform modules demonstrating secure cloud infrastructure.

**AWS modules:** Secure S3 bucket, IAM baseline, CloudTrail
**Azure modules:** NSG baseline with deny-all default

## Data Flow

```
Cloud Config (YAML/dict)
        │
        ├──→ Security Scanner ──→ Findings (CRITICAL/HIGH/MEDIUM/LOW)
        │
        ├──→ Compliance Engine ──→ Pass/Fail per CIS Control + Score
        │
        └──→ (Future) Live API integration

CloudTrail Events (JSON)
        │
        └──→ Detection Engine ──→ Matches with MITRE ATT&CK mapping
```

## Technology Choices

| Technology | Rationale |
|-----------|-----------|
| Python 3.11+ | Modern features (StrEnum, type unions), wide security tooling ecosystem |
| Click | CLI framework — simple, composable, well-documented |
| Rich | Terminal output — colored severity levels, formatted tables |
| httpx | Async-capable HTTP client for OpenRouter API |
| Terraform | Industry standard IaC, multi-cloud support |
| GitHub Actions | Free CI/CD, cron scheduling for automation |
| Ruff | Fast Python linter with built-in security rules |
| Bandit | Python-specific security static analysis |
