# ☁️ Cloud Security Autonomous Lab

[![CI](https://github.com/USERNAME/cloud-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/USERNAME/cloud-security-lab/actions/workflows/ci.yml)
[![Terraform](https://github.com/USERNAME/cloud-security-lab/actions/workflows/terraform-validate.yml/badge.svg)](https://github.com/USERNAME/cloud-security-lab/actions/workflows/terraform-validate.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS-AWS%20Foundations%20v2.0-orange.svg)](https://www.cisecurity.org/benchmark/amazon_web_services)

> AI-assisted Cloud Security Engineering Lab implementing automated security scanning, compliance assessment, and threat detection for AWS and Azure environments.

## 🎯 What This Does

A production-style cloud security automation platform that provides:

- **Security Scanning** — Automated misconfiguration detection for AWS IAM, S3, CloudTrail
- **Compliance Assessment** — CIS AWS Foundations Benchmark Level 1 checks (15 controls)
- **Detection Engineering** — CloudTrail-based threat detection rules with MITRE ATT&CK mapping
- **Infrastructure as Code** — Secure Terraform modules for AWS and Azure
- **AI Automation** — Self-evolving project through OpenRouter AI integration

No cloud credentials required — all tools work against configurable mock data for testing and demonstration.

---

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/USERNAME/cloud-security-lab.git
cd cloud-security-lab
pip install -e ".[dev]"
```

### Run Security Scanner

```bash
# Run all scanners against demo configuration
cloudsec scan --demo

# Scan a custom configuration file
cloudsec scan --config path/to/config.yaml
```

### Run Compliance Assessment

```bash
# Run CIS AWS Foundations Benchmark checks
cloudsec-comply assess --demo

# Assess specific framework
cloudsec-comply assess --framework cis-aws --config path/to/config.yaml
```

### Run Detection Engine

```bash
# Analyze sample CloudTrail events
cloudsec-detect analyze --demo

# List all detection rules with MITRE ATT&CK mapping
cloudsec-detect rules

# Analyze CloudTrail events from file
cloudsec-detect analyze --events path/to/events.json
```

---

## 📁 Project Structure

```
cloud-security-lab/
├── src/
│   ├── security_scanner/        # Cloud security scanning engine
│   │   ├── aws/
│   │   │   ├── iam_scanner.py       # IAM security checks
│   │   │   ├── s3_scanner.py        # S3 bucket security checks
│   │   │   └── cloudtrail_scanner.py # CloudTrail config checks
│   │   ├── base_scanner.py      # Abstract scanner interface
│   │   ├── models.py            # Finding, ScanResult, Severity
│   │   ├── report.py            # Report generation (text/JSON/rich)
│   │   └── cli.py               # CLI interface
│   │
│   ├── compliance/              # Compliance assessment engine
│   │   ├── cis_aws/
│   │   │   ├── iam_checks.py        # CIS 1.x IAM controls
│   │   │   ├── logging_checks.py    # CIS 2.x/3.x logging controls
│   │   │   ├── networking_checks.py # CIS 4.x network controls
│   │   │   └── encryption_checks.py # CIS 2.x encryption controls
│   │   ├── engine.py            # Compliance assessment runner
│   │   ├── models.py            # ComplianceCheck, CheckResult
│   │   └── cli.py               # CLI interface
│   │
│   └── detectors/               # Threat detection engine
│       ├── cloudtrail/
│       │   ├── root_login.py        # Root account login detection
│       │   ├── iam_changes.py       # IAM privilege escalation
│       │   ├── security_group_changes.py # Network changes
│       │   └── logging_disabled.py  # Logging evasion detection
│       ├── engine.py            # Detection rule processor
│       ├── models.py            # DetectionRule, DetectionMatch
│       └── cli.py               # CLI interface
│
├── automation/                  # AI automation system
│   ├── ai_agent.py              # Main autonomous agent
│   ├── openrouter_client.py     # OpenRouter API client
│   ├── task_generator.py        # Security task templates
│   ├── github_manager.py        # Git operations manager
│   └── config.py                # Configuration management
│
├── infra/                       # Terraform infrastructure modules
│   ├── aws/
│   │   ├── s3_secure_bucket/        # CIS-aligned S3 bucket
│   │   ├── iam_baseline/           # IAM security baseline
│   │   └── cloudtrail/             # CloudTrail configuration
│   └── azure/
│       └── nsg_baseline/           # NSG deny-all baseline
│
├── docs/                        # Engineering documentation
│   ├── architecture.md          # System architecture
│   ├── threat-model.md          # Cloud threat model
│   ├── security-decisions.md    # Architecture decision records
│   └── changelog.md             # Release changelog
│
├── research/                    # Security research notes
│   ├── aws-security-notes.md
│   └── cloud-threats-2024.md
│
├── tests/                       # Test suite
├── .github/workflows/           # CI/CD pipelines
├── pyproject.toml               # Project configuration
└── Makefile                     # Developer shortcuts
```

---

## 🔍 Security Scanner

The scanner analyzes cloud configurations against security best practices:

| Scanner | Checks | Target |
|---------|--------|--------|
| **IAM Scanner** | Root access keys, MFA enforcement, unused credentials, admin policies, password policy, key rotation | AWS IAM |
| **S3 Scanner** | Public access blocks, encryption at rest, versioning, access logging, bucket policies | AWS S3 |
| **CloudTrail Scanner** | Multi-region trails, log file validation, KMS encryption, logging enabled | AWS CloudTrail |

### Sample Output

```
Security Scan Report
═══════════════════

Scanner: AWS IAM Security Scanner
Findings: 6

 CRITICAL  Root Account Access Keys Exist
           Resource: root-account
           Recommendation: Remove root account access keys immediately

 HIGH      User Missing MFA: admin
           Resource: iam-user/admin
           Recommendation: Enable MFA for all IAM users with console access

 MEDIUM    Weak Password Policy
           Resource: account-password-policy
           Recommendation: Set minimum length to 14, require all character types
```

---

## ✅ Compliance Engine

Automated assessment against CIS AWS Foundations Benchmark v2.0:

| Category | Controls | Example Checks |
|----------|----------|----------------|
| **IAM** | 6 | Root MFA, password policy, unused credentials, admin policies |
| **Logging** | 3 | CloudTrail enabled, log validation, encryption |
| **Networking** | 3 | Default SG, SSH restriction, VPC flow logs |
| **Encryption** | 3 | EBS default, S3 encryption, RDS encryption |

### Sample Output

```
CIS AWS Foundations Benchmark Assessment
════════════════════════════════════════

Controls: 15 | Pass: 9 | Fail: 6
Compliance Score: 60%

 ✅ PASS  1.1  No root account access keys
 ❌ FAIL  1.2  Root MFA not enabled
 ❌ FAIL  1.3  Users with console access missing MFA: admin, developer
 ✅ PASS  1.4  Access keys rotated within 90 days
```

---

## 🔔 Detection Engine

CloudTrail-based threat detection with MITRE ATT&CK mapping:

| Rule | Severity | MITRE Tactic |
|------|----------|-------------|
| Root Console Login | CRITICAL | Initial Access |
| Admin Policy Attachment | CRITICAL | Privilege Escalation |
| CloudTrail Stopped | CRITICAL | Defense Evasion |
| CloudTrail Deleted | CRITICAL | Defense Evasion |
| New User Creation | HIGH | Persistence |
| Policy Modification | HIGH | Persistence |
| Security Group Opened | HIGH | Defense Evasion |
| Config Recorder Stopped | CRITICAL | Defense Evasion |

---

## 🏗️ Infrastructure as Code

Terraform modules with security best practices:

- **AWS S3 Secure Bucket** — Encryption, public access blocking, SSL enforcement, versioning, access logging
- **AWS IAM Baseline** — Password policy, security audit role, root usage alarm
- **AWS CloudTrail** — Multi-region, KMS encryption, log validation, CloudWatch integration
- **Azure NSG Baseline** — Deny-all default, SSH/RDP blocking, flow logs

```bash
# Validate all Terraform modules
make tf-validate

# Format Terraform files
make tf-fmt
```

---

## 🤖 AI Automation

The project includes an autonomous agent that continuously improves the codebase:

1. Assesses current project state
2. Generates realistic security engineering tasks
3. Implements improvements
4. Validates with tests and linting
5. Commits with conventional commit messages

Works with or without an OpenRouter API key — falls back to a built-in task generator.

```bash
# Configure (copy .env.example to .env and set your API key)
cp .env.example .env

# Run the agent
python -m automation.ai_agent
```

---

## 🧪 Development

```bash
# Install dev dependencies
make dev

# Run tests
make test

# Run tests with coverage
make test-cov

# Lint
make lint

# Format code
make format

# Security scan
make scan

# Run everything
make all
```

---

## 📖 Documentation

- [Architecture](docs/architecture.md) — System design and component overview
- [Threat Model](docs/threat-model.md) — Cloud threat analysis with MITRE ATT&CK mapping
- [Security Decisions](docs/security-decisions.md) — Architecture decision records
- [Changelog](docs/changelog.md) — Release history
- [AWS Security Notes](research/aws-security-notes.md) — Research and best practices
- [Cloud Threats 2024](research/cloud-threats-2024.md) — Current threat landscape

---

## 🛡️ Security Tools Integration

This project integrates with:

| Tool | Purpose |
|------|---------|
| **Ruff** | Python linting with security rules |
| **Bandit** | Python security static analysis |
| **Gitleaks** | Secret detection in commits |
| **Checkov** | Terraform security scanning |
| **pre-commit** | Automated security checks on commit |

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
