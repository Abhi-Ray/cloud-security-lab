# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-15

### Added

- **Security Scanner Module**
  - AWS IAM Scanner: root access keys, MFA, unused credentials, admin policies, password policy, key rotation
  - AWS S3 Scanner: public access blocks, encryption, versioning, logging, bucket policy
  - AWS CloudTrail Scanner: enabled, multi-region, log validation, KMS encryption
  - Report generator: text, JSON, and Rich terminal output
  - CLI: `cloudsec scan --demo` for quick demonstration

- **Compliance Engine**
  - CIS AWS Foundations Benchmark Level 1 checks (15 controls)
  - IAM checks: root access keys, root MFA, unused credentials, key rotation, password policy, admin policies
  - Logging checks: CloudTrail enabled, log validation, encryption
  - Networking checks: default SG, unrestricted SSH, VPC flow logs
  - Encryption checks: EBS default, S3 encryption, RDS encryption
  - CLI: `cloudsec-comply assess --demo` for compliance assessment

- **Detection Engine**
  - CloudTrail-based detection rules with MITRE ATT&CK mapping
  - Root console login detection (CRITICAL)
  - IAM changes: admin policy attachment, new user creation, policy modification
  - Security group changes: ingress modification, deletion
  - Logging evasion: CloudTrail stopped/deleted, Config stopped
  - CLI: `cloudsec-detect analyze --demo` for detection demonstration

- **Terraform Modules**
  - AWS: Secure S3 bucket (CIS-aligned), IAM baseline, CloudTrail
  - Azure: NSG baseline with deny-all default

- **AI Automation System**
  - OpenRouter API client with rate limiting
  - Task generator with 30+ realistic security engineering tasks
  - Git manager with conventional commit validation
  - Security Lab Agent orchestrator

- **CI/CD Pipelines**
  - GitHub Actions: CI (lint, test, security scan), Security Agent (varied cron), Terraform validate

- **Documentation**
  - Architecture document with component diagrams
  - Threat model with MITRE ATT&CK mapping
  - Security architecture decision records (ADRs)
  - AWS security research notes
  - Cloud threats landscape notes
