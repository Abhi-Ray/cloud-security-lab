# Cloud Security Lab — Threat Model

## Scope

This threat model covers common cloud security threats across AWS and Azure environments that the Cloud Security Lab is designed to detect, prevent, and assess.

## Methodology

Based on:
- **MITRE ATT&CK for Cloud** (IaaS matrix)
- **OWASP Cloud Security Top 10**
- **CSA Cloud Controls Matrix (CCM)**

---

## 1. Identity & Access Threats

### T1.1 — Credential Compromise
- **Attack vector:** Stolen API keys, leaked credentials in code, phishing
- **Impact:** Full account takeover, data exfiltration
- **Mitigations:**
  - Enforce MFA on all accounts (CIS 1.2, 1.3)
  - Rotate access keys every 90 days (CIS 1.4)
  - No root account access keys (CIS 1.1)
  - Implement least-privilege IAM policies
- **Detection:** Root console login, new access key creation from unusual IP
- **Lab coverage:** IAM Scanner, CIS IAM checks, root login detection

### T1.2 — Privilege Escalation
- **Attack vector:** Overly permissive IAM policies, role chaining, policy modification
- **Impact:** Attacker gains admin access from limited initial access
- **Mitigations:**
  - No `*:*` policies (CIS 1.6)
  - Restrict `iam:*` and `sts:AssumeRole` permissions
  - Use permission boundaries
- **Detection:** Admin policy attachment, policy modification with dangerous permissions
- **Lab coverage:** IAM Scanner (admin policy check), IAM changes detection rules

### T1.3 — Unused/Stale Credentials
- **Attack vector:** Dormant accounts compromised without detection
- **Impact:** Long-term persistent access
- **Mitigations:**
  - Disable credentials unused >90 days (CIS 1.3)
  - Regular credential auditing
- **Detection:** Access from accounts inactive for extended periods
- **Lab coverage:** IAM Scanner (unused credentials), CIS credential checks

---

## 2. Data Security Threats

### T2.1 — Public Data Exposure
- **Attack vector:** Misconfigured S3 buckets, public access blocks disabled
- **Impact:** Sensitive data exposed to the internet
- **Mitigations:**
  - Enable S3 Block Public Access (CIS 2.1.5)
  - No `Principal: *` bucket policies
  - Enable encryption at rest (CIS 2.1.1)
- **Detection:** S3 public access configuration changes
- **Lab coverage:** S3 Scanner, encryption compliance checks

### T2.2 — Missing Encryption
- **Attack vector:** Data at rest or in transit without encryption
- **Impact:** Data readable if storage is compromised
- **Mitigations:**
  - EBS default encryption enabled
  - S3 bucket encryption enabled
  - RDS encryption enabled
  - Enforce SSL/TLS in bucket policies
- **Lab coverage:** Encryption compliance checks, S3 Scanner

---

## 3. Network Security Threats

### T3.1 — Unrestricted Network Access
- **Attack vector:** Security groups allowing 0.0.0.0/0 on SSH (22) or RDP (3389)
- **Impact:** Direct attack surface from the internet
- **Mitigations:**
  - Default security group restricts all traffic (CIS 4.1)
  - No unrestricted SSH/RDP (CIS 4.2)
  - Use VPN or bastion hosts for management access
- **Detection:** Security group ingress modifications allowing 0.0.0.0/0
- **Lab coverage:** Networking compliance checks, SG change detection rules, Azure NSG module

### T3.2 — Missing Network Monitoring
- **Attack vector:** Lateral movement without detection
- **Impact:** Attacker moves through network undetected
- **Mitigations:**
  - VPC Flow Logs enabled (CIS 4.3)
  - Azure NSG flow logs enabled
  - Network traffic analytics
- **Lab coverage:** Networking compliance checks, Azure NSG Terraform module

---

## 4. Logging & Monitoring Threats

### T4.1 — Logging Evasion
- **Attack vector:** Attacker disables CloudTrail, Config, or other logging services
- **Impact:** No audit trail of attacker activity
- **Mitigations:**
  - CloudTrail enabled in all regions (CIS 3.1)
  - Log file validation enabled (CIS 3.2)
  - KMS encryption on logs (CIS 3.7)
  - Alert on logging changes
- **Detection:** StopLogging, DeleteTrail, StopConfigurationRecorder events
- **Lab coverage:** CloudTrail Scanner, logging compliance checks, logging disabled detection rules

### T4.2 — Log Tampering
- **Attack vector:** Modification of audit logs to hide activity
- **Impact:** Compromised forensic evidence
- **Mitigations:**
  - CloudTrail log file validation (integrity hashes)
  - Immutable log storage (S3 Object Lock)
  - Separate log account
- **Lab coverage:** CloudTrail Scanner (log validation check)

---

## 5. Infrastructure Threats

### T5.1 — Insecure Default Configurations
- **Attack vector:** Using cloud service defaults which are often permissive
- **Impact:** Unintended exposure of resources
- **Mitigations:**
  - Override all security-relevant defaults
  - Infrastructure as Code with security guardrails
  - Automated configuration scanning
- **Lab coverage:** All scanner modules, Terraform modules with secure defaults

---

## MITRE ATT&CK Cloud Mapping

| Tactic | Lab Detection Rules |
|--------|-------------------|
| Initial Access | Root console login |
| Persistence | New user creation, admin policy attachment |
| Privilege Escalation | Admin policy attachment, policy modification |
| Defense Evasion | CloudTrail stopped/deleted, Config stopped, SG changes |
| Credential Access | (Future: key creation monitoring) |
| Discovery | (Future: reconnaissance API monitoring) |
| Exfiltration | (Future: S3 data transfer monitoring) |
| Impact | (Future: resource deletion monitoring) |

---

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [CIS AWS Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
- [CSA Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
