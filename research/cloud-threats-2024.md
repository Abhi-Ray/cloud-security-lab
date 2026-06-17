# Cloud Threat Landscape — 2024

## Top Cloud Security Threats

Based on CSA (Cloud Security Alliance) and OWASP Cloud Security research.

### 1. Misconfiguration and Inadequate Change Control
- **Still the #1 cloud threat** per CSA Top Threats report
- Root cause: complexity of cloud services, default-open configurations
- Examples: public S3 buckets, open security groups, disabled logging
- **Mitigation:** Infrastructure as Code, automated scanning, policy-as-code

### 2. Identity and Access Management Weaknesses
- Overprivileged accounts, missing MFA, stale credentials
- Cloud IAM is more complex than traditional on-prem identity
- Cross-account access and role chaining create escalation paths
- **Mitigation:** Least privilege, MFA everywhere, regular access reviews

### 3. Insecure Interfaces and APIs
- Cloud services are API-first — every API is an attack surface
- Misconfigured API gateways, missing authentication
- Leaked API keys in public repositories
- **Mitigation:** API authentication/authorization, secret scanning, rate limiting

### 4. Insufficient Logging and Monitoring
- Many organizations don't enable CloudTrail in all regions
- Log analysis is difficult at cloud scale
- Alert fatigue leads to missed detections
- **Mitigation:** Centralized logging, automated detection rules, SLA on alert triage

### 5. Supply Chain Vulnerabilities
- Third-party container images, Lambda layers, Terraform modules
- Dependency confusion attacks
- Compromised CI/CD pipelines
- **Mitigation:** Image scanning, SBOM, signed artifacts, pipeline security

---

## Notable Cloud Security Incidents

### Capital One Breach (2019)
- **What:** SSRF attack exploiting misconfigured WAF to access EC2 instance metadata
- **Impact:** 100 million customer records exposed
- **Root cause:** Overly permissive IAM role on WAF instance + SSRF vulnerability
- **Lessons:** Least privilege IAM, IMDSv2 enforcement, WAF hardening

### Microsoft Power Apps Data Exposure (2021)
- **What:** 38 million records exposed due to misconfigured OData API permissions
- **Impact:** PII from government agencies, airlines, major corporations
- **Root cause:** Default API permissions were overly permissive
- **Lessons:** Review default configurations, data classification, access controls

### Uber Data Breach (2022)
- **What:** Attacker used stolen contractor credentials, MFA fatigue attack
- **Impact:** Internal systems compromised, data from Slack, HackerOne
- **Root cause:** Hardcoded credentials in PowerShell scripts, MFA push spam
- **Lessons:** Phishing-resistant MFA, no hardcoded credentials, privileged access management

### LastPass Breach (2022-2023)
- **What:** Attacker compromised developer account, then accessed cloud backup storage
- **Impact:** Customer vault data exfiltrated (encrypted)
- **Root cause:** Single engineer had access to decryption keys, insufficient segmentation
- **Lessons:** Separation of duties, key management, cloud storage access controls

---

## Emerging Attack Techniques

### 1. Cloud-Native Lateral Movement
- Exploiting service-linked roles and cross-service permissions
- Pivoting through Lambda → S3 → RDS chains
- Using metadata services for credential harvesting

### 2. AI/LLM-Assisted Attacks
- Automated reconnaissance of cloud environments
- LLM-generated phishing for credential theft
- Automated exploit generation from cloud documentation

### 3. Container and Serverless Attacks
- Escape from container isolation
- Cold start injection in serverless functions
- Supply chain attacks via public container registries

### 4. Cloud Ransomware
- Encrypting S3 buckets with attacker-controlled KMS keys
- Deleting backups before encryption
- Demanding ransom for KMS key access

---

## Defense Recommendations

1. **Implement CIS Benchmarks** — Baseline configuration for every cloud service
2. **Enable comprehensive logging** — CloudTrail (all regions), VPC Flow Logs, S3 access logs
3. **Automate security scanning** — Run compliance checks in CI/CD pipeline
4. **Use Infrastructure as Code** — Terraform/CloudFormation with security guardrails
5. **Enforce MFA everywhere** — Especially root, admin, and API access
6. **Regular access reviews** — Automated credential rotation, unused account cleanup
7. **Detection engineering** — Custom rules for your specific environment
8. **Incident response runbooks** — Pre-built playbooks for common cloud incidents
9. **Network segmentation** — VPC design with security group layering
10. **Security training** — Cloud-specific security awareness for engineers

---

## References

- [CSA Top Threats to Cloud Computing 2024](https://cloudsecurityalliance.org/research/top-threats/)
- [OWASP Cloud-Native Application Security Top 10](https://owasp.org/www-project-cloud-native-application-security-top-10/)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Datadog State of Cloud Security 2024](https://www.datadoghq.com/state-of-cloud-security/)
