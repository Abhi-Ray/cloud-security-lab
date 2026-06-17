# AWS Security Research Notes

## IAM Best Practices

### Principle of Least Privilege
- Grant only the permissions required to perform a task
- Use IAM Access Analyzer to identify unused permissions
- Implement permission boundaries for delegation
- Regularly review and remove unused permissions

### Root Account Security
- **Never** create access keys for the root account
- Enable MFA (hardware key preferred) on root
- Use root only for tasks that require it (billing, support plan changes)
- Set up CloudWatch alarm for root account usage

### Credential Management
- Rotate access keys every 90 days maximum
- Use IAM roles instead of long-term access keys where possible
- Use AWS SSO / IAM Identity Center for human access
- Disable credentials for users inactive >90 days
- Never embed credentials in code — use environment variables or Secrets Manager

### Password Policy Requirements (CIS Level 1)
- Minimum 14 characters
- Require uppercase, lowercase, numbers, symbols
- Maximum age: 90 days
- Prevent reuse of last 24 passwords

---

## S3 Security Configuration

### Block Public Access (Account + Bucket Level)
```
BlockPublicAcls: true        — Block new public ACLs
IgnorePublicAcls: true       — Ignore existing public ACLs
BlockPublicPolicy: true      — Block new public bucket policies
RestrictPublicBuckets: true  — Restrict public access points
```

### Encryption
- **SSE-S3 (AES-256):** AWS-managed keys, simplest option
- **SSE-KMS:** Customer-managed keys, audit trail via CloudTrail, key rotation
- **SSE-C:** Customer-provided keys, customer manages key lifecycle
- **Default encryption:** Enable at bucket level, applies to all new objects

### Access Logging
- Enable server access logging to a separate logging bucket
- Logging bucket should NOT log to itself (infinite loop)
- Use S3 analytics for access pattern optimization

### Bucket Policies
- Always deny non-HTTPS access (`aws:SecureTransport: false`)
- Restrict `Principal` — never use `*` without conditions
- Use `aws:PrincipalOrgID` condition for organization-only access

---

## CloudTrail Analysis Patterns

### High-Value Events to Monitor
| Event | Why |
|-------|-----|
| `ConsoleLogin` (Root) | Root account should never login |
| `StopLogging` | Attacker hiding tracks |
| `DeleteTrail` | Attacker hiding tracks |
| `AttachUserPolicy` (Admin) | Privilege escalation |
| `CreateUser` | Persistence mechanism |
| `AuthorizeSecurityGroupIngress` (0.0.0.0/0) | Opening network access |
| `PutBucketPolicy` (public) | Data exposure risk |
| `CreateAccessKey` (for other user) | Credential theft |
| `DisableKey` (KMS) | Denial of service on encrypted resources |

### CloudTrail Event Structure
```json
{
    "eventTime": "2024-01-15T10:30:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "AttachUserPolicy",
    "userIdentity": {
        "type": "IAMUser|Root|AssumedRole",
        "arn": "arn:aws:iam::ACCOUNT:user/NAME",
        "principalId": "AIDAEXAMPLE"
    },
    "sourceIPAddress": "198.51.100.1",
    "requestParameters": { ... },
    "responseElements": { ... }
}
```

---

## Common AWS Misconfigurations (Top 10)

1. **Public S3 buckets** — Still the #1 cause of data breaches
2. **Overly permissive IAM policies** — `*:*` action/resource combinations
3. **No MFA on root/admin accounts** — Single factor compromise = full access
4. **Security groups open to 0.0.0.0/0** — Unnecessary internet exposure
5. **CloudTrail not enabled in all regions** — Blind spots in logging
6. **Unencrypted storage** — EBS, S3, RDS without encryption at rest
7. **Unused/stale credentials** — Old access keys never rotated or disabled
8. **Default VPC security groups with inbound rules** — Should be empty
9. **No VPC Flow Logs** — Cannot investigate network-level incidents
10. **Hardcoded credentials** — API keys in code, Lambda env vars in plaintext

---

## References

- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [CIS AWS Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Prowler — AWS Security Tool](https://github.com/prowler-cloud/prowler)
- [ScoutSuite — Multi-Cloud Auditing](https://github.com/nccgroup/ScoutSuite)
