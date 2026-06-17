# Secure S3 Bucket Module

Creates an S3 bucket with security best practices aligned to CIS AWS Foundations Benchmark.

## Security Controls

| Control | Implementation |
|---------|---------------|
| CIS 2.1.1 | Server-side encryption (AES-256 or KMS) |
| CIS 2.1.5 | Block all public access |
| SSL/TLS | Bucket policy denies non-HTTPS requests |
| Versioning | Enabled for data protection |
| Logging | Access logging to separate bucket |
| Lifecycle | Auto-transition to cheaper storage tiers |

## Usage

```hcl
module "secure_bucket" {
  source = "../../modules/s3_secure_bucket"

  bucket_name    = "my-secure-data-bucket"
  environment    = "prod"
  kms_key_arn    = aws_kms_key.s3.arn
  logging_bucket = module.logging_bucket.bucket_id

  tags = {
    Team    = "security"
    Project = "cloud-security-lab"
  }
}
```

## Inputs

| Name | Description | Type | Required |
|------|-------------|------|----------|
| `bucket_name` | Globally unique bucket name | `string` | Yes |
| `environment` | Environment (dev/staging/prod) | `string` | No |
| `kms_key_arn` | KMS key ARN for encryption | `string` | No |
| `logging_bucket` | Bucket for access logs | `string` | No |
| `tags` | Additional resource tags | `map(string)` | No |

## Outputs

| Name | Description |
|------|-------------|
| `bucket_arn` | ARN of the created bucket |
| `bucket_id` | Name/ID of the bucket |
| `bucket_domain_name` | Domain name of the bucket |
