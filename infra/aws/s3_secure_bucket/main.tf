terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ------------------------------------------------------------------------------
# S3 Secure Bucket Module
# Implements CIS AWS Foundations Benchmark controls for S3:
#   - Block all public access (CIS 2.1.5)
#   - Enable server-side encryption (CIS 2.1.1)
#   - Enable versioning for data protection
#   - Enable access logging for audit trail
#   - Enforce SSL/TLS-only access via bucket policy
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name

  tags = merge(var.tags, {
    Module      = "s3-secure-bucket"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

# --- Versioning ---
# Protects against accidental deletion and enables object recovery
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

# --- Server-Side Encryption ---
# Encrypts all objects at rest (CIS 2.1.1)
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

# --- Block Public Access ---
# Prevents any public access to the bucket (CIS 2.1.5)
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Access Logging ---
# Records all access requests for security auditing
resource "aws_s3_bucket_logging" "this" {
  count = var.logging_bucket != null ? 1 : 0

  bucket        = aws_s3_bucket.this.id
  target_bucket = var.logging_bucket
  target_prefix = "${var.bucket_name}/logs/"
}

# --- Bucket Policy: Enforce SSL/TLS ---
# Denies any requests that don't use HTTPS
resource "aws_s3_bucket_policy" "enforce_ssl" {
  bucket = aws_s3_bucket.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceSSLOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.this.arn,
          "${aws_s3_bucket.this.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.this]
}

# --- Lifecycle Rules ---
# Cost management: transition old objects to cheaper storage
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}
