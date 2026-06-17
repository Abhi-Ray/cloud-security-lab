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
# CloudTrail Module
# Implements CIS AWS Foundations Benchmark logging controls:
#   - Multi-region trail (CIS 3.1)
#   - Log file validation (CIS 3.2)
#   - KMS encryption (CIS 3.7)
#   - CloudWatch Logs integration
#   - S3 bucket logging for the trail bucket
# ------------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# --- KMS Key for CloudTrail Encryption ---
# CIS 3.7: Encrypt CloudTrail logs with customer-managed KMS key
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Module  = "cloudtrail"
    Purpose = "cloudtrail-encryption"
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.environment}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# --- CloudWatch Log Group ---
# Delivers CloudTrail events to CloudWatch for real-time monitoring
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Module = "cloudtrail"
  })
}

# IAM role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.environment}-cloudtrail-cloudwatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, { Module = "cloudtrail" })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "${var.environment}-cloudtrail-cloudwatch"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# --- CloudTrail ---
# CIS 3.1: Multi-region trail
# CIS 3.2: Log file validation enabled
resource "aws_cloudtrail" "main" {
  name                       = "${var.environment}-security-trail"
  s3_bucket_name             = var.s3_bucket_name
  s3_key_prefix              = "cloudtrail"
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.cloudtrail.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  # Log management events (read + write)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = merge(var.tags, {
    Module      = "cloudtrail"
    Environment = var.environment
    CIS         = "3.1,3.2,3.7"
  })

  depends_on = [aws_iam_role_policy.cloudtrail_cloudwatch]
}
