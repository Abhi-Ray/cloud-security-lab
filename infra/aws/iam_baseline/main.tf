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
# IAM Security Baseline Module
# Implements CIS AWS Foundations Benchmark IAM controls:
#   - Account password policy (CIS 1.8-1.14)
#   - Security audit role for least-privilege auditing
#   - CloudWatch alarm for root account usage (CIS 1.7)
# ------------------------------------------------------------------------------

# --- Account Password Policy ---
# CIS 1.8-1.14: Enforce strong password requirements
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = var.password_min_length
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = var.password_max_age_days
  password_reuse_prevention      = var.password_reuse_count
  hard_expiry                    = false
}

# --- Security Audit Role ---
# Read-only access to security services for auditing and compliance checks
resource "aws_iam_role" "security_auditor" {
  name = "${var.environment}-security-auditor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Module      = "iam-baseline"
    Environment = var.environment
    Purpose     = "security-auditing"
  })
}

# Attach AWS managed SecurityAudit policy
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.security_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# --- CloudWatch Alarm: Root Account Usage ---
# CIS 1.7: Monitor and alert on root account activity
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "${var.environment}-root-account-usage"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "CloudSecurityLab/IAM"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${var.environment}-root-account-usage"
  alarm_description   = "Alert when AWS root account is used (CIS 1.7)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CloudSecurityLab/IAM"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arn != null ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Module = "iam-baseline"
  })
}
