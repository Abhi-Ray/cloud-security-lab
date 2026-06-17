output "trail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.main.arn
}

output "trail_name" {
  description = "Name of the CloudTrail trail."
  value       = aws_cloudtrail.main.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Logs group for CloudTrail."
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Logs group."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for CloudTrail encryption."
  value       = aws_kms_key.cloudtrail.arn
}
