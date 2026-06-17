output "audit_role_arn" {
  description = "ARN of the security auditor IAM role."
  value       = aws_iam_role.security_auditor.arn
}

output "audit_role_name" {
  description = "Name of the security auditor IAM role."
  value       = aws_iam_role.security_auditor.name
}

output "password_policy_set" {
  description = "Whether the account password policy has been configured."
  value       = true
}
