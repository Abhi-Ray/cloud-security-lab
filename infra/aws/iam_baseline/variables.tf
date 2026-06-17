variable "account_id" {
  description = "AWS Account ID for trust policy configuration."
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "password_min_length" {
  description = "Minimum password length (CIS recommends >= 14)."
  type        = number
  default     = 14
}

variable "password_max_age_days" {
  description = "Maximum password age in days (CIS recommends <= 90)."
  type        = number
  default     = 90
}

variable "password_reuse_count" {
  description = "Number of previous passwords to prevent reuse (CIS recommends >= 24)."
  type        = number
  default     = 24
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch Logs group name where CloudTrail delivers logs."
  type        = string
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for security alarms. If null, alarms have no action."
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}
