variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail log storage."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}
