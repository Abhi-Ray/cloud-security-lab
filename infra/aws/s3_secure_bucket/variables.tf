variable "bucket_name" {
  description = "Name of the S3 bucket. Must be globally unique."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Bucket name must be 3-63 characters, lowercase, and DNS-compliant."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for server-side encryption. If null, AES-256 is used."
  type        = string
  default     = null
}

variable "logging_bucket" {
  description = "Name of the S3 bucket to receive access logs. If null, logging is disabled."
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}
