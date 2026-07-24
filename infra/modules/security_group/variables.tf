# Variables for Add Terraform security-group module with CIS presets

variable "name" {
  description = "Name for the resource"
  type        = string
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "tags" {
  description = "Additional tags to apply"
  type        = map(string)
  default     = {}
}
