variable "nsg_name" {
  description = "Name of the Network Security Group."
  type        = string
}

variable "location" {
  description = "Azure region for the resources."
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group."
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "allow_https" {
  description = "Whether to allow HTTPS inbound traffic."
  type        = bool
  default     = true
}

variable "https_source_prefix" {
  description = "Source address prefix for HTTPS access."
  type        = string
  default     = "*"
}

variable "enable_flow_logs" {
  description = "Enable NSG flow logs for network monitoring."
  type        = bool
  default     = false
}

variable "network_watcher_name" {
  description = "Name of the Network Watcher (required if flow logs enabled)."
  type        = string
  default     = ""
}

variable "network_watcher_resource_group" {
  description = "Resource group of the Network Watcher."
  type        = string
  default     = ""
}

variable "flow_log_storage_account_id" {
  description = "Storage account ID for flow log storage."
  type        = string
  default     = ""
}

variable "flow_log_retention_days" {
  description = "Number of days to retain flow logs."
  type        = number
  default     = 90
}

variable "enable_traffic_analytics" {
  description = "Enable Traffic Analytics for NSG flow logs."
  type        = bool
  default     = false
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for Traffic Analytics."
  type        = string
  default     = ""
}

variable "log_analytics_workspace_resource_id" {
  description = "Full resource ID of the Log Analytics workspace."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}
