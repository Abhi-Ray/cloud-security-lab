terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.80"
    }
  }
}

# ------------------------------------------------------------------------------
# Azure NSG Security Baseline Module
# Implements network security controls:
#   - Default deny-all inbound rule
#   - Explicit allow for required ports only
#   - Block SSH/RDP from internet
#   - NSG flow logs for network monitoring
# ------------------------------------------------------------------------------

resource "azurerm_network_security_group" "this" {
  name                = "${var.environment}-${var.nsg_name}"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = merge(var.tags, {
    Module      = "nsg-baseline"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

# --- Default Deny All Inbound ---
# Security best practice: deny all inbound by default, explicitly allow required traffic
resource "azurerm_network_security_rule" "deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

# --- Allow HTTPS Inbound ---
# Only allow HTTPS traffic from specified sources
resource "azurerm_network_security_rule" "allow_https" {
  count = var.allow_https ? 1 : 0

  name                        = "AllowHTTPS"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = var.https_source_prefix
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

# --- Explicitly Deny SSH from Internet ---
# CIS Azure: Ensure SSH access is restricted from the internet
resource "azurerm_network_security_rule" "deny_ssh_internet" {
  name                        = "DenySSHFromInternet"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

# --- Explicitly Deny RDP from Internet ---
# CIS Azure: Ensure RDP access is restricted from the internet
resource "azurerm_network_security_rule" "deny_rdp_internet" {
  name                        = "DenyRDPFromInternet"
  priority                    = 210
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

# --- NSG Flow Logs ---
# Enable flow logs for network traffic analysis and security monitoring
resource "azurerm_network_watcher_flow_log" "this" {
  count = var.enable_flow_logs ? 1 : 0

  name                      = "${var.environment}-${var.nsg_name}-flowlog"
  network_watcher_name      = var.network_watcher_name
  resource_group_name       = var.network_watcher_resource_group
  network_security_group_id = azurerm_network_security_group.this.id
  storage_account_id        = var.flow_log_storage_account_id
  enabled                   = true
  version                   = 2

  retention_policy {
    enabled = true
    days    = var.flow_log_retention_days
  }

  traffic_analytics {
    enabled               = var.enable_traffic_analytics
    workspace_id          = var.log_analytics_workspace_id
    workspace_region      = var.location
    workspace_resource_id = var.log_analytics_workspace_resource_id
    interval_in_minutes   = 10
  }

  tags = merge(var.tags, {
    Module = "nsg-baseline"
  })
}
