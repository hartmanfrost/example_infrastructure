#  ┐ ┬┬─┐┬─┐o┬─┐┬─┐┬  ┬─┐┐─┐
#  │┌┘│─┤│┬┘││─┤│─││  ├─ └─┐
#  └┘ ┘ ┘┘└┘┘┘ ┘┘─┘┘─┘┴─┘──┘

variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-west-1"
}

# PCI DSS: Additional security variables
variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring"
  type        = bool
  default     = true
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "enable_config_recorder" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain logs for PCI DSS compliance"
  type        = number
  default     = 90
  
  validation {
    condition     = var.log_retention_days >= 90
    error_message = "PCI DSS requires log retention of at least 90 days."
  }
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the cluster (empty for internal only)"
  type        = list(string)
  default     = []
}

variable "enable_irsa" {
  description = "Enable IAM Roles for Service Accounts"
  type        = bool
  default     = true
}

variable "enable_cluster_encryption" {
  description = "Enable EKS cluster encryption"
  type        = bool
  default     = true
}
