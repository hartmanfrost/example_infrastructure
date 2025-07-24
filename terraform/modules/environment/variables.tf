variable "region" {
  type = string
  default = "us-west-1"
}

variable "azs" {
  type = list(string)
  default = ["us-west-1a", "us-west-1b", "us-west-1c"]
}

variable "vpc_cidr" {
  type = string
  default = "10.0.0.0/16"
}

# PCI DSS: EKS configuration with security requirements
variable "eks" {
  description = "EKS cluster configuration for PCI DSS compliance"
  type = object({
    version = string
    node_groups = object({
      pci_zone = object({
        instance_types = list(string)
        min_size       = number
        max_size       = number
        desired_size   = number
        disk_size      = number
      })
      general = object({
        instance_types = list(string)
        min_size       = number
        max_size       = number
        desired_size   = number
        disk_size      = number
      })
    })
    # PCI DSS: Security-related configurations
    enable_irsa                = bool
    enable_cluster_encryption  = bool
    enable_audit_logs         = bool
    endpoint_public_access    = bool
    endpoint_private_access   = bool
    # PCI DSS: Network segmentation
    authorized_networks       = list(string)
  })
  default = {
    version = "1.29"
    node_groups = {
      pci_zone = {
        instance_types = ["m5.large"]
        min_size       = 3
        max_size       = 7
        desired_size   = 3
        disk_size      = 100
      }
      general = {
        instance_types = ["t3.medium"]
        min_size       = 2
        max_size       = 5
        desired_size   = 2
        disk_size      = 50
      }
    }
    enable_irsa                = true
    enable_cluster_encryption  = true
    enable_audit_logs         = true
    endpoint_public_access    = false
    endpoint_private_access   = true
    authorized_networks       = []
  }
  
  validation {
    condition     = !var.eks.endpoint_public_access
    error_message = "PCI DSS requires endpoint_public_access to be false for security."
  }
  
  validation {
    condition     = var.eks.enable_cluster_encryption
    error_message = "PCI DSS requires cluster encryption to be enabled."
  }
  
  validation {
    condition     = var.eks.enable_audit_logs
    error_message = "PCI DSS requires audit logs to be enabled."
  }
}
