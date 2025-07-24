# Development Environment - PCI DSS Compliant EKS Infrastructure

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.1"
    }
  }

  # PCI DSS: Use remote state with encryption
  backend "s3" {
    # Configure these values according to your setup
    # bucket = "your-terraform-state-bucket"
    # key    = "development/eks/terraform.tfstate"
    # region = "us-west-1"
    # encrypt = true
    # kms_key_id = "arn:aws:kms:us-west-1:ACCOUNT:key/KEY-ID"
  }
}

provider "aws" {
  region = var.region

  # PCI DSS: Ensure all resources are tagged
  default_tags {
    tags = {
      Environment        = "development"
      Project           = "pci-dss-eks"
      ManagedBy         = "terraform"
      Owner             = "devops-team"
      CostCenter        = "engineering"
      ComplianceLevel   = "pci-dss"
      DataClassification = "restricted"
    }
  }
}

# PCI DSS: Get current AWS account information
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}

locals {
  name   = "dev-pci-eks"
  region = var.region

  # PCI DSS: Use only available AZs
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    Environment      = "development"
    Project         = "pci-dss-eks"
    Repository      = "https://github.com/company/infrastructure"
    ComplianceLevel = "pci-dss"
  }
}

module "environment" {
  source = "../../modules/environment"

  # Context configuration
  enabled     = true
  namespace   = "company"
  environment = "dev"
  stage       = "development"
  name        = "pci-eks"

  # Regional configuration
  region = local.region
  azs    = local.azs

  # PCI DSS: Use smaller CIDR for better network control
  vpc_cidr = "10.0.0.0/16"

  # EKS Configuration with PCI DSS requirements
  eks = {
    version = "1.32"
    
    node_groups = {
      pci_zone = {
        instance_types = ["m5.large"]
        min_size       = 3
        max_size       = 10
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
    
    # PCI DSS: Security configurations
    enable_irsa                 = true
    enable_cluster_encryption   = true
    enable_audit_logs          = true
    endpoint_public_access     = false
    endpoint_private_access    = true
    authorized_networks        = [] # No public access
  }

  # Additional tags
  tags = local.tags
}
