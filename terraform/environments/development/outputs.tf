# EKS Cluster Outputs
output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.environment.eks_cluster_endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.environment.eks_cluster_id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = module.environment.eks_cluster_arn
}

output "cluster_version" {
  description = "EKS cluster Kubernetes version"
  value       = module.environment.eks_cluster_version
}

# PCI DSS Security Information
output "kms_key_arn" {
  description = "KMS key ARN used for encryption"
  value       = module.environment.eks_encryption_key_arn
  sensitive   = true
}

output "audit_log_group" {
  description = "CloudWatch log group for audit logs"
  value       = module.environment.eks_audit_log_group
}

output "audit_s3_bucket" {
  description = "S3 bucket for audit log storage"
  value       = module.environment.eks_audit_s3_bucket
}

# Security Groups
output "database_security_group_id" {
  description = "Security group for database pods"
  value       = module.environment.eks_database_security_group_id
}

output "application_security_group_id" {
  description = "Security group for application pods"
  value       = module.environment.eks_application_security_group_id
}

output "worker_security_group_id" {
  description = "Security group for worker nodes"
  value       = module.environment.eks_worker_security_group_id
}

# VPC Information
output "vpc_id" {
  description = "VPC ID"
  value       = module.environment.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.environment.private_subnet_ids
}

# Monitoring and Alerting
output "alerts_topic_arn" {
  description = "SNS topic for security alerts"
  value       = module.environment.pci_alerts_topic_arn
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = module.environment.cloudtrail_arn
}

# Access Instructions
output "kubectl_config_command" {
  description = "Command to configure kubectl"
  value       = module.environment.kubectl_config
}

# PCI DSS Compliance Status
output "pci_dss_compliance_tags" {
  description = "PCI DSS compliance tags applied"
  value       = module.environment.pci_dss_tags
}
