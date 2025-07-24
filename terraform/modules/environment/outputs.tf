#  ┌─┐┬ ┬┌┬┐┌─┐┬ ┬┌┬┐┌─┐
#  │ ││ │ │ ├─┘│ │ │ └─┐
#  └─┘└─┘ ┴ ┴  └─┘ ┴ └─┘

# EKS Cluster Information
output "eks_cluster_id" {
  description = "EKS cluster ID"
  value       = module.eks.cluster_id
}

output "eks_cluster_arn" {
  description = "EKS cluster ARN"
  value       = module.eks.cluster_arn
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_version" {
  description = "EKS cluster version"
  value       = module.eks.cluster_version
}

output "eks_oidc_provider_arn" {
  description = "EKS OIDC provider ARN"
  value       = module.eks.oidc_provider_arn
}

output "eks_oidc_provider" {
  description = "EKS OIDC provider"
  value       = module.eks.oidc_provider
}

output "eks_cluster_security_group_id" {
  description = "EKS cluster security group ID"
  value       = module.eks.cluster_security_group_id
}

# PCI DSS Security Information
output "eks_encryption_key_arn" {
  description = "KMS key ARN used for EKS encryption"
  value       = aws_kms_key.eks.arn
  sensitive   = true
}

output "eks_audit_log_group" {
  description = "CloudWatch log group for EKS audit logs"
  value       = aws_cloudwatch_log_group.eks_cluster.name
}

output "eks_audit_s3_bucket" {
  description = "S3 bucket for long-term audit log storage"
  value       = aws_s3_bucket.eks_audit_logs.bucket
}

# Security Groups for Pod-level Security
output "eks_database_security_group_id" {
  description = "Security group ID for database pods"
  value       = aws_security_group.eks_database_pods.id
}

output "eks_application_security_group_id" {
  description = "Security group ID for application pods"
  value       = aws_security_group.eks_application_pods.id
}

output "eks_worker_security_group_id" {
  description = "Security group ID for worker nodes"
  value       = aws_security_group.eks_worker_nodes.id
}

# PCI DSS IAM Role for Service Accounts
output "pci_workload_irsa_role_arn" {
  description = "IAM role ARN for PCI workload service account (IRSA)"
  value       = aws_iam_role.pci_workload_irsa.arn
}

# Node Group Information
output "eks_node_groups" {
  description = "EKS node groups"
  value       = module.eks.eks_managed_node_groups
}

# VPC Information
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnets
}

# Monitoring and Alerting
output "pci_alerts_topic_arn" {
  description = "SNS topic ARN for PCI DSS security alerts"
  value       = aws_sns_topic.pci_alerts.arn
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN for audit logging"
  value       = aws_cloudtrail.eks_audit_trail.arn
}

# Access Configuration
output "kubectl_config" {
  description = "kubectl config command to access the cluster"
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_id}"
}

# PCI DSS Compliance Tags
output "pci_dss_tags" {
  description = "PCI DSS compliance tags applied to resources"
  value = {
    "PCI-DSS-Compliant"    = "true"
    "Encryption-At-Rest"   = "enabled"
    "Encryption-In-Transit" = "enabled"
    "Audit-Logging"        = "enabled"
    "Network-Segmentation" = "enabled"
    "Access-Control"       = "enabled"
  }
}
