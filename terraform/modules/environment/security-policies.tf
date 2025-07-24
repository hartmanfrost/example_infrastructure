#  ┌─┐┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬   ┌─┐┌─┐┬  ┬┌─┐┬┌─┐┌─┐
#  └─┐├┤ │  │ │├┬┘│ │ └┬┘───├─┘│ ││  ││  │├┤ └─┐
#  └─┘└─┘└─┘└─┘┴└─┴ ┴  ┴    ┴  └─┘┴─┘┴└─┘┴└─┘└─┘

# PCI DSS: IAM role for EKS service account with least privilege
resource "aws_iam_role" "eks_node_group_pci" {
  name = "${module.this.name}-eks-node-group-pci"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(module.this.tags, {
    "PCI-DSS-Compliant" = "true"
    "Role-Purpose"      = "EKS-NodeGroup-PCI"
  })
}

# PCI DSS: Attach required policies with minimum permissions
resource "aws_iam_role_policy_attachment" "eks_node_group_pci_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group_pci.name
}

resource "aws_iam_role_policy_attachment" "eks_node_group_pci_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group_pci.name
}

resource "aws_iam_role_policy_attachment" "eks_node_group_pci_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group_pci.name
}

# PCI DSS: Custom policy for audit logging and compliance monitoring
resource "aws_iam_policy" "eks_pci_compliance_policy" {
  name        = "${module.this.name}-eks-pci-compliance"
  description = "PCI DSS compliance policy for EKS nodes"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "AllowSystemsManagerForCompliance"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssm:UpdateInstanceInformation",
          "ssm:SendCommand"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/aws/service/eks/optimized-ami/*",
          "arn:aws:ssm:*:*:instance/*"
        ]
      },
      {
        Sid    = "AllowKMSForEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.eks.arn
      }
    ]
  })

  tags = merge(module.this.tags, {
    "PCI-DSS-Compliant" = "true"
  })
}

resource "aws_iam_role_policy_attachment" "eks_node_group_pci_compliance_policy" {
  policy_arn = aws_iam_policy.eks_pci_compliance_policy.arn
  role       = aws_iam_role.eks_node_group_pci.name
}

# PCI DSS: IAM role for IRSA (IAM Roles for Service Accounts) for PCI workloads
resource "aws_iam_role" "pci_workload_irsa" {
  name = "${module.this.name}-pci-workload-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:pci-workload:pci-service-account"
            "${module.eks.oidc_provider}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(module.this.tags, {
    "PCI-DSS-Compliant" = "true"
    "Role-Purpose"      = "IRSA-PCI-Workload"
  })
}

# PCI DSS: Policy for PCI workload IRSA role
resource "aws_iam_policy" "pci_workload_irsa_policy" {
  name        = "${module.this.name}-pci-workload-irsa-policy"
  description = "Policy for PCI workload service account with minimal permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecretsManagerAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:pci-workload/*"
        ]
      },
      {
        Sid    = "AllowParameterStoreAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/pci-workload/*"
        ]
      },
      {
        Sid    = "AllowKMSDecryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.eks.arn
      }
    ]
  })

  tags = merge(module.this.tags, {
    "PCI-DSS-Compliant" = "true"
  })
}

resource "aws_iam_role_policy_attachment" "pci_workload_irsa_policy" {
  policy_arn = aws_iam_policy.pci_workload_irsa_policy.arn
  role       = aws_iam_role.pci_workload_irsa.name
}

# PCI DSS: CloudWatch log group for EKS audit logs
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${module.this.name}/cluster"
  retention_in_days = 90  # PCI DSS: Retain logs for 90 days minimum
  kms_key_id        = aws_kms_key.eks.arn

  tags = merge(module.this.tags, {
    "PCI-DSS-Audit-Log" = "true"
  })
}

# PCI DSS: CloudWatch log group for node group logs
resource "aws_cloudwatch_log_group" "eks_node_group" {
  name              = "/aws/eks/${module.this.name}/nodegroup"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.eks.arn

  tags = merge(module.this.tags, {
    "PCI-DSS-Audit-Log" = "true"
  })
}

# PCI DSS: Network ACL for additional security layer
resource "aws_network_acl" "eks_private_nacl" {
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Allow HTTPS traffic
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 443
    to_port    = 443
  }

  # Allow Kubernetes API traffic
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 6443
    to_port    = 6443
  }

  # Allow kubelet communication
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 10250
    to_port    = 10250
  }

  # Allow ephemeral ports for responses
  ingress {
    protocol   = "tcp"
    rule_no    = 130
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Deny all other inbound traffic
  ingress {
    protocol   = "-1"
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow all outbound traffic (can be restricted further based on requirements)
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(module.this.tags, {
    Name = "${module.this.name}-eks-private-nacl"
    "PCI-DSS-Network-Control" = "true"
  })
}

# PCI DSS: S3 bucket for audit logs with encryption and versioning
resource "aws_s3_bucket" "eks_audit_logs" {
  bucket = "${module.this.name}-eks-audit-logs-${random_id.bucket_suffix.hex}"

  tags = merge(module.this.tags, {
    "PCI-DSS-Audit-Storage" = "true"
  })
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "eks_audit_logs" {
  bucket = aws_s3_bucket.eks_audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "eks_audit_logs" {
  bucket = aws_s3_bucket.eks_audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.eks.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "eks_audit_logs" {
  bucket = aws_s3_bucket.eks_audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# PCI DSS: Lifecycle policy for audit logs
resource "aws_s3_bucket_lifecycle_configuration" "eks_audit_logs" {
  bucket = aws_s3_bucket.eks_audit_logs.id

  rule {
    id     = "audit_log_lifecycle"
    status = "Enabled"

    # Add filter to apply to all objects
    filter {
      prefix = ""
    }

    # PCI DSS: Transition to cheaper storage after 30 days
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # PCI DSS: Move to Glacier after 90 days
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # PCI DSS: Keep logs for 7 years (2555 days) for compliance
    expiration {
      days = 2555
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
