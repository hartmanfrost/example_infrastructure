#  ┬─┐┬┌ ┐─┐
#  ├─ ├┴┐└─┐
#  ┴─┘┘ ┘──┘

# PCI DSS: KMS key for EKS encryption
resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EKS to use the key"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(module.this.tags, {
    Name        = "${module.this.name}-eks-kms"
    Description = "KMS key for EKS cluster encryption"
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${module.this.name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

data "aws_caller_identity" "current" {}

# PCI DSS: Enhanced security group for EKS control plane
resource "aws_security_group" "eks_control_plane_additional" {
  name_prefix = "${module.this.name}-eks-control-plane-additional"
  vpc_id      = module.vpc.vpc_id
  description = "Additional security group for EKS control plane with PCI DSS compliance"

  # PCI DSS: Restrict access to necessary ports only
  ingress {
    description = "HTTPS from private subnets only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }

  tags = merge(module.this.tags, {
    Name = "${module.this.name}-eks-control-plane-additional"
  })
}

# PCI DSS: Security group for worker nodes
resource "aws_security_group" "eks_worker_nodes" {
  name_prefix = "${module.this.name}-eks-worker-nodes"
  vpc_id      = module.vpc.vpc_id
  description = "Security group for EKS worker nodes with PCI DSS compliance"

  # EKS: Node to node communication (all ports within cluster)
  ingress {
    description = "Node to node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # EKS: CoreDNS
  ingress {
    description = "CoreDNS TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "CoreDNS UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    self        = true
  }

  # EKS: NodePort services range
  ingress {
    description = "NodePort services"
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }

  tags = merge(module.this.tags, {
    Name = "${module.this.name}-eks-worker-nodes"
  })
}

# Separate security group rules to avoid circular dependencies

# Control plane to worker nodes egress rules
resource "aws_security_group_rule" "control_plane_to_workers_https" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_worker_nodes.id
  security_group_id        = aws_security_group.eks_control_plane_additional.id
  description              = "Control plane to worker nodes HTTPS"
}

resource "aws_security_group_rule" "control_plane_to_workers_kubelet" {
  type                     = "egress"
  from_port                = 10250
  to_port                  = 10250
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_worker_nodes.id
  security_group_id        = aws_security_group.eks_control_plane_additional.id
  description              = "Control plane to worker nodes kubelet"
}

# Worker nodes to control plane ingress rules
resource "aws_security_group_rule" "workers_from_control_plane_kubelet" {
  type                     = "ingress"
  from_port                = 10250
  to_port                  = 10250
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_control_plane_additional.id
  security_group_id        = aws_security_group.eks_worker_nodes.id
  description              = "Control plane to worker kubelets"
}

resource "aws_security_group_rule" "workers_from_control_plane_https" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_control_plane_additional.id
  security_group_id        = aws_security_group.eks_worker_nodes.id
  description              = "Control plane to worker nodes HTTPS"
}

# Worker nodes to control plane egress rules
resource "aws_security_group_rule" "workers_to_control_plane_https" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_control_plane_additional.id
  security_group_id        = aws_security_group.eks_worker_nodes.id
  description              = "Worker nodes to control plane HTTPS"
}

resource "aws_security_group_rule" "workers_to_control_plane_kubelet" {
  type                     = "egress"
  from_port                = 10250
  to_port                  = 10250
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.eks_control_plane_additional.id
  security_group_id        = aws_security_group.eks_worker_nodes.id
  description              = "Worker nodes to control plane for logs/exec/port-forward"
}

# Worker nodes egress rules for internet access
resource "aws_security_group_rule" "workers_https_outbound" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.eks_worker_nodes.id
  description       = "HTTPS outbound for pulling images"
}

resource "aws_security_group_rule" "workers_http_outbound" {
  type              = "egress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.eks_worker_nodes.id
  description       = "HTTP outbound for package updates"
}

resource "aws_security_group_rule" "workers_dns_tcp_outbound" {
  type              = "egress"
  from_port         = 53
  to_port           = 53
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.eks_worker_nodes.id
  description       = "DNS TCP outbound"
}

resource "aws_security_group_rule" "workers_dns_udp_outbound" {
  type              = "egress"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.eks_worker_nodes.id
  description       = "DNS UDP outbound"
}

resource "aws_security_group_rule" "workers_ntp_outbound" {
  type              = "egress"
  from_port         = 123
  to_port           = 123
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.eks_worker_nodes.id
  description       = "NTP outbound"
}

resource "aws_security_group_rule" "workers_node_to_node_outbound" {
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.eks_worker_nodes.id
  description       = "Node to node communication"
}

# PCI DSS: Additional security group for database pods
resource "aws_security_group" "eks_database_pods" {
  name_prefix = "${module.this.name}-eks-database-pods"
  vpc_id      = module.vpc.vpc_id
  description = "Security group for database pods with PCI DSS compliance"

  # Only allow specific database ports from application pods
  ingress {
    description = "PostgreSQL from application pods"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.eks_worker_nodes.id]
  }

  ingress {
    description = "MySQL from application pods"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.eks_worker_nodes.id]
  }

  egress {
    description = "Limited outbound for database updates only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(module.this.tags, {
    Name = "${module.this.name}-eks-database-pods"
    "PCI-DSS-Zone" = "cardholder-data"
  })
}

# PCI DSS: Security group for application pods
resource "aws_security_group" "eks_application_pods" {
  name_prefix = "${module.this.name}-eks-app-pods"
  vpc_id      = module.vpc.vpc_id
  description = "Security group for application pods with PCI DSS compliance"

  ingress {
    description = "HTTP from load balancer"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }

  ingress {
    description = "HTTPS from load balancer"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }

  egress {
    description = "HTTPS to external services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "PostgreSQL access"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.eks_database_pods.id]
  }
  egress {
    description = "MySQL access"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.eks_database_pods.id]
  }

  tags = merge(module.this.tags, {
    Name = "${module.this.name}-eks-application-pods"
    "PCI-DSS-Zone" = "application"
  })
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  # Cluster configuration
  name               = module.this.name
  kubernetes_version = var.eks.version
  
  # PCI DSS: Network security - disable public access
  endpoint_public_access  = false
  endpoint_private_access = true
  endpoint_public_access_cidrs = []

  # PCI DSS: Enable encryption at rest for EKS secrets
  encryption_config = {
    provider_key_arn = aws_kms_key.eks.arn
    resources        = ["secrets"]
  }

  # PCI DSS: Enable comprehensive audit logging
  enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  # PCI DSS: CloudWatch log group configuration
  create_cloudwatch_log_group            = true
  cloudwatch_log_group_retention_in_days = 90
  cloudwatch_log_group_kms_key_id        = aws_kms_key.eks.arn

  # Network configuration
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # PCI DSS: Use additional security groups
  additional_security_group_ids = [
    aws_security_group.eks_control_plane_additional.id
  ]
  
  # EKS Add-ons configuration with auto-latest versions
  addons = {
    coredns = {
      most_recent = true  # Automatically use the latest compatible version
    }
    eks-pod-identity-agent = {
      before_compute = true
      most_recent    = true  # Automatically use the latest compatible version
    }
    kube-proxy = {
      most_recent = true  # Automatically use the latest compatible version
    }
    vpc-cni = {
      before_compute = true
      most_recent    = true  # Automatically use the latest compatible version
      configuration_values = jsonencode({
        env = {
          ENABLE_POD_ENI = "true"
          # PCI DSS: Enable network policies support
          ENABLE_PREFIX_DELEGATION = "true"
        }
      })
    }
    # PCI DSS: Add EBS CSI driver for encrypted storage
    aws-ebs-csi-driver = {
      most_recent = true  # Automatically use the latest compatible version
      configuration_values = jsonencode({
        controller = {
          extraArgs = {
            kms-key-id = aws_kms_key.eks.arn
          }
        }
      })
    }
  }


  # PCI DSS: Access entries for secure access control
  access_entries = {
    devops-admin = {
      principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/devops-role"
      kubernetes_groups = ["system:masters"]
      
      policy_associations = {
        cluster_admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
      
      tags = {
        "Access-Level" = "admin"
        "PCI-DSS-Role" = "administrator"
      }
    }
    
    developer-readonly = {
      principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/developer-role"
      kubernetes_groups = ["developers"]
      
      policy_associations = {
        view_only = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
      
      tags = {
        "Access-Level" = "readonly"
        "PCI-DSS-Role" = "viewer"
      }
    }
    
    # PCI DSS: Dedicated service account for deploying PCI workloads from CI/CD
    # TODO: Add OIDC provider and service account association
    pci-workload-service = {
      principal_arn = aws_iam_role.eks_node_group_pci.arn
      kubernetes_groups = ["pci-workload"]
      
      policy_associations = {
        edit_pci_namespace = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
          access_scope = {
            type = "namespace"
            namespaces = ["pci-workload"]
          }
        }
      }
      
      tags = {
        "Access-Level" = "namespace-edit"
        "PCI-DSS-Role" = "workload-manager"
      }
    }
  }

  # PCI DSS: EKS Managed Node Groups with enhanced security
  eks_managed_node_groups = {
    # PCI DSS: Dedicated node group for PCI workloads
    pci_zone = {
      # Basic configuration
      name           = "${module.this.name}-pci-nodes"
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = var.eks.node_groups.pci_zone.instance_types
      capacity_type  = "ON_DEMAND"  # PCI DSS: No spot instances for critical workloads
      
      # Scaling configuration
      min_size     = var.eks.node_groups.pci_zone.min_size
      max_size     = var.eks.node_groups.pci_zone.max_size
      desired_size = var.eks.node_groups.pci_zone.desired_size
      
      # PCI DSS: Encrypted storage with larger volumes for audit logs
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = var.eks.node_groups.pci_zone.disk_size
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 150
            encrypted             = true
            kms_key_id            = aws_kms_key.eks.arn
            delete_on_termination = true
          }
        }
      }
      
      # PCI DSS: Network security
      vpc_security_group_ids = [aws_security_group.eks_worker_nodes.id]
      subnet_ids            = module.vpc.private_subnets
      
      # PCI DSS: Enhanced monitoring and security
      enable_monitoring = true
      
      # PCI DSS: Force tokens for IMDSv2 (Instance Metadata Service Version 2) for security
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 2
        instance_metadata_tags      = "disabled"
      }
      
      # Launch template configuration
      create_launch_template = true
      launch_template_tags = {
        "PCI-DSS-Template" = "true"
        "Security-Level"   = "high"
      }
      
      # PCI DSS: Security labels and taints for workload isolation
      labels = {
        "compliance.pci-dss"     = "true"
        "security.zone"          = "restricted"
        "monitoring.enabled"     = "true"
        "workload.isolation"     = "enabled"
      }
      
      taints = {
        pci_workload = {
          key    = "compliance/pci-dss"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
      
      # Update configuration for rolling updates
      update_config = {
        max_unavailable_percentage = 25
      }
      
      # Tags
      tags = merge(module.this.tags, {
        "PCI-DSS-Compliant" = "true"
        "Security-Zone"     = "restricted"
        "Node-Group-Type"   = "pci-workload"
      })
    }
    
    # General purpose node group for non-PCI workloads
    general = {
      # Basic configuration
      name           = "${module.this.name}-general-nodes"
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = var.eks.node_groups.general.instance_types
      capacity_type  = "SPOT"  # Cost optimization for non-critical workloads
      
      # Scaling configuration
      min_size     = var.eks.node_groups.general.min_size
      max_size     = var.eks.node_groups.general.max_size
      desired_size = var.eks.node_groups.general.desired_size
      
      # Storage configuration
      disk_size = var.eks.node_groups.general.disk_size
      
      # Network security
      vpc_security_group_ids = [aws_security_group.eks_worker_nodes.id]
      subnet_ids            = module.vpc.private_subnets
      
      # Basic monitoring
      enable_monitoring = false
      
      # Security labels
      labels = {
        "security.zone"     = "general"
        "workload.type"     = "non-critical"
        "cost.optimization" = "enabled"
      }
      
      # Update configuration
      update_config = {
        max_unavailable_percentage = 50  # More aggressive updates for non-critical
      }
      
      # Tags
      tags = merge(module.this.tags, {
        "Security-Zone"     = "general"
        "Node-Group-Type"   = "general-workload"
        "Cost-Optimized"    = "true"
      })
    }
  }

  # PCI DSS: Enable IRSA for secure service account management
  enable_irsa = var.eks.enable_irsa

  # PCI DSS: Cluster creator admin permissions
  enable_cluster_creator_admin_permissions = false

  # PCI DSS: Authentication mode
  authentication_mode = "API_AND_CONFIG_MAP"

  # PCI DSS: Additional cluster tags
  cluster_tags = {
    "Compliance.PCI-DSS"     = "true"
    "Security.Level"         = "high"
    "Monitoring.Required"    = "true"
    "Encryption.Enabled"     = "true"
    "Audit.Required"         = "true"
  }

  # PCI DSS: Node security group configuration
  node_security_group_enable_recommended_rules = true
  node_security_group_additional_rules = {
    # Allow ECR access for image pulling
    ecr_https_outbound = {
      description = "ECR HTTPS outbound for image pulling"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
    
    # Allow S3 access for add-ons and logging
    s3_https_outbound = {
      description = "S3 HTTPS outbound for add-ons and logging"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = module.this.tags
}
