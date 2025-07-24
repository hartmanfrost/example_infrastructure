#  ┌┬┐┌─┐┌┐┌┬┌┬┐┌─┐┬─┐┬┌┐┌┌─┐
#  ││││ ││││││ │ │ │├┬┘│││││ ┬
#  ┴ ┴└─┘┘└┘┴ ┴ └─┘┴└─┴┘└┘└─┘

# PCI DSS: CloudWatch alarms for security monitoring
resource "aws_cloudwatch_metric_alarm" "eks_api_server_errors" {
  alarm_name          = "${module.this.name}-eks-api-server-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "cluster_failed_request_count"
  namespace           = "AWS/EKS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors EKS API server errors"
  alarm_actions       = [aws_sns_topic.pci_alerts.arn]

  dimensions = {
    ClusterName = module.this.name
  }

  tags = merge(module.this.tags, {
    "PCI-DSS-Monitoring" = "true"
  })
}

# PCI DSS: Monitor failed authentication attempts
resource "aws_cloudwatch_log_metric_filter" "failed_authentication" {
  name           = "${module.this.name}-failed-authentication"
  log_group_name = aws_cloudwatch_log_group.eks_cluster.name
  pattern        = "[version, account, time, ip, verb=\"GET\", uri=\"/api*\", protocol, code=\"401\", ...]"

  metric_transformation {
    name      = "FailedAuthenticationAttempts"
    namespace = "EKS/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "failed_authentication_alarm" {
  alarm_name          = "${module.this.name}-failed-authentication"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "FailedAuthenticationAttempts"
  namespace           = "EKS/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Multiple failed authentication attempts detected"
  alarm_actions       = [aws_sns_topic.pci_alerts.arn]

  tags = merge(module.this.tags, {
    "PCI-DSS-Security-Alert" = "true"
  })
}

# PCI DSS: Monitor privileged operations
resource "aws_cloudwatch_log_metric_filter" "privileged_operations" {
  name           = "${module.this.name}-privileged-operations"
  log_group_name = aws_cloudwatch_log_group.eks_cluster.name
  pattern        = "[version, account, time, ip, verb, uri, protocol, code, ...]"

  metric_transformation {
    name      = "PrivilegedOperations"
    namespace = "EKS/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "privileged_operations_alarm" {
  alarm_name          = "${module.this.name}-privileged-operations"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "PrivilegedOperations"
  namespace           = "EKS/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "20"
  alarm_description   = "High number of privileged operations detected"
  alarm_actions       = [aws_sns_topic.pci_alerts.arn]

  tags = merge(module.this.tags, {
    "PCI-DSS-Security-Alert" = "true"
  })
}

# PCI DSS: SNS topic for security alerts
resource "aws_sns_topic" "pci_alerts" {
  name              = "${module.this.name}-pci-security-alerts"
  kms_master_key_id = aws_kms_key.eks.arn

  tags = merge(module.this.tags, {
    "PCI-DSS-Alerting" = "true"
  })
}

# PCI DSS: CloudTrail for comprehensive audit logging
resource "aws_cloudtrail" "eks_audit_trail" {
  name           = "${module.this.name}-eks-audit-trail"
  s3_bucket_name = aws_s3_bucket.eks_audit_logs.bucket
  s3_key_prefix  = "cloudtrail-logs"

  # PCI DSS: Enable log file validation
  enable_log_file_validation = true

  # PCI DSS: Enable logging for all regions
  is_multi_region_trail = true

  # PCI DSS: Include global service events
  include_global_service_events = true

  # PCI DSS: Enable encryption
  kms_key_id = aws_kms_key.eks.arn

  # PCI DSS: Enable CloudWatch integration
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.eks_cluster.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_logs_role.arn

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true

    # PCI DSS: Monitor S3 data events for audit bucket
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.eks_audit_logs.arn}/*"]
    }

    data_resource {
      type   = "AWS::S3::Bucket"
      values = [aws_s3_bucket.eks_audit_logs.arn]
    }
  }

  tags = merge(module.this.tags, {
    "PCI-DSS-Audit-Trail" = "true"
  })

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs_policy]
}

# IAM role for CloudTrail CloudWatch integration
resource "aws_iam_role" "cloudtrail_logs_role" {
  name = "${module.this.name}-cloudtrail-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(module.this.tags, {
    "PCI-DSS-Service-Role" = "true"
  })
}

resource "aws_iam_role_policy" "cloudtrail_logs_policy" {
  name = "${module.this.name}-cloudtrail-logs-policy"
  role = aws_iam_role.cloudtrail_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogGroup",
          "logs:CreateLogStream"
        ]
        Resource = "${aws_cloudwatch_log_group.eks_cluster.arn}:*"
      }
    ]
  })
}

# S3 bucket policy for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.eks_audit_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.eks_audit_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.eks_audit_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# PCI DSS: Config rules for compliance monitoring
resource "aws_config_configuration_recorder" "pci_recorder" {
  name     = "${module.this.name}-pci-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [aws_s3_bucket_policy.config_bucket_policy]
}

resource "aws_config_delivery_channel" "pci_delivery_channel" {
  name           = "${module.this.name}-pci-config-delivery"
  s3_bucket_name = aws_s3_bucket.eks_audit_logs.bucket
  s3_key_prefix  = "config-logs"

  depends_on = [aws_s3_bucket_policy.config_bucket_policy]
}

# IAM role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "${module.this.name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(module.this.tags, {
    "PCI-DSS-Service-Role" = "true"
  })
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# Additional S3 bucket policy for Config
resource "aws_s3_bucket_policy" "config_bucket_policy" {
  bucket = aws_s3_bucket.eks_audit_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.eks_audit_logs.arn
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.eks_audit_logs.arn
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.eks_audit_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
