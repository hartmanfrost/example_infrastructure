# EKS Infrastructure with PCI DSS Compliance

This Terraform infrastructure creates an Amazon EKS cluster with full PCI DSS compliance.

## PCI DSS Compliance

### 1. Requirement 3: Protect stored cardholder data

- **Encryption at rest**: All EBS volumes are encrypted with KMS
- **Secret encryption**: Kubernetes secrets are encrypted with AWS KMS
- **Key rotation**: Automatic KMS key rotation is enabled

### 2. Requirement 4: Encrypt transmission of cardholder data

- **TLS for API Server**: All traffic to Kubernetes API is encrypted
- **Node-to-node encryption**: Inter-node encryption through VPC CNI
- **Private endpoints**: API server is accessible only through private endpoints

### 3. Requirement 6: Develop and maintain secure systems

- **Managed node groups**: Using managed node groups
- **IMDSv2**: Enforced use of Instance Metadata Service v2
- **Security patches**: Automatic updates through managed node groups

### 4. Requirement 7: Restrict access to cardholder data

- **RBAC**: Detailed access control through Kubernetes RBAC
- **IAM roles**: Minimal privileges for service roles
- **Network segmentation**: Network separation through security groups and NACLs

### 5. Requirement 8: Identification and authentication

- **IAM integration**: Integration with AWS IAM for authentication
- **Service accounts**: Using IRSA for pod-level authentication
- **Access entries**: Controlled cluster access through access entries

### 6. Requirement 10: Track and monitor access

- **Comprehensive logging**: All EKS log types are enabled
- **CloudTrail**: Detailed logging of API calls
- **CloudWatch**: Monitoring of security metrics and alerts
- **Log retention**: Logs are retained for 90+ days

### 7. Requirement 11: Regularly test security systems

- **AWS Config**: Automatic compliance checking
- **Security groups**: Restrictive rules for network traffic
- **Network ACLs**: Additional network security layer

## Security Components

### KMS Encryption
```hcl
# Automatic key rotation
enable_key_rotation = true

# EKS secrets encryption
cluster_encryption_config = {
  provider_key_arn = aws_kms_key.eks.arn
  resources        = ["secrets"]
}
```

### Network Segmentation
- **PCI Zone**: Dedicated node group for card data processing
- **General Zone**: Separate group for general workloads
- **Database Security Groups**: Restricted database access
- **Application Security Groups**: Application traffic control

### Monitoring and Alerting
- Alerts for failed authentication attempts
- Monitoring of privileged operations
- Tracking of API server errors
- Notifications through SNS

### Audit and Compliance
- CloudTrail for all regions
- Config Rules for automatic checking
- S3 bucket with encryption for log storage
- Lifecycle policies for data management

## Recommended Additions

### 1. Pod Security Standards

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: pci-workload
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 2. Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

### 3. Admission Controllers

- Pod Security Policy (if using Kubernetes < 1.25)
- Open Policy Agent (OPA) Gatekeeper
- Falco for runtime security

## Compliance Testing

### Automated checks

```bash
# Kube-bench for CIS Kubernetes Benchmark
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-eks.yaml

# Kube-hunter for vulnerability scanning
kubectl create -f https://raw.githubusercontent.com/aquasecurity/kube-hunter/main/job.yaml
```

### Manual checks

1. Verify all pods are running in private subnets
2. Ensure API server is not accessible from the internet
3. Check encryption settings in CloudWatch logs
4. Verify correct security group configuration

## Support and Updates

### Regular tasks

1. Update Kubernetes version (quarterly)
2. Update AMI for worker nodes (monthly)
3. Rotate KMS keys (annually)
4. Review and update security groups (quarterly)

### Compliance monitoring

- Monthly AWS Config reports
- CloudTrail log analysis
- Review security metrics in CloudWatch
- Audit IAM roles and permissions

## Contacts

For security or PCI DSS compliance questions:

- DevOps Team: devops@company.com
- Security Team: security@company.com
- Compliance Officer: compliance@company.com
