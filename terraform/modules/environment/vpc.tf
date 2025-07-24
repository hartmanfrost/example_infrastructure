#  ┐ ┬┬─┐┌─┐
#  │┌┘│─┘│
#  └┘ ┘  └─┘

locals {
  azs = slice(var.azs, 0, length(var.azs))
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.0"

  name = module.this.name
  cidr = var.vpc_cidr

  azs             = var.azs
  private_subnets = [for k, v in var.azs : cidrsubnet(var.vpc_cidr, 4, k)]       # 10.0.0.0/20,   10.0.16.0/20,  10.0.32.0/20,  ...
  public_subnets  = [for k, v in var.azs : cidrsubnet(var.vpc_cidr, 8, k + 80)]  # 10.0.80.0/24,  10.0.81.0/24,  10.0.82.0/24,  ...
  intra_subnets   = [for k, v in var.azs : cidrsubnet(var.vpc_cidr, 8, k + 100)] # 10.0.100.0/24, 10.0.101.0/24, 10.0.102.0/24, ...

  # PCI DSS: Use multiple NAT gateways for high availability and security
  enable_nat_gateway = true
  single_nat_gateway = false
  one_nat_gateway_per_az = true

  # PCI DSS: Enable VPC Flow Logs for network monitoring
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  flow_log_destination_type            = "cloud-watch-logs"
  flow_log_cloudwatch_log_group_retention_in_days = 90

  # PCI DSS: Enable DNS features for secure resolution
  enable_dns_hostnames = true
  enable_dns_support   = true

  # PCI DSS: Disable default security group rules
  manage_default_security_group = true
  default_security_group_ingress = []
  default_security_group_egress  = []

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = module.this.tags
}
