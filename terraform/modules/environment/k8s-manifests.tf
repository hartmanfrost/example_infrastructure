#  ┬┌ ┌─┐┐─┐  ┌┌┐┬─┐┌┐┐o┬─┐┬─┐┐─┐┌┐┐┐─┐
#  ├┴┐├─┤└─┐  ││││─┤││││├─ ├─ └─┐ │ └─┐
#  ┘ ┘└─┘──┘  ┘ ┘┘ ┘┘└┘┘┘  ┴─┘──┘ ┘ ──┘

# Creating files with Kubernetes manifests for PCI DSS compliance

locals {
  k8s_manifests = {
    # PCI DSS: Namespace with Pod Security Standards
    "pci-namespace.yaml" = templatefile("${path.module}/k8s-manifests/pci-namespace.yaml.tpl", {
      namespace_name = "pci-workload"
    })

    # PCI DSS: Network Policy for complete isolation
    "deny-all-network-policy.yaml" = templatefile("${path.module}/k8s-manifests/deny-all-network-policy.yaml.tpl", {
      namespace_name = "pci-workload"
    })

    # PCI DSS: Resource Quota for resource control
    "pci-resource-quota.yaml" = templatefile("${path.module}/k8s-manifests/pci-resource-quota.yaml.tpl", {
      namespace_name = "pci-workload"
    })

    # PCI DSS: Service Account with minimal privileges
    "pci-service-account.yaml" = templatefile("${path.module}/k8s-manifests/pci-service-account.yaml.tpl", {
      namespace_name = "pci-workload"
      cluster_name   = module.this.name
      account_id     = data.aws_caller_identity.current.account_id
    })
  }
}

# Creating directory for Kubernetes manifests
resource "local_file" "k8s_manifests" {
  for_each = local.k8s_manifests

  filename = "${path.root}/k8s-manifests/${each.key}"
  content  = each.value

  depends_on = [module.eks]
}
