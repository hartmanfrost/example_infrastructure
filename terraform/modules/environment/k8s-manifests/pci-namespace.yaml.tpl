apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace_name}
  labels:
    # PCI DSS: Pod Security Standards - Restricted profile
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    # PCI DSS: Compliance labeling
    compliance.pci-dss: "true"
    security.zone: "cardholder-data"
    data.classification: "restricted"
  annotations:
    # PCI DSS: Documentation for compliance
    compliance.documentation: "This namespace is configured for PCI DSS compliance"
    security.policy: "restricted-workloads-only"
