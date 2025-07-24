apiVersion: v1
kind: ServiceAccount
metadata:
  name: pci-service-account
  namespace: ${namespace_name}
  labels:
    compliance.pci-dss: "true"
  annotations:
    # PCI DSS: IRSA annotation for AWS IAM role binding
    eks.amazonaws.com/role-arn: arn:aws:iam::${account_id}:role/${cluster_name}-pci-workload-role
automountServiceAccountToken: false # PCI DSS: Disable automatic token mounting
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pci-workload-role
  namespace: ${namespace_name}
  labels:
    compliance.pci-dss: "true"
rules:
# PCI DSS: Minimal permissions for PCI workloads
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
  resourceNames: ["pci-app-secrets"] # Specific secret access only
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
  resourceNames: ["pci-app-config"] # Specific configmap access only
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pci-workload-rolebinding
  namespace: ${namespace_name}
  labels:
    compliance.pci-dss: "true"
subjects:
- kind: ServiceAccount
  name: pci-service-account
  namespace: ${namespace_name}
roleRef:
  kind: Role
  name: pci-workload-role
  apiGroup: rbac.authorization.k8s.io
