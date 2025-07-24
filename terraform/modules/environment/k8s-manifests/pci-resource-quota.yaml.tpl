apiVersion: v1
kind: ResourceQuota
metadata:
  name: pci-resource-quota
  namespace: ${namespace_name}
  labels:
    compliance.pci-dss: "true"
spec:
  hard:
    # PCI DSS: Limit resource consumption for security
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    # PCI DSS: Limit number of resources
    persistentvolumeclaims: "10"
    pods: "20"
    secrets: "10"
    configmaps: "10"
    services: "5"
    # PCI DSS: Storage limits
    requests.storage: "100Gi"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: pci-limit-range
  namespace: ${namespace_name}
  labels:
    compliance.pci-dss: "true"
spec:
  limits:
  # PCI DSS: Pod limits
  - type: Pod
    max:
      cpu: "2"
      memory: 4Gi
    min:
      cpu: "100m"
      memory: 128Mi
  # PCI DSS: Container limits
  - type: Container
    default:
      cpu: "500m"
      memory: 512Mi
    defaultRequest:
      cpu: "100m"
      memory: 128Mi
    max:
      cpu: "1"
      memory: 2Gi
    min:
      cpu: "50m"
      memory: 64Mi
  # PCI DSS: PVC limits
  - type: PersistentVolumeClaim
    max:
      storage: 50Gi
    min:
      storage: 1Gi
