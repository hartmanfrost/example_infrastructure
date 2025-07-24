apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress-egress
  namespace: ${namespace_name}
  labels:
    compliance.pci-dss: "true"
spec:
  # PCI DSS: Apply to all pods in namespace
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  # PCI DSS: Deny all ingress traffic by default
  ingress: []
  # PCI DSS: Allow only essential egress traffic
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow HTTPS for essential external communication
  - to: []
    ports:
    - protocol: TCP
      port: 443
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: ${namespace_name}
  labels:
    compliance.pci-dss: "true"
spec:
  # PCI DSS: Allow communication within the same namespace only
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ${namespace_name}
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: ${namespace_name}
