# cd-manifests

Unified configuration repository for Bacchus-managed clusters.

## Structure

```
├── argocd/<cluster>
│   └── <cluster>
│       ├── top-level.yaml         # top-level app of apps
│       │
│       ├── <app>                  # if using Helm
│       │   ├── app.yaml           # ArgoCD Application
│       │   ├── values.yaml        # Helm values
│       │   └── resources.yaml     # extra manifests to apply
│       │
│       └── <app>                  # if using Kustomize
│           ├── app.yaml           # ArgoCD Application
│           ├── kustomization.yaml # top-level Kustomization
│           └── <resource>.yaml    # individual resources
│
└── nodes/<cluster>                # kubeadm, API authentication and node firewall configuration
```
