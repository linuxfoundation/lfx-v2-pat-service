# LFX V2 Personal Access Token Service

Creating and managing long lived personal access tokens for different audiences

## Service Setup

**Delete this section after working through the template PRs:**

- [ ] [Merge the OpenTofu PR](https://github.com/linuxfoundation/lfx-v2-opentofu/pull/256) to create service accounts used in the ArgoCD PR
- [ ] [Merge the ArgoCD PR](https://github.com/linuxfoundation/lfx-v2-argocd/pull/1608) to deploy the new service
- [ ] [Merge the Backstage Config PR](https://github.com/linuxfoundation/lfx-backstage/pull/81) to sync the service into Backstage


## Getting Started

1. Generate the Goa API code (this repo does not commit generated code — it must be generated once before the module will build):

   ```bash
   make apigen
   ```

   Commit the resulting `gen/` directory along with your other changes.
2. Implement your service logic in `internal/service/service.go` and wire any dependencies in `internal/container/container.go`.
