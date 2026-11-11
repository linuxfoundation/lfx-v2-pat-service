<!-- Copyright The Linux Foundation and each contributor to LFX. -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# LFX V2 Personal Access Token Service

Issues, lists, revokes and validates long-lived personal access tokens scoped to an audience. LFX One's Developer
Settings manages tokens for users through the platform gateway; the Auth0 Custom Token Exchange action validates
a secret when a consumer (first, the LFX Insights API through its Cloudflare Worker) exchanges it for a
short-lived JWT.

- [API](api.md): endpoints, bodies, error codes and the principal policy.
- [Secret format](secret-format.md): what a secret looks like, what is stored, and why.
- Configuration, local development and layout are in the repository README.

Design records: ADR-0006, ADR-0015 and ADR-0020 in the LFX Insights repository.
