# Historical ESO migration acceptance (2026-11-24)

**Closed:** [talos-cluster issue #15](https://github.com/AgenticHomelab/talos-cluster/issues/15).
The one-shot SOPS-to-ESO migration driver and its synthetic tests are retained
in this repository's Git history at commit
`bb288a5029a88e6b56a9710df867497b20d10ff3`. They are not current operational
entrypoints. Do not rerun inventory, prepare, plan or apply from the historical
driver to recover or extend ESO.

The operator deployed the dedicated OCI user, group, public API signing key
and exact runtime-read policy, verified positive runtime bundle reads and
negative bootstrap/unrelated reads, and recovered the two independent
bootstrap Secrets via Ansible. The bulk cutover preserved all 32 Kubernetes
Secret UIDs, types, keys and bytes; all ExternalSecrets and Flux units were
Ready and applications functional. Active Flux decryption and the live
`sops-age` Secret were removed; private encrypted manifests and historical
age keys were retained in Git history and independent operator custody,
respectively. No credential rotation or additional OCI apply occurred during
cleanup.

Current operations:

- [Independent bootstrap recovery](talos-secrets-bootstrap.md): recover the
  private Git SSH and ESO API signing credentials from pinned Vault bundles,
  using the independently retained operator OCI identity and protected inputs.
- [OCI IAM contract](talos-eso-iam.md): maintain exact runtime permissions and
  preserve the existing backend, state and credential boundaries.
- [Kubernetes GitOps](https://github.com/AgenticHomelab/talos-cluster/blob/main/docs/gitops.md):
  app-local ExternalSecrets and consumer verification.

Keep protected bootstrap selectors, effective IAM tfvars, operator credentials
and historical recovery identities independently available. A full isolated
cluster restore, deliberate live provider outage and new historical ciphertext
decryption test were not performed as part of the cutover acceptance.
