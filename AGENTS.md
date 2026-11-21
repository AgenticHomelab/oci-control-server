# Repository contributor and agent instructions

This source is intended to be a **new public repository with no inherited Git
history** after a separate publication review. Treat this file as an operating
contract, not deployment or credential authorization.

- Read the current `main` implementation and the scoped runbook before edits.
- Write code and documentation in English and use Conventional Commits.
- Work on focused branches with reviewed PRs; never push directly to `main`.
- Stay read-only by default. Git source changes do not authorize OpenTofu
  apply, infrastructure imports, service changes, credential rotation, or
  production Ansible reconciliation.
- OpenTofu owns OCI infrastructure and IAM **metadata**, Ansible owns the
  management host, Omni owns Talos lifecycle, Flux owns persistent Kubernetes
  desired state, and native applications own mutable runtime data.
- Never publish real private network topology, administrator credential paths,
  Vault secret identifiers, user-selected private DNS names or personal
  endpoints, historical backup object identities, or raw sensitive evidence.
- Approved private noncredential inputs belong in
  `AgenticHomelab/homelab-secrets`; credential plaintext and decryption keys
  stay out of Git. OCI Vault retains existing stable credential authority.
- Keep OCI S3 state, backend config, protected tfvars, plans and recovery
  identities outside the public repository. Offline tests must use synthetic
  values and never access production.
- Report verified checks accurately; a passing offline CI does not prove
  state, deployment, backup or restoration success.

Publication requires a separate final-content audit and explicit go/no-go.
