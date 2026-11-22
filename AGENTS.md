# Repository contributor and agent instructions

This repository is the published, clean-history public desired-state source
for the OCI control server. Treat these instructions as an operating contract,
not authorization for deployment, state migration or credential access.

**The cross-repository source migration is closed (2026-11-22).** This
repository is the accepted production OCI OpenTofu, Ansible and isolated Hermes
operations source; private Hermes assets are owned by
`AgenticHomelab/homelab-secrets`. Former `antief/*` repositories are archived
historical references, not active execution or recovery dependencies. Dated
handover plans do not imply another pending cutover. Future production changes
still require their own authorization and verification.

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

Use the isolated Hermes Ansible playbooks and the approved private assets
in `AgenticHomelab/homelab-secrets/operations/hermes/`. The isolated plays
have their own entrypoints. See [the Hermes source contract](docs/hermes-operations-source.md)
for exact-file, check-mode and runtime acceptance.

An approved source-level review does not switch existing production commands,
scheduled tasks or private Hermes operational playbook ownership. Changing an
execution path requires a separately reviewed operator approval, complete
protected inputs, preserved original backend and native locks, a fresh
no-unexpected-change plan, and appropriate rollback and independent recovery.
