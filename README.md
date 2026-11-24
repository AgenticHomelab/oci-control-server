# OCI Control Server

Declarative infrastructure and host configuration for a homelab management
server. The published source is used for normal OCI OpenTofu and control-host
Ansible operations.

OpenTofu declares the OCI compute, network and infrastructure metadata.
Ansible declares persistent host configuration, including Omni, Hermes,
observability, HTTPS ingress, and approved service integrations. Native
applications own their mutable runtime data; Talos and Kubernetes desired
state are managed by their separate owners.

## Source boundaries

- Public source defines implementation, tests and reusable operational
  patterns. Do not hardcode production network routes, IP addresses,
  privileged service DNS, tenant identifiers, or recovery credentials.
- An approved protected checkout of
  `AgenticHomelab/homelab-secrets` supplies **noncredential** environment
  configuration. It is not reconciled automatically by this repository.
- OCI Vault remains the authoritative source for existing stable service
  credentials, and protected consumer-local files preserve current service
  delivery semantics.
- Original OpenTofu state, S3 backend selectors, native locks, provider
  identity, and all resource addresses must remain unchanged when selecting
  or changing an execution path.

## Talos runtime credentials

This repository owns the dedicated OCI ESO IAM metadata
([IAM runbook](docs/talos-eso-iam.md)) and the isolated
[bootstrap recovery playbook](docs/talos-secrets-bootstrap.md). Flux owns the
declarations and ESO synchronizes stable Kubernetes credentials from OCI Vault.
The 2026-11-24 migration is complete; see [historical acceptance](docs/eso-migration-runbook.md).
No routine migration or new secret-sync daemon is needed.

## Offline review

Review `terraform/` and `ansible/` as separate owners. CI performs offline
tests and selected Ansible syntax checks using synthetic inputs, without
fetching production credentials or remote state. It does not establish that
a live plan is unchanged or that backup recovery has been tested.

The generic [OCI Monitoring and Notifications runbook](docs/oci-monitoring-alerts.md)
describes the optional, disabled-by-default alert resources and their separate
live verification gate.

The [private input contract](docs/private-publication-inputs.md) describes the
selected execution inputs. The [native Hermes operations source handover](docs/hermes-operations-source.md)
records the accepted installed source. The isolated Hermes playbooks live
here. Protected prompts, job definitions and the Omni renewal helper live in
`AgenticHomelab/homelab-secrets/operations/hermes/`. The private
[control host recovery runbook](https://github.com/AgenticHomelab/homelab-secrets/blob/main/operations/hermes/runbooks/control-host-recovery.md)
covers the existing bootstrap and recovery dependencies.
On the selected execution paths, live verification matched the original
backend and state, produced a locked, refreshing plan with zero proposed
actions, and reproduced the selected host templates. Apply and other
production reconciliation require separate authorization. Independent
off-host restoration and Vaultwarden recovery retrieval remain unverified.
