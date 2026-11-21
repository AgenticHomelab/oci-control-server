# OCI Control Server

Declarative infrastructure and host configuration for a homelab management
server. This is the published public OCI desired-state source, not a deployment
controller. Existing private production invocations remain selected until a
separately reviewed execution-path cutover.

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

## Offline review

Review `terraform/` and `ansible/` as separate owners. CI performs offline
tests and selected Ansible syntax checks using synthetic inputs, without
fetching production credentials or remote state. It does not establish that
a live plan is unchanged or that backup recovery has been tested.

The generic [OCI Monitoring and Notifications runbook](docs/oci-monitoring-alerts.md)
describes the optional, disabled-by-default alert resources and their separate
live verification gate.

`docs/private-publication-inputs.md` explains the private execution-input
contract. The existing private repository retains operational recovery evidence
and its separate Hermes operational playbooks. Operator-reported acceptance of
the published source found an unchanged original-backend, locked and refreshing
OpenTofu plan and reviewed selected Ansible render parity. This is not evidence
of an already switched production invocation, off-host recovery, or permission
to apply changes. Each runtime source switch still requires explicit operator
approval, correct protected inputs, preserved rollback, and recovery checks.
