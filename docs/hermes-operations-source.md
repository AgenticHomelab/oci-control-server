# Native Hermes operations source handover

This repository owns the isolated **Ansible** implementation for native Hermes
operations. The operator accepted the live source handover on 2026-11-22
after exact-file comparison, bounded reconciliation and read-back. Native
job identities, schedules, delivery and existing credentials were preserved.

## Source ownership

| Source | Responsibility |
| --- | --- |
| `AgenticHomelab/oci-control-server/ansible/` | Isolated Ansible playbooks, roles, systemd unit templates, pinned host tooling |
| `AgenticHomelab/homelab-secrets/operations/hermes/` | Private fleet prompts and skills, native scheduler job registry, current Omni key renewal helper and private operational runbooks |
| Existing protected operator and host files / OCI Vault | Credentials, recovery identities, full protected input maps and backend selectors |

These entrypoints are isolated: none is imported by `ansible/playbook.yml`
or by `ansible/roles/hermes/tasks/main.yml`. No new runner, daemon or
scheduler has been introduced.

## Available opt-in playbooks

- `hermes-fleet-health.yml`: installs reviewed native fleet prompts/skills.
  Job identities and schedules remain with Hermes's existing native scheduler.
- `hermes-operational-access.yml`: existing scoped native administrator
  configuration and approved operational skills.
- `hermes-omni-key-renewal.yml`: staged native Omni key renewal helper/timer.
  This is not authorization to activate or change any Omni identity.
- `hermes-truenas-opentofu.yml`: approved arm64 OpenTofu tool and protected
  workspace preparation; no plan/apply or credential discovery.
- `talos-renovate-dispatch.yml`: existing single GitHub Actions dispatch
  service/timer; no new automation owner.

For the first three, explicitly provide `hermes_private_operations_dir`
as an **absolute controller-local** path to a verified
`homelab-secrets/operations/hermes` checkout. The public Ansible role loads
the required private files directly from that path. It does not fetch,
decrypt or synchronize the private repository itself.
The protected OCI input mapping also supplies `hermes_omni_credential_file`
for the existing native Omni credential environment. Neither its exact path
nor its contents is committed to this public source. Private values in the
native job registry, Ansible inventory, existing protected host overlays and
Vault-selected credentials remain subject to their existing ownership.

## GitHub App repository selection

The App helper uses the private organization repository map. Set `GH_REPO`
to an approved repository for every `gh` command through the Hermes wrapper.
Git HTTPS selects the repository from the remote URL. The App identity,
signing key and token permissions remain under their existing custody.

## Verification for future changes

1. Record the exact public playbook and private asset revisions. Compare them
   with the installed files and validate protected inputs without logging
   values.
2. Confirm the approved native runner can read both new checkouts and still
   resolve the original protected inventory, host overlays, recovery inputs
   and GitHub App identity. Retain the prior reviewed files for rollback.
3. Validate syntax and controller-side source resolution. Run the existing
   isolated playbooks in check mode with their current reviewed variables.
   Inspect **every predicted change**; no all-roles production play.
4. Under separate production cutover approval, select only the matching
   new playbooks, inspect the bounded apply and verify byte-identical assets,
   idempotence, enabled systemd timers, existing native Hermes job IDs,
   schedules, delivery, GitHub dispatch and host read-only health.
5. Verify rollback from the retained protected files and current organization
   sources. Keep the exact native job metadata available for in-place prompt
   rollback. Review any scheduler or identity change as a separate operation.

Do not force an Omni renewal, rotate keys, replay nightly maintenance, start
a second Renovate merger or perform an OpenTofu apply to demonstrate source
migration. The private [recovery runbook](https://github.com/AgenticHomelab/homelab-secrets/blob/main/operations/hermes/runbooks/control-host-recovery.md)
describes recovery from the current sources.
