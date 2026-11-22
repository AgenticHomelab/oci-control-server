# Native Hermes operations source handover

This repository stages the **Ansible-owned** implementations that were still
maintained in `antief/oci-control-server` after normal OCI source migration.
Their current **installed** state remains unchanged. Do not interpret this
document or a source PR merge as a host cutover.

## Source ownership

| Source | Responsibility |
| --- | --- |
| `AgenticHomelab/oci-control-server/ansible/` | Isolated Ansible playbooks, roles, systemd unit templates, pinned host tooling |
| `AgenticHomelab/homelab-secrets/operations/hermes/` | Private fleet prompts and skills, native scheduler job registry, current Omni key renewal helper and private operational runbooks |
| Existing protected operator and host files / OCI Vault | Credentials, recovery identities, full protected input maps and backend selectors |
| `antief/oci-control-server` | **Currently deployed** Hermes operational source and rollback until separately accepted cutover |

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
decrypt or synchronize the private repository itself. Private values in the
native job registry, Ansible inventory, existing protected host overlays and
Vault-selected credentials remain subject to their existing ownership.

## Cutover acceptance, not performed by this PR

1. Freeze and compare the old private operations revision, the new public
   role/playbooks and the exact private asset revisions. Review real privacy
   inputs and the installed file paths without emitting their contents.
2. Confirm the approved native runner can read both new checkouts and still
   resolve the original protected inventory, host overlays, recovery inputs
   and GitHub App identity. Keep the old private checkout available.
3. Validate syntax and controller-side source resolution. Run the existing
   isolated playbooks in check mode with their current reviewed variables.
   Inspect **every predicted change**; no all-roles production play.
4. Under separate production cutover approval, select only the matching
   new playbooks, inspect the bounded apply and verify byte-identical assets,
   idempotence, enabled systemd timers, existing native Hermes job IDs,
   schedules, delivery, GitHub dispatch and host read-only health.
5. Verify independent rollback using the retained original private checkout.
   Only then remove installed execution dependencies on the legacy Git
   source and consider archiving the legacy repository. Permanent deletion
   must not precede replacement of recovery Git references and custody.

Do not force an Omni renewal, rotate keys, replay nightly maintenance, start
a second Renovate merger or perform an OpenTofu apply to demonstrate source
migration. The original private operations and recovery evidence remain
available for rollback pending the live acceptance.
