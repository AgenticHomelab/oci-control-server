# Manually applying control-01 dependency updates

The public OCI repository defines **reviewed source versions**. Renovate discovers
new versions and opens PRs; it never upgrades the VM. A merge changes Git only.
Ansible owns host reconciliation. OpenTofu owns OCI infrastructure metadata.
No second runner, automatic deployment, or unattended container updater exists.

## Discovery and scope

`renovate.json` creates review-only PRs with a Dependency Dashboard. It watches:

- Omni and Dex image tags in `ansible/group_vars/all/versions.yml`;
- stable Hermes Agent releases in that file, without prerelease/canary tracking;
- kubectl, talosctl, Flux CLI and Helm version pins in that file;
  Renovate names these as host CLI updates (`kubectl`, `talosctl`,
  `flux-cli`, `helm-cli`), while upstream release lookups retain their real
  Kubernetes, Talos, Flux and Helm repository identifiers. These proposals
  do not upgrade Kubernetes or Talos cluster nodes;
- GitHub Actions SHA references; and
- OpenTofu provider constraints and lockfile through Renovate's Terraform manager
  using `registry.opentofu.org`. The OpenTofu CLI version constraint is excluded.

The `# renovate:` comments next to selected Ansible pins explicitly opt them in.
Other pins are intentionally excluded: Grafana's build and SHA256, Alloy's APT
version, Loki and VictoriaMetrics archives/checksums, OCI CLI, the OpenTofu
tool binary/checksum, Hermes's Node/npm runtime details, and Vault
credential version numbers. Do not add those to Renovate until their
coupled metadata and safe upgrade procedures can be updated and validated.

PRs require human/operator review; the Talos nightly merge workflow does not
run here. A successful CI check is not deployment or runtime acceptance.

## Review and deploy

1. Inspect the Renovate PR diff and upstream release notes, including version
   jumps, persistence formats and compatibility. Check the exact current head
   and passing offline CI. Do not accept unsupported upgrade paths or PRs that
   modify credentials, private inputs or unrelated infrastructure.
2. Merge the reviewed PR. On the **approved Ansible controller**, use an
   up-to-date checkout of `main` and the **existing reviewed** inventory,
   private variables, credential sources and SSH path. Never copy secrets to
   public Git, pass them in shell history, or replace production inputs with
   placeholders. Do not run the complete `ansible/playbook.yml` for a single
   service upgrade.
3. Check affected service health, independent operator access, backup freshness
   and recovery prerequisites *before* a production change. A backup file
   alone is not a tested restore. Confirm the target is compatible with the
   running state. Schedule the operation as a separate authorized deployment.
4. Preview the matching **scoped** playbook with `--check --diff`, inspect
   every predicted change and abort if unrelated resources would change.
   Check mode does not prove the download or migration will work. Execute
   the same scoped playbook without `--check` only when the change is approved.
5. Validate installed **runtime** versions, functionality, authentication and
   dependencies after deployment. Record the observed result in the owning
   operational record. If a rollback is needed, first check whether the
   application/data format supports it; reverting a Git pin alone is not
   sufficient or always safe.

All commands below are examples from the `ansible/` directory. Replace
`<approved-inventory>` with the existing controller inventory and supply
the established protected variable overlays through the normal operator
procedure. **Do not run these examples against production merely to test the
runbook.**

### Omni and Dex

Use `omni-update.yml`. It renders only the existing Omni configuration and
reconciles its Compose deployment. It does not run the other host roles,
alter the OCI infrastructure or run the Omni backup role.

```sh
ansible-playbook -i <approved-inventory> omni-update.yml --check --diff
# After separate production approval and a clean reviewed preview:
ansible-playbook -i <approved-inventory> omni-update.yml
```

Before executing, inspect the current Omni/Dex versions in Git and on the
host, a recent application-consistent Omni backup and its external copy,
identity/decryption custody, and the version-specific upstream upgrade path.
Preserve independent operator access. Omni manages the Talos control plane:
an outage can affect normal cluster administration even while workloads run.

Afterward, confirm the running Compose image IDs/tags, Omni and Dex service
status, Omni authentication, machine API and Kubernetes proxy operation, and
the next relevant backup. Never claim success from `docker compose ps` alone.
A version change does not upgrade Talos or Kubernetes nodes.

### Management CLIs

Use `toolchain-update.yml` to update only kubectl, talosctl, Flux CLI and
Helm (plus the GitHub CLI package installed by the existing role). It does not
restart Omni or other host services.

```sh
ansible-playbook -i <approved-inventory> toolchain-update.yml --check --diff
# After separate production approval:
ansible-playbook -i <approved-inventory> toolchain-update.yml
```

Verify each CLI's actual installed version and compatibility with the
current cluster. Updating talosctl is **not** approval to upgrade Talos nodes.

### OpenTofu provider and GitHub Actions

A reviewed GitHub Actions PR takes effect on subsequent GitHub workflow runs;
no host playbook is needed. Validate those workflow runs.

For provider PRs, verify the provider and lockfile from the approved
OpenTofu checkout and run the existing offline CI. A future live plan must
reuse the original protected backend, state and locking, with a reviewed
refreshing plan before any separately approved apply. No apply is performed
by Renovate or CI. A new provider version must not silently change state
ownership or resource identities.

### Observability, Hermes and OS packages

For Grafana and Alloy, maintain the paired build/package versions and approved
artifact checksums in `ansible/roles/observability/defaults/main.yml`. Use
the existing isolated `ansible/observability.yml` playbook after reviewing
the release and its checksums. Loki and VictoriaMetrics similarly require
their archive checksums; Loki has `ansible/loki.yml` and an additional
version-specific assertion in `ansible/roles/loki/tasks/main.yml`.
These are not covered by the initial Renovate custom manager.

### Hermes Agent

Renovate follows only upstream stable `vX.Y.Z` releases through
`hermes_release_version`. The normal Hermes role does not upgrade the
installation. It checks that the installed checkout is at the exact commit
of the reviewed local release tag. An upgrade PR **must not be merged
ahead of the corresponding reviewed deployment** if routine host applies
must remain valid in the interim.

The first transition from the existing October 2026 Git commit to the
November stable release is a larger application upgrade, not a simple
binary replacement. The native updater can migrate app state and may
restart the user services. Confirm a recoverable, independent copy of
Hermes state and private operational assets, available capacity for the
upstream `--backup` archive, and a maintenance window before attempting it.
Avoid running the generic `playbook.yml` as part of this upgrade.

Run the isolated play from the approved controller with the existing
protected inventory and overlays:

```sh
ansible-playbook -i <approved-inventory> hermes-update.yml --check --diff
# After review, from the approved checkout with operator authorization:
ansible-playbook -i <approved-inventory> hermes-update.yml -e hermes_update_reviewed=true
```

The isolated play verifies an official clean checkout, a stable release tag,
the currently latest upstream stable release, and the resolved exact tag
commit before invoking `hermes update --channel stable --yes --backup`.
The upstream updater owns dependency changes, backup and gateway restart.
Ansible verifies the expected Git commit and checks gateway/dashboard
systemd units afterward. Do not separately run `hermes update` from an
unreviewed automation job; doing so bypasses the reviewed Git release pin.

If upstream publishes another stable release between the preflight and the
native update, the updater might select it. Post-verification rejects an
unexpected commit, but cannot undo changes already made. Repeat the
preflight immediately before the change; abort on new upstream releases.
Do not assume Git rollback reverses data migrations.

Verify dashboard login, gateway messaging, approved native scheduled jobs,
GitHub App use, operational permissions, and relevant backup/recovery paths
afterward. Systemd `active` alone does not establish functional acceptance.
Record actual runtime revision and outcomes before merging the matching
release PR.

Ubuntu security updates and third-party APT packages use the host's existing
APT policy. Renovate does not replace unattended-upgrades or provide assurance
that all third-party APT packages are up to date.

## Verification and activation

The PR CI validates Renovate configuration, the annotated extraction map,
OpenTofu (without the production backend), Ansible syntax and existing offline
contracts. It does **not** run Ansible against control-01 or verify an
upstream release can be installed. On initial merge, confirm the Renovate
GitHub App is authorized for `AgenticHomelab/oci-control-server`, then observe
its Dependency Dashboard and at least one correctly extracted dependency.
Do not grant the Talos nightly merger authority over this repository.
