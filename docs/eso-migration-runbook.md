# Operator-run ESO migration driver (issue #15)

`scripts/eso-migration/eso_migrate.py` is a one-shot, operator-invoked
driver that carries the approved ESO enablement end to end on the operator's
own machine, using only the existing native CLIs (`tofu`, OCI CLI, `kubectl`,
`openssl`, `git`, `ansible-playbook`) and the existing isolated bootstrap
play. It creates no services, schedulers or daemons.

It is **not** wired into any playbook, cron or CI execution. CI only runs
its synthetic offline test suite.

## Modes

Run strictly in order, each an explicit operator command:

```sh
python3 scripts/eso-migration/eso_migrate.py prepare  --config /protected/migrate.json
python3 scripts/eso-migration/eso_migrate.py plan     --config /protected/migrate.json
python3 scripts/eso-migration/eso_migrate.py apply    --config /protected/migrate.json --approve <plan_digest>
python3 scripts/eso-migration/eso_migrate.py verify   --config /protected/migrate.json
python3 scripts/eso-migration/eso_migrate.py bootstrap --config /protected/migrate.json
```

- **prepare** verifies the original git source (exact origin, clean
  terraform tree, `.terraform/environment` = `default`, original S3
  backend block with `use_lockfile = true` and exact bucket/key/region),
  verifies the independent operator OCI **API-key** profile (matching root
  tenancy/compartment; `InstancePrincipal`, security-token profiles and
  `DEFAULT` are refused) by an actual `iam user get`/`iam compartment get`,
  mints the new ESO RSA-4096 signing key **once** into private custody,
  imports the ESO bundle into the **existing** Vault (reusing an equal
  entry; refusing to touch differing content — no overwrite, no rotation),
  pins the existing independent Flux bundle's CURRENT version, and writes
  public-metadata-only tfvars plus a resumable journal.
- **plan** runs a full locked `tofu plan` (refresh on, no `-target`, no
  `-refresh=false`, no `-lock=false`) with the custody tfvars, inspects the
  saved plan JSON and fails closed unless it contains exactly the four new
  `talos_eso` resources and nothing else, and prints a sanitized
  address/action summary plus the saved-plan digest.
- **apply** applies the exact saved plan bytes only after
  `--approve <digest>` matches, then records the wiring metadata
  (`eso_user_ocid`, fingerprint, K8s auth Secret selector) in the journal.
  The registered public fingerprint is safe-compared with the custody key's
  fingerprint; mismatch fails closed.
- **verify** performs the IAM validation as the new ESO identity (signed
  with the custody key through a generated, protected ephemeral config):
  GetVault success and by-name `GetSecretBundleByName` for every runtime
  target (exact secret-id match, CURRENT stage), plus read **denials** on
  the two bootstrap OCIDs and the unrelated sentinel. Read-only: the ESO
  signer never writes, deletes or lists unrelated resources.
- **bootstrap** materializes exactly the two pinned Secrets
  (`external-secrets/oci-vault-auth`, `flux-system/homelab-secrets-git`)
  through the existing isolated `ansible/talos-secrets-bootstrap.yml` with
  private mode-0600 extra-vars generated from the journal. No SOPS, no ESO
  restore, no controller deployment. This leaves the K8s auth Secret in
  place for autonomous Hermes continuation (live ESO reconciliation stays
  with the parent).

## Private inputs (outside Git, mode 0600)

- **config** (`--config`): schema, explicit `approved: true`, workspace
  path, expected git origin, expected tenancy/compartment/region/vault/
  operator-user OCIDs, expected backend bucket/key/region, inventory path,
  custody dir, operator OCI config+profile, absolute native tool paths,
  kubeconfig, explicit context.
- **inventory**: schema, vault/compartment OCIDs, explicit runtime targets
  (name, secret OCID, data keys), operator-confirmed
  `reuse_vault_secret_ocids` for byte-identical shared payloads (e.g. the
  shared Cloudflare token and shared CA bytes — reuse is explicit, detected
  duplicates among new targets are rejected, equality is evaluated in
  memory only and only counts are reported), eso/flux bundle names+keys,
  the two bootstrap deny OCIDs and an unrelated sentinel OCID.
- **custody dir** (0700): `eso-signing.pem` (0600, created once, reused on
  every rerun), `eso-signing.pub`, `eso.tfvars.json`, `journal.json`
  (resumable metadata: source HEAD, bundle OCIDs+versions, applied flag,
  wiring metadata — no secret values), `plan.bin`, `plan.json`,
  `bootstrap-inputs.json`.

The tfvars contain **only** public metadata: the PUBLIC key PEM, runtime
and bootstrap secret OCIDs. The private key never enters tofu inputs,
state, argv, tracked files or logs.

## Safety properties (enforced, synthetic-tested)

- Refuses `init`/reconfigure/backend drift: never invokes `tofu init`, and
  the backend block must still be the original locked S3 backend.
- Refuses dirty terraform trees, wrong git origin, wrong workspace
  environment, InstancePrincipal/security-token/`DEFAULT` profiles,
  operator≠root-tenancy identity, ESO-user-as-operator identity.
- Vault import is create-once or reuse-equal; a differing existing bundle
  fails closed without printing values or hashes.
- Plan gate: exactly four `create` actions on the `talos_eso` addresses;
  any unrelated change (including any Hermes policy) fails closed with a
  sanitized message.
- Apply only from the exact saved plan bytes with an explicit digest typed
  by the operator; no `-auto-approve`.
- All native stdout/stderr is captured and discarded; operator output is
  one sanitized JSON status line per invocation. Child environment is
  stripped of `OCI_*` overrides.
- Journal/source mismatch (source HEAD changed) fails closed in plan/apply/
  verify/bootstrap.
- Idempotent reruns: no key rotation, no duplicate Vault create, single
  bootstrap invocation per run.

## Offline verification

Synthetic suite (fake oci/tofu/kubectl/ansible executables, real git
workspace, real openssl; no live calls):

```sh
python3 -m pytest tests/test_eso_migration.py -q
```

## Explicitly out of scope / remaining acceptance

- Live ESO reconciliation test (parent's continuation path).
- Live IAM validation evidence (the driver automates the calls; producing
  the actual evidence requires operator credentials and is intentionally
  not exercised here).
- Per-target ExternalSecret generation from the persisted selectors
  mapping (parent consumes `journal.json`'s `runtime_targets` +
  `reuse_vault_secret_ocids`).
