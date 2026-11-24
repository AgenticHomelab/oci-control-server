# Historical ESO migration driver and bootstrap recovery (issue #15)

`scripts/eso-migration/eso_migrate.py` is a one-shot, operator-invoked
driver that carries the approved ESO enablement end to end on the operator's
own machine, using only the existing native CLIs (`tofu`, OCI CLI, `kubectl`,
`openssl`, `git`, `ansible-playbook`) and the existing isolated bootstrap
play. It creates no services, schedulers or daemons.

It is **not** wired into any playbook, cron or CI execution. CI only runs
its synthetic offline test suite.

## Current recovery path

The 2026-11-24 migration was accepted: 32/32 synchronized runtime targets,
unchanged UIDs/types/keys/bytes and functional applications. Do not rerun
inventory, prepare, plan or apply as routine recovery. Retain the protected
bootstrap-inputs.json and pinned bundle selectors independently. On the
operator workstation, with independent OCI API-key access and the intended
Kubernetes context, provision the flux-system and external-secrets namespaces
if absent, then run the isolated bootstrap playbook using the protected
extra-vars file:

```sh
ansible-playbook ansible/talos-secrets-bootstrap.yml --extra-vars @/protected/bootstrap-inputs.json
```

The role validates namespaces and exact pinned bundle versions, creates missing
Secrets, verifies readback and refuses rotation. It does not need ESO, Flux or
SOPS. Keep the actual file and contents outside Git and logs. If the original
migration journal is needed, retain its source revision separately; the driver
refuses a changed source HEAD. The standalone role is the normal recovery path.

## Historical migration modes

The following commands record the one-time migration sequence, not pending work:

```sh
python3 scripts/eso-migration/eso_migrate.py inventory --config /protected/migrate.json
python3 scripts/eso-migration/eso_migrate.py prepare   --config /protected/migrate.json
python3 scripts/eso-migration/eso_migrate.py plan      --config /protected/migrate.json
python3 scripts/eso-migration/eso_migrate.py apply     --config /protected/migrate.json --approve <plan_digest>
python3 scripts/eso-migration/eso_migrate.py verify    --config /protected/migrate.json
python3 scripts/eso-migration/eso_migrate.py bootstrap --config /protected/migrate.json
```

- **inventory** (read-only) enumerates the current migration surface
  directly from the cluster: every `flux-system` Kustomization that still
  carries `.spec.decryption` contributes the Secrets in its status
  inventory; the Flux bootstrap Secret is covered by the explicit Flux
  bundle and never as a runtime target. Each target Secret is read in
  memory (type, data keys, annotations). It writes a **draft**
  `inventory.json` (schema 2) into the custody dir with runtime targets
  (`k8s-<namespace>-<name>` vault names, K8s selectors, no OCIDs),
  reuse entries derived from explicit OCIDs in the `k0ti.com/oci-vault-secret`
  annotation plus any operator `reuse_hints` from the config. Legacy Vault
  names in that annotation are provenance only: absent an explicit reuse
  hint, the target is imported separately (or deduplicated by bytes).
  Malformed OCID annotations still fail closed. The draft includes byte-equal duplicate
  groups reported as selectors only (no values), and the Flux bundle
  contract with the Secret's real keys. Review the draft, then point the
  config's `inventory` at it (or merge it into your reviewed copy).
- **vault-status** is an optional read-only check before or after prepare.
  It validates the operator identity and lists Vault metadata only. The
  JSON reports expected/found counts and lifecycle states for runtime
  candidate names, bootstrap names and reused OCIDs, without printing
  names, identifiers or secret content. Runtime counts can be lower
  than inventory counts because equal payloads share a representative.
  Existing entries are not evidence of equality; prepare verifies content
  in memory. Prepare uses the same complete paginated metadata listing
  and matches exact names locally: OCI CLI can produce no JSON for
  an empty server-side name filter. A missing or malformed complete
  listing fails closed, rather than permitting creation. JSON parsing
  errors report the operation and whether the output was empty or
  invalid, without replaying it. Run with the same config:

  `python3 scripts/eso-migration/eso_migrate.py vault-status --config /protected/migrate.json`
- **prepare** verifies the original git source (exact origin, clean
  terraform tree, native `tofu workspace show` = default, `terraform/.terraform` initialized data directory (TF_DATA_DIR unset), original S3
  backend block with `use_lockfile = true` (the bucket/key/region selectors
  live in the existing initialized backend configuration, never touched here)),
  verifies the independent operator OCI **API-key** profile (matching root
  tenancy; `InstancePrincipal` and security-token profiles are refused,
  while the existing `DEFAULT` profile is acceptable) with `iam user get`.
  Validates the separate Vault resource compartment with `iam compartment get`
  or `iam tenancy get` when the Vault is in the root compartment,
  then imports everything authorized into the **existing** Vault with
  create-once/reuse-equal semantics (equal existing content is reused,
  differing content fails closed — never overwrite, never rotate).
  Readback explicitly selects CURRENT and checks the native `stages`,
  secret ID, version number, BASE64 encoding and exact content separately.
  A metadata error is reported separately from a value mismatch:

  every runtime target is read from Kubernetes (exact key set and type,
  live object, UTF-8 values; anything else fails sanitized), imported as a
  compact JSON map under its derived vault name — byte-equal targets share
  a single vault secret — each reuse entry is resolved to its vault NAME
  and equality-verified against the K8s bytes of its targets (raw bytes
  or decoded map), the Flux deploy-key bundle
  (`flux-system/homelab-secrets-git`: `identity`, `known_hosts`, optional
  `identity.pub`) is imported under the flux bundle name, and the ESO
  RSA-4096 signing key is minted **once** into private custody and its
  bundle imported. It then writes public-metadata-only tfvars (runtime
  OCIDs = resolved targets + reuse OCIDs; bootstrap deny OCIDs = the two
  discovered bundle OCIDs plus config extras) and a resumable journal.
- **plan** runs a full locked `tofu plan` (refresh on, no `-target`, no
  `-refresh=false`, no `-lock=false`) with the custody tfvars, inspects the
  saved plan JSON and fails closed unless it contains exactly the four new
  `talos_eso` resources and nothing else, and prints a sanitized
  address/action summary plus the saved-plan digest. Unchanged resource
  entries (`no-op`) are excluded from the mutation count; moves, imports,
  and other unrelated changes still fail closed.
- **apply** applies the exact saved plan bytes only after
  `--approve <digest>` matches, then records the wiring metadata
  (`eso_user_ocid`, fingerprint, K8s auth Secret selector) in the journal.
  The named OpenTofu output is read as the value itself, not the
  all-outputs metadata envelope. The registered public fingerprint is safe-compared with the custody key's
  fingerprint; mismatch fails closed.
- **verify** performs the IAM validation as the new ESO identity (signed
  with the custody key through a generated, protected ephemeral config):
  GetVault (`oci kms management vault get`) and by-name `GetSecretBundleByName` (`oci secrets secret-bundle get-secret-bundle-by-name`) for every runtime
  target **and** every reuse entry (exact secret-id match, CURRENT stage),
  plus read **denials** on both discovered bootstrap bundle OCIDs and the
  unrelated sentinel. A denial counts **only** when the OCI CLI error parses
  as HTTP 404 `NotAuthorizedOrNotFound`, and the independent operator
  successfully reads that same secret. CLI warnings before the structured
  `ServiceError:` response are allowed. Authentication failures, network
  errors, 5xx responses and malformed output are not proof of denial. Read-only: the ESO
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
  path, expected git origin, expected tenancy/compartment/region/vault/vault-key/
  operator-user OCIDs (`vault_key_ocid` is the existing master key the
  real `oci vault secret create-base64 --key-id` requires), expected backend bucket/key/region, inventory path,
  custody dir, operator OCI config+profile, absolute native tool paths,
  kubeconfig, explicit context. Optional: `reuse_hints`
  (`"namespace/name": {"ocid": <existing vault secret OCID>}`) for
  operator-known shared payloads (the host Cloudflare reuse proposal was
  rejected during this migration), `unrelated_sentinel_secret_ocid`, `flux_bundle.name`,
  `bootstrap_extra_secret_ocids`.
- **inventory** (schema 2): vault/compartment OCIDs, runtime targets
  (`name`, `keys`, `k8s: {namespace, name}`, `secret_ocid` null until
  prepare resolves it — schema-1 inventories with pre-resolved OCIDs keep
  working), explicit `reuse_entries` (`ocid`, `targets`,
  `content_shape: raw|json_map`) whose equality prepare verifies against
  the K8s bytes, `duplicate_groups` advisory lists (selectors only),
  eso/flux bundle names+keys, and the unrelated sentinel OCID. The
  `inventory` mode writes a reviewed-ready draft of this file.
- **custody dir** (0700): `eso-signing.pem` (0600, created once, reused on
  every rerun), `eso-signing.pub`, `inventory.json` draft, `eso.tfvars.json`,
  `journal.json` (resumable metadata: source HEAD, resolved target
  OCIDs+names+content shapes, reuse entries, bundle OCIDs+versions, applied
  flag, wiring metadata — no secret values), `plan.bin`, `plan.json`,
  `bootstrap-inputs.json`.

The tfvars contain **only** public metadata: the PUBLIC key PEM, runtime
and bootstrap secret OCIDs. The private key never enters tofu inputs,
state, argv, tracked files or logs. Vault content shapes: imported targets
are compact JSON maps (`content_shape: json_map`); reused existing host
secrets keep their raw single-value shape (`content_shape: raw`). The
parent's ExternalSecret generation consumes these shapes from the journal:
`json_map` targets map each data key through one by-name reference;
`raw` reuse entries map their single key with the raw bundle bytes.

## Safety properties (enforced, synthetic-tested)

- Refuses `init`/reconfigure/backend drift: never invokes `tofu init`, and
  the backend block must still be the original locked S3 backend.
- Refuses dirty terraform trees, wrong git origin, wrong workspace
  environment, InstancePrincipal/security-token profiles,
  operator≠root-tenancy identity, ESO-user-as-operator identity.
  The `DEFAULT` profile is allowed when those identity checks still pass.
- Vault import is create-once or reuse-equal for **every** payload class
  (runtime targets, reuse entries, Flux bundle, ESO bundle); a differing
  existing bundle fails closed without printing values or hashes.
- Kubernetes reads touch only the enumerated targets; key-set/type/
  deletionTimestamp mismatches and non-UTF-8 values fail sanitized.
- Byte-equal duplicate targets create a single vault secret; group members
  reference it (one IAM allowlist entry, no duplicated content).
- Plan gate: exactly four `create` actions on the `talos_eso` addresses;
  any unrelated change (including any Hermes policy) fails closed with a
  sanitized message.
- Apply only from the exact saved plan bytes with an explicit digest typed
  by the operator; no `-auto-approve`.
- Verify distinguishes real IAM authorization denials from any other API
  failure; only the former count, the latter fail the mode.
- Native stdout/stderr is captured; raw output is never replayed. Failures
  report the fixed operation, exit status or timeout, and a recognized OCI
  error code if available. Child environment is stripped of `OCI_*`
  overrides. Vault create uses a mode-0600 JSON input file via
  `--from-json file://...`, waits for ACTIVE and verifies the CURRENT
  bundle against the input in memory. If a create times out, inspect
  vault-status before retrying; do not delete partial entries or signing
  key custody. Non-ACTIVE existing candidates fail closed.
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

## Accepted deployment evidence

See AgenticHomelab/talos-cluster#15 for the live IAM, bootstrap, pilot, bulk
reconciliation and consumer acceptance. No repeat plan/apply, credential
rotation or destructive recovery exercise is implied by this record.
