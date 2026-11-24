# Isolated Talos bootstrap Secret recovery

`ansible/talos-secrets-bootstrap.yml` is a manually invoked, localhost-only
entrypoint. It is **not** imported by the control-host play or any scheduled job.
It restores only:

| Pinned Vault JSON bundle | Kubernetes target | Required data keys |
| --- | --- | --- |
| Existing private Flux deploy identity | `flux-system/homelab-secrets-git` | `identity`, `known_hosts` |
| Existing ESO OCI API signing identity | `external-secrets/oci-vault-auth` | `privatekey`, `fingerprint` |

The Flux bundle may additionally contain the existing `identity.pub`; nothing
is derived or generated. The stored SSH identity, optional public key and
previously verified `known_hosts` are copied byte for byte. No key generation,
`ssh-keyscan`, credential rotation, SOPS decryption, ESO controller, Terraform,
full-cluster bootstrap, or continuous secret-sync daemon is involved.

## Dependencies and custody gates

- Linux controller with Python 3 and Ansible core (`command` with
  `expand_argument_vars`, supported since core 2.16); no OCI or Kubernetes
  Ansible collection and no Python Kubernetes SDK are required.
- Existing native OCI CLI and `kubectl`, explicitly selected by absolute paths.
  OCI CLI is already installed at `/opt/oci-cli/bin/oci` on the reviewed runner;
  it need not be on `PATH`. The implementation does not install dependencies.
- Independently retained **operator API-key** OCI configuration, a named profile
  other than `DEFAULT`, and its existing signing key. Config and key must be
  regular, non-symlink files owned by the invoking user with no group/other
  permissions. The key path must be absolute. The CLI alone reads the key bytes.
- The profile user must equal the explicit operator user and differ from the
  explicit ESO user. The operator and restored ESO fingerprints must also differ.
  `InstancePrincipal`, security-token profiles and inherited `OCI_*` auth,
  endpoint or debug overrides are not accepted. OCI CLI RC loading is disabled.
- The operator must already have approved read access to exactly the two selected
  OCI secret versions. Pin positive **integer version numbers**, not a moving
  `CURRENT`/`LATEST` stage. Returned secret IDs, version numbers, BASE64 envelope,
  JSON schema and nonempty values are checked before Kubernetes is contacted.
- Both namespaces must already exist under their established owners. A trusted,
  independent operator kubeconfig and **explicit context** must already work.
  RBAC needs namespace get and Secret get/create/update in the two namespaces;
  this play does not create namespaces or deploy controllers. Recovery must not
  depend on obtaining either operator credential from the Secrets being restored.
- Separately approve access to existing credential bytes and execution against
  the exact cluster/context. Existing SSH deploy authorization and verified host
  keys must be retained. Independently verify that the ESO PEM/fingerprint pair
  belongs to the approved ESO user before staging the bundle. Structural checks
  here do not prove cryptographic key validity, GitHub authorization or IAM scope.
- Prepare the two existing bundles through separately authorized custody. This
  play never creates Vault secrets/versions, signing keys, IAM policies or OCI
  API-key registrations. Those operations retain their own review gates.

Selectors and kubeconfig/context belong only in protected private inputs, not
public Git. Credential **values** belong in Vault and protected operator custody,
not either Git repository. Do not dump config, environment, raw command results,
Secret objects, fingerprints or debug output during diagnosis.

## Private noncredential input contract

Supply one mapping, `talos_secrets_bootstrap`, using an approved private extra-vars
file. The following is a **synthetic**, non-deployable schema illustration:

```yaml
talos_secrets_bootstrap:
  approved: true                 # explicit per-execution operator approval
  auth: api_key                  # only supported mode
  oci_cli: /opt/oci-cli/bin/oci
  kubectl: /usr/local/bin/kubectl
  config_file: /protected/example/operator-oci.config
  profile: SYNTHETIC_RECOVERY
  region: example-region-1
  operator_user_ocid: ocid1.user.oc1..syntheticoperator
  eso_user_ocid: ocid1.user.oc1..syntheticeso
  kubeconfig: /protected/example/operator.kubeconfig
  context: synthetic-recovery
  flux:
    secret_id: ocid1.vaultsecret.oc1..syntheticflux
    version_number: 3
  eso:
    secret_id: ocid1.vaultsecret.oc1..syntheticeso
    version_number: 5
```

No defaults select production. Unknown/missing fields, ambiguous authentication,
identical user/bundle selectors, malformed OCIDs, noninteger version pins,
relative paths and an empty/option-like context fail before any credential or
API read. The named OCI profile region must match the supplied region.

## Check, execution and reconciliation semantics

Offline syntax and the credential-free input gate:

```sh
ansible-playbook -i localhost, ansible/talos-secrets-bootstrap.yml --syntax-check
ansible-playbook -i localhost, ansible/talos-secrets-bootstrap.yml --list-tasks
ansible-playbook -i localhost, ansible/talos-secrets-bootstrap.yml \
  --check --diff --extra-vars @/protected/example/bootstrap-inputs.yaml
```

`--check` validates **only selector structure and approval**. It does not open the
OCI config/key or kubeconfig, invoke OCI/kubectl, inspect existing Secrets,
contact APIs, or forecast changes. Missing credential files are deliberately
allowed in this metadata-only mode. A successful check does not verify access,
pins, key validity, existing data, readiness or idempotence.

Only after the separate gates above may an operator run the same isolated
entrypoint without `--check`, using the reviewed private inputs. Do not run the
normal host play, change the current context, or bootstrap other cluster owners.

Normal execution checks the operator profile, retrieves exactly the two pinned
bundles through explicit `--auth api_key`, then preflights **both** target Secrets
before any write:

- A successful `kubectl get --ignore-not-found` with empty output means **absent
  recovery**: create that exact Secret. API/auth/network failures are never
  interpreted as absence. Concurrent creation fails rather than overwriting.
- An existing Opaque Secret with exactly the selected key/value bytes is a no-op.
- Missing data keys may be completed only if every present key/value matches the
  selected bundle. Metadata is preserved and `kubectl replace` uses the observed
  `resourceVersion` for concurrency protection. An immutable incomplete Secret
  fails closed.
- Any changed value, extra data key, wrong type or deleting object blocks the
  entire preflight. Nothing is silently rotated, removed, adopted or forced.
  Include the existing optional `identity.pub` in the approved Flux bundle if it
  exists on the target. An unexplained difference needs a separate custody or
  rotation decision; do not delete a Secret to bypass the guard.
- Every target is read back and compared, including no-op targets. There is no
  multi-object Kubernetes transaction: a later API failure can leave an earlier
  approved creation/completion in place. No destructive rollback is attempted;
  investigate safely and repeat with the same pins after the cause is resolved.

OCI output, decoded values and Kubernetes request/response data stay inside the
short-lived helper and native processes. Secret manifests travel through
`kubectl` stdin, never argv, files, Ansible registered output or cached facts.
No client-side `apply`/last-applied annotation or secret-bearing temporary file
is created. The only Ansible result is a sanitized changed/error status; its task
has `no_log: true` and `diff: false`, including validation and check mode. Native
stdout/stderr are captured and never replayed on errors; core dumps are disabled.
No byte-zeroization guarantee is made for Python process memory. Trusted native
binaries, kubeconfig exec plugins, existing auth caches, OS swap policy and
Kubernetes Secret-safe audit policy remain operator security prerequisites;
`no_log` cannot suppress API-server audit request bodies or third-party plugins.

## Offline verification and recovery ownership

Run the standard-library synthetic suite (requires Ansible for its real local
entrypoint exercise; OCI and kubectl are replaced with synthetic executables):

```sh
python3 -m unittest discover -s tests -p test_talos_secrets_bootstrap.py -v
```

The suite exercises the real helper and isolated play, including absent recovery,
byte preservation, second-run idempotence, missing-key completion, check-mode
zero reads, invalid selectors/profiles, identity reuse, mismatches, pinned-bundle
errors, native failures and read-back failure. It is not a live restore rehearsal.
The existing shared offline CI gate runs these bootstrap tests and the ESO IAM
contracts, and syntax-checks the isolated bootstrap entrypoint. It uses only
synthetic inputs and does not retrieve production credentials.

Omni still owns machine/control-plane recovery; Flux owns persistent Kubernetes
desired state. The public Talos bootstrap runbook's independent private-source SSH
credential contract remains unchanged. Existing age custody is not touched and
is not needed for these two targets. This helper recovers no other application
Secrets, application data or GitOps state. Confirm subsequent Flux source and ESO
store readiness separately through their native owners, without dumping Secrets.
