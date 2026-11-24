# Talos ESO IAM metadata (deployed; explicit opt-in)

`terraform/talos_eso.tf` manages a dedicated Identity Domains user, group,
operator-supplied API signing **public** key registration, and a compartment IAM
policy. It does not deploy ESO or create/read Vault secret contents.

## Boundary

- `talos_eso_enabled = false` by default: zero ESO IAM resources and a null
  ESO output. Enabling ESO never modifies the existing Hermes plan-reader
  policy: `terraform/hermes_oci_plan.tf` keeps exactly its original metadata
  inspection statements with no `talos-eso-vault-reader` names, no
  `talos_eso_enabled` conditional, and no new permission verbs.
- OpenTofu `plan`/`apply` for this module run **operator-only** on the
  original desktop workspace with its existing initialized backend; ESO IAM
  staging alone grants no execution authority. Hermes permanent OCI
  permissions are unchanged by this module.
- The dedicated user can use API signing keys only. Console/password login,
  Customer Secret Keys, auth tokens, OAuth, database and SMTP credentials are
  disabled. The dedicated group has only that user as a managed member.
- The runtime policy grants one `SECRET_BUNDLE_READ` statement per exact
  `talos_eso_runtime_secret_ocids` entry, plus `VAULT_READ` for exactly
  `oci_kms_vault.control[0].id`, all within the existing control compartment.
  It grants no secret listing/metadata permission, secret writes, key access,
  domain administration, or tenancy-wide secret-family permission.
- The original Vault/key resources, backend, state object and native `.tflock`
  address are not changed or duplicated. This change is not authority to create
  another Vault or migrate state. All four new IAM resources have
  `prevent_destroy = true`; removing the opt-in after deployment or replacing a
  registered public key requires an explicit lifecycle/rotation review, not a
  blind toggle or override.
- No private signing material is generated, accepted as an input, written to a
  file, output, or stored in OpenTofu state. There are no secret-bundle data
  sources, secret resources, local/external commands, or private-key resources.
  The public PEM, its fingerprint, identity OCIDs and allowlisted secret OCIDs
  are metadata and may appear in state. Keep private material independently.

## Operator requirements for future authorized IAM changes

The operator deployed the four IAM resources on 2026-11-24. The 28 exact
runtime bundle reads, one Vault validation and negative bootstrap/unrelated
bundle tests passed; all 32 Kubernetes targets later synchronized without
rotation. Keep the protected effective tfvars and existing backend. Future
IAM changes and credential creation still require separate approval. Do not
initialize a backend, plan, apply or read protected state to test source changes.

Enabling requires all of the following non-secret metadata:

| Input | Default | Required when enabled |
| --- | --- | --- |
| `talos_eso_enabled` | `false` | Explicit approved opt-in |
| `talos_eso_api_signing_public_key_pem` | `null` | Independently operator-created RSA API signing PUBLIC KEY PEM, never a path/private key/certificate/bundle |
| `talos_eso_runtime_secret_ocids` | `[]` | Nonempty exact allowlist of operator-created runtime secrets |
| `talos_eso_bootstrap_secret_ocids` | `[]` | Nonempty explicit denylist of bootstrap secrets, including the separately managed ESO signing-key bundle and any Git/SOPS bootstrap credentials |

The existing `control_vault_enabled` must already represent the approved,
managed control Vault. Reuse the existing Identity Domains endpoint and
operator email inputs (`hermes_truenas_s3_identity_domain_url` and
`hermes_truenas_s3_iam_email`); no additional domain is created.

Runtime IDs must be disjoint from the explicit bootstrap denylist and every
configured `control_*_secret_ocid` credential ID in `vault.tf`. The original
host Cloudflare reuse proposal was rejected during the live byte-equality
check. The three Kubernetes Cloudflare consumers share their own JSON-map
Vault bundle; `control_cloudflare_secret_ocid` remains outside the runtime
allowlist. The final source guard denies the host token too; the deployed
allowlist already excluded it. This is not permission to change IAM.
A lifecycle precondition fails on overlap, missing public key, missing
allowlist/denylist, or disabled control Vault. Null host credential IDs are
omitted from the union.
Secret OCID inputs reject whitespace, wildcards, quotes and IAM policy syntax.
The public-key check is a lexical PEM envelope/base64 check, not cryptographic
RSA validation: the operator must independently verify its algorithm, strength,
and correspondence to the private key before approved registration.

The denylist is not automatic discovery. Operators must attest that it includes
all bootstrap credentials, that runtime IDs identify the intended secrets in
this exact Vault/compartment, and that the ESO group has no additional external
members or policies. Existing broader tenancy policies could still grant
capabilities beyond this module's scoped policy. Such effective IAM verification
and live positive/negative runtime tests remain separate approval gates.

`talos_eso_iam_metadata` outputs tenancy/user/group OCIDs, API-key fingerprint,
existing Vault OCID and sorted runtime secret OCIDs only. It is not a credential
bundle. Provisioning or transporting the independently kept private key into
ESO's bootstrap Secret is outside this Terraform boundary and requires its own
approved operational path. ESO must never retrieve its own bootstrap key.

## Pinned provider contract: ESO 2.15.0

In the pinned upstream `providers/v1/oracle/oracle.go`, `GetSecret` passes
`remoteRef.key` as a **secret name** directly to `GetSecretBundleByName`, with the
configured Vault ID. It does not first call GetSecret or ListSecrets for an
explicit name. Therefore use the exact secret name in the ExternalSecret;
**do not put its OCID in `remoteRef.key`**. The IAM allowlist is by secret OCID,
not by the provider's name string; confirm this name-to-ID relationship outside
OpenTofu before deployment.

`Validate` calls `GetVault`. Without its permission the provider can return
Unknown for authorization/not-found errors, which is why the separate, exact
`VAULT_READ` statement is included. No broader Vault or secret-family grant is
needed for this source contract. `dataFrom.find` performs listing and is not
supported by these permissions; PushSecret/write workflows are also excluded.
Do not broaden IAM if an unreviewed provider version or workflow needs more.

Source references:

- ESO 2.15.0: `https://github.com/external-secrets/external-secrets/blob/v2.15.0/providers/v1/oracle/oracle.go`
- OCI provider 8.29.0 public key resource: `https://github.com/oracle/terraform-provider-oci/blob/v8.29.0/website/docs/r/identity_domains_api_key.html.markdown`

## Offline checks (no init, no plan, no apply)

Install `requirements-test.txt` and `tests/requirements-eso-iam.txt` in a
separate scratch virtualenv, then run:

```sh
python -m pytest tests/test_talos_eso_iam.py -q
tofu -chdir=terraform fmt -check -diff talos_eso.tf hermes_oci_plan.tf
```

Run `tofu -chdir=terraform validate -no-color` with a scratch `TF_DATA_DIR`
containing only the exact provider package under
`providers/registry.opentofu.org/oracle/oci/8.29.0/linux_arm64/` (use the matching
architecture on another host). The provider package checksum must match the
existing `.terraform.lock.hcl`; do not run init or alter the original lock or
backend. Validation exercises the actual root configuration and installed
provider schema without initializing the backend or configuring OCI auth.

The tests parse actual HCL, exercise its literal lexical-validation patterns,
verify every existing bootstrap credential variable is denied, and check that
disabled metadata-policy templates retain their original strings. These are
source contracts plus native schema validation, **not** a Terraform plan-time
precondition execution, IAM evaluation, live credential validation or proof of
successful ESO reconciliation. Live acceptance is recorded in AgenticHomelab/talos-cluster#15; offline tests do not replace it.
