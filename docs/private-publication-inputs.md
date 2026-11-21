# Private environment inputs for the clean-history export

Production-specific, noncredential host, DNS, OCI Vault selector and
network inputs live in the private `AgenticHomelab/homelab-secrets` source.

- `config/oci-control-server.yaml`: Ansible DNS and host inputs.
- `config/oci-terraform.tfvars`: OpenTofu networking and ingress inputs.

At a separately authorized execution time, supply the files from a protected
operator or runner checkout, preserving all other current local runtime inputs:

```sh
ansible-playbook -i inventory.ini playbook.yml \
  --extra-vars @/approved/private/checkout/config/oci-control-server.yaml

tofu -chdir=terraform plan \
  -var-file=/approved/private/checkout/config/oci-terraform.tfvars
```

These examples are not executable cutover instructions without verifying
Ansible variable precedence, existing OCI S3 backend selection, remaining
protected OpenTofu inputs and source/value equivalence.

The same private YAML also holds the full Grafana DNS alias/target and
Hermes Matrix delivery destination. The separately gated
`ansible/grafana-tailnet-dns.yml` play must receive **scoped** selectors:
feeding the entire host configuration as extra vars overrides its
one-record play vars, and the new fail-closed guard deliberately rejects
that wider DNS mapping. Do not weaken the guard to make an unsafe
invocation pass. The Grafana Tailnet role also consumes
`grafana_tailnet_hostname` and existing `hermes_hostname`.

OCI Vault remains authoritative for existing stable credential values.
No secrets, keys, state, or plans belong in the private Git configuration.
No synchronization daemon, host apply, state migration, or publish operation
is authorized by this draft. Review and sanitize all remaining source docs,
templates, test fixtures, and release metadata before public export.

## Talos receiver TLS inputs

The isolated Talos metrics and logs receiver plays now require two private,
noncredential hostname selectors from the same approved Ansible input source:
`talos_metrics_receiver_hostname` (the verified public certificate SAN) and
`talos_metrics_receiver_tailnet_hostname` (the existing internal Host alias).
Both names are used consistently in Nginx server and Host matching, certificate
path and SAN validation, conflict preflight, and the bounded 401 probe. Do not
replace hostname validation with an insecure TLS fallback. The original
Git-declared values were checked for exact equivalence with the private inputs;
no live receiver or certificate was inspected or changed.

## Host firewall privacy and source-equivalence boundary

The SideroLink IPv6 boot-time `ip6tables-restore` baseline and the existing
one-shot reconciler now use one private noncredential selector pair:
`siderolink_ipv6_tcp_ports` and `siderolink_ipv6_tcp_port_range`.
The host role validates the private inputs before rendering either template.
The prior static copies were removed; there is no extra firewall daemon or
independent control plane. Offline source comparisons showed that rendering
the original Git-declared private values reproduces both former source files
byte for byte. This does **not** establish effective kernel rule equivalence
or post-reboot behavior.

The reviewed host role is now provisionally included in the future public
source export, retaining the existing IPv4 instance-service exceptions,
Tailscale-managed runtime chains, rule order, local etcd restriction and
SideroLink/public ingress templates. This source review is not an independent
audit of runtime rules, post-reboot behavior, or console recovery access.
No host deployment or firewall reconciliation is authorized by this change.

## Hermes GitHub App and recovery selectors

The existing approved App ID, installation IDs and repository ID mappings
are supplied by the same private Ansible YAML. The root-only signing PEM and Vault-selector metadata locations are likewise
provided exclusively as `hermes_github_app_key_file` and
`hermes_github_app_metadata_file`; their values are not present in the public
source. The retrieval helper is rendered from a Jinja template with those same
paths, and the contributor/token-minter roles consume the same PEM selector.
Path validation requires regular absolute paths under the protected system
configuration tree and the two files to share one directory. Preserve the
existing private path values and key bytes; this is source refactoring only,
not a credential rotation, file relocation, or host reconciliation.

The role renders the existing short-lived token minter and repository-restricted Git credential helper from
Jinja2 templates, preserving the previous allowlist and permissions. Never
publish these identifying selectors or the signing PEM; do not add the future
public repository until its installation and scope are separately approved.

The existing OCI offsite backup bucket name also comes from private Ansible
inputs. The public Omni access-policy file is a synthetic, non-deployable
example. The production ACL and Hermes native fleet job identities, schedules
and prompts remain in the private operations source and are not in the public
export allowlist. Their native owners and ongoing runtime behavior are
unchanged. Validate the exact rendered source and current consumers before
any cutover.

