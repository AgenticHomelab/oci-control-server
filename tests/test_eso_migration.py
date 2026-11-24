"""Synthetic offline tests for the operator-run ESO migration driver.

Exercises the real scripts/eso-migration/eso_migrate.py against fake native
executables (oci, tofu, kubectl, ansible-playbook), a real throwaway git
workspace and real openssl. No OCI, Kubernetes or backend is ever contacted.
All identities, fingerprints and contents are synthetic.
"""
import base64
import json
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'eso-migration' / 'eso_migrate.py'

GIT_ORIGIN_PATH = 'AgenticHomelab/oci-control-server.git'

TENANCY = 'ocid1.tenancy.oc1..synthtenancy'
COMPARTMENT = 'ocid1.compartment.oc1..synthcomp'
VAULT = 'ocid1.vault.eu-stockholm-1.synthvault'
VAULT_KEY = 'ocid1.key.eu-stockholm-1.synthvaultkey'
REGION = 'eu-stockholm-1'
OPERATOR_USER = 'ocid1.user.oc1..synthoperator'
ESO_USER = 'ocid1.user.oc1..syntheticeso'
OPERATOR_FP = 'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99'

REUSE_ANNOTATION = 'k0ti.com/oci-vault-secret'
# Schema-2 K8s-backed runtime targets (Vault OCID resolved during prepare).
RUNTIME = [
    {'name': 'k8s-alloy-talos-metrics-ingestion',
     'keys': ['password'], 'k8s': {'namespace': 'alloy',
                                   'name': 'talos-metrics-ingestion'}},
    {'name': 'k8s-mumble-mumble-superuser-password',
     'keys': ['password'], 'k8s': {'namespace': 'mumble',
                                   'name': 'mumble-superuser-password'}},
]
# Byte-equal duplicate group sharing the Cloudflare token bytes.
DUP_A = {'namespace': 'cert-manager', 'name': 'cloudflare-api-token'}
DUP_B = {'namespace': 'cloudflare-ddns', 'name': 'cloudflare-ddns-secret'}
DUP_BYTES = b'SYNTH-SHARED-TOKEN'
SHARED_REUSE_OCID = 'ocid1.vaultsecret.eu-stockholm-1.synthsharedcf'
SHARED_VAULT_NAME = 'control-cloudflare-token'
SENTINEL_OCID = 'ocid1.vaultsecret.eu-stockholm-1.synthsentinel'
ESO_BUNDLE_NAME = 'talos-eso-signing-bundle'
FLUX_BUNDLE_NAME = 'talos-flux-deploy'
FLUX_NS, FLUX_SECRET = 'flux-system', 'homelab-secrets-git'
FLUX_CONTENT = {'identity': 'SYNTH-SSH-KEY\n',
                'known_hosts': 'github.example.invalid ssh-ed25519 SYNTH\n'}

BACKEND_TF = '''\
terraform {
  backend "s3" {
    bucket             = "oci-control-server-state"
    key                = "control-server/terraform.tfstate"
    region             = "eu-stockholm-1"
    use_lockfile       = true
    skip_credentials_validation = true
  }
}
'''

TOFU_PLAN_OK = {
    'format_version': '1.2',
    'planned_values': {'root_module': {}},
    'resource_changes': [
        {'address': 'oci_identity_domains_user.talos_eso[0]',
         'change': {'actions': ['create']}},
        {'address': 'oci_identity_domains_api_key.talos_eso[0]',
         'change': {'actions': ['create']}},
        {'address': 'oci_identity_domains_group.talos_eso[0]',
         'change': {'actions': ['create']}},
        {'address': 'oci_identity_policy.talos_eso[0]',
         'change': {'actions': ['create']}},
    ],
}


def write_exec(path, body):
    path.write_text(body)
    path.chmod(0o755)


def protected(path, content=''):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o600)
    return path


def b64(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.b64encode(value).decode()


def kustomization(name, secrets):
    return {
        'apiVersion': 'kustomize.toolkit.fluxcd.io/v1', 'kind': 'Kustomization',
        'metadata': {'name': name, 'namespace': 'flux-system'},
        'spec': {'decryption': {'provider': 'sops'}},
        'status': {'inventory': {'entries': [
            {'id': f'{ns}_{n}_Secret', 'v': 'v1'}
            for ns, n in secrets]}},
    }


def k8s_secret(namespace, name, values, annotations=None, stype='Opaque',
               deleting=False):
    meta = {'namespace': namespace, 'name': name}
    if annotations:
        meta['annotations'] = annotations
    if deleting:
        meta['deletionTimestamp'] = '2026-01-01T00:00:00Z'
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': stype,
            'metadata': meta,
            'data': {k: b64(v) for k, v in values.items()}}


def inventory_fixture(tmp, **over):
    data = {
        'schema': 2,
        'vault_ocid': VAULT,
        'compartment_ocid': COMPARTMENT,
        'runtime_targets': [dict(t, secret_ocid=None) for t in RUNTIME],
        'reuse_entries': [
            {'ocid': SHARED_REUSE_OCID, 'content_shape': 'raw',
             'targets': ['cert-manager/cloudflare-api-token',
                         'cloudflare-ddns/cloudflare-ddns-secret'],
             'name': None}],
        'duplicate_groups': [['cert-manager/cloudflare-api-token',
                               'cloudflare-ddns/cloudflare-ddns-secret']],
        'eso_bundle': {'name': ESO_BUNDLE_NAME,
                       'keys': ['privatekey', 'fingerprint']},
        'flux_bundle': {'name': FLUX_BUNDLE_NAME,
                        'keys': ['identity', 'known_hosts']},
        'unrelated_sentinel_secret_ocid': SENTINEL_OCID,
    }
    data.update(over)
    return protected(tmp / 'inventory.json', json.dumps(data))


class Fixture:
    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.tmp.chmod(0o700)
        self.calls = self.tmp / 'calls'
        self.calls.mkdir()
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        self.custody = self.tmp / 'custody'
        self.custody.mkdir(0o700)
        self.oci_state = self.tmp / 'oci-state.json'
        # Cluster state served by the kubectl fake.
        self.kube_secrets = {
            'alloy/talos-metrics-ingestion': k8s_secret(
                'alloy', 'talos-metrics-ingestion',
                {'password': 'SYNTH-METRICS-PW'}),
            'mumble/mumble-superuser-password': k8s_secret(
                'mumble', 'mumble-superuser-password',
                {'password': 'SYNTH-MUMBLE-PW'}),
            # Byte-equal duplicate group with a reuse annotation on one member.
            f'{DUP_A["namespace"]}/{DUP_A["name"]}': k8s_secret(
                DUP_A['namespace'], DUP_A['name'], {'api-token': DUP_BYTES},
                annotations={REUSE_ANNOTATION: SHARED_REUSE_OCID}),
            f'{DUP_B["namespace"]}/{DUP_B["name"]}': k8s_secret(
                DUP_B['namespace'], DUP_B['name'], {'api-token': DUP_BYTES}),
            f'{FLUX_NS}/{FLUX_SECRET}': k8s_secret(
                FLUX_NS, FLUX_SECRET, FLUX_CONTENT),
        }
        self.kustomizations = [
            kustomization('alloy-secrets',
                          [('alloy', 'talos-metrics-ingestion')]),
            kustomization('mumble-secrets',
                          [('mumble', 'mumble-superuser-password')]),
            kustomization('cert-manager-config-secrets',
                          [(DUP_A['namespace'], DUP_A['name'])]),
            kustomization('cloudflare-ddns-secrets',
                          [(DUP_B['namespace'], DUP_B['name'])]),
            kustomization('flux-system', [(FLUX_NS, FLUX_SECRET)]),
            # A non-SOPS owner that must be ignored.
            {'apiVersion': 'kustomize.toolkit.fluxcd.io/v1',
             'kind': 'Kustomization',
             'metadata': {'name': 'apps', 'namespace': 'flux-system'},
             'spec': {}, 'status': {'inventory': {'entries': [
                 {'id': 'immich_immich-values__Secret', 'v': 'v1'}]}}},
        ]
        self.oci_state.write_text(json.dumps({
            'tofu_plan_json': None, 'tofu_apply': False,
        }))
        self._make_workspace()
        self._make_fakes()

    # -- workspace -----------------------------------------------------
    def _make_workspace(self):
        ws = self.tmp / 'ws'
        (ws / 'terraform').mkdir(parents=True)
        (ws / 'terraform' / 'backend.tf').write_text(BACKEND_TF)
        (ws / 'terraform' / 'talos_eso.tf').write_text(
            'variable "talos_eso_enabled" { type = bool, default = false }\n')
        (ws / 'ansible').mkdir()
        (ws / 'ansible' / 'talos-secrets-bootstrap.yml').write_text(
            '# synthetic isolated play\n')
        (ws / 'terraform' / '.terraform').mkdir(parents=True)
        (ws / 'terraform' / '.terraform' / 'environment').write_text(
            'default\n')
        self.ws = ws
        subprocess.run(['git', 'init', '-q', str(ws)], check=True)
        subprocess.run(['git', '-C', str(ws), 'remote', 'add', 'origin',
                        'https://github.com/' + GIT_ORIGIN_PATH], check=True)
        subprocess.run(['git', '-C', str(ws), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(ws), '-c', 'user.email=t@t',
                        '-c', 'user.name=t', 'commit', '-qm', 'synth'],
                       check=True)

    # -- fakes ---------------------------------------------------------
    def _make_fakes(self):
        # Shared live state, mutated by both fakes and the tests.
        state_bridge = self.tmp / 'oci-live.json'
        state_bridge.write_text(json.dumps({
            'vault_created': {},
            'kube_secrets': self.kube_secrets,
            'kustomizations': self.kustomizations,
            'deny_success': False, 'denial_code': 'NotAuthorizedOrNotFound',
        }))

        head = '''\
            #!/usr/bin/env python3
            import base64, json, os, sys
            from pathlib import Path
            HERE = Path(__file__).resolve().parent.parent
            state = json.loads((HERE / "oci-state.json").read_text())
            live = json.loads((HERE / "oci-live.json").read_text())
            args = sys.argv[1:]
            (HERE / "calls" / "TOOL").open("a").write(json.dumps(args) + "\\n")
            '''
        oci = textwrap.dedent(head.replace('TOOL', 'oci')) + textwrap.dedent('''\
            def out(payload):
                print(json.dumps(payload)); sys.exit(0)
            def deny_or_exit():
                # Emit an OCI-style CLI error on stderr with a code field.
                code = live.get("denial_code") or "NotAuthorizedOrNotFound"
                sys.stderr.write(json.dumps(
                    {"code": code, "message": "synthetic"}))
                sys.exit(1)
            profile = args[args.index("--profile")+1] if "--profile" in args else "?"
            # vcmd is the service path derived per real CLI structure,
            # located past the global flags the real CLI also accepts.
            vcmd = ""
            SERVICE = {"iam", "vault", "secrets", "kms"}
            si = next((i for i, a in enumerate(args) if a in SERVICE), None)
            if si is not None:
                rest = args[si:]
                if rest[:2] == ["secrets", "secret-bundle"]:
                    vcmd = "secret-bundle"
                elif rest[:2] == ["vault", "secret"]:
                    vcmd = "secret"
                elif rest[:4] == ["kms", "management", "vault", "get"]:
                    vcmd = "vault-get"
            if "iam" in args and "user" in args and "get" in args:
                if profile != "SYNTHETIC_OPERATOR" and profile != "ESO_IDENTITY":
                    sys.exit(1)
                uid = args[args.index("--user-id")+1]
                out({"data": {"id": uid, "tenancy-id": "%(tenancy)s",
                             "compartment-id": "%(comp)s"}})
            if "iam" in args and "compartment" in args and "get" in args:
                out({"data": {"id": "%(comp)s",
                             "compartment-id": "%(comp)s"}})
            if vcmd == "vault-get":
                out({"data": {"id": "%(vault)s"}})
            if vcmd == "secret" and "list" in args:
                name = args[args.index("--name")+1]
                if name in live["vault_created"]:
                    out({"data": [{"id": "ocid1.vaultsecret.eu-stockholm-1."
                                         "v-" + name, "secret-name": name}]})
                out({"data": []})
            if vcmd == "secret" and "get" in args and "--secret-id" in args:
                sid = args[args.index("--secret-id")+1]
                if sid == "%(shared)s":
                    out({"data": {"id": sid,
                                  "secret-name": "%(shared_name)s",
                                  "vault-id": "%(vault)s"}})
                sys.exit(1)
            if vcmd == "secret-bundle" and "get-secret-bundle-by-name" in args:
                name = args[args.index("--secret-name")+1]
                created = live["vault_created"]
                if name in created:
                    content = created[name]
                    sid = "ocid1.vaultsecret.eu-stockholm-1.v-" + name
                elif name == "%(shared_name)s":
                    content = base64.b64encode(b"%(dup_bytes)s").decode()
                    sid = "%(shared)s"
                else:
                    sys.exit(1)
                out({"data": {"secret-id": sid, "secret-name": name,
                              "version-number": 1,
                              "version-stages": ["CURRENT"],
                              "secret-bundle-content": {
                                  "content-type": "BASE64",
                                  "content": content}}})
            if vcmd == "secret" and "create-base64" in args:
                f = args[args.index("--secret-content-content-file")+1]
                content = Path(f).read_text()
                name = args[args.index("--secret-name")+1]
                if name in live["vault_created"]:
                    sys.exit(1)  # create exactly once
                live["vault_created"][name] = content
                (HERE / "oci-live.json").write_text(json.dumps(live))
                out({"data": {"id": "ocid1.vaultsecret.eu-stockholm-1.v-" + name}})
            if vcmd == "secret-bundle" and "get" in args \\
                    and "get-by-name" not in args and "--secret-id" in args:
                sid = args[args.index("--secret-id")+1]
                if live.get("deny_success") and profile == "ESO_IDENTITY":
                    out({"data": {"secret-id": sid}})
                deny_or_exit()
            sys.exit(1)
            ''' % {'tenancy': TENANCY, 'comp': COMPARTMENT, 'vault': VAULT,
                   'shared': SHARED_REUSE_OCID,
                   'shared_name': SHARED_VAULT_NAME,
                   'dup_bytes': DUP_BYTES.decode()})
        write_exec(self.bin / 'oci', oci)

        tofu = textwrap.dedent(head.replace('TOOL', 'tofu')) + textwrap.dedent('''\
            if "init" in args:
                sys.exit(0)
            if "workspace" in args and "show" in args:
                print("default"); sys.exit(0)
            if "plan" in args and "show" not in args:
                Path(args[args.index("-out")+1]).write_bytes(b"SYNTHETIC-PLAN-BYTES")
                sys.exit(0)
            if "show" in args:
                plan = state.get("tofu_plan_json")
                if plan is None:
                    sys.exit(1)
                print(json.dumps(plan)); sys.exit(0)
            if "apply" in args:
                state["tofu_apply"] = True
                (HERE / "oci-state.json").write_text(json.dumps(state))
                sys.exit(0)
            if "output" in args:
                fp = state.get("api_key_fingerprint") or "SYNTHFP"
                try:
                    jr = json.loads((HERE / "custody" / "journal.json").read_text())
                    fp = jr.get("api_key_fingerprint") or fp
                except (OSError, ValueError):
                    pass
                print(json.dumps({"value": {
                    "tenancy_ocid": "%(tenancy)s", "user_ocid": "%(esouser)s",
                    "group_ocid": "ocid1.group.oc1..synthgroup",
                    "api_key_fingerprint": fp,
                    "vault_ocid": "%(vault)s",
                    "runtime_secret_ocids": []}}))
                sys.exit(0)
            sys.exit(1)
            ''' % {'tenancy': TENANCY, 'esouser': ESO_USER, 'vault': VAULT})
        write_exec(self.bin / 'tofu', tofu)

        kubectl = textwrap.dedent(head.replace('TOOL', 'kubectl')) + textwrap.dedent('''\
            if "get" in args and "kustomizations" in args:
                print(json.dumps({"apiVersion": "v1", "kind": "List",
                                  "items": live["kustomizations"]}))
                sys.exit(0)
            if "get" in args and ("secret" in args or "secrets" in args) \\
                    and "kustomizations" not in args:
                ns = args[args.index("-n")+1] if "-n" in args \\
                    else args[args.index("--namespace")+1]
                name = None
                for i, a in enumerate(args):
                    if a in ("secret", "secrets") and i + 1 < len(args):
                        name = args[i+1]
                key = ns + "/" + name
                if name and key in live["kube_secrets"]:
                    print(json.dumps(live["kube_secrets"][key]))
                    sys.exit(0)
                sys.exit(1)
            if "create" in args or "replace" in args or "apply" in args:
                data = json.loads(sys.stdin.read())
                key = (data["metadata"]["namespace"] + "/" +
                       data["metadata"]["name"])
                live["kube_secrets"][key] = data
                (HERE / "oci-live.json").write_text(json.dumps(live))
            sys.exit(0)
            ''')
        write_exec(self.bin / 'kubectl', kubectl)

        ap = textwrap.dedent(head.replace('TOOL', 'ansible')) + textwrap.dedent('''\
            try:
                candidates = [a[1:] for a in args if a.startswith("@")]
                extra = candidates[0] if candidates \\
                    else args[args.index("--extra-vars")+1]
                mode = os.stat(extra).st_mode & 0o077
                content = Path(extra).read_text()
                (HERE / "ansible-input.json").write_text(content)
                if mode != 0:
                    sys.exit(1)
            except (IndexError, OSError):
                sys.exit(1)
            sys.exit(0)
            ''')
        write_exec(self.bin / 'ansible-playbook', ap)

        self.tools = {
            'git': 'git', 'tofu': str(self.bin / 'tofu'),
            'oci': str(self.bin / 'oci'), 'kubectl': str(self.bin / 'kubectl'),
            'openssl': 'openssl',
            'ansible_playbook': str(self.bin / 'ansible-playbook'),
        }

    # -- config --------------------------------------------------------
    def operator_config(self):
        key = protected(self.tmp / 'operator-key.pem',
                        'SYNTHETIC OPERATOR KEY MATERIAL\n')
        cfg = protected(self.tmp / 'operator-oci.config', textwrap.dedent(f'''\
            [SYNTHETIC_OPERATOR]
            user={OPERATOR_USER}
            tenancy={TENANCY}
            region={REGION}
            fingerprint={OPERATOR_FP}
            key_file={key}
            auth=api_key
            '''))
        return cfg

    def make_config(self, **over):
        cfg = {
            'schema': 1, 'approved': True, 'workspace': str(self.ws),
            'git_origin': GIT_ORIGIN_PATH,
            'expected': {
                'tenancy_ocid': TENANCY, 'compartment_ocid': COMPARTMENT,
                'region': REGION, 'vault_ocid': VAULT,
                'vault_key_ocid': VAULT_KEY,
                'operator_user_ocid': OPERATOR_USER,
                'backend': {'bucket': 'oci-control-server-state',
                            'key': 'control-server/terraform.tfstate',
                            'region': REGION},
            },
            'inventory': str(inventory_fixture(self.tmp)),
            'custody_dir': str(self.custody),
            'operator': {'config_file': str(self.operator_config()),
                         'profile': 'SYNTHETIC_OPERATOR'},
            'tools': dict(self.tools),
            'kubeconfig': str(protected(self.tmp / 'kube.config')),
            'context': 'synthetic-ctx',
            'unrelated_sentinel_secret_ocid': SENTINEL_OCID,
        }
        cfg.update(over)
        path = protected(self.tmp / 'config.json', json.dumps(cfg))
        return path

    # -- runner --------------------------------------------------------
    def run(self, mode, config, *extra, env=None):
        e = {'ESO_MIGRATE_FIXTURE': str(self.tmp),
             'ESO_MIGRATE_OCI_STATE': str(self.oci_state)}
        e.update(env or {})
        return subprocess.run(
            [sys.executable, str(SCRIPT), mode, '--config', str(config), *extra],
            capture_output=True, text=True, env=e, timeout=120)

    def calls_of(self, tool):
        path = self.calls / tool
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    @property
    def journal(self):
        return json.loads((self.custody / 'journal.json').read_text())

    def journal_set(self, **over):
        j = self.journal
        j.update(over)
        (self.custody / 'journal.json').write_text(json.dumps(j))

    def plan_pending(self):
        (self.custody / 'plan.bin').write_bytes(b'SYNTHETIC-PLAN-BYTES')
        state = json.loads(self.oci_state.read_text())
        state['tofu_plan_json'] = TOFU_PLAN_OK
        self.oci_state.write_text(json.dumps(state))

    def live_set(self, **over):
        live = json.loads((self.tmp / 'oci-live.json').read_text())
        live.update(over)
        (self.tmp / 'oci-live.json').write_text(json.dumps(live))


@pytest.fixture
def fx(tmp_path):
    return Fixture(tmp_path)


# =====================================================================
# basic contract
# =====================================================================

def test_script_exists():
    assert SCRIPT.is_file(), 'operator entrypoint missing'


def test_usage_no_config_fails_closed():
    result = subprocess.run([sys.executable, str(SCRIPT), 'prepare'],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode != 0


# =====================================================================
# inventory mode
# =====================================================================

def test_inventory_enumerates_sops_targets_and_writes_draft(fx):
    result = fx.run('inventory', fx.make_config())
    assert result.returncode == 0, result.stdout
    status = json.loads(result.stdout.strip().splitlines()[-1])
    assert status['ok'] is True
    draft = json.loads(Path(status['draft']).read_text())
    assert draft['schema'] == 2
    selectors = {t['k8s']['namespace'] + '/' + t['k8s']['name']
                 for t in draft['runtime_targets']}
    # SOPS-delivered secrets only; flux bootstrap excluded; immich-values
    # (non-SOPS owner) excluded.
    assert selectors == {'alloy/talos-metrics-ingestion',
                         'mumble/mumble-superuser-password'}
    # The annotated Cloudflare member is a reuse entry, not a new target.
    reuse = {e['ocid']: e for e in draft['reuse_entries']}
    assert SHARED_REUSE_OCID in reuse
    assert sorted(reuse[SHARED_REUSE_OCID]['targets']) == [
        f'{DUP_A["namespace"]}/{DUP_A["name"]}',
        f'{DUP_B["namespace"]}/{DUP_B["name"]}']
    # Byte-equal duplicate group is reported (selectors only, no values).
    assert draft['duplicate_groups'] == [[
        f'{DUP_A["namespace"]}/{DUP_A["name"]}',
        f'{DUP_B["namespace"]}/{DUP_B["name"]}']]
    # Flux bundle contract present with real keys.
    assert draft['flux_bundle']['name'] == FLUX_BUNDLE_NAME
    assert set(draft['flux_bundle']['keys']) <= {
        'identity', 'known_hosts', 'identity.pub'}
    # No values anywhere in the draft.
    assert 'SYNTH-SHARED-TOKEN' not in json.dumps(draft)
    assert stat.S_IMODE(Path(status['draft']).stat().st_mode) == 0o600


def test_inventory_draft_matches_operator_review_shape(fx):
    result = fx.run('inventory', fx.make_config())
    status = json.loads(result.stdout.strip().splitlines()[-1])
    assert status['runtime_targets'] == 2
    assert status['duplicate_groups'] == 1
    assert status['reuse_entries'] == 1


# =====================================================================
# prepare mode
# =====================================================================

def test_prepare_imports_runtime_flux_and_eso_bundles(fx):
    result = fx.run('prepare', fx.make_config())
    assert result.returncode == 0, (result.stdout, result.stderr)
    status = json.loads(result.stdout.strip().splitlines()[-1])
    assert status['ok'] is True
    live = json.loads((fx.tmp / 'oci-live.json').read_text())
    created = live['vault_created']
    # Two runtime targets + flux + eso bundles imported as vault secrets.
    assert set(created) == ({t['name'] for t in RUNTIME}
                            | {FLUX_BUNDLE_NAME, ESO_BUNDLE_NAME})
    # Runtime payloads are compact JSON maps of the K8s values.
    for target in RUNTIME:
        ns = target['k8s']['namespace']
        payload = json.loads(base64.b64decode(created[target['name']]))
        expected_pw = 'SYNTH-METRICS-PW' if ns == 'alloy' else 'SYNTH-MUMBLE-PW'
        assert payload == {'password': expected_pw}
    # Flux payload preserves identity/known_hosts bytes exactly.
    flux_payload = json.loads(base64.b64decode(created[FLUX_BUNDLE_NAME]))
    assert flux_payload == FLUX_CONTENT
    # Reuse entry resolved to its vault NAME and kept, no new secret created.
    assert SHARED_VAULT_NAME not in created
    journal = fx.journal
    reuse = journal['reuse_entries']
    assert len(reuse) == 1
    assert reuse[0]['name'] == SHARED_VAULT_NAME
    assert reuse[0]['ocid'] == SHARED_REUSE_OCID
    # Journal runtime targets carry resolved OCIDs and content shapes.
    assert all(t['secret_ocid'] for t in journal['runtime_targets'])
    assert all(t['content_shape'] == 'json_map'
               for t in journal['runtime_targets'])
    # Bootstrap deny list comes from the DISCOVERED bundle OCIDs.
    tfvars = json.loads((fx.custody / 'eso.tfvars.json').read_text())
    assert sorted(tfvars['talos_eso_bootstrap_secret_ocids']) == sorted(
        [journal['flux_bundle']['secret_ocid'],
         journal['eso_bundle']['secret_ocid']])
    assert sorted(tfvars['talos_eso_runtime_secret_ocids']) == sorted(
        [t['secret_ocid'] for t in journal['runtime_targets']]
        + [SHARED_REUSE_OCID])


def test_prepare_key_custody_and_sanitized_outputs(fx):
    cfg = fx.make_config()
    assert fx.run('prepare', cfg).returncode == 0
    key = Path(fx.custody) / 'eso-signing.pem'
    assert key.is_file()
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert not (fx.ws / 'eso-signing.pem').exists()
    journal = fx.journal
    assert journal['applied'] is False
    assert 'SYNTH-SHARED-TOKEN' not in json.dumps(journal)
    for call in fx.calls_of('oci'):
        assert not any('SYNTH-SHARED-TOKEN' in a for a in call)
        assert not any('PRIVATE KEY-----' in a for a in call)
    # tofu init must not have been called.
    assert all('init' not in c for c in fx.calls_of('tofu'))


def test_prepare_refuses_unapproved(fx):
    result = fx.run('prepare', fx.make_config(approved=False))
    assert result.returncode != 0
    assert fx.calls_of('oci') == []


def test_prepare_refuses_backend_lineage_mismatch(fx):
    (fx.ws / 'terraform' / 'backend.tf').write_text(
        BACKEND_TF.replace('use_lockfile       = true',
                           'use_lockfile       = false'))
    subprocess.run(['git', '-C', str(fx.ws), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(fx.ws), '-c', 'user.email=t@t',
                    '-c', 'user.name=t', 'commit', '-qm', 'drift'], check=True)
    result = fx.run('prepare', fx.make_config())
    assert result.returncode != 0
    assert 'backend' in result.stdout.lower()
    assert fx.calls_of('tofu') == [], 'no tofu after refusal'


def test_prepare_refuses_wrong_git_origin(fx):
    subprocess.run(['git', '-C', str(fx.ws), 'remote', 'set-url', 'origin',
                    'https://github.com/Evil/other.git'], check=True)
    result = fx.run('prepare', fx.make_config())
    assert result.returncode != 0
    assert fx.calls_of('tofu') == []


def test_prepare_refuses_dirty_terraform(fx):
    (fx.ws / 'terraform' / 'talos_eso.tf').write_text('drift\n')
    result = fx.run('prepare', fx.make_config())
    assert result.returncode != 0
    assert fx.calls_of('oci') == []


def test_prepare_refuses_bad_operator_profile(fx):
    cfg = fx.make_config()
    cfgfile = Path(json.loads(cfg.read_text())['operator']['config_file'])
    cfgfile.write_text(textwrap.dedent(f'''\
        [SYNTHETIC_OPERATOR]
        user={OPERATOR_USER}
        tenancy=ocid1.tenancy.oc1..othertenancy
        region={REGION}
        fingerprint={OPERATOR_FP}
        key_file={fx.tmp / 'operator-key.pem'}
        auth=security_token
        '''))
    cfgfile.chmod(0o600)
    result = fx.run('prepare', cfg)
    assert result.returncode != 0
    assert fx.calls_of('oci') == [], 'no identity read before profile gate'


def test_prepare_idempotent_no_rotation_single_create(fx):
    cfg = fx.make_config()
    assert fx.run('prepare', cfg).returncode == 0
    key_before = (Path(fx.custody) / 'eso-signing.pem').read_bytes()
    live_before = json.loads((fx.tmp / 'oci-live.json').read_text())
    result = fx.run('prepare', cfg)
    assert result.returncode == 0, result.stdout
    assert (Path(fx.custody) / 'eso-signing.pem').read_bytes() == key_before
    live_after = json.loads((fx.tmp / 'oci-live.json').read_text())
    assert live_after['vault_created'] == live_before['vault_created']


def test_prepare_never_overwrites_differing_vault_content(fx):
    cfg = fx.make_config()
    assert fx.run('prepare', cfg).returncode == 0
    live = json.loads((fx.tmp / 'oci-live.json').read_text())
    target = RUNTIME[0]['name']
    payload = json.loads(base64.b64decode(live['vault_created'][target]))
    payload['password'] = 'CHANGED'
    live['vault_created'][target] = b64(json.dumps(
        payload, separators=(',', ':')).encode())
    (fx.tmp / 'oci-live.json').write_text(json.dumps(live))
    result = fx.run('prepare', cfg)
    assert result.returncode != 0
    for stream in (result.stdout, result.stderr):
        assert 'CHANGED' not in stream
        assert 'PRIVATE KEY-----' not in stream


def test_prepare_rejects_reuse_equality_mismatch(fx):
    cfg = fx.make_config()
    live = json.loads((fx.tmp / 'oci-live.json').read_text())
    live['vault_created'][SHARED_VAULT_NAME] = b64(b'OTHER-TOKEN')
    (fx.tmp / 'oci-live.json').write_text(json.dumps(live))
    result = fx.run('prepare', cfg)
    assert result.returncode != 0
    assert 'OTHER-TOKEN' not in result.stdout


def test_prepare_rejects_key_mismatch_and_deleting_secret(fx):
    inv_bad_keys = json.loads(inventory_fixture(fx.tmp).read_text())
    inv_bad_keys['runtime_targets'][0]['keys'] = ['password', 'extra']
    bad = protected(fx.tmp / 'inventory-bad.json', json.dumps(inv_bad_keys))
    result = fx.run('prepare', fx.make_config(inventory=str(bad)))
    assert result.returncode != 0
    live = json.loads((fx.tmp / 'oci-live.json').read_text())
    key = f'{FLUX_NS}/{FLUX_SECRET}'
    live['kube_secrets'][key]['metadata']['deletionTimestamp'] = 'x'
    (fx.tmp / 'oci-live.json').write_text(json.dumps(live))
    result = fx.run('prepare', fx.make_config())
    assert result.returncode != 0


def test_prepare_reuse_ocid_must_be_disjoint_from_new_targets(fx):
    inv = json.loads(inventory_fixture(fx.tmp).read_text())
    shared_ocid = 'ocid1.vaultsecret.eu-stockholm-1.synthrt1'
    inv['reuse_entries'][0]['ocid'] = shared_ocid
    inv['runtime_targets'][0]['secret_ocid'] = shared_ocid
    bad = protected(fx.tmp / 'inventory-bad.json', json.dumps(inv))
    result = fx.run('prepare', fx.make_config(inventory=str(bad)))
    assert result.returncode != 0


# =====================================================================
# plan mode
# =====================================================================

def test_plan_requires_prepare_journal(fx):
    result = fx.run('plan', fx.make_config())
    assert result.returncode != 0


def test_plan_happy_path_saves_sanitized_summary(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    result = fx.run('plan', fx.make_config())
    assert result.returncode == 0, result.stdout
    assert (Path(fx.custody) / 'plan.bin').read_bytes() == b'SYNTHETIC-PLAN-BYTES'
    summary = json.loads(result.stdout.strip().splitlines()[-1])
    assert summary['ok'] is True
    assert summary['plan_digest']
    assert summary['new_resources'] == 4
    assert not any('-target' in a for c in fx.calls_of('tofu') for a in c)
    assert not any('-refresh=false' in a or '-lock=false' in a
                   for c in fx.calls_of('tofu') for a in c)


def test_plan_rejects_unrelated_change(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    plan = json.loads(json.dumps(TOFU_PLAN_OK))
    plan['resource_changes'].append(
        {'address': 'oci_kms_vault.control[0]',
         'change': {'actions': ['update']}})
    state = json.loads(fx.oci_state.read_text())
    state['tofu_plan_json'] = plan
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('plan', fx.make_config())
    assert result.returncode != 0
    assert 'oci_kms_vault' not in result.stdout, 'sanitized refusals only'


def test_plan_rejects_hermes_policy_change(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    plan = json.loads(json.dumps(TOFU_PLAN_OK))
    plan['resource_changes'].append(
        {'address': 'oci_identity_policy.hermes[0]',
         'change': {'actions': ['update']}})
    state = json.loads(fx.oci_state.read_text())
    state['tofu_plan_json'] = plan
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('plan', fx.make_config())
    assert result.returncode != 0


def test_plan_rejects_wrong_resource_count(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    plan = json.loads(json.dumps(TOFU_PLAN_OK))
    plan['resource_changes'] = plan['resource_changes'][:3]
    state = json.loads(fx.oci_state.read_text())
    state['tofu_plan_json'] = plan
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('plan', fx.make_config())
    assert result.returncode != 0


# =====================================================================
# apply mode
# =====================================================================

def test_apply_requires_explicit_approval_digest(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    result = fx.run('apply', fx.make_config())
    assert result.returncode != 0
    assert not json.loads(fx.oci_state.read_text())['tofu_apply']


def test_apply_rejects_wrong_digest(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    result = fx.run('apply', fx.make_config(), '--approve', 'wrong-digest')
    assert result.returncode != 0
    assert not json.loads(fx.oci_state.read_text())['tofu_apply']


def test_apply_happy_path_applies_saved_plan(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    summary = json.loads(
        fx.run('plan', fx.make_config()).stdout.strip().splitlines()[-1])
    result = fx.run('apply', fx.make_config(),
                    '--approve', summary['plan_digest'])
    assert result.returncode == 0, result.stdout
    assert json.loads(fx.oci_state.read_text())['tofu_apply'] is True
    apply_calls = [c for c in fx.calls_of('tofu') if 'apply' in c]
    assert apply_calls, 'apply must invoke tofu'
    assert any('plan.bin' in a for a in apply_calls[0])
    assert not any('-auto-approve' in a for a in apply_calls[0])
    journal = fx.journal
    assert journal['applied'] is True
    assert journal['eso_user_ocid'] == ESO_USER
    # tofu output echoed the custody key's real fingerprint.
    assert re.fullmatch(r'(?:[0-9a-f]{2}:){19}[0-9a-f]{2}',
                        journal['api_key_fingerprint'])
    assert journal['kubernetes']['auth_secret'] == 'external-secrets/oci-vault-auth'


def test_apply_refuses_before_plan(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    result = fx.run('apply', fx.make_config(), '--approve', 'x')
    assert result.returncode != 0
    assert not json.loads(fx.oci_state.read_text())['tofu_apply']


# =====================================================================
# verify mode
# =====================================================================

def _applied(fx):
    fx.plan_pending()
    fx.journal_set(applied=True, eso_user_ocid=ESO_USER,
                   api_key_fingerprint='SYNTHFP')


def test_verify_positive_includes_reuse_entries(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    _applied(fx)
    result = fx.run('verify', fx.make_config())
    assert result.returncode == 0, result.stdout
    status = json.loads(result.stdout.strip().splitlines()[-1])
    assert status['ok'] is True
    assert status['runtime_verified'] == len(fx.journal['runtime_targets'])
    assert status['reuse_verified'] == 1
    # by-name read for the reuse entry's resolved vault name happened.
    assert any(SHARED_VAULT_NAME in ' '.join(c)
               for c in fx.calls_of('oci')
               if 'get-secret-bundle-by-name' in c)


def test_verify_fails_when_denial_missing(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    _applied(fx)
    fx.live_set(deny_success=True)
    result = fx.run('verify', fx.make_config())
    assert result.returncode != 0


def test_verify_fails_on_non_authorization_api_error(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    _applied(fx)
    # A 500-style error must NOT count as an IAM denial.
    fx.live_set(denial_code='InternalServerFailure')
    result = fx.run('verify', fx.make_config())
    assert result.returncode != 0
    assert 'authorization' in result.stdout.lower()


def test_verify_counts_real_authorization_denials(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    _applied(fx)
    fx.live_set(denial_code='NotAuthenticated')
    result = fx.run('verify', fx.make_config())
    assert result.returncode == 0, result.stdout


def test_verify_requires_applied_journal(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    result = fx.run('verify', fx.make_config())
    assert result.returncode != 0


# =====================================================================
# bootstrap mode
# =====================================================================

def test_bootstrap_reuses_isolated_play_with_private_inputs(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    _applied(fx)
    result = fx.run('bootstrap', fx.make_config())
    assert result.returncode == 0, result.stdout
    calls = fx.calls_of('ansible')
    assert len(calls) == 1, 'exactly one isolated play invocation'
    assert any('talos-secrets-bootstrap.yml' in a for a in calls[0])
    payload = json.loads((fx.tmp / 'ansible-input.json').read_text())
    inputs = payload['talos_secrets_bootstrap']
    assert inputs['approved'] is True
    assert inputs['eso']['secret_id'] == fx.journal['eso_bundle']['secret_ocid']
    assert inputs['flux']['secret_id'] == fx.journal['flux_bundle']['secret_ocid']
    assert inputs['eso_user_ocid'] == ESO_USER
    wiring = fx.journal['kubernetes']
    assert wiring['auth_secret'] == 'external-secrets/oci-vault-auth'
    assert wiring['git_secret'] == 'flux-system/homelab-secrets-git'


def test_bootstrap_requires_verified_journal(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    result = fx.run('bootstrap', fx.make_config())
    assert result.returncode != 0
    assert fx.calls_of('ansible') == []


# =====================================================================
# end-to-end pipeline and idempotence
# =====================================================================

def test_full_pipeline_then_rerun_is_safe(fx):
    cfg = fx.make_config()
    assert fx.run('inventory', cfg).returncode == 0
    assert fx.run('prepare', cfg).returncode == 0
    fx.plan_pending()
    summary = json.loads(fx.run('plan', cfg).stdout.strip().splitlines()[-1])
    assert fx.run('apply', cfg, '--approve',
                  summary['plan_digest']).returncode == 0
    assert fx.run('verify', cfg).returncode == 0
    assert fx.run('bootstrap', cfg).returncode == 0
    key_before = (Path(fx.custody) / 'eso-signing.pem').read_bytes()
    live_before = json.loads((fx.tmp / 'oci-live.json').read_text())
    for mode in ('prepare', 'verify', 'bootstrap'):
        assert fx.run(mode, cfg).returncode == 0, mode
    live_after = json.loads((fx.tmp / 'oci-live.json').read_text())
    assert live_after['vault_created'] == live_before['vault_created']
    assert (Path(fx.custody) / 'eso-signing.pem').read_bytes() == key_before


def test_journal_mismatch_fails_closed(fx):
    cfg = fx.make_config()
    assert fx.run('prepare', cfg).returncode == 0
    fx.journal_set(source_head='0' * 40)
    result = fx.run('verify', cfg)
    assert result.returncode != 0


def test_inventory_legacy_vault_name_is_provenance_only(fx):
    live = json.loads((fx.tmp / 'oci-live.json').read_text())
    selector = 'alloy/talos-metrics-ingestion'
    live['kube_secrets'][selector]['metadata']['annotations'] = {
        REUSE_ANNOTATION: 'legacy-vault-entry'}
    (fx.tmp / 'oci-live.json').write_text(json.dumps(live))
    result = fx.run('inventory', fx.make_config())
    assert result.returncode == 0, result.stdout
    status = json.loads(result.stdout.strip().splitlines()[-1])
    draft = json.loads(Path(status['draft']).read_text())
    assert any(t['k8s'] == {'namespace': 'alloy',
                           'name': 'talos-metrics-ingestion'}
               for t in draft['runtime_targets'])
    assert all(selector not in entry['targets']
               for entry in draft['reuse_entries'])
    assert 'legacy-vault-entry' not in json.dumps(draft)


def test_inventory_rejects_malformed_annotation_ocid(fx):
    # A typo'd annotation value must fail closed, not become a new target.
    live = json.loads((fx.tmp / 'oci-live.json').read_text())
    key = f'{DUP_A["namespace"]}/{DUP_A["name"]}'
    live['kube_secrets'][key]['metadata']['annotations'][
        REUSE_ANNOTATION] = 'ocid1.vaultsecret.typo'
    (fx.tmp / 'oci-live.json').write_text(json.dumps(live))
    result = fx.run('inventory', fx.make_config())
    assert result.returncode != 0
    assert 'typo' not in result.stdout


def test_verify_reports_exact_denial_codes(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    _applied(fx)
    result = fx.run('verify', fx.make_config())
    assert result.returncode == 0, result.stdout
    status = json.loads(result.stdout.strip().splitlines()[-1])
    assert status['denial_codes'] == ['NotAuthorizedOrNotFound']
