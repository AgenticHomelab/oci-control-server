"""Synthetic offline tests for the operator-run ESO migration driver.

Exercises the real scripts/eso-migration/eso_migrate.py against fake native
executables (oci, tofu, kubectl, ansible-playbook), a real throwaway git
workspace and real openssl. No OCI, Kubernetes or backend is ever contacted.
All identities, fingerprints and contents are synthetic.
"""
import base64
import json
import os
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
REGION = 'eu-stockholm-1'
OPERATOR_USER = 'ocid1.user.oc1..synthoperator'
ESO_USER = 'ocid1.user.oc1..syntheticeso'
OPERATOR_FP = 'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99'

RUNTIME = [
    {'name': 'app-a-token',
     'secret_ocid': 'ocid1.vaultsecret.eu-stockholm-1.synthrt1',
     'keys': ['token']},
    {'name': 'app-b-api',
     'secret_ocid': 'ocid1.vaultsecret.eu-stockholm-1.synthrt2',
     'keys': ['api_key']},
]
SHARED_OCIDs = [
    'ocid1.vaultsecret.eu-stockholm-1.synthsharedca',
    'ocid1.vaultsecret.eu-stockholm-1.synthsharedcf',
]
BOOT_OCID_FLUX = 'ocid1.vaultsecret.eu-stockholm-1.synthbootflux'
BOOT_OCID_ESO = 'ocid1.vaultsecret.eu-stockholm-1.synthbooteso'
SENTINEL_OCID = 'ocid1.vaultsecret.eu-stockholm-1.synthsentinel'
ESO_BUNDLE_NAME = 'talos-eso-signing-bundle'
FLUX_BUNDLE_NAME = 'talos-flux-deploy'
KUBE_ESO_NS, KUBE_ESO_SECRET = 'external-secrets', 'oci-vault-auth'
KUBE_FLUX_NS, KUBE_FLUX_SECRET = 'flux-system', 'homelab-secrets-git'

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

# The ESO runtime policy plan the fake tofu reports for a successful apply.
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
    'output_changes': {
        'talos_eso_iam_metadata': {'after': {
            'tenancy_ocid': TENANCY, 'user_ocid': ESO_USER,
            'group_ocid': 'ocid1.group.oc1..synthgroup',
            'api_key_fingerprint': 'SYNTHFP',
            'vault_ocid': VAULT,
            'runtime_secret_ocids': sorted(t['secret_ocid'] for t in RUNTIME),
        }},
    },
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


def inventory_fixture(tmp, **over):
    data = {
        'schema': 1,
        'vault_ocid': VAULT,
        'compartment_ocid': COMPARTMENT,
        'runtime_targets': RUNTIME,
        'reuse_vault_secret_ocids': {
            'cert-manager/cloudflare-api-token': {
                'ocid': SHARED_OCIDs[1],
                'targets': ['cloudflare-ddns/cloudflare-ddns-secret',
                            'external-dns/external-dns-cloudflare']},
        },
        'eso_bundle': {'name': ESO_BUNDLE_NAME,
                       'keys': ['privatekey', 'fingerprint']},
        'flux_bundle': {'name': FLUX_BUNDLE_NAME,
                        'keys': ['identity', 'known_hosts']},
        'bootstrap_secret_ocids': [BOOT_OCID_FLUX, BOOT_OCID_ESO],
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
        self.oci_state.write_text(json.dumps({
            'mode': 'absent',  # absent | equal | mismatch
            'existing_content': 'SYNTHETIC-EXISTING-DIFFERENT',
            'created': {},
            'tofu_plan_json': None,
            'tofu_apply': False,
            'kube_secret': None,
            'kube_secrets': {},
            'deny_success': False,
            'kube_flux_content': None,
        }))
        self.tools = {}
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
        (ws / '.terraform').mkdir()
        (ws / '.terraform' / 'environment').write_text('default\n')
        self.ws = ws
        subprocess.run(['git', 'init', '-q', str(ws)], check=True)
        subprocess.run(['git', '-C', str(ws), 'remote', 'add', 'origin',
                       'https://github.com/' + GIT_ORIGIN_PATH], check=True)
        subprocess.run(['git', '-C', str(ws), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(ws), '-c', 'user.email=t@t',
                        '-c', 'user.name=t', 'commit', '-qm', 'synth'],
                       check=True)

    # -- fakes ---------------------------------------------------------
    def _record(self, tool, argv):
        with open(self.calls / tool, 'a') as stream:
            stream.write(json.dumps(argv) + '\n')

    def _make_fakes(self):
        head = '''\
            #!/usr/bin/env python3
            import base64, json, os, sys
            from pathlib import Path
            HERE = Path(__file__).resolve().parent.parent
            state = json.loads((HERE / "oci-state.json").read_text())
            args = sys.argv[1:]
            (HERE / "calls" / "TOOL").open("a").write(json.dumps(args) + "\\n")
            '''
        oci = textwrap.dedent(head.replace('TOOL', 'oci')) + textwrap.dedent('''\
            def out(payload):
                print(json.dumps(payload)); sys.exit(0)
            profile = args[args.index("--profile")+1] if "--profile" in args else "?"
            if "iam" in args and "user" in args and "get" in args:
                if profile != "SYNTHETIC_OPERATOR":
                    sys.exit(1)
                uid = args[args.index("--user-id")+1]
                out({"data": {"id": uid, "tenancy-id": "%s",
                             "compartment-id": "%s"}})
            if "iam" in args and "compartment" in args and "get" in args:
                out({"data": {"id": "%s",
                             "compartment-id": "%s"}})
            if "vault" in args and "secrets" in args and "list" in args:
                name = args[args.index("--name")+1]
                if name == "%s" and state["mode"] != "absent":
                    out({"data": [{"id": "ocid1.vaultsecret.eu-stockholm-1.created1",
                                   "secret-name": name}]})
                elif name == "%s":
                    out({"data": [{"id": "ocid1.vaultsecret.eu-stockholm-1.createdflux",
                                   "secret-name": name}]})
                else:
                    out({"data": []})
            if "vault" in args and "secret-bundle" in args and "get-by-name" in args:
                name = args[args.index("--secret-name")+1]
                if name == "%s":
                    content = base64.b64encode(
                        (state.get("kube_flux_content") or
                         "SYNTH-FLUX-JSON").encode()).decode()
                    secret_id = "ocid1.vaultsecret.eu-stockholm-1.createdflux"
                elif name == "%s" and state["mode"] == "equal":
                    content = base64.b64encode(
                        state["existing_content"].encode()).decode()
                    secret_id = "ocid1.vaultsecret.eu-stockholm-1.created1"
                elif name == "%s" and state["mode"] == "mismatch":
                    content = base64.b64encode(
                        b"SYNTHETIC-EXISTING-DIFFERENT").decode()
                    secret_id = "ocid1.vaultsecret.eu-stockholm-1.created1"
                elif name in %s:
                    content = base64.b64encode(
                        b"SYNTH-RUNTIME-VALUE").decode()
                    secret_id = [t["secret_ocid"] for t in %s
                                 if t["name"] == name][0]
                else:
                    sys.exit(1)
                out({"data": {"secret-id": secret_id, "secret-name": name,
                              "version-number": 1,
                              "version-stages": ["CURRENT"],
                              "secret-bundle-content": {
                                  "content-type": "BASE64",
                                  "content": content}}})
            if "vault" in args and "secret-bundle" in args and "get" in args \\
                    and "get-by-name" not in args and "--secret-id" in args:
                sid = args[args.index("--secret-id")+1]
                if state.get("bundle_by_id", {}).get(sid):
                    out({"data": {"secret-id": sid,
                                  "secret-bundle-content": {
                                      "content-type": "BASE64",
                                      "content": state["bundle_by_id"][sid]}}})
                if state.get("deny_success") and profile == "ESO_IDENTITY":
                    out({"data": {"secret-id": sid}})
                sys.exit(1)
            if "vault" in args and "vault" in args and "get" in args:
                out({"data": {"id": "%s"}})
            if "vault" in args and "secret" in args and "create" in args:
                f = args[args.index("--secret-content-content-file")+1]
                content = Path(f).read_text()
                state["created"][args[args.index("--secret-name")+1]] = content
                state["mode"] = "equal"
                state["existing_content"] = base64.b64decode(content).decode()
                (HERE / "oci-state.json").write_text(json.dumps(state))
                out({"data": {"id": "ocid1.vaultsecret.eu-stockholm-1.created1"}})
            sys.exit(1)
            ''' % (TENANCY, COMPARTMENT, COMPARTMENT, TENANCY,
                   ESO_BUNDLE_NAME, FLUX_BUNDLE_NAME, FLUX_BUNDLE_NAME,
                   ESO_BUNDLE_NAME, ESO_BUNDLE_NAME,
                   json.dumps([t['name'] for t in RUNTIME]),
                   json.dumps(RUNTIME), VAULT))

        write_exec(self.bin / 'oci', oci)

        tofu = textwrap.dedent(head.replace('TOOL', 'tofu')) + textwrap.dedent('''\
            if "init" in args:
                sys.exit(0)
            if "plan" in args:
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
                fp = state.get("api_key_fingerprint")
                try:
                    jr = json.loads((HERE / "custody" / "journal.json").read_text())
                    fp = jr.get("api_key_fingerprint") or fp
                except (OSError, ValueError):
                    pass
                if not fp:
                    pem = (HERE / "custody" / "journal.json").read_text()
                    pub = [l for l in pem.splitlines() if "KEY-----" not in l]
                    digest = __import__("hashlib").sha1(
                        b"".join(l.encode() for l in pub)).hexdigest()
                    fp = ":".join(digest[i:i+2] for i in range(0, 40, 2))
                print(json.dumps({"value": {
                    "tenancy_ocid": "%s", "user_ocid": "%s",
                    "group_ocid": "ocid1.group.oc1..synthgroup",
                    "api_key_fingerprint": fp,
                    "vault_ocid": "%s",
                    "runtime_secret_ocids": sorted(t["secret_ocid"] for t in %s)}}))
                sys.exit(0)
            sys.exit(1)
            ''' % (TENANCY, ESO_USER, VAULT, json.dumps(RUNTIME)))
        write_exec(self.bin / 'tofu', tofu)

        kubectl = textwrap.dedent(head.replace('TOOL', 'kubectl')) + textwrap.dedent('''\
            if "delete" in args:
                sys.exit(0)
            if "get" in args and "secret" in args:
                ns = args[args.index("--namespace")+1]
                name = args[args.index("secret")+1]
                key = ns+"/"+name
                if state["kube_secrets"].get(key):
                    print(json.dumps(state["kube_secrets"][key]))
                sys.exit(0)
            if "create" in args or ("apply" in args and "-f" in args):
                data = json.loads(sys.stdin.read())
                key = (data["metadata"]["namespace"] + "/" +
                       data["metadata"]["name"])
                state["kube_secrets"][key] = data
                (HERE / "oci-state.json").write_text(json.dumps(state))
            sys.exit(0)
            ''')
        write_exec(self.bin / 'kubectl', kubectl)

        ap = textwrap.dedent(head.replace('TOOL', 'ansible')) + textwrap.dedent('''\
            # The private extra-vars file must exist and be mode 0600.
            if "@@" in " ".join(args):
                sys.exit(1)
            try:
                candidates = [a[1:] for a in args if a.startswith("@")]
                extra = candidates[0] if candidates else args[args.index("--extra-vars")+1]
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
        (self.custody / 'plan.json').write_text(json.dumps(TOFU_PLAN_OK))
        state = json.loads(self.oci_state.read_text())
        state['tofu_plan_json'] = TOFU_PLAN_OK
        self.oci_state.write_text(json.dumps(state))


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
# prepare mode
# =====================================================================

def test_prepare_happy_path(fx):
    cfg = fx.make_config()
    result = fx.run('prepare', cfg)
    assert result.returncode == 0, (result.stdout, result.stderr)
    status = json.loads(result.stdout.strip().splitlines()[-1])
    assert status['ok'] is True
    # key custody: outside git, mode 0600
    key = Path(fx.custody) / 'eso-signing.pem'
    assert key.is_file()
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert not (fx.ws / 'eso-signing.pem').exists()
    # journal: resumable metadata only
    journal = fx.journal
    assert journal['eso_bundle']['secret_ocid']
    assert journal['eso_bundle']['version_number'] == 1
    assert journal['flux_bundle']['secret_ocid']
    assert journal['flux_bundle']['version_number'] == 1
    assert journal['applied'] is False
    assert 'PRIVATE KEY' not in json.dumps(journal).replace('-----BEGIN', '')
    # tfvars: public metadata only, in custody not workspace
    tfvars = Path(fx.custody) / 'eso.tfvars.json'
    assert tfvars.is_file() and not (fx.ws / 'eso.tfvars.json').exists()
    data = json.loads(tfvars.read_text())
    assert data['talos_eso_enabled'] is True
    assert data['talos_eso_api_signing_public_key_pem'].startswith(
        '-----BEGIN PUBLIC KEY-----')
    assert sorted(data['talos_eso_runtime_secret_ocids']) == sorted(
        [t['secret_ocid'] for t in RUNTIME] + [SHARED_OCIDs[1]])
    assert set(data['talos_eso_bootstrap_secret_ocids']) >= {
        BOOT_OCID_FLUX, BOOT_OCID_ESO}
    assert 'PRIVATE KEY-----' not in tfvars.read_text()
    assert stat.S_IMODE(tfvars.stat().st_mode) == 0o600
    # tofu init must not have been called (backend already initialized)
    assert all('init' not in c for c in fx.calls_of('tofu'))


def test_prepare_refuses_unapproved(fx):
    result = fx.run('prepare', fx.make_config(approved=False))
    assert result.returncode != 0
    status = json.loads(result.stdout.strip().splitlines()[-1])
    assert status['ok'] is False
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
    cfg = fx.make_config()  # creates the good profile file first
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


def test_prepare_idempotent_reuses_key_and_equal_vault_entry(fx):
    cfg = fx.make_config()
    assert fx.run('prepare', cfg).returncode == 0
    key_before = (Path(fx.custody) / 'eso-signing.pem').read_bytes()
    state = json.loads(fx.oci_state.read_text())
    created = state['created'][ESO_BUNDLE_NAME]
    state['mode'] = 'equal'
    state['existing_content'] = base64.b64decode(created).decode()
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('prepare', cfg)
    assert result.returncode == 0, result.stdout
    assert (Path(fx.custody) / 'eso-signing.pem').read_bytes() == key_before
    creates = [c for c in fx.calls_of('oci') if 'create' in c]
    assert len(creates) == 1, 'equal vault entry must be reused, not recreated'


def test_prepare_never_overwrites_differing_vault_content(fx):
    cfg = fx.make_config()
    assert fx.run('prepare', cfg).returncode == 0
    state = json.loads(fx.oci_state.read_text())
    state['mode'] = 'mismatch'
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('prepare', cfg)
    assert result.returncode != 0
    for stream in (result.stdout, result.stderr):
        assert 'SYNTHETIC-EXISTING-DIFFERENT' not in stream
        assert 'PRIVATE KEY-----' not in stream


def test_prepare_detects_duplicate_runtime_targets(fx):
    cfg = fx.make_config()
    dup = list(RUNTIME)
    dup[1] = dict(dup[0], name=dup[0]['name'])
    inv = inventory_fixture(fx.tmp, runtime_targets=dup)
    data = json.loads(cfg.read_text())
    data['inventory'] = str(inv)
    cfg.write_text(json.dumps(data))
    cfg.chmod(0o600)
    result = fx.run('prepare', cfg)
    assert result.returncode != 0


def test_prepare_no_secret_values_in_output_or_argv(fx):
    cfg = fx.make_config()
    result = fx.run('prepare', cfg)
    assert result.returncode == 0
    for stream in (result.stdout, result.stderr):
        assert 'PRIVATE KEY-----' not in stream
    for call in fx.calls_of('oci'):
        assert not any('PRIVATE KEY-----' in a for a in call)


def test_prepare_reuse_ocid_must_be_disjoint_from_new_targets(fx):
    cfg = fx.make_config()
    inv = inventory_fixture(fx.tmp, reuse_vault_secret_ocids={
        'cert-manager/cloudflare-api-token': {
            'ocid': RUNTIME[0]['secret_ocid'],
            'targets': ['x/y']}})
    data = json.loads(cfg.read_text())
    data['inventory'] = str(inv)
    cfg.write_text(json.dumps(data))
    cfg.chmod(0o600)
    result = fx.run('prepare', cfg)
    assert result.returncode != 0


# =====================================================================
# plan mode
# =====================================================================

def test_plan_requires_prepare_journal(fx):
    result = fx.run('plan', fx.make_config())
    assert result.returncode != 0


def test_plan_happy_path_saves_sanitized_summary(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    state = json.loads(fx.oci_state.read_text())
    state['tofu_plan_json'] = TOFU_PLAN_OK
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('plan', fx.make_config())
    assert result.returncode == 0, result.stdout
    assert (Path(fx.custody) / 'plan.bin').read_bytes() == b'SYNTHETIC-PLAN-BYTES'
    summary = json.loads(result.stdout.strip().splitlines()[-1])
    assert summary['ok'] is True
    assert summary['plan_digest']
    assert summary['new_resources'] == 4
    addresses = {a for c in fx.calls_of('tofu') if 'plan' in c for a in c
                 if 'talos_eso' in str(a)}
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
    # saved plan bytes only, no plan arg mutation
    assert any('plan.bin' in a for a in apply_calls[0])
    assert not any('-auto-approve' in a for a in apply_calls[0])
    journal = fx.journal
    assert journal['applied'] is True
    # wiring metadata recorded for continuation, incl. auth Secret ref
    assert journal['eso_user_ocid'] == ESO_USER
    assert re.fullmatch(r'(?:[0-9a-f]{2}:){19}[0-9a-f]{2}',
                        journal['api_key_fingerprint'])
    assert journal['kubernetes']['auth_secret'] == 'external-secrets/oci-vault-auth'


def test_apply_refuses_before_plan(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    result = fx.run('apply', fx.make_config(), '--approve', 'x')
    assert result.returncode != 0
    assert not json.loads(fx.oci_state.read_text())['tofu_apply']


# =====================================================================
# verify mode (IAM positive/negative as new ESO identity)
# =====================================================================

def test_verify_positive_reads_and_negative_denials(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    fx.journal_set(applied=True, eso_user_ocid=ESO_USER,
                   api_key_fingerprint='SYNTHFP')
    state = json.loads(fx.oci_state.read_text())
    state['deny_success'] = False  # get-by-id on denied OCIDs must be refused
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('verify', fx.make_config())
    assert result.returncode == 0, result.stdout
    oci_calls = fx.calls_of('oci')
    # positive: by-name bundle reads for runtime names and vault get
    by_name = [c for c in oci_calls if 'get-by-name' in c]
    assert len(by_name) >= len(RUNTIME)
    # negative: reads of bootstrap/sentinel OCIDs attempted and refused
    by_id = [c for c in oci_calls if 'get' in c and '--secret-id' in c]
    assert any(BOOT_OCID_ESO in ' '.join(c) for c in by_id)
    assert any(SENTINEL_OCID in ' '.join(c) for c in by_id)
    for stream in (result.stdout, result.stderr):
        assert 'SYNTHETIC' not in stream or 'SYNTHETIC-OPERATOR' not in stream


def test_verify_fails_when_denial_missing(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    fx.journal_set(applied=True, eso_user_ocid=ESO_USER,
                   api_key_fingerprint='SYNTHFP')
    state = json.loads(fx.oci_state.read_text())
    state['deny_success'] = True  # denial unexpectedly succeeds -> fail closed
    fx.oci_state.write_text(json.dumps(state))
    result = fx.run('verify', fx.make_config())
    assert result.returncode != 0


def test_verify_requires_applied_journal(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    result = fx.run('verify', fx.make_config())
    assert result.returncode != 0


# =====================================================================
# bootstrap mode (reuse isolated Ansible play)
# =====================================================================

def test_bootstrap_reuses_isolated_play_with_private_inputs(fx):
    assert fx.run('prepare', fx.make_config()).returncode == 0
    fx.plan_pending()
    fx.journal_set(applied=True, eso_user_ocid=ESO_USER,
                   api_key_fingerprint='SYNTHFP')
    result = fx.run('bootstrap', fx.make_config())
    assert result.returncode == 0, result.stdout
    calls = fx.calls_of('ansible')
    assert len(calls) == 1, 'exactly one isolated play invocation'
    argv = calls[0]
    assert any('talos-secrets-bootstrap.yml' in a for a in argv)
    # private input file captured by fake; verify schema and protection
    payload = json.loads((fx.tmp / 'ansible-input.json').read_text())
    inputs = payload['talos_secrets_bootstrap']
    assert inputs['approved'] is True
    assert inputs['eso']['secret_id'] == fx.journal['eso_bundle']['secret_ocid']
    assert inputs['flux']['secret_id'] == fx.journal['flux_bundle']['secret_ocid']
    assert inputs['operator_user_ocid'] == OPERATOR_USER
    assert inputs['eso_user_ocid'] == ESO_USER
    assert inputs['context'] == 'synthetic-ctx'
    wiring = fx.journal['kubernetes']
    assert wiring['auth_secret'] == f'{KUBE_ESO_NS}/{KUBE_ESO_SECRET}'
    assert wiring['git_secret'] == f'{KUBE_FLUX_NS}/{KUBE_FLUX_SECRET}'


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
    assert fx.run('prepare', cfg).returncode == 0
    state = json.loads(fx.oci_state.read_text())
    state['tofu_plan_json'] = TOFU_PLAN_OK
    fx.oci_state.write_text(json.dumps(state))
    summary = json.loads(fx.run('plan', cfg).stdout.strip().splitlines()[-1])
    assert fx.run('apply', cfg, '--approve', summary['plan_digest']).returncode == 0
    assert fx.run('verify', cfg).returncode == 0
    assert fx.run('bootstrap', cfg).returncode == 0
    # rerun full pipeline: no key rotation, no new create, idempotent
    state = json.loads(fx.oci_state.read_text())
    created_before = dict(state['created'])
    key_before = (Path(fx.custody) / 'eso-signing.pem').read_bytes()
    for mode in ('prepare', 'verify', 'bootstrap'):
        assert fx.run(mode, cfg).returncode == 0, mode
    state = json.loads(fx.oci_state.read_text())
    for name, content in created_before.items():
        assert state['created'][name] == content
    assert (Path(fx.custody) / 'eso-signing.pem').read_bytes() == key_before
    assert len([c for c in fx.calls_of('ansible') if
                'talos-secrets-bootstrap.yml' in ' '.join(c)]) == 2
    # no output ever contained private key material
    assert 'PRIVATE KEY-----' not in json.dumps(state.get('created', {}))


def test_journal_mismatch_fails_closed(fx):
    cfg = fx.make_config()
    assert fx.run('prepare', cfg).returncode == 0
    fx.journal_set(source_head='0' * 40)
    result = fx.run('verify', cfg)
    assert result.returncode != 0
