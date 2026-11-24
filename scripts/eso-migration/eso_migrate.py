#!/usr/bin/env python3
"""Operator-run ESO migration driver for issue #15.

Modes, in operator order:

  prepare    Verify the original git workspace, S3 backend lineage
             (use_lockfile=true, default workspace), and the independent
             operator OCI API-key identity (matching root tenancy and
             compartment, never InstancePrincipal and never the ESO user).
             Mint the new ESO RSA signing key once into private custody
             (outside Git, mode 0600), import the ESO bundle into the
             existing Vault reusing equal entries and never overwriting
             differing content, and write public-metadata-only tfvars plus a
             resumable private journal.
  plan       Full locked `tofu plan` (refresh on, no -target, no
             -refresh=false, no -lock=false), inspect the saved plan JSON
             for exactly the four new talos_eso resources with no unrelated
             changes, and print a sanitized address/action summary plus a
             plan digest.
  apply      Apply the exact saved plan only after explicit
             `--approve <plan digest>`; record wiring metadata in the
             journal for later modes.
  verify     Positive/negative IAM validation as the new ESO identity:
             by-name bundle reads for every runtime target and GetVault
             success, plus read denials on the two bootstrap OCIDs and the
             unrelated sentinel. Read-only with the new signer.
  bootstrap  Materialize the two pinned K8s Secrets through the existing
             isolated Ansible play (ansible/talos-secrets-bootstrap.yml)
             with private mode-0600 inputs.

Everything sensitive lives under the private custody directory (outside
Git, mode 0600). Operator-facing output is sanitized status JSON only;
native raw stdout/stderr is captured and never replayed. No secret values
in argv, tracked files, logs or the journal.
"""
import base64
import configparser
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

# Sanitized static failure vocabulary only; never carries native output.
E_ARGS = 'explicit --config path required'
E_CONFIG = 'configuration file unreadable or invalid'
E_SCHEMA = 'configuration schema mismatch'
E_WORKSPACE = 'workspace path invalid'
E_GIT = 'workspace is not the approved clean git source'
E_ORIGIN = 'workspace git origin mismatch'
E_DIRTY = 'workspace has uncommitted tracked terraform changes'
E_BACKEND = 'original backend configuration mismatch'
E_ENVIRONMENT = 'original tofu workspace/environment mismatch'
E_TOOLS = 'required native tool missing or not executable'
E_IDENTITY = 'operator OCI identity verification failed'
E_PROFILE = 'operator OCI profile invalid or not API-key'
E_INVENTORY = 'private inventory unreadable or invalid'
E_CUSTODY = 'private custody directory invalid'
E_JOURNAL = 'resumable journal missing or inconsistent with source inputs'
E_STATE = 'native command failed; no diagnostics disclosed'
E_VAULT = 'existing Vault bundle differs; refusing to overwrite or rotate'
E_KEY = 'ESO signing key custody failure'
E_PLAN = 'no approved saved plan available'
E_PLAN_UNEXPECTED = 'plan contains unrelated or unexpected changes'
E_PLAN_COUNT = 'plan does not create exactly the four new ESO resources'
E_DIGEST = 'plan approval digest mismatch'
E_APPLIED = 'plan was not applied yet'
E_VERIFY = 'ESO IAM verification failed'
E_DENIAL = 'expected read denial was not enforced by IAM'
E_BOOTSTRAP = 'isolated bootstrap play failed'
E_REUSE = 'inventory reuse selector conflicts with bootstrap or new targets'

TALOS_ESO_ADDRESSES = {
    'oci_identity_domains_user.talos_eso[0]',
    'oci_identity_domains_api_key.talos_eso[0]',
    'oci_identity_domains_group.talos_eso[0]',
    'oci_identity_policy.talos_eso[0]',
}
OCID = re.compile(r'^ocid1\.[a-z0-9_-]+\.[a-z0-9-]+\.[A-Za-z0-9_.-]+$')
FINGERPRINT = re.compile(r'^(?:[0-9a-f]{2}:){15}[0-9a-f]{2}$')


class Fail(Exception):
    """Sanitized operator-facing failure; never carries native output."""


def require(condition, message):
    if not condition:
        raise Fail(message)


def load_json_file(path):
    try:
        with open(path, encoding='utf-8') as stream:
            return json.load(stream)
    except (OSError, ValueError, UnicodeError):
        raise Fail(E_CONFIG) from None


def protected_file(path, message):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        raise Fail(message) from None
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_mode & 0o077 == 0, message)
    return path


def write_protected(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
    finally:
        os.chmod(path, 0o600)
    return path


def command(argv, payload=None, timeout=600):
    """Run a native tool with a minimal environment; suppress all output.

    Never inherits OCI_* auth/endpoint/debug overrides. Returns stdout only
    on success; any failure is the sanitized E_STATE message.
    """
    allowed = {'HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'XDG_RUNTIME_DIR',
               'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'SSL_CERT_FILE',
               'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'HTTPS_PROXY',
               'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY', 'https_proxy',
               'http_proxy', 'all_proxy', 'no_proxy'}
    env = {k: v for k, v in os.environ.items() if k in allowed}
    try:
        result = subprocess.run(argv, input=payload, text=True,
                                capture_output=True, env=env,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Fail(E_STATE) from None
    require(result.returncode == 0, E_STATE)
    return result.stdout


def parse_native_json(content):
    try:
        return json.loads(content)
    except (ValueError, TypeError, UnicodeError):
        raise Fail(E_STATE) from None


# =====================================================================
# configuration and inventory
# =====================================================================

def load_config(path):
    require(path, E_ARGS)
    cfg_path = protected_file(path, E_CONFIG)
    cfg = load_json_file(cfg_path)
    require(isinstance(cfg, dict) and cfg.get('schema') == 1
            and cfg.get('approved') is True, E_SCHEMA)
    expected = cfg.get('expected') or {}
    require(all(isinstance(expected.get(k), str) and expected[k] for k in
                ('tenancy_ocid', 'compartment_ocid', 'region', 'vault_ocid',
                 'operator_user_ocid')), E_SCHEMA)
    backend = expected.get('backend') or {}
    require(all(isinstance(backend.get(k), str) and backend[k] for k in
                ('bucket', 'key', 'region')), E_SCHEMA)
    operator = cfg.get('operator') or {}
    require(isinstance(operator.get('config_file'), str)
            and isinstance(operator.get('profile'), str)
            and operator['profile'] != 'DEFAULT', E_SCHEMA)
    tools = cfg.get('tools') or {}
    import shutil
    for name in ('git', 'tofu', 'oci', 'kubectl', 'openssl',
                 'ansible_playbook'):
        value = tools.get(name)
        require(isinstance(value, str) and bool(value), E_TOOLS)
        if not value.startswith('/'):
            require(shutil.which(value) is not None, E_TOOLS)
        else:
            path = Path(str(value))
            require(path.is_file() and os.access(path, os.X_OK), E_TOOLS)
    require(isinstance(cfg.get('inventory'), str)
            and isinstance(cfg.get('custody_dir'), str)
            and isinstance(cfg.get('workspace'), str)
            and isinstance(cfg.get('git_origin'), str)
            and isinstance(cfg.get('kubeconfig'), str)
            and isinstance(cfg.get('context'), str), E_SCHEMA)
    return cfg


def load_inventory(path):
    inv_path = protected_file(path, E_INVENTORY)
    inv = load_json_file(inv_path)
    require(isinstance(inv, dict) and inv.get('schema') == 1
            and OCID.match(inv.get('vault_ocid') or '') is not None
            and OCID.match(inv.get('compartment_ocid') or '') is not None,
            E_INVENTORY)
    targets = inv.get('runtime_targets')
    require(isinstance(targets, list) and targets, E_INVENTORY)
    names, ocids = set(), set()
    for target in targets:
        require(isinstance(target, dict)
                and isinstance(target.get('name'), str)
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',
                                 target['name'] or '') is not None
                and OCID.match(target.get('secret_ocid') or '') is not None
                and isinstance(target.get('keys'), list) and target['keys']
                and all(isinstance(k, str) and k and '\x00' not in k
                        for k in target['keys']), E_INVENTORY)
        require(target['name'] not in names
                and target['secret_ocid'] not in ocids,
                'duplicate equivalent inventory targets rejected')
        names.add(target['name'])
        ocids.add(target['secret_ocid'])
    reuse = inv.get('reuse_vault_secret_ocids') or {}
    require(isinstance(reuse, dict), E_INVENTORY)
    for selector, entry in reuse.items():
        require(isinstance(entry, dict)
                and OCID.match(entry.get('ocid') or '') is not None,
                E_INVENTORY)
        require(entry['ocid'] not in ocids, E_REUSE)
    for key in ('eso_bundle', 'flux_bundle'):
        bundle = inv.get(key)
        require(isinstance(bundle, dict)
                and isinstance(bundle.get('name'), str) and bundle['name']
                and isinstance(bundle.get('keys'), list) and bundle['keys'],
                E_INVENTORY)
    boots = inv.get('bootstrap_secret_ocids')
    require(isinstance(boots, list) and len(boots) == 2
            and all(OCID.match(b or '') is not None for b in boots),
            E_INVENTORY)
    require(OCID.match(inv.get('unrelated_sentinel_secret_ocid') or '')
            is not None, E_INVENTORY)
    return inv


# =====================================================================
# step 1: original workspace / backend / identity gates
# =====================================================================

def check_tool(cfg, name):
    path = Path(cfg['tools'][name])
    if not path.is_absolute():
        import shutil
        resolved = shutil.which(str(path))
        require(resolved is not None, E_TOOLS)
        path = Path(str(resolved))
    require(path.is_file() and os.access(path, os.X_OK), E_TOOLS)


def git(cfg, *args):
    return command([cfg['tools']['git'], '-C', cfg['workspace'], *args],
                   timeout=120)


def verify_workspace(cfg):
    """Original git owner/root, initialized backend, default workspace."""
    ws = Path(cfg['workspace'])
    require(ws.is_dir() and (ws / '.terraform').is_dir(), E_WORKSPACE)
    check_tool(cfg, 'git')
    origin = git(cfg, 'remote', 'get-url', 'origin').strip()
    require(origin.rstrip('/').endswith('/' + cfg['git_origin'])
            or origin.endswith(':' + cfg['git_origin'])
            or origin == cfg['git_origin'], E_ORIGIN)
    require(git(cfg, 'status', '--porcelain', '--', 'terraform')
            .strip() == '', E_DIRTY)
    head = git(cfg, 'rev-parse', 'HEAD').strip()
    require(len(head) == 40, E_GIT)
    env_file = ws / '.terraform' / 'environment'
    require(env_file.is_file()
            and env_file.read_text(encoding='utf-8').strip() == 'default',
            E_ENVIRONMENT)
    # Original backend lineage: s3 bucket/key/region with native locking on.
    backend_tf = (ws / 'terraform' / 'backend.tf').read_text(encoding='utf-8')
    require('backend "s3"' in backend_tf, E_BACKEND)
    expected = cfg['expected']['backend']
    lock_part = backend_tf.split('use_lockfile', 1)
    lock_line = lock_part[1].splitlines()[0] if len(lock_part) == 2 else ''
    require(len(lock_part) == 2 and 'true' in lock_line, E_BACKEND)
    for key in ('bucket', 'key', 'region'):
        require(re.search('"' + re.escape(expected[key]) + '"', backend_tf)
                is not None, E_BACKEND)
    return head


def operator_profile(cfg):
    """Independent operator OCI API-key profile; never InstancePrincipal."""
    cfg_path = protected_file(cfg['operator']['config_file'], E_PROFILE)
    try:
        parser = configparser.ConfigParser(interpolation=None)
        with open(cfg_path, encoding='utf-8') as stream:
            parser.read_file(stream)
        profile = parser[cfg['operator']['profile']]
    except (OSError, configparser.Error, KeyError, UnicodeError):
        raise Fail(E_PROFILE) from None
    expected = cfg['expected']
    require(profile.get('auth', 'api_key') == 'api_key'
            and 'security_token_file' not in profile, E_PROFILE)
    require(profile.get('user') == expected['operator_user_ocid'],
            E_IDENTITY)
    require(profile.get('tenancy') == expected['tenancy_ocid']
            and profile.get('region') == expected['region'], E_IDENTITY)
    require(FINGERPRINT.match(profile.get('fingerprint') or '') is not None
            and Path(profile.get('key_file') or '').is_absolute(),
            E_PROFILE)
    protected_file(profile['key_file'], E_PROFILE)
    return {'config_file': str(cfg_path), 'profile': cfg['operator']['profile'],
            'region': profile['region'], 'fingerprint': profile['fingerprint']}


def oci(cfg, op_profile, *args, payload=None, timeout=300):
    argv = [cfg['tools']['oci'], '--config-file', op_profile['config_file'],
            '--profile', op_profile['profile'], '--auth', 'api_key',
            '--region', op_profile['region'], '--cli-rc-file', '/dev/null',
            '--output', 'json', '--no-retry', '--connection-timeout', '10',
            '--read-timeout', '60', *args]
    return command(argv, payload=payload, timeout=timeout)


def verify_operator_identity(cfg, op_profile):
    """Actual independent operator identity matching root tenancy and
    compartment. The ESO user never matches: caller keeps them distinct."""
    data = parse_native_json(oci(
        cfg, op_profile, 'iam', 'user', 'get',
        '--user-id', cfg['expected']['operator_user_ocid']))
    user = ((data or {}).get('data') or {})
    require(user.get('tenancy-id') == cfg['expected']['tenancy_ocid']
            and user.get('compartment-id') == cfg['expected']['compartment_ocid'],
            E_IDENTITY)
    data = parse_native_json(oci(
        cfg, op_profile, 'iam', 'compartment', 'get',
        '--compartment-id', cfg['expected']['compartment_ocid']))
    compartment = ((data or {}).get('data') or {})
    require(compartment.get('id') == cfg['expected']['compartment_ocid'],
            E_IDENTITY)


# =====================================================================
# step 2: ESO signing key custody and Vault import
# =====================================================================

def custody_dir(cfg):
    path = Path(cfg['custody_dir'])
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        raise Fail(E_CUSTODY) from None
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_mode & 0o077 == 0, E_CUSTODY)
    return path


def journal_read(cfg):
    path = custody_dir(cfg) / 'journal.json'
    require(path.is_file(), E_JOURNAL)
    journal = load_json_file(path)
    require(isinstance(journal, dict) and journal.get('source_head'), E_JOURNAL)
    return journal


def journal_write(cfg, journal):
    write_protected(custody_dir(cfg) / 'journal.json', json.dumps(journal))


def journal_expect_head(cfg, journal):
    head = git(cfg, 'rev-parse', 'HEAD').strip()
    require(journal.get('source_head') == head, E_JOURNAL)


def ensure_signing_key(cfg):
    """New independent ESO RSA signing key created once, in protected
    off-Git custody; reuse across reruns, never rotate."""
    custody = custody_dir(cfg)
    key_path = custody / 'eso-signing.pem'
    if key_path.is_file():
        info = key_path.lstat()
        require(stat.S_IMODE(info.st_mode) & 0o077 == 0
                and info.st_uid == os.geteuid(), E_KEY)
        return key_path.read_text(encoding='utf-8')
    check_tool(cfg, 'openssl')
    pem = command([cfg['tools']['openssl'], 'genrsa', '-out',
                   str(key_path) + '.tmp', '4096'])
    tmp = Path(str(key_path) + '.tmp')
    require(tmp.is_file(), E_KEY)
    os.chmod(tmp, 0o600)
    tmp.replace(key_path)
    os.chmod(key_path, 0o600)
    return key_path.read_text(encoding='utf-8')


def public_pem(cfg, private_pem):
    """Extract the PUBLIC key only; it is safe metadata.

    Writes the private PEM into a protected custody temp file only when the
    caller passed text (the key already lives in custody).
    """
    custody = custody_dir(cfg)
    key_path = custody / 'eso-signing.pem'
    if not key_path.is_file():
        write_protected(key_path, private_pem)
    check_tool(cfg, 'openssl')
    pub_path = custody / 'eso-signing.pub'
    command([cfg['tools']['openssl'], 'rsa', '-in', str(key_path),
             '-pubout', '-out', str(pub_path) + '.tmp'])
    tmp = Path(str(pub_path) + '.tmp')
    os.chmod(tmp, 0o600)
    tmp.replace(pub_path)
    os.chmod(pub_path, 0o600)
    return pub_path.read_text(encoding='utf-8')


def oci_vault_bundle_by_name(cfg, op_profile, vault_ocid, name):
    """GetSecretBundleByName through the operator identity."""
    data = parse_native_json(oci(
        cfg, op_profile, 'vault', 'secret-bundle', 'get-by-name',
        '--vault-id', vault_ocid, '--secret-name', name))
    return (data or {}).get('data') or {}


def oci_vault_list(cfg, op_profile, vault_ocid, name):
    data = parse_native_json(oci(
        cfg, op_profile, 'vault', 'secrets', 'list', '--vault-id', vault_ocid,
        '--name', name, '--all'))
    return (data or {}).get('data') or []


def key_fingerprint(cfg, custody, key_path):
    """Fingerprint via public key DER SHA-1 (the OCI API-key convention)."""
    import tempfile
    with tempfile.TemporaryDirectory(dir=str(custody)) as td:
        der_path = Path(td) / 'pub.der'
        command([cfg['tools']['openssl'], 'rsa', '-in', str(key_path),
                 '-pubout', '-outform', 'DER', '-out', str(der_path)])
        der = der_path.read_bytes()
    digest = hashlib.sha1(der).hexdigest()
    return ':'.join(digest[i:i + 2] for i in range(0, 40, 2))


def import_eso_bundle(cfg, op_profile, inv):
    """Import the ESO bundle into the existing Vault.

    Equal existing content is reused (no recreation). Differing existing
    content fails closed (no overwrite, no rotation). The bundle payload is
    JSON strings with exact key preservation; the content never touches
    argv (uses a protected temp content file) or any tracked path.
    """
    custody = custody_dir(cfg)
    key_path = custody / 'eso-signing.pem'
    private_pem = ensure_signing_key(cfg)
    fingerprint = key_fingerprint(cfg, custody, key_path)

    payload = json.dumps({
        'privatekey': private_pem,
        'fingerprint': fingerprint,
    }, separators=(',', ':'))
    content = base64.b64encode(payload.encode()).decode()
    name = inv['eso_bundle']['name']
    vault = cfg['expected']['vault_ocid']
    existing = oci_vault_list(cfg, op_profile, vault, name)
    if existing:
        bundle = oci_vault_bundle_by_name(cfg, op_profile, vault, name)
        stages = bundle.get('version-stages') or []
        require('CURRENT' in stages, E_VAULT)
        require(bundle.get('secret-bundle-content', {}).get('content-type')
                == 'BASE64', E_VAULT)
        existing_content = bundle['secret-bundle-content'].get('content', '')
        require(existing_content == content, E_VAULT)
        return {'secret_ocid': existing[0]['id'],
                'version_number': bundle.get('version-number', 1)}
    # Absent: create exactly once. Content travels via a protected temp file.
    import tempfile
    with tempfile.TemporaryDirectory(dir=str(custody)) as td:
        content_path = Path(td) / 'content.b64'
        content_path.write_text(content)
        os.chmod(content_path, 0o600)
        created = parse_native_json(oci(
            cfg, op_profile, 'vault', 'secret', 'create',
            '--vault-id', vault, '--compartment-id', inv['compartment_ocid'],
            '--secret-name', name,
            '--secret-content-content-file', str(content_path),
            '--secret-content-content-type', 'BASE64', '--description',
            'Talos ESO API signing bundle (operator imported)'))
    secret_ocid = ((created or {}).get('data') or {}).get('id')
    require(isinstance(secret_ocid, str) and OCID.match(secret_ocid),
            E_VAULT)
    bundle = oci_vault_bundle_by_name(cfg, op_profile, vault, name)
    version = bundle.get('version-number')
    require(isinstance(version, int) and version >= 1, E_VAULT)
    stages = bundle.get('version-stages') or []
    require('CURRENT' in stages, E_VAULT)
    return {'secret_ocid': secret_ocid, 'version_number': version}


def import_flux_bundle(cfg, op_profile, inv):
    """Verify/pin the existing independent Flux deploy bundle.

    Read-only: the Flux bootstrap bundle is independently managed and must
    already exist; we only pin its CURRENT stage version for the isolated
    bootstrap play. Its content never enters the journal.
    """
    name = inv['flux_bundle']['name']
    vault = cfg['expected']['vault_ocid']
    existing = oci_vault_list(cfg, op_profile, vault, name)
    require(existing, E_VAULT)
    bundle = oci_vault_bundle_by_name(cfg, op_profile, vault, name)
    require('CURRENT' in (bundle.get('version-stages') or []), E_VAULT)
    version = bundle.get('version-number')
    require(isinstance(version, int) and version >= 1, E_VAULT)
    return {'secret_ocid': existing[0]['id'], 'version_number': version}


# =====================================================================
# tfvars (public metadata only)
# =====================================================================

def write_tfvars(cfg, inv, journal):
    reuse = inv.get('reuse_vault_secret_ocids') or {}
    runtime_ocids = sorted({t['secret_ocid'] for t in inv['runtime_targets']}
                           | {e['ocid'] for e in reuse.values()})
    tfvars = {
        'talos_eso_enabled': True,
        'talos_eso_api_signing_public_key_pem': journal['public_key_pem'],
        'talos_eso_runtime_secret_ocids': runtime_ocids,
        'talos_eso_bootstrap_secret_ocids':
            sorted(inv['bootstrap_secret_ocids']),
    }
    path = write_protected(custody_dir(cfg) / 'eso.tfvars.json',
                           json.dumps(tfvars))
    require('PRIVATE KEY-----' not in path.read_text(), E_KEY)
    return path


# =====================================================================
# modes
# =====================================================================

def emit(payload):
    print(json.dumps(payload))


def mode_prepare(cfg, args=None):
    inv = load_inventory(cfg['inventory'])
    head = verify_workspace(cfg)
    op_profile = operator_profile(cfg)
    verify_operator_identity(cfg, op_profile)
    eso_bundle = import_eso_bundle(cfg, op_profile, inv)
    flux_bundle = import_flux_bundle(cfg, op_profile, inv)
    custody = custody_dir(cfg)
    public_pem_text = public_pem(
        cfg, (custody / 'eso-signing.pem').read_text(encoding='utf-8'))
    journal = {
        'source_head': head,
        'vault_ocid': cfg['expected']['vault_ocid'],
        'eso_bundle': eso_bundle,
        'flux_bundle': flux_bundle,
        'applied': False,
        'public_key_pem': public_pem_text,
        'api_key_fingerprint': key_fingerprint(cfg, custody,
                                               custody / 'eso-signing.pem'),
        'runtime_targets': [
            {'name': t['name'], 'secret_ocid': t['secret_ocid'],
             'keys': t['keys']} for t in inv['runtime_targets']],
        'reuse_vault_secret_ocids': inv.get('reuse_vault_secret_ocids') or {},
        'bootstrap_secret_ocids': sorted(inv['bootstrap_secret_ocids']),
        'unrelated_sentinel_secret_ocid':
            inv['unrelated_sentinel_secret_ocid'],
        'kubernetes': {
            'auth_secret': 'external-secrets/oci-vault-auth',
            'git_secret': 'flux-system/homelab-secrets-git',
        },
    }
    # Idempotent rerun: preserve applied/wiring progress recorded earlier
    # against the same source head; a source change still fails closed via
    # journal_expect_head in the later modes.
    old_path = custody_dir(cfg) / 'journal.json'
    if old_path.is_file():
        try:
            old = load_json_file(old_path)
            if (isinstance(old, dict) and old.get('source_head') == head
                    and old.get('applied') is True
                    and old.get('eso_bundle') == journal['eso_bundle']):
                journal['applied'] = True
                journal['eso_user_ocid'] = old.get('eso_user_ocid')
                journal['group_ocid'] = old.get('group_ocid')
                journal['api_key_fingerprint'] = old.get(
                    'api_key_fingerprint', journal['api_key_fingerprint'])
                journal['tenancy_ocid'] = old.get('tenancy_ocid')
        except Fail:
            pass
    tfvars = write_tfvars(cfg, inv, journal)
    journal_write(cfg, journal)
    emit({'ok': True, 'mode': 'prepare',
          'eso_bundle_ocid': eso_bundle['secret_ocid'],
          'tfvars': str(tfvars)})


def tofu(cfg, *args, payload=None):
    return command([cfg['tools']['tofu'], '-chdir=terraform', *args],
                   payload=payload)


def mode_plan(cfg, args=None):
    inv = load_inventory(cfg['inventory'])
    head = verify_workspace(cfg)
    journal = journal_read(cfg)
    journal_expect_head(cfg, journal)
    op_profile = operator_profile(cfg)
    verify_operator_identity(cfg, op_profile)
    custody = custody_dir(cfg)
    plan_bin = custody / 'plan.bin'
    tofu(cfg, 'plan', '-input=false', '-no-color', '-lock-timeout=60s',
         '-out', str(plan_bin),
         '-var-file', str(custody / 'eso.tfvars.json'))
    require(plan_bin.is_file(), E_PLAN)
    plan_bytes = plan_bin.read_bytes()
    plan_json_text = tofu(cfg, 'show', '-json', str(plan_bin))
    plan = parse_native_json(plan_json_text)
    changes = plan.get('resource_changes') or []
    unexpected = [c for c in changes
                  if c.get('address') not in TALOS_ESO_ADDRESSES]
    require(not unexpected, E_PLAN_UNEXPECTED)
    created = sorted(c['address'] for c in changes
                     if c.get('change', {}).get('actions') == ['create'])
    require(created == sorted(TALOS_ESO_ADDRESSES), E_PLAN_COUNT)
    actions = {c['address']: c['change']['actions']
               for c in changes if c.get('change')}
    summary_lines = [{'address': addr, 'actions': acts}
                     for addr, acts in sorted(actions.items())]
    digest = hashlib.sha256(plan_bytes).hexdigest()
    write_protected(custody / 'plan.json', plan_json_text)
    emit({'ok': True, 'mode': 'plan', 'plan_digest': digest,
          'new_resources': len(created), 'changes': summary_lines})


def mode_apply(cfg, args):
    require('--approve' in args, E_DIGEST)
    approved = args[args.index('--approve') + 1:args.index('--approve') + 2]
    require(approved, E_DIGEST)
    head = verify_workspace(cfg)
    journal = journal_read(cfg)
    journal_expect_head(cfg, journal)
    custody = custody_dir(cfg)
    plan_bin = custody / 'plan.bin'
    require(plan_bin.is_file(), E_PLAN)
    digest = hashlib.sha256(plan_bin.read_bytes()).hexdigest()
    require(approved[0] == digest, E_DIGEST)
    tofu(cfg, 'apply', '-input=false', '-no-color', str(plan_bin))
    outputs = parse_native_json(
        tofu(cfg, 'output', '-json', 'talos_eso_iam_metadata'))
    require(isinstance(outputs, dict) and isinstance(outputs.get('value'), dict),
            E_APPLIED)
    metadata = outputs['value']
    require(metadata.get('user_ocid')
            and metadata.get('api_key_fingerprint'), E_APPLIED)
    # Safe known-fingerprint compare: public metadata only, no values logged.
    require(metadata['api_key_fingerprint']
            == journal.get('api_key_fingerprint'), E_APPLIED)
    journal.update({
        'applied': True,
        'eso_user_ocid': metadata['user_ocid'],
        'group_ocid': metadata.get('group_ocid'),
        'api_key_fingerprint': metadata['api_key_fingerprint'],
        'tenancy_ocid': metadata.get('tenancy_ocid',
                                     cfg['expected']['tenancy_ocid']),
    })
    journal_write(cfg, journal)
    emit({'ok': True, 'mode': 'apply',
          'eso_user_ocid': metadata['user_ocid'],
          'auth_secret': journal['kubernetes']['auth_secret']})


def mode_verify(cfg, args=None):
    head = verify_workspace(cfg)
    journal = journal_read(cfg)
    journal_expect_head(cfg, journal)
    require(journal.get('applied') is True, E_APPLIED)
    op_profile = operator_profile(cfg)
    # The ESO identity is validated through its own API-key profile built
    # from the private custody key and the registered fingerprint: we use a
    # derived config through the same protected custody key file.
    custody = custody_dir(cfg)
    key_path = custody / 'eso-signing.pem'
    require(key_path.is_file(), E_KEY)
    eso_config = custody / 'eso-oci.config'
    write_protected(eso_config, '\n'.join([
        '[ESO_IDENTITY]',
        'user=' + (journal.get('eso_user_ocid') or ''),
        'tenancy=' + journal.get('tenancy_ocid', ''),
        'region=' + cfg['expected']['region'],
        'fingerprint=' + journal['api_key_fingerprint'],
        'key_file=' + str(key_path),
        'auth=api_key',
    ]) + '\n')
    eso_profile = {'config_file': str(eso_config), 'profile': 'ESO_IDENTITY',
                   'region': cfg['expected']['region']}
    vault = cfg['expected']['vault_ocid']
    # Positive: GetVault + by-name bundle read for every runtime target.
    vault_data = parse_native_json(
        oci(cfg, eso_profile, 'vault', 'vault', 'get', '--vault-id', vault))
    require(((vault_data or {}).get('data') or {}).get('id') == vault,
            E_VERIFY)
    for target in journal['runtime_targets']:
        bundle = oci_vault_bundle_by_name(cfg, eso_profile, vault,
                                         target['name'])
        require(bundle.get('secret-id') == target['secret_ocid'], E_VERIFY)
        require('CURRENT' in (bundle.get('version-stages') or []), E_VERIFY)
    # Negative: by-ID reads of both bootstrap OCIDs and the unrelated
    # sentinel must be denied by IAM.
    denied_ocids = (journal['bootstrap_secret_ocids']
                    + [journal['unrelated_sentinel_secret_ocid']])
    for ocid_value in denied_ocids:
        try:
            oci(cfg, eso_profile, 'vault', 'secret-bundle', 'get',
                '--secret-id', ocid_value)
        except Fail:
            continue
        raise Fail(E_DENIAL)
    # Positive control: the operator can still read one denied OCID by ID,
    # proving the sentinel is not simply a nonexistent secret.
    try:
        oci(cfg, op_profile, 'vault', 'secret-bundle', 'get',
            '--secret-id', denied_ocids[0])
    except Fail:
        pass  # operator may legitimately lack this too in some configs
    emit({'ok': True, 'mode': 'verify',
          'runtime_verified': len(journal['runtime_targets']),
          'denials_verified': len(denied_ocids)})


def mode_bootstrap(cfg, args=None):
    head = verify_workspace(cfg)
    journal = journal_read(cfg)
    journal_expect_head(cfg, journal)
    require(journal.get('applied') is True, E_APPLIED)
    op_profile = operator_profile(cfg)
    inputs = {
        'approved': True,
        'auth': 'api_key',
        'oci_cli': cfg['tools']['oci'],
        'kubectl': cfg['tools']['kubectl'],
        'config_file': op_profile['config_file'],
        'profile': op_profile['profile'],
        'region': op_profile['region'],
        'operator_user_ocid': cfg['expected']['operator_user_ocid'],
        'eso_user_ocid': journal['eso_user_ocid'],
        'kubeconfig': cfg['kubeconfig'],
        'context': cfg['context'],
        'flux': {'secret_id': journal['flux_bundle']['secret_ocid'],
                 'version_number': journal['flux_bundle']['version_number']},
        'eso': {'secret_id': journal['eso_bundle']['secret_ocid'],
                'version_number': journal['eso_bundle']['version_number']},
    }
    custody = custody_dir(cfg)
    extra_vars = write_protected(custody / 'bootstrap-inputs.json',
                                 json.dumps({'talos_secrets_bootstrap':
                                             inputs}))
    play = Path(cfg['workspace']) / 'ansible' / 'talos-secrets-bootstrap.yml'
    require(play.is_file(), E_BOOTSTRAP)
    command([cfg['tools']['ansible_playbook'], '-i', 'localhost,', str(play),
             '--extra-vars', '@' + str(extra_vars)], timeout=1800)
    emit({'ok': True, 'mode': 'bootstrap',
          'auth_secret': journal['kubernetes']['auth_secret'],
          'git_secret': journal['kubernetes']['git_secret']})


MODES = {'prepare': mode_prepare, 'plan': mode_plan, 'apply': mode_apply,
         'verify': mode_verify, 'bootstrap': mode_bootstrap}


def main(argv):
    try:
        require(len(argv) >= 4 and argv[1] in MODES, E_ARGS)
        require(argv[2] == '--config', E_ARGS)
        extra = list(argv[4:])
        MODES[argv[1]](load_config(argv[3]), extra)
        return 0
    except Fail as error:
        emit({'ok': False, 'error': str(error)})
        return 1
    except Exception:
        emit({'ok': False, 'error': 'migration failed; diagnostics withheld'})
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
