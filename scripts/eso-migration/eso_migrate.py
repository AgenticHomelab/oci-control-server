#!/usr/bin/env python3
"""Operator-run ESO migration driver for issue #15.

Modes, in operator order:

  inventory  Enumerate migration targets automatically from the live
             cluster, read-only, via kubectl and the configured
             kubeconfig/context: every flux-system Kustomization with
             .spec.decryption contributes the Secrets in its current
             status inventory, plus the explicit flux-system/
             homelab-secrets-git bootstrap target. Emits a DRAFT
             schema-2 inventory.json into private custody (mode 0600)
             for operator review: runtime targets (k8s selectors, key
             sets, derived vault names), advisory byte-duplicate
             groups, and reuse entries derived from the
             k0ti.com/oci-vault-secret annotation plus operator
             reuse_hints. Prints a sanitized summary only.
  prepare    Verify the original git workspace, S3 backend lineage
             (use_lockfile=true, default workspace), and the independent
             operator OCI API-key identity (matching root tenancy and
             compartment, never InstancePrincipal and never the ESO user).
             Mint the new ESO RSA signing key once into private custody
             (outside Git, mode 0600), import the current K8s runtime
             Secrets and the Flux deploy-key bundle into the existing
             Vault (create-once, reuse-equal, never overwrite differing
             content), resolve and verify reuse entries against the K8s
             bytes of their targets, and write public-metadata-only
             tfvars plus a resumable private journal.
  plan       Full locked `tofu plan` (refresh on, no -target, no
             -refresh=false, no -lock=false), inspect the saved plan JSON
             for exactly the four new talos_eso resources with no unrelated
             changes, and print a sanitized address/action summary plus a
             plan digest.
  apply      Apply the exact saved plan only after explicit
             `--approve <plan digest>`; record wiring metadata in the
             journal for later modes.
  verify     Positive/negative IAM validation as the new ESO identity:
             by-name bundle reads for every runtime target and every
             reuse entry (by resolved name; exact secret-id and CURRENT
             stage), plus GetVault success, plus read denials on the two
             discovered bootstrap bundle OCIDs and the unrelated
             sentinel. Denials count only when the OCI CLI error parses
             as a real authorization failure code
             (NotAuthorizedOrNotFound/NotAuthenticated); any other API
             failure fails the mode distinctly. Read-only.
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
E_KUBE = 'Kubernetes secret rejected (keys, type or encoding mismatch); no values disclosed'
E_VAULT = 'existing Vault bundle differs; refusing to overwrite or rotate'
E_KEY = 'ESO signing key custody failure'
E_PLAN = 'no approved saved plan available'
E_PLAN_UNEXPECTED = 'plan contains unrelated or unexpected changes'
E_PLAN_COUNT = 'plan does not create exactly the four new ESO resources'
E_DIGEST = 'plan approval digest mismatch'
E_APPLIED = 'plan was not applied yet'
E_VERIFY = 'ESO IAM verification failed'
E_VERIFY_API = ('verification API call failed with a non-authorization '
                'error; no diagnostics disclosed')
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
VAULTSECRET = 'ocid1.vaultsecret.'
FINGERPRINT = re.compile(r'^(?:[0-9a-f]{2}:){15}[0-9a-f]{2}$')
KUBE_SELECTOR = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*/'
                           r'[A-Za-z0-9][A-Za-z0-9_.-]*$')
VAULT_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')
REUSE_ANNOTATION = 'k0ti.com/oci-vault-secret'
FLUX_K8S_SECRET = ('flux-system', 'homelab-secrets-git')
FLUX_ALLOWED_KEYS = {'identity', 'known_hosts', 'identity.pub'}
CONTENT_SHAPES = ('json_map', 'raw')
DENIAL_CODES = {'NotAuthorizedOrNotFound', 'NotAuthenticated'}
DEFAULT_ESO_BUNDLE = {'name': 'talos-eso-signing-bundle',
                     'keys': ['privatekey', 'fingerprint']}
DEFAULT_FLUX_BUNDLE = {'name': 'talos-flux-deploy',
                       'keys': ['identity', 'known_hosts']}


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


def _child_env():
    allowed = {'HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'XDG_RUNTIME_DIR',
               'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'SSL_CERT_FILE',
               'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'HTTPS_PROXY',
               'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY', 'https_proxy',
               'http_proxy', 'all_proxy', 'no_proxy'}
    return {k: v for k, v in os.environ.items() if k in allowed}


def command(argv, payload=None, timeout=600):
    """Run a native tool with a minimal environment; suppress all output.

    Never inherits OCI_* auth/endpoint/debug overrides. Returns stdout only
    on success; any failure is the sanitized E_STATE message.
    """
    try:
        result = subprocess.run(argv, input=payload, text=True,
                                capture_output=True, env=_child_env(),
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Fail(E_STATE) from None
    require(result.returncode == 0, E_STATE)
    return result.stdout


def command_raw(argv, payload=None, timeout=600):
    """Raw-result variant of command(): (rc, stdout, stderr), never fails.

    Used only where the caller must classify the failure itself (verify
    denial classification). Output is still captured, never printed.
    """
    try:
        result = subprocess.run(argv, input=payload, text=True,
                                capture_output=True, env=_child_env(),
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return (None, '', '')
    return (result.returncode, result.stdout, result.stderr)


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
                 'vault_key_ocid', 'operator_user_ocid')), E_SCHEMA)
    backend = expected.get('backend') or {}
    require(isinstance(backend, dict), E_SCHEMA)
    operator = cfg.get('operator') or {}
    require(isinstance(operator.get('config_file'), str)
            and isinstance(operator.get('profile'), str)
            and operator['profile'], E_SCHEMA)
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
    # Optional keys, validated fail-closed when present.
    hints = cfg.get('reuse_hints')
    if hints is not None:
        require(isinstance(hints, dict), E_SCHEMA)
        for selector, hint in hints.items():
            require(isinstance(selector, str)
                    and KUBE_SELECTOR.match(selector) is not None
                    and isinstance(hint, dict)
                    and OCID.match(str(hint.get('ocid') or '')) is not None,
                    E_SCHEMA)
    if cfg.get('unrelated_sentinel_secret_ocid') is not None:
        require(OCID.match(cfg['unrelated_sentinel_secret_ocid'])
                is not None, E_SCHEMA)
    flux_cfg = cfg.get('flux_bundle')
    if flux_cfg is not None:
        require(isinstance(flux_cfg, dict)
                and isinstance(flux_cfg.get('name'), str)
                and flux_cfg['name'], E_SCHEMA)
    extras = cfg.get('bootstrap_extra_secret_ocids')
    if extras is not None:
        require(isinstance(extras, list)
                and all(OCID.match(str(b) or '') is not None
                        for b in extras), E_SCHEMA)
    return cfg


def _normalize_reuse_legacy(inv):
    entries = []
    for selector, entry in (inv.get('reuse_vault_secret_ocids')
                            or {}).items():
        require(isinstance(entry, dict)
                and OCID.match(str(entry.get('ocid') or '')) is not None,
                E_INVENTORY)
        targets = entry.get('targets') or []
        require(isinstance(targets, list)
                and all(isinstance(t, str) and t for t in targets),
                E_INVENTORY)
        entries.append({'ocid': entry['ocid'], 'targets': list(targets),
                        'content_shape': 'raw', 'name': None,
                        'verified': False})
    return entries


def load_inventory(path, cfg=None):
    inv_path = protected_file(path, E_INVENTORY)
    inv = load_json_file(inv_path)
    require(isinstance(inv, dict)
            and inv.get('schema') in (1, 2)
            and OCID.match(inv.get('vault_ocid') or '') is not None
            and OCID.match(inv.get('compartment_ocid') or '') is not None,
            E_INVENTORY)
    schema = inv.get('schema')
    targets = inv.get('runtime_targets')
    require(isinstance(targets, list) and targets, E_INVENTORY)
    normalized, names, ocids = [], set(), set()
    for target in targets:
        require(isinstance(target, dict)
                and isinstance(target.get('name'), str)
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',
                                 target['name'] or '') is not None
                and isinstance(target.get('keys'), list) and target['keys']
                and all(isinstance(k, str) and k and '\x00' not in k
                        for k in target['keys']), E_INVENTORY)
        secret_ocid = target.get('secret_ocid')
        k8s = target.get('k8s')
        if secret_ocid is not None:
            require(OCID.match(str(secret_ocid)) is not None, E_INVENTORY)
            require(secret_ocid not in ocids,
                    'duplicate equivalent inventory targets rejected')
            ocids.add(secret_ocid)
        else:
            require(schema == 2 and isinstance(k8s, dict)
                    and isinstance(k8s.get('namespace'), str)
                    and k8s['namespace']
                    and isinstance(k8s.get('name'), str) and k8s['name'],
                    E_INVENTORY)
        require(target['name'] not in names, E_INVENTORY)
        names.add(target['name'])
        normalized.append({'name': target['name'], 'keys': target['keys'],
                           'secret_ocid': secret_ocid,
                           'k8s': k8s if isinstance(k8s, dict) else None,
                           'type': target.get('type') or 'Opaque'})
    # Reuse entries: schema 2 explicit list; schema 1 legacy mapping.
    reuse = []
    if schema == 2:
        raw_entries = inv.get('reuse_entries') or []
        require(isinstance(raw_entries, list), E_INVENTORY)
        reuse_ocids = set()
        for entry in raw_entries:
            require(isinstance(entry, dict)
                    and OCID.match(str(entry.get('ocid') or '')) is not None
                    and isinstance(entry.get('targets'), list)
                    and entry['targets']
                    and all(isinstance(t, str)
                            and KUBE_SELECTOR.match(t) is not None
                            for t in entry['targets'])
                    and entry.get('content_shape', 'raw') in CONTENT_SHAPES,
                    E_INVENTORY)
            require(entry['ocid'] not in ocids, E_REUSE)
            require(entry['ocid'] not in reuse_ocids, E_INVENTORY)
            reuse_ocids.add(entry['ocid'])
            reuse.append({'ocid': entry['ocid'],
                          'targets': sorted(entry['targets']),
                          'content_shape': entry.get('content_shape', 'raw'),
                          'name': entry.get('name'), 'verified': True})
    else:
        reuse = _normalize_reuse_legacy(inv)
        for entry in reuse:
            require(entry['ocid'] not in ocids, E_REUSE)
    for key, default in (('eso_bundle', DEFAULT_ESO_BUNDLE),
                         ('flux_bundle', DEFAULT_FLUX_BUNDLE)):
        bundle = inv.get(key)
        if bundle is None:
            require(schema == 2, E_INVENTORY)
            bundle = default
        require(isinstance(bundle, dict)
                and isinstance(bundle.get('name'), str) and bundle['name']
                and isinstance(bundle.get('keys'), list) and bundle['keys'],
                E_INVENTORY)
        inv[key] = bundle
    boots = inv.get('bootstrap_secret_ocids')
    if schema == 1:
        require(isinstance(boots, list) and len(boots) == 2
                and all(OCID.match(b or '') is not None for b in boots),
                E_INVENTORY)
    else:
        require(boots is None or (isinstance(boots, list) and all(
            OCID.match(str(b) or '') is not None for b in boots)),
            E_INVENTORY)
    sentinel = inv.get('unrelated_sentinel_secret_ocid')
    if not sentinel and isinstance(cfg, dict):
        sentinel = cfg.get('unrelated_sentinel_secret_ocid')
    require(OCID.match(str(sentinel or '')) is not None, E_INVENTORY)
    groups = inv.get('duplicate_groups') or []
    require(isinstance(groups, list)
            and all(isinstance(g, list) and g for g in groups), E_INVENTORY)
    inv.update({'runtime_targets': normalized, 'reuse_entries': reuse,
                'unrelated_sentinel_secret_ocid': sentinel,
                'bootstrap_secret_ocids': boots})
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


def kubectl(cfg, *args):
    argv = [cfg['tools']['kubectl'], '--kubeconfig', cfg['kubeconfig'],
            '--context', cfg['context'], *args]
    return command(argv, timeout=120)


def verify_workspace(cfg):
    """Original git owner/root, initialized backend, default workspace.

    Real environment evidence: the initialized OpenTofu data directory is
    terraform/.terraform (TF_DATA_DIR unset); backend.tf holds only the s3
    backend type and use_lockfile — the actual selectors live in the
    existing local backend configuration from init, which is never changed
    here. The active workspace is checked with the native
    `tofu workspace show`.
    """
    ws = Path(cfg['workspace'])
    data_dir = ws / 'terraform' / '.terraform'
    require(ws.is_dir() and data_dir.is_dir(), E_WORKSPACE)
    check_tool(cfg, 'git')
    origin = git(cfg, 'remote', 'get-url', 'origin').strip()
    require(origin.rstrip('/').endswith('/' + cfg['git_origin'])
            or origin.endswith(':' + cfg['git_origin'])
            or origin == cfg['git_origin'], E_ORIGIN)
    require(git(cfg, 'status', '--porcelain', '--', 'terraform')
            .strip() == '', E_DIRTY)
    head = git(cfg, 'rev-parse', 'HEAD').strip()
    require(len(head) == 40, E_GIT)
    # Backend lineage without touching init or state: the block must
    # still select the s3 backend with native locking on. The bucket/key/
    # region selectors are deliberately NOT read from backend.tf — they
    # live in the existing initialized backend configuration.
    backend_tf = (ws / 'terraform' / 'backend.tf').read_text(encoding='utf-8')
    require('backend "s3"' in backend_tf, E_BACKEND)
    lock_part = backend_tf.split('use_lockfile', 1)
    lock_line = lock_part[1].splitlines()[0] if len(lock_part) == 2 else ''
    require(len(lock_part) == 2 and 'true' in lock_line, E_BACKEND)
    # Native workspace check against the initialized data directory.
    workspace = tofu(cfg, 'workspace', 'show').strip()
    require(workspace == 'default', E_ENVIRONMENT)
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


def oci_raw(cfg, op_profile, *args, timeout=300):
    """Raw-result oci call for denial classification; never prints."""
    argv = [cfg['tools']['oci'], '--config-file', op_profile['config_file'],
            '--profile', op_profile['profile'], '--auth', 'api_key',
            '--region', op_profile['region'], '--cli-rc-file', '/dev/null',
            '--output', 'json', '--no-retry', '--connection-timeout', '10',
            '--read-timeout', '60', *args]
    return command_raw(argv, timeout=timeout)


def _denial_payload_code(stderr):
    """The parsed error code string from the CLI stderr, or None."""
    try:
        payload = json.loads(stderr or '')
    except (ValueError, TypeError, UnicodeError):
        return None
    if not isinstance(payload, dict):
        return None
    code = payload.get('code')
    if not isinstance(code, str):
        nested = payload.get('error')
        code = nested.get('code') if isinstance(nested, dict) else None
    return code if isinstance(code, str) else None


def denial_code(stderr):
    """The exact authorization failure code, or None when not a denial."""
    code = _denial_payload_code(stderr)
    return code if isinstance(code, str) and code in DENIAL_CODES else None


def authorization_denial(stderr):
    """True only for a real OCI authorization failure code.

    Parses the CLI error payload structure (never prints it). Network
    errors, 5xx bodies and malformed output are NOT denials.
    """
    return denial_code(stderr) is not None


def verify_operator_identity(cfg, op_profile):
    """Actual independent operator identity matching root tenancy and
    compartment. The ESO user never matches: caller keeps them distinct."""
    data = parse_native_json(oci(
        cfg, op_profile, 'iam', 'user', 'get',
        '--user-id', cfg['expected']['operator_user_ocid']))
    user = ((data or {}).get('data') or {})
    expected = cfg['expected']
    # OCI IAM User.compartment-id is the root tenancy, not the Vault's
    # resource compartment. The User model has no tenancy-id field.
    require(user.get('id') == expected['operator_user_ocid']
            and user.get('compartment-id') == expected['tenancy_ocid'],
            E_IDENTITY)
    compartment_id = expected['compartment_ocid']
    if compartment_id == expected['tenancy_ocid']:
        data = parse_native_json(oci(
            cfg, op_profile, 'iam', 'tenancy', 'get',
            '--tenancy-id', compartment_id))
    else:
        data = parse_native_json(oci(
            cfg, op_profile, 'iam', 'compartment', 'get',
            '--compartment-id', compartment_id))
    compartment = ((data or {}).get('data') or {})
    require(compartment.get('id') == compartment_id, E_IDENTITY)


# =====================================================================
# step 2: custody, K8s reads, and Vault import
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
    """GetSecretBundleByName through the given identity."""
    data = parse_native_json(oci(
        cfg, op_profile, 'secrets', 'secret-bundle',
        'get-secret-bundle-by-name',
        '--vault-id', vault_ocid, '--secret-name', name))
    return (data or {}).get('data') or {}


def oci_vault_list(cfg, op_profile, vault_ocid, compartment_ocid, name):
    data = parse_native_json(oci(
        cfg, op_profile, 'vault', 'secret', 'list',
        '--vault-id', vault_ocid, '--compartment-id', compartment_ocid,
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


# -- Kubernetes reads -------------------------------------------------

def kube_secret_raw(cfg, namespace, name):
    """Read one K8s Secret -o json into memory (read-only)."""
    data = parse_native_json(kubectl(cfg, 'get', 'secret', name,
                                     '-n', namespace, '-o', 'json'))
    require(isinstance(data, dict)
            and isinstance(data.get('data'), dict)
            and isinstance(data.get('metadata'), dict), E_KUBE)
    return data


def kube_secret_bytes(secret):
    """Raw data bytes dict; fail sanitized on invalid base64."""
    out = {}
    for key, value in (secret.get('data') or {}).items():
        try:
            out[key] = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise Fail(E_KUBE) from None
    return out


def kube_secret_text(secret):
    """Decoded UTF-8 data values; non-UTF-8 is rejected sanitized."""
    out = {}
    for key, value in (secret.get('data') or {}).items():
        try:
            out[key] = base64.b64decode(value, validate=True).decode('utf-8')
        except (ValueError, TypeError, UnicodeError):
            raise Fail(E_KUBE) from None
    return out


def kube_secret_live(secret):
    require(not (secret.get('metadata') or {}).get('deletionTimestamp'),
            E_KUBE)


def json_map_payload(values):
    """Deterministic compact JSON map payload for vault content."""
    return json.dumps({k: values[k] for k in sorted(values)},
                      separators=(',', ':'))


def vault_create_or_reuse_equal(cfg, op_profile, inv, name, payload_text,
                                description):
    """Create-once / reuse-equal vault secret import.

    Equal existing content is reused (no recreation). Differing existing
    content fails closed (no overwrite, no rotation). Content travels via
    a protected temp file, never argv or tracked paths.
    """
    custody = custody_dir(cfg)
    vault = cfg['expected']['vault_ocid']
    content = base64.b64encode(payload_text.encode()).decode()
    existing = oci_vault_list(cfg, op_profile, vault,
                              inv['compartment_ocid'], name)
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
            cfg, op_profile, 'vault', 'secret', 'create-base64',
            '--vault-id', vault, '--compartment-id', inv['compartment_ocid'],
            '--key-id', cfg['expected']['vault_key_ocid'],
            '--secret-name', name,
            '--secret-content-content-file', str(content_path),
            '--description', description))
    secret_ocid = ((created or {}).get('data') or {}).get('id')
    require(isinstance(secret_ocid, str) and OCID.match(secret_ocid),
            E_VAULT)
    bundle = oci_vault_bundle_by_name(cfg, op_profile, vault, name)
    version = bundle.get('version-number')
    require(isinstance(version, int) and version >= 1, E_VAULT)
    require('CURRENT' in (bundle.get('version-stages') or []), E_VAULT)
    return {'secret_ocid': secret_ocid, 'version_number': version}


def import_eso_bundle(cfg, op_profile, inv):
    """Import the ESO signing bundle into the existing Vault."""
    custody = custody_dir(cfg)
    key_path = custody / 'eso-signing.pem'
    private_pem = ensure_signing_key(cfg)
    fingerprint = key_fingerprint(cfg, custody, key_path)
    payload = json.dumps({
        'privatekey': private_pem,
        'fingerprint': fingerprint,
    }, separators=(',', ':'))
    return vault_create_or_reuse_equal(
        cfg, op_profile, inv, inv['eso_bundle']['name'], payload,
        'Talos ESO API signing bundle (operator imported)')


def import_runtime_targets(cfg, op_profile, inv):
    """Resolve and import every runtime target from the inventory.

    Targets with a pre-resolved OCID (schema 1 legacy or operator review)
    are verified by-name only, exactly as before. Targets with a K8s
    selector are read via kubectl (live, exact key set and type, UTF-8
    values), imported create-once/reuse-equal under the derived name,
    and byte-equal targets within the set share a single vault secret
    (one create per content group, members record the same OCID).
    """
    vault = cfg['expected']['vault_ocid']
    resolved = {}  # content signature -> created/reused entry
    out = []
    for target in inv['runtime_targets']:
        if target.get('secret_ocid'):
            bundle = oci_vault_bundle_by_name(cfg, op_profile, vault,
                                              target['name'])
            require(bundle.get('secret-id') == target['secret_ocid'],
                    E_VAULT)
            require('CURRENT' in (bundle.get('version-stages') or []),
                    E_VAULT)
            out.append({'name': target['name'],
                        'vault_name': target['name'],
                        'secret_ocid': target['secret_ocid'],
                        'keys': target['keys'],
                        'content_shape': 'raw',
                        'k8s': target.get('k8s')})
            continue
        namespace = target['k8s']['namespace']
        name = target['k8s']['name']
        secret = kube_secret_raw(cfg, namespace, name)
        kube_secret_live(secret)
        require((secret.get('type') or 'Opaque')
                == (target.get('type') or 'Opaque'), E_KUBE)
        values = kube_secret_text(secret)
        require(set(values) == set(target['keys']), E_KUBE)
        payload = json_map_payload(values)
        signature = ('json_map', payload)
        entry = resolved.get(signature)
        if entry is None:
            entry = vault_create_or_reuse_equal(
                cfg, op_profile, inv, target['name'], payload,
                'Talos ESO runtime secret (operator imported)')
            entry = dict(entry, vault_name=target['name'])
            resolved[signature] = entry
        # Byte-equal group members reference the representative vault
        # secret (single create per content group, same OCID via reuse).
        out.append({'name': target['name'],
                    'vault_name': entry['vault_name'],
                    'secret_ocid': entry['secret_ocid'],
                    'version_number': entry.get('version_number'),
                    'keys': target['keys'],
                    'content_shape': 'json_map',
                    'k8s': {'namespace': namespace, 'name': name}})
    return out


def import_flux_bundle(cfg, op_profile, inv):
    """Import the Flux deploy-key bundle from the K8s bootstrap Secret.

    Reads flux-system/homelab-secrets-git (identity, known_hosts, optional
    identity.pub; no unexpected keys), builds the JSON map, and imports
    create-once/reuse-equal under the flux bundle name. Its content never
    enters the journal.
    """
    namespace, name = FLUX_K8S_SECRET
    secret = kube_secret_raw(cfg, namespace, name)
    kube_secret_live(secret)
    keys = set(secret.get('data') or {})
    require(keys <= FLUX_ALLOWED_KEYS and 'identity' in keys, E_KUBE)
    values = kube_secret_text(secret)
    payload = json_map_payload(values)
    return vault_create_or_reuse_equal(
        cfg, op_profile, inv, inv['flux_bundle']['name'], payload,
        'Talos Flux deploy bundle (operator imported)')


def resolve_reuse_entries(cfg, op_profile, inv):
    """Resolve reuse entries: vault NAME from the OCID, then equality.

    For each entry the vault secret NAME is resolved via
    `oci vault secret get --secret-id` (metadata only). Verified entries
    (schema 2) are compared against the K8s bytes of each target in
    memory: raw shape compares raw bytes exactly (single-key target);
    json_map compares the decoded maps. Equal -> keep; mismatch ->
    E_VAULT fail closed.
    """
    vault = cfg['expected']['vault_ocid']
    out = []
    for entry in inv['reuse_entries']:
        data = parse_native_json(oci(
            cfg, op_profile, 'vault', 'secret', 'get',
            '--secret-id', entry['ocid']))
        meta = (data or {}).get('data') or {}
        name = meta.get('secret-name')
        require(isinstance(name, str) and name
                and VAULT_NAME.match(name) is not None
                and meta.get('id') == entry['ocid'], E_VAULT)
        record = {'name': name, 'ocid': entry['ocid'],
                  'targets': list(entry['targets']),
                  'content_shape': entry['content_shape']}
        if entry.get('verified'):
            bundle = oci_vault_bundle_by_name(cfg, op_profile, vault, name)
            require(bundle.get('secret-id') == entry['ocid'], E_VAULT)
            require('CURRENT' in (bundle.get('version-stages') or []),
                    E_VAULT)
            try:
                vault_bytes = base64.b64decode(
                    bundle['secret-bundle-content']['content'], validate=True)
            except (KeyError, ValueError, TypeError):
                raise Fail(E_VAULT) from None
            for selector in entry['targets']:
                namespace, sname = selector.split('/', 1)
                secret = kube_secret_raw(cfg, namespace, sname)
                kube_secret_live(secret)
                raw = kube_secret_bytes(secret)
                if entry['content_shape'] == 'raw':
                    require(len(raw) == 1, E_KUBE)
                    require(list(raw.values())[0] == vault_bytes, E_VAULT)
                else:
                    try:
                        vault_map = json.loads(
                            vault_bytes.decode('utf-8'))
                        kube_map = {k: v.decode('utf-8')
                                    for k, v in raw.items()}
                    except (ValueError, TypeError, UnicodeError):
                        raise Fail(E_VAULT) from None
                    require(vault_map == kube_map, E_VAULT)
        out.append(record)
    return out


# =====================================================================
# inventory mode (draft enumeration, read-only)
# =====================================================================

def sops_target_refs(cfg):
    """Current SOPS-delivered targets: Secrets in the status inventory of
    every flux-system Kustomization with .spec.decryption.

    Real Flux status inventory entries carry only {id, v}; the id encodes
    "namespace_name_group_kind" (e.g. "alloy_app_Secret").
    """
    listing = parse_native_json(kubectl(cfg, 'get', 'kustomizations',
                                         '-n', 'flux-system', '-o', 'json'))
    require(isinstance(listing, dict), E_STATE)
    refs = {}
    for item in listing.get('items') or []:
        if not isinstance(item, dict):
            continue
        if not ((item.get('spec') or {}).get('decryption') or None):
            continue
        entries = ((item.get('status') or {}).get('inventory')
                   or {}).get('entries') or []
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get('id'):
                continue
            # Real Flux id shape: "namespace_name[_group]_kind", where the
            # name may itself contain underscores; split only the fixed
            # suffix (kind, optional group) off the end.
            parts = str(entry['id']).rsplit('_', 3)
            if len(parts) == 4:
                namespace, name, _group, kind = parts
            elif len(parts) == 3:
                namespace, name, kind = parts
            else:
                continue
            if kind != 'Secret':
                continue
            if not namespace or not name:
                continue
            selector = namespace + '/' + name
            # The Flux bootstrap Secret is covered by the explicit
            # flux bundle, never as a runtime target.
            if selector != (FLUX_K8S_SECRET[0] + '/' + FLUX_K8S_SECRET[1]):
                refs.setdefault(selector)
    return list(refs)


def mode_inventory(cfg, args=None):
    check_tool(cfg, 'kubectl')
    custody = custody_dir(cfg)
    selectors = sops_target_refs(cfg)
    # Read every target Secret in memory: type, data keys, annotations.
    targets = []
    for selector in selectors:
        namespace, name = selector.split('/', 1)
        secret = kube_secret_raw(cfg, namespace, name)
        annotations = (secret.get('metadata') or {}).get('annotations') or {}
        targets.append({
            'selector': selector,
            'k8s': {'namespace': namespace, 'name': name},
            'name': 'k8s-%s-%s' % (namespace, name),
            'keys': sorted((secret.get('data') or {}).keys()),
            'type': secret.get('type') or 'Opaque',
            'annotation_ocid': annotations.get(REUSE_ANNOTATION),
            'bytes': kube_secret_bytes(secret),
        })
    # Explicit Flux bootstrap target always present (bundle, not runtime).
    flux_secret = kube_secret_raw(cfg, *FLUX_K8S_SECRET)
    flux_keys = sorted((flux_secret.get('data') or {}).keys())
    require(set(flux_keys) <= FLUX_ALLOWED_KEYS and 'identity' in flux_keys,
            E_KUBE)
    # Byte-equal duplicate groups, in memory only.
    by_bytes = {}
    for target in targets:
        signature = (target['type'], tuple(sorted(
            (k, v) for k, v in target['bytes'].items())))
        by_bytes.setdefault(signature, []).append(target['selector'])
    duplicate_groups = [sorted(members) for members in by_bytes.values()
                        if len(members) > 1]
    # Reuse entries: annotation-derived, then operator reuse_hints merged;
    # byte-equal siblings of a claimed target join the same entry.
    reuse = {}
    claimed = set()
    for target in targets:
        ocid = target.get('annotation_ocid')
        if ocid is not None:
            # Legacy Vault names describe provenance, not permission to reuse.
            # Only an explicit OCID or operator hint authorizes existing reuse.
            if not ocid.startswith('ocid1.') and VAULT_NAME.fullmatch(ocid):
                continue
            require(ocid.startswith(VAULTSECRET) and OCID.match(ocid),
                    E_REUSE)
            entry = reuse.setdefault(ocid, {'ocid': ocid, 'targets': []})
            if target['selector'] not in entry['targets']:
                entry['targets'].append(target['selector'])
            claimed.add(target['selector'])
    hints = cfg.get('reuse_hints') or {}
    selectors_known = {t['selector'] for t in targets}
    for selector, hint in hints.items():
        require(selector in selectors_known, E_REUSE)
        ocid = hint['ocid']
        entry = reuse.setdefault(ocid, {'ocid': ocid, 'targets': []})
        if selector not in entry['targets']:
            entry['targets'].append(selector)
        claimed.add(selector)
    for members in duplicate_groups:
        for entry in reuse.values():
            if any(m in entry['targets'] for m in members):
                for member in members:
                    if member not in entry['targets']:
                        entry['targets'].append(member)
                    claimed.add(member)
    runtime_targets = [
        {'name': t['name'], 'keys': t['keys'], 'k8s': t['k8s'],
         'type': t['type'], 'secret_ocid': None}
        for t in targets if t['selector'] not in claimed]
    flux_cfg = cfg.get('flux_bundle') or {}
    draft = {
        'schema': 2,
        'vault_ocid': cfg['expected']['vault_ocid'],
        'compartment_ocid': cfg['expected']['compartment_ocid'],
        'runtime_targets': runtime_targets,
        'reuse_entries': [
            {'ocid': e['ocid'], 'content_shape': 'raw',
             'targets': sorted(e['targets']), 'name': None}
            for e in reuse.values()],
        'duplicate_groups': duplicate_groups,
        'eso_bundle': dict(DEFAULT_ESO_BUNDLE),
        'flux_bundle': {'name': flux_cfg.get('name')
                         or DEFAULT_FLUX_BUNDLE['name'],
                        'keys': flux_keys},
        'unrelated_sentinel_secret_ocid':
            cfg.get('unrelated_sentinel_secret_ocid'),
    }
    path = write_protected(custody / 'inventory.json',
                           json.dumps(draft, sort_keys=True))
    emit({'ok': True, 'mode': 'inventory', 'draft': str(path),
          'runtime_targets': len(runtime_targets),
          'duplicate_groups': len(duplicate_groups),
          'reuse_entries': len(reuse)})


# =====================================================================
# tfvars (public metadata only)
# =====================================================================

def write_tfvars(cfg, journal):
    runtime_ocids = sorted({t['secret_ocid'] for t in journal['runtime_targets']}
                           | {e['ocid'] for e in journal['reuse_entries']})
    tfvars = {
        'talos_eso_enabled': True,
        'talos_eso_api_signing_public_key_pem': journal['public_key_pem'],
        'talos_eso_runtime_secret_ocids': runtime_ocids,
        'talos_eso_bootstrap_secret_ocids':
            sorted(journal['bootstrap_secret_ocids']),
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
    inv = load_inventory(cfg['inventory'], cfg)
    head = verify_workspace(cfg)
    op_profile = operator_profile(cfg)
    verify_operator_identity(cfg, op_profile)
    runtime_targets = import_runtime_targets(cfg, op_profile, inv)
    reuse_entries = resolve_reuse_entries(cfg, op_profile, inv)
    flux_bundle = import_flux_bundle(cfg, op_profile, inv)
    eso_bundle = import_eso_bundle(cfg, op_profile, inv)
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
        'runtime_targets': runtime_targets,
        'reuse_entries': reuse_entries,
        'bootstrap_secret_ocids': sorted(
            [flux_bundle['secret_ocid'], eso_bundle['secret_ocid']]
            + list(cfg.get('bootstrap_extra_secret_ocids') or [])),
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
    tfvars = write_tfvars(cfg, journal)
    journal_write(cfg, journal)
    emit({'ok': True, 'mode': 'prepare',
          'eso_bundle_ocid': eso_bundle['secret_ocid'],
          'flux_bundle_ocid': flux_bundle['secret_ocid'],
          'runtime_imported': len(runtime_targets),
          'reuse_resolved': len(reuse_entries),
          'tfvars': str(tfvars)})


def tofu(cfg, *args, payload=None):
    return command([cfg['tools']['tofu'], '-chdir=terraform', *args],
                   payload=payload)


def mode_plan(cfg, args=None):
    inv = load_inventory(cfg['inventory'], cfg)
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
    # Positive: GetVault + by-name bundle read for every runtime target
    # AND every reuse entry (by resolved NAME; exact OCID, CURRENT stage).
    vault_data = parse_native_json(
        oci(cfg, eso_profile, 'kms', 'management', 'vault', 'get',
                '--vault-id', vault))
    require(((vault_data or {}).get('data') or {}).get('id') == vault,
            E_VERIFY)
    for target in journal['runtime_targets']:
        bundle = oci_vault_bundle_by_name(cfg, eso_profile, vault,
                                          target.get('vault_name')
                                          or target['name'])
        require(bundle.get('secret-id') == target['secret_ocid'], E_VERIFY)
        require('CURRENT' in (bundle.get('version-stages') or []), E_VERIFY)
    for entry in journal.get('reuse_entries') or []:
        bundle = oci_vault_bundle_by_name(cfg, eso_profile, vault,
                                          entry['name'])
        require(bundle.get('secret-id') == entry['ocid'], E_VERIFY)
        require('CURRENT' in (bundle.get('version-stages') or []), E_VERIFY)
    # Negative: by-ID reads of both bootstrap bundle OCIDs and the
    # unrelated sentinel must be DENIED by IAM. A denial counts only
    # when the CLI error parses as a real authorization failure code;
    # any other failure (network, 5xx, malformed) fails the mode.
    denied_ocids = (journal['bootstrap_secret_ocids']
                    + [journal['unrelated_sentinel_secret_ocid']])
    denial_codes = []
    for ocid_value in denied_ocids:
        rc, _out, err = oci_raw(cfg, eso_profile, 'secrets', 'secret-bundle',
                                'get', '--secret-id', ocid_value)
        if rc == 0:
            raise Fail(E_DENIAL)
        if authorization_denial(err):
            denial_codes.append(denial_code(err))
            continue
        raise Fail(E_VERIFY_API)
    # Positive control: the operator can still read one denied OCID by ID,
    # proving the sentinel is not simply a nonexistent secret.
    oci_raw(cfg, op_profile, 'secrets', 'secret-bundle', 'get',
            '--secret-id', denied_ocids[0])
    emit({'ok': True, 'mode': 'verify',
          'runtime_verified': len(journal['runtime_targets']),
          'reuse_verified': len(journal.get('reuse_entries') or []),
          'denials_verified': len(denied_ocids),
          # Exact public error codes only; enables operator forensics
          # without exposing any payload or path.
          'denial_codes': sorted(set(denial_codes))})


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


MODES = {'inventory': mode_inventory, 'prepare': mode_prepare,
         'plan': mode_plan, 'apply': mode_apply,
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
