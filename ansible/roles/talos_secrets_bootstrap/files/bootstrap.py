#!/usr/bin/env python3
"""One-shot recovery: credentials stay in process memory and kubectl stdin."""
import base64
import binascii
import configparser
import json
import os
from pathlib import Path
import re
import stat
import subprocess

TARGETS = (('flux', 'flux-system', 'homelab-secrets-git'),
           ('eso', 'external-secrets', 'oci-vault-auth'))
FINGERPRINT = r'(?:[0-9a-f]{2}:){15}[0-9a-f]{2}'


class BootstrapError(Exception):
    """Static sanitized messages only; never include external diagnostics."""


def require(condition, message):
    if not condition:
        raise BootstrapError(message)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def ocid(value, kind):
    return matches(r'ocid1\.' + kind + r'\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9]+', value)


def absolute_path(value):
    return (isinstance(value, str) and value.startswith('/')
            and value != '/' and not any(char in value for char in '\x00\r\n')
            and '..' not in value.split('/'))


def validate(inputs):
    """Metadata only. This is the entire check-mode execution path."""
    expected = {'approved', 'auth', 'oci_cli', 'kubectl', 'config_file', 'profile',
                'region', 'operator_user_ocid', 'eso_user_ocid', 'kubeconfig',
                'context', 'flux', 'eso'}
    require(isinstance(inputs, dict) and set(inputs) == expected, 'invalid input fields')
    require(inputs['approved'] is True and inputs['auth'] == 'api_key',
            'explicit approval and API-key authentication required')
    require(matches(r'[A-Za-z0-9][A-Za-z0-9_.-]*', inputs['profile'])
            and inputs['profile'], 'explicit operator profile required')
    require(matches(r'[a-z0-9][a-z0-9-]+', inputs['region']), 'explicit OCI region required')
    require(matches(r'[A-Za-z0-9][A-Za-z0-9_./:@-]*', inputs['context']),
            'explicit Kubernetes context required')
    for field in ('oci_cli', 'kubectl', 'config_file', 'kubeconfig'):
        require(absolute_path(inputs[field]), 'absolute selector paths required')
    for field in ('operator_user_ocid', 'eso_user_ocid'):
        require(ocid(inputs[field], 'user'), 'invalid identity selector')
    require(inputs['operator_user_ocid'] != inputs['eso_user_ocid'],
            'operator identity must be independent of ESO')
    for kind in ('flux', 'eso'):
        value = inputs[kind]
        require(isinstance(value, dict) and set(value) == {'secret_id', 'version_number'},
                'exact pinned bundle selectors required')
        require(ocid(value['secret_id'], 'vaultsecret'), 'invalid Vault selector')
        require(type(value['version_number']) is int and value['version_number'] > 0,
                'positive integer pinned bundle version required')
    require(inputs['flux']['secret_id'] != inputs['eso']['secret_id'],
            'independent bundle selectors required')


def protected_file(path):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and info.st_mode & 0o077 == 0, 'protected operator files required')


def operator_profile(inputs):
    """Check named API-key profile before allowing the OCI CLI to read its key."""
    try:
        protected_file(inputs['config_file'])
        config = configparser.ConfigParser(interpolation=None)
        with open(inputs['config_file'], encoding='utf-8') as stream:
            config.read_file(stream)
        require(inputs['profile'] in config.sections(), 'operator profile unavailable')
        profile = config[inputs['profile']]
        require(profile.get('user') == inputs['operator_user_ocid']
                and profile.get('user') != inputs['eso_user_ocid'],
                'operator profile identity mismatch')
        require(profile.get('auth', 'api_key') == 'api_key'
                and 'security_token_file' not in profile, 'API-key profile required')
        require(ocid(profile.get('tenancy'), 'tenancy')
                and matches(FINGERPRINT, profile.get('fingerprint')),
                'invalid API-key profile metadata')
        require(profile.get('region') == inputs['region'], 'operator region mismatch')
        require(absolute_path(profile.get('key_file')), 'absolute operator key path required')
        protected_file(profile['key_file'])  # Metadata only; CLI reads the key itself.
        return profile['fingerprint']
    except (OSError, configparser.Error, UnicodeError):
        raise BootstrapError('operator profile unavailable or invalid') from None


def command(argv, payload=None):
    # Do not inherit OCI auth/endpoint/debug overrides or unrelated service secrets.
    allowed = {'HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'XDG_RUNTIME_DIR',
               'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
               'REQUESTS_CA_BUNDLE', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY',
               'https_proxy', 'http_proxy', 'all_proxy', 'no_proxy'}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    try:
        result = subprocess.run(argv, input=payload, text=True, capture_output=True,
                                env=env, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise BootstrapError('native command unavailable or timed out') from None
    require(result.returncode == 0, 'native command failed; no diagnostics disclosed')
    return result.stdout


def kube(inputs, args, payload=None):
    return command([inputs['kubectl'], '--kubeconfig', inputs['kubeconfig'],
                    '--context', inputs['context'], '--request-timeout=30s',
                    *args], payload)


def json_value(content):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON fields rejected')
            result[key] = value
        return result
    try:
        return json.loads(content, object_pairs_hook=unique)
    except (ValueError, TypeError, UnicodeError):
        raise BootstrapError('invalid JSON response or payload') from None


def decode(value):
    try:
        require(isinstance(value, str), 'invalid base64 value')
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise BootstrapError('invalid base64 value') from None


def bundle(inputs, kind):
    selector = inputs[kind]
    output = command([
        inputs['oci_cli'], '--config-file', inputs['config_file'],
        '--profile', inputs['profile'], '--auth', 'api_key',
        '--region', inputs['region'], '--cli-rc-file', '/dev/null',
        '--output', 'json', '--no-retry', '--connection-timeout', '10',
        '--read-timeout', '30', 'secrets', 'secret-bundle', 'get',
        '--secret-id', selector['secret_id'],
        '--version-number', str(selector['version_number']),
    ])
    try:
        data = json_value(output)['data']
        require(data['secret-id'] == selector['secret_id']
                and type(data['version-number']) is int
                and data['version-number'] == selector['version_number'],
                'returned bundle does not match pin')
        content = data['secret-bundle-content']
        require(content['content-type'] == 'BASE64', 'unsupported bundle encoding')
        decoded = json_value(decode(content['content']))
        required = {'identity', 'known_hosts'} if kind == 'flux' else {'privatekey', 'fingerprint'}
        allowed = required | ({'identity.pub'} if kind == 'flux' else set())
        require(isinstance(decoded, dict) and required <= set(decoded) <= allowed,
                'invalid bundle key schema')
        require(all(isinstance(value, str) and value.strip() and '\x00' not in value
                    and len(value.encode()) <= 131072 for value in decoded.values()),
                'empty or invalid bundle value')
        if kind == 'eso':
            require(matches(FINGERPRINT, decoded['fingerprint']), 'invalid ESO fingerprint')
        # Never strip, reformat, derive or regenerate key/known_hosts bytes.
        return {key: base64.b64encode(value.encode()).decode()
                for key, value in decoded.items()}
    except (KeyError, TypeError):
        raise BootstrapError('invalid bundle envelope') from None


def get_secret(inputs, namespace, name):
    output = kube(inputs, ['--namespace', namespace, 'get', 'secret', name,
                           '--ignore-not-found', '-o', 'json'])
    if not output.strip():
        return None  # Only successful --ignore-not-found means absent, never an API error.
    value = json_value(output)
    require(isinstance(value, dict) and value.get('kind') == 'Secret'
            and value.get('apiVersion') == 'v1'
            and value.get('metadata', {}).get('namespace') == namespace
            and value.get('metadata', {}).get('name') == name, 'unexpected Secret response')
    return value


def plan(existing, desired, namespace, name):
    if existing is None:
        return 'create', {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                          'metadata': {'namespace': namespace, 'name': name}, 'data': desired}
    require(existing.get('type') == 'Opaque'
            and not existing['metadata'].get('deletionTimestamp'),
            'existing Secret type or lifecycle mismatch')
    current = existing.get('data') or {}
    require(isinstance(current, dict) and set(current) <= set(desired),
            'existing Secret contains unapproved data keys')
    require(all(decode(value) == decode(desired[key]) for key, value in current.items()),
            'existing Secret data mismatch; rotation refused')
    if set(current) == set(desired):
        return None, existing
    require(not existing.get('immutable')
            and isinstance(existing['metadata'].get('resourceVersion'), str)
            and bool(existing['metadata']['resourceVersion']),
            'existing Secret cannot be safely completed')
    # Preserve metadata and use resourceVersion for optimistic concurrency, never force.
    return 'replace', dict(existing, data=desired)


def bootstrap(inputs, check=False):
    validate(inputs)  # Must precede every file, credential and API read.
    if check:
        return {'changed': False, 'validation_only': True}
    operator_fingerprint = operator_profile(inputs)
    payloads = {kind: bundle(inputs, kind) for kind in ('flux', 'eso')}
    require(decode(payloads['eso']['fingerprint']).decode() != operator_fingerprint,
            'operator and ESO signing keys must be independent')
    plans = []
    # All targets validated before the first write; namespace ownership stays elsewhere.
    for kind, namespace, name in TARGETS:
        kube(inputs, ['get', 'namespace', namespace, '-o', 'json'])
        existing = get_secret(inputs, namespace, name)
        action, value = plan(existing, payloads[kind], namespace, name)
        plans.append((kind, namespace, name, action, value))
    changed = False
    for kind, namespace, name, action, value in plans:
        if action:
            kube(inputs, ['--namespace', namespace, action, '-f', '-', '-o', 'json'],
                 json.dumps(value))
            changed = True
        actual = get_secret(inputs, namespace, name)
        require(actual is not None, 'Secret read-back verification failed')
        verified_action, _ = plan(actual, payloads[kind], namespace, name)
        require(verified_action is None, 'Secret read-back verification failed')
    return {'changed': changed}


def main():
    import resource
    import sys
    # Disable core dumps containing process-memory credentials. Never emit a traceback.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in ('--check', '--apply'),
                'explicit execution mode required')
        result = bootstrap(json_value(sys.stdin.read()), check=sys.argv[1] == '--check')
    except BootstrapError as error:
        print(json.dumps({'changed': False, 'error': str(error)}))
        return 1
    except Exception:
        print(json.dumps({'changed': False, 'error': 'bootstrap failed; diagnostics withheld'}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
