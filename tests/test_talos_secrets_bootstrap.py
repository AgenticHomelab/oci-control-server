"""Offline bootstrap tests. OCI/Kubernetes subprocesses use synthetic state only.

Run: python3 -m unittest discover -s tests -p test_talos_secrets_bootstrap.py -v
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'ansible/roles/talos_secrets_bootstrap/files/bootstrap.py'
OCID = lambda kind, name: f'ocid1.{kind}.oc1..{name}'
FINGERPRINT = ':'.join(['ab'] * 16)


def encoded(value):
    return base64.b64encode(value.encode()).decode()


class SyntheticCommands:
    """Only substitutes the external services; real bootstrap code is exercised."""
    def __init__(self, inputs):
        self.inputs = inputs
        self.calls = []
        self.objects = {}
        self.payloads = {
            'flux': {'identity': 'SYNTHETIC_SSH_PRIVATE_KEY\n',
                     'known_hosts': 'github.example.invalid ssh-ed25519 SYNTHETIC\n'},
            'eso': {'privatekey': 'SYNTHETIC_OCI_PRIVATE_KEY\n',
                    'fingerprint': ':'.join(['cd'] * 16)},
        }

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[0] == self.inputs['oci_cli']:
            selector = argv[argv.index('--secret-id') + 1]
            kind = next(k for k in ('flux', 'eso')
                        if self.inputs[k]['secret_id'] == selector)
            data = {'secret-id': selector,
                    'version-number': self.inputs[kind]['version_number'],
                    'secret-bundle-content': {'content-type': 'BASE64',
                                              'content': encoded(json.dumps(self.payloads[kind]))}}
            return subprocess.CompletedProcess(argv, 0, json.dumps({'data': data}), '')
        self.assert_kube_target(argv)
        if 'get' in argv:
            action = argv.index('get')
            if argv[action + 1] == 'namespace':
                return subprocess.CompletedProcess(argv, 0, '{}', '')
            namespace = argv[argv.index('--namespace') + 1]
            name = argv[action + 2]
            value = self.objects.get((namespace, name))
            return subprocess.CompletedProcess(argv, 0, json.dumps(value) if value else '', '')
        if 'create' in argv or 'replace' in argv:
            value = json.loads(kwargs['input'])
            key = value['metadata']['namespace'], value['metadata']['name']
            if 'create' in argv and key in self.objects:
                return subprocess.CompletedProcess(argv, 1, '', 'synthetic concurrent creation')
            value['metadata']['resourceVersion'] = str(
                int(self.objects.get(key, {}).get('metadata', {}).get('resourceVersion', '0')) + 1)
            self.objects[key] = value
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), '')
        raise AssertionError(f'Unexpected mock operation: {argv}')

    def assert_kube_target(self, argv):
        assert argv[0] == self.inputs['kubectl']
        assert argv[argv.index('--context') + 1] == self.inputs['context']
        assert argv[argv.index('--kubeconfig') + 1] == self.inputs['kubeconfig']

    @property
    def writes(self):
        return [call for call in self.calls if 'create' in call[0] or 'replace' in call[0]]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bootstrap-synthetic-',
                                              dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        self.key = folder / 'synthetic-operator.pem'
        self.key.write_text('NOT A REAL KEY\n')
        self.key.chmod(0o600)
        self.config = folder / 'synthetic-oci-config'
        self.config.write_text(
            '[RECOVERY]\nuser=' + OCID('user', 'operator') + '\n'
            'fingerprint=' + FINGERPRINT + '\n'
            'tenancy=' + OCID('tenancy', 'synthetic') + '\n'
            'region=example-region-1\nkey_file=' + str(self.key) + '\n')
        self.config.chmod(0o600)
        self.inputs = {
            'approved': True, 'auth': 'api_key', 'oci_cli': '/synthetic/bin/oci',
            'kubectl': '/synthetic/bin/kubectl', 'config_file': str(self.config),
            'profile': 'RECOVERY', 'region': 'example-region-1',
            'operator_user_ocid': OCID('user', 'operator'),
            'eso_user_ocid': OCID('user', 'eso'),
            'kubeconfig': str(folder / 'synthetic-kubeconfig'), 'context': 'synthetic-recovery',
            'flux': {'secret_id': OCID('vaultsecret', 'flux'), 'version_number': 3},
            'eso': {'secret_id': OCID('vaultsecret', 'eso'), 'version_number': 5},
        }
        self.fake = SyntheticCommands(self.inputs)

    def load(self):
        self.assertTrue(HELPER.is_file(), 'isolated bootstrap implementation is missing')
        spec = importlib.util.spec_from_file_location('synthetic_bootstrap', HELPER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def invoke(self, module, **kwargs):
        with patch.object(module.subprocess, 'run', side_effect=self.fake), \
                patch.dict(module.os.environ, {'HOME': self.tmp.name, 'PATH': '/usr/bin:/bin',
                                              'OCI_CLI_AUTH': 'instance_principal',
                                              'UNRELATED_SECRET': 'SYNTHETIC_DO_NOT_FORWARD'}, clear=True):
            return module.bootstrap(self.inputs, **kwargs)

    def test_check_mode_validates_without_reads_or_commands(self):
        module = self.load()
        self.config.unlink()
        self.key.unlink()
        self.assertEqual(self.invoke(module, check=True),
                         {'changed': False, 'validation_only': True})
        self.assertEqual(self.fake.calls, [])

    def test_invalid_inputs_fail_before_any_reads(self):
        module = self.load()
        invalid = [
            {'approved': False}, {'approved': 'true'}, {'auth': 'instance_principal'},
            {'auth': 'InstancePrincipal'}, {'context': ''}, {'context': '-unsafe'},
            {'operator_user_ocid': self.inputs['eso_user_ocid']},
            {'profile': 'DEFAULT'}, {'config_file': 'relative'}, {'kubeconfig': '/a/../b'},
            {'region': ''}, {'oci_cli': 'oci'}, {'kubectl': 'kubectl'},
            {'eso': {'secret_id': 'bad', 'version_number': 1}},
            {'flux': {'secret_id': self.inputs['flux']['secret_id'], 'version_number': 0}},
            {'flux': {'secret_id': self.inputs['flux']['secret_id'], 'version_number': True}},
            {'flux': {'secret_id': self.inputs['flux']['secret_id'], 'version_number': 'CURRENT'}},
            {'eso': self.inputs['flux']}, {'extra_unknown': True},
        ]
        baseline = dict(self.inputs)
        self.config.unlink()
        for change in invalid:
            with self.subTest(change=change):
                self.inputs = dict(baseline, **change)
                for check in (False, True):
                    with self.assertRaises(module.BootstrapError):
                        self.invoke(module, check=check)
                self.assertEqual(self.fake.calls, [])

    def test_operator_profile_must_be_independent_before_vault_read(self):
        module = self.load()
        baseline = self.config.read_text()
        for content in (baseline.replace(OCID('user', 'operator'), OCID('user', 'eso')),
                        baseline.replace('[RECOVERY]', '[OTHER]'),
                        baseline + 'auth=InstancePrincipal\n',
                        baseline + 'security_token_file=/synthetic/token\n',
                        baseline.replace('fingerprint=', 'not_fingerprint=')):
            with self.subTest(content=content):
                self.config.write_text(content)
                with self.assertRaises(module.BootstrapError):
                    self.invoke(module)
                self.assertEqual(self.fake.calls, [])
        self.config.write_text(baseline)
        self.config.chmod(0o644)
        with self.assertRaises(module.BootstrapError):
            self.invoke(module)
        self.assertEqual(self.fake.calls, [])

    def test_all_targets_preflighted_and_mismatches_never_rotate(self):
        module = self.load()
        self.invoke(module)
        self.fake.objects.pop(('flux-system', 'homelab-secrets-git'))
        self.fake.objects['external-secrets', 'oci-vault-auth']['data']['privatekey'] = encoded('DIFFERENT')
        self.fake.calls.clear()
        with self.assertRaises(module.BootstrapError):
            self.invoke(module)
        self.assertEqual(self.fake.writes, [])
        self.assertNotIn(('flux-system', 'homelab-secrets-git'), self.fake.objects)

    def test_missing_data_can_be_filled_without_changing_present_data(self):
        module = self.load()
        self.invoke(module)
        flux = self.fake.objects['flux-system', 'homelab-secrets-git']
        flux['data'].pop('known_hosts')
        flux['metadata']['annotations'] = {'keep.example.invalid/annotation': 'unchanged'}
        flux['metadata']['labels'] = {'keep': 'unchanged'}
        self.fake.calls.clear()
        self.assertTrue(self.invoke(module)['changed'])
        self.assertEqual(len(self.fake.writes), 1)
        argv, options = self.fake.writes[0]
        self.assertIn('replace', argv)
        sent = json.loads(options['input'])
        self.assertEqual(sent['metadata']['resourceVersion'], '1')
        self.assertEqual(sent['metadata']['labels'], {'keep': 'unchanged'})
        self.assertEqual(sent['metadata']['annotations'],
                         {'keep.example.invalid/annotation': 'unchanged'})
        self.assertEqual(sent['data']['identity'], encoded(self.fake.payloads['flux']['identity']))
        self.assertFalse(self.invoke(module)['changed'])

    def test_invalid_bundle_data_stops_before_kubernetes(self):
        module = self.load()
        self.fake.payloads['eso']['privatekey'] = ''
        with self.assertRaises(module.BootstrapError):
            self.invoke(module)
        self.assertFalse(any(argv[0] == self.inputs['kubectl'] for argv, _ in self.fake.calls))

    def test_wrong_bundle_version_encoding_and_schema_fail_closed(self):
        module = self.load()
        original = self.fake.__call__
        for problem in ('version', 'selector', 'encoding', 'base64', 'json', 'keys'):
            self.fake.calls.clear()
            def corrupt(argv, **kwargs):
                result = original(argv, **kwargs)
                if argv[0] == self.inputs['oci_cli']:
                    result = json.loads(result.stdout)
                    data = result['data']
                    if problem == 'version':
                        data['version-number'] = 99
                    elif problem == 'selector':
                        data['secret-id'] = OCID('vaultsecret', 'unapproved')
                    elif problem == 'encoding':
                        data['secret-bundle-content']['content-type'] = 'OTHER'
                    elif problem == 'base64':
                        data['secret-bundle-content']['content'] = '!not-base64'
                    elif problem == 'json':
                        data['secret-bundle-content']['content'] = encoded('not-json')
                    else:
                        data['secret-bundle-content']['content'] = encoded('{"unexpected":"value"}')
                    return subprocess.CompletedProcess(argv, 0, json.dumps(result), '')
                return result
            with self.subTest(problem=problem), patch.object(module.subprocess, 'run', side_effect=corrupt):
                with self.assertRaises(module.BootstrapError):
                    module.bootstrap(self.inputs)
                self.assertFalse(any(argv[0] == self.inputs['kubectl'] for argv, _ in self.fake.calls))

    def test_native_errors_are_not_absence_and_do_not_disclose_diagnostics(self):
        module = self.load()
        for point in ('vault', 'namespace', 'secret'):
            self.fake.calls.clear()
            original = self.fake.__call__
            def failing(argv, **kwargs):
                if ((point == 'vault' and argv[0] == self.inputs['oci_cli'])
                        or point in argv):
                    return subprocess.CompletedProcess(argv, 1, 'SYNTHETIC_PRIVATE', 'SYNTHETIC_PRIVATE')
                return original(argv, **kwargs)
            with self.subTest(point=point), patch.object(module.subprocess, 'run', side_effect=failing):
                with self.assertRaises(module.BootstrapError) as error:
                    module.bootstrap(self.inputs)
                self.assertNotIn('SYNTHETIC_PRIVATE', str(error.exception))
                self.assertFalse(self.fake.writes)

    def test_existing_extra_data_wrong_type_and_immutable_partial_refused(self):
        module = self.load()
        self.invoke(module)
        original = json.loads(json.dumps(self.fake.objects['flux-system', 'homelab-secrets-git']))
        for problem in ('extra', 'type', 'immutable'):
            value = json.loads(json.dumps(original))
            if problem == 'extra':
                value['data']['unapproved'] = encoded('do-not-drop')
            elif problem == 'type':
                value['type'] = 'kubernetes.io/tls'
            else:
                value['immutable'] = True
                value['data'].pop('known_hosts')
            self.fake.objects['flux-system', 'homelab-secrets-git'] = value
            self.fake.calls.clear()
            with self.subTest(problem=problem), self.assertRaises(module.BootstrapError):
                self.invoke(module)
            self.assertFalse(self.fake.writes)

    def test_write_failure_and_readback_tamper_are_errors(self):
        module = self.load()
        for problem in ('write', 'tamper'):
            self.fake.objects.clear()
            original = self.fake.__call__
            def faulty(argv, **kwargs):
                if 'create' in argv and problem == 'write':
                    return subprocess.CompletedProcess(argv, 1, '', 'SYNTHETIC_PRIVATE')
                result = original(argv, **kwargs)
                if 'create' in argv and problem == 'tamper':
                    self.fake.objects['flux-system', 'homelab-secrets-git']['data']['identity'] = encoded('WRONG')
                return result
            with self.subTest(problem=problem), patch.object(module.subprocess, 'run', side_effect=faulty):
                with self.assertRaises(module.BootstrapError):
                    module.bootstrap(self.inputs)

    def test_eso_signing_key_cannot_be_the_operator_key(self):
        module = self.load()
        self.fake.payloads['eso']['fingerprint'] = FINGERPRINT
        with self.assertRaises(module.BootstrapError):
            self.invoke(module)
        self.assertFalse(any(argv[0] == self.inputs['kubectl'] for argv, _ in self.fake.calls))

    def test_actual_ansible_entrypoint_with_synthetic_executables(self):
        playbook = ROOT / 'ansible/talos-secrets-bootstrap.yml'
        self.assertTrue(playbook.is_file(), 'isolated Ansible entrypoint is missing')
        folder = Path(self.tmp.name)
        for name in ('oci', 'kubectl'):
            path = folder / name
            path.write_text(
                f'#!{sys.executable}\nimport json, pathlib, sys\n'
                f'sys.path.insert(0, {str(ROOT / "tests")!r})\n'
                'from test_talos_secrets_bootstrap import SyntheticCommands\n'
                'folder = pathlib.Path(__file__).parent\n'
                'fake = SyntheticCommands(json.loads((folder / "inputs.json").read_text()))\n'
                'state = folder / "objects.json"\n'
                'if state.exists():\n'
                '    for value in json.loads(state.read_text()):\n'
                '        fake.objects[value["metadata"]["namespace"], value["metadata"]["name"]] = value\n'
                'payload = sys.stdin.read() if "-f" in sys.argv else None\n'
                'result = fake(sys.argv, input=payload)\n'
                'state.write_text(json.dumps(list(fake.objects.values())))\n'
                'with (folder / "calls.txt").open("a") as stream:\n'
                '    stream.write("call\\n")\n'
                'sys.stdout.write(result.stdout)\n'
                'sys.stderr.write(result.stderr)\nsys.exit(result.returncode)\n')
            path.chmod(0o700)
            self.inputs['oci_cli' if name == 'oci' else 'kubectl'] = str(path)
        (folder / 'inputs.json').write_text(json.dumps(self.inputs))
        variables = folder / 'vars.json'
        variables.write_text(json.dumps({'talos_secrets_bootstrap': self.inputs}))
        env = {key: os.environ[key] for key in ('HOME', 'PATH', 'TMPDIR') if key in os.environ}
        env.update({'ANSIBLE_CONFIG': str(ROOT / 'ansible/ansible.cfg'),
                    'ANSIBLE_NOCOLOR': '1', 'ANSIBLE_LOCAL_TEMP': str(folder / 'ansible-local')})
        ansible = shutil.which('ansible-playbook')
        self.assertIsNotNone(ansible, 'ansible-playbook is required for the synthetic entrypoint test')
        argv = [ansible, '-i', 'localhost,', str(playbook),
                '-e', '@' + str(variables)]
        # Check mode must not even open a missing operator credential/config file.
        self.config.rename(folder / 'held-config')
        result = subprocess.run([*argv, '--check', '--diff'], capture_output=True,
                                text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('changed=0', result.stdout)
        self.assertFalse((folder / 'calls.txt').exists())
        (folder / 'held-config').rename(self.config)
        for changed in (1, 0):
            result = subprocess.run([*argv, '--diff', '-vvv'], capture_output=True,
                                    text=True, env=env, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn(f'changed={changed}', result.stdout)
            for marker in ('SYNTHETIC_SSH_PRIVATE_KEY', 'SYNTHETIC_OCI_PRIVATE_KEY',
                           self.inputs['eso']['secret_id'], self.inputs['context']):
                self.assertNotIn(marker, result.stdout + result.stderr)
        self.inputs['auth'] = 'InstancePrincipal'
        variables.write_text(json.dumps({'talos_secrets_bootstrap': self.inputs}))
        before = (folder / 'calls.txt').read_text()
        result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((folder / 'calls.txt').read_text(), before)
        self.assertNotIn('InstancePrincipal', result.stdout + result.stderr)

    def test_bootstrap_stays_isolated_and_sensitive_task_is_protected(self):
        role = ROOT / 'ansible/roles/talos_secrets_bootstrap'
        tasks = (role / 'tasks/main.yml').read_text()
        self.assertIn('no_log: true', tasks)
        self.assertIn('diff: false', tasks)
        self.assertNotIn('set_fact', tasks)
        self.assertNotIn('cacheable', tasks)
        for path in (ROOT / 'ansible').glob('*.yml'):
            if path.name != 'talos-secrets-bootstrap.yml':
                self.assertNotIn('talos_secrets_bootstrap', path.read_text())

    def test_absent_recovery_roundtrip_and_repeat(self):
        module = self.load()
        result = self.invoke(module)
        self.assertTrue(result['changed'])
        self.assertEqual(len(self.fake.writes), 2)
        flux = self.fake.objects['flux-system', 'homelab-secrets-git']
        eso = self.fake.objects['external-secrets', 'oci-vault-auth']
        self.assertEqual(base64.b64decode(flux['data']['identity']).decode(),
                         self.fake.payloads['flux']['identity'])
        self.assertEqual(base64.b64decode(flux['data']['known_hosts']).decode(),
                         self.fake.payloads['flux']['known_hosts'])
        self.assertEqual(set(eso['data']), {'privatekey', 'fingerprint'})
        self.assertFalse(self.invoke(module)['changed'])
        self.assertEqual(len(self.fake.writes), 2)
        for argv, options in self.fake.calls:
            self.assertTrue(options['capture_output'])
            self.assertFalse(any(value in ' '.join(argv)
                                 for payload in self.fake.payloads.values()
                                 for value in payload.values()))
            self.assertNotIn('OCI_CLI_AUTH', options['env'])
            if argv[0] == self.inputs['oci_cli']:
                self.assertEqual(argv[argv.index('--auth') + 1], 'api_key')
                self.assertEqual(argv[argv.index('--profile') + 1], 'RECOVERY')
                self.assertIn('--version-number', argv)
                self.assertNotIn('--stage', argv)


if __name__ == '__main__':
    unittest.main()
