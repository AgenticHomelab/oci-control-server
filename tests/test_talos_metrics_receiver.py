"""Offline contracts; native Nginx behavior is tested in the disposable fixture."""
from pathlib import Path

import yaml
from jinja2 import Template

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / 'ansible/roles/talos_metrics_receiver'


def test_inert_and_independently_scoped():
    assert all(value is False for value in yaml.safe_load((ROLE / 'defaults/main.yml').read_text()).values())
    assert 'talos_metrics_receiver' not in (ROOT / 'ansible/playbook.yml').read_text()
    assert 'talos_metrics_receiver' not in (ROOT / 'ansible/observability.yml').read_text()
    play = yaml.safe_load((ROOT / 'ansible/talos-metrics-receiver.yml').read_text())[0]
    assert play['roles'] == ['talos_metrics_receiver']


def test_binding_and_fixed_backend():
    conf = Template((ROLE / 'templates/receiver.conf.j2').read_text()).render(tailscale_ipv4_address='100.100.1.2', talos_metrics_receiver_hostname='metrics.example.invalid', talos_metrics_receiver_tailnet_hostname='control.example.invalid')
    assert 'listen 100.100.1.2:443 ssl;' in conf
    assert 'server_name metrics.example.invalid control.example.invalid;' in conf
    assert 'metrics\\.example\\.invalid|control\\.example\\.invalid' in conf
    assert '{{ talos_metrics_receiver_hostname }}' not in conf

    assert conf.count('listen ') == 1
    assert 'default_server' not in conf
    assert 'proxy_pass http://127.0.0.1:8428/api/v1/write;' in conf
    assert conf.count('proxy_pass ') == 1
    assert '3000' not in conf


def test_transaction_and_secret_metadata_only():
    tasks = yaml.safe_load((ROLE / 'tasks/main.yml').read_text())
    names = [task['name'] for task in tasks]
    assert len(names) == len(set(names)), 'Duplicated receiver tasks would repeat guarded operations'
    assert tasks[0]['ansible.builtin.assert']['that'][0] == 'talos_metrics_receiver_deploy | bool'
    for task in tasks:
        if 'ansible.builtin.stat' in task:
            assert task['ansible.builtin.stat']['get_checksum'] is False
            assert task['ansible.builtin.stat']['get_mime'] is False
        if 'ansible.builtin.slurp' in task:
            assert task['ansible.builtin.slurp']['src'].endswith('zz-talos-metrics-receiver.conf')
    transaction = tasks[-1]
    assert transaction['block'][1]['ansible.builtin.command'] == 'nginx -t'
    assert transaction['rescue'][-1]['ansible.builtin.fail']
    assert all('ansible.builtin.apt' not in task for task in tasks)


def test_default_gate_fails_before_host_access(tmp_path):
    import shutil
    import subprocess

    import pytest

    executable = shutil.which('ansible-playbook')
    if not executable:
        pytest.skip('Ansible is required for gate execution')
    playbook = tmp_path / 'gate.yml'
    playbook.write_text(yaml.safe_dump([{
        'name': 'Exercise receiver gate locally', 'hosts': 'localhost',
        'gather_facts': False,
        'tasks': [{'name': 'Use actual receiver role', 'ansible.builtin.include_role': {
            'name': str(ROLE)}}],
    }]))
    result = subprocess.run([executable, '-i', 'localhost,', '-c', 'local', str(playbook)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 2
    assert 'Supply the existing Tailnet IPv4' in result.stdout
    assert 'TASK [talos_metrics_receiver : Validate protected prerequisite' not in result.stdout


def test_effective_nginx_preflight_order_and_conflict(tmp_path):
    import shutil
    import subprocess

    import pytest

    executable = shutil.which('ansible-playbook')
    if not executable:
        pytest.skip('Ansible is required for effective config assertions')
    tasks = yaml.safe_load((ROLE / 'tasks/main.yml').read_text())
    assertion = next(task for task in tasks if task['name'].startswith('Require standard include'))
    baseline = """user www-data;
include /etc/nginx/sites-enabled/*;
# configuration file /etc/nginx/sites-enabled/hermes:
server {
    listen 100.100.1.2:443 ssl;
    server_name hermes.example.invalid;
}
"""
    cases = [(baseline, 0), (baseline.replace('/hermes:', '/zzz-existing:'), 2),
             (baseline + 'server_name metrics.example.invalid;\n', 2)]
    for index, (config, expected) in enumerate(cases):
        playbook = tmp_path / f'config-{index}.yml'
        playbook.write_text(yaml.safe_dump([{
            'name': 'Validate synthetic Nginx metadata', 'hosts': 'localhost',
            'gather_facts': False, 'vars': {'tailscale_ipv4_address': '100.100.1.2',
                                         'talos_metrics_receiver_hostname': 'metrics.example.invalid', 'talos_metrics_receiver_tailnet_hostname': 'control.example.invalid', 'receiver_nginx': {'stdout': config, 'stderr': ''}},
            'tasks': [assertion],
        }]))
        result = subprocess.run([executable, '-i', 'localhost,', '-c', 'local', str(playbook)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == expected, result.stdout


def test_logs_route_is_opt_in_and_fixed():
    template = Template((ROLE / 'templates/receiver.conf.j2').read_text())
    disabled = template.render(tailscale_ipv4_address='100.100.1.2', talos_metrics_receiver_hostname='metrics.example.invalid', talos_metrics_receiver_tailnet_hostname='control.example.invalid')
    enabled = template.render(tailscale_ipv4_address='100.100.1.2', talos_metrics_receiver_hostname='metrics.example.invalid', talos_metrics_receiver_tailnet_hostname='control.example.invalid', talos_logs_receiver_enabled=True)
    assert '/loki/api/v1/push' not in disabled
    assert enabled.count('listen ') == 1
    assert enabled.count('proxy_pass ') == 2
    assert 'proxy_pass http://127.0.0.1:3100/loki/api/v1/push;' in enabled
    assert 'auth_basic_user_file /etc/oci-control-server/talos-logs/htpasswd;' in enabled
    assert 'error_log /dev/null;' in enabled
    assert 'client_max_body_size 1m;' in enabled
    assert 'if ($request_uri != "/loki/api/v1/push") { return 400; }' in enabled
    assert enabled.count('proxy_set_header Authorization "";') == 2
    # Entire existing metrics location stays identical.
    def metrics(config):
        return config.split('location = /api/v1/write {')[1].split('    }')[0]
    assert metrics(disabled) == metrics(enabled)
    play = yaml.safe_load((ROOT / 'ansible/talos-logs-receiver.yml').read_text())[0]
    assert play['roles'][0]['vars']['talos_logs_receiver_deploy'] is True


def test_logging_state_survives_normal_reconciliation(tmp_path):
    import shutil
    import subprocess
    import base64
    import pytest

    executable = shutil.which('ansible-playbook')
    if not executable:
        pytest.skip('Ansible required for reconciliation selection')
    tasks = yaml.safe_load((ROLE / 'tasks/main.yml').read_text())
    selection = next(t for t in tasks if t['name'].startswith('Preserve activated logging'))
    for index, (installed, requested, disable, expected) in enumerate([
        (False, False, False, False), (False, True, False, True),
        (True, False, False, True), (True, True, True, False),
    ]):
        content = 'location = /loki/api/v1/push {' if installed else ''
        play = [{'hosts': 'localhost', 'gather_facts': False, 'vars': {
            'talos_logs_receiver_deploy': requested, 'talos_logs_receiver_disable': disable,
            'receiver_previous': {'content': base64.b64encode(content.encode()).decode()},
        }, 'tasks': [selection, {'name': 'Verify selection', 'ansible.builtin.assert': {
            'that': [f'talos_logs_receiver_enabled == {str(expected).lower()}']}}]}]
        path = tmp_path / f'selection-{index}.yml'
        path.write_text(yaml.safe_dump(play))
        result = subprocess.run([executable, '-i', 'localhost,', '-c', 'local', str(path)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout
