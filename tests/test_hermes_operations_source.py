"""Offline contracts for staging the former private Hermes Ansible entrypoints."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"
ROLE = ANSIBLE / "roles/hermes"

PLAYBOOKS = {
    "hermes-fleet-health.yml": {"fleet-health"},
    "hermes-omni-key-renewal.yml": {"omni-key-renewal"},
    "hermes-operational-access.yml": {"operational-access"},
    "hermes-truenas-opentofu.yml": {"truenas-opentofu", "truenas-opentofu-selector"},
    "talos-renovate-dispatch.yml": {"renovate-nightly-dispatch"},
}


def test_all_legacy_operations_have_isolated_entrypoints():
    for name, expected in PLAYBOOKS.items():
        plays = yaml.safe_load((ANSIBLE / name).read_text())
        assert len(plays) == 1, name
        tasks = plays[0]["tasks"]
        actual = {
            task["ansible.builtin.import_role"]["tasks_from"]
            for task in tasks
            if "ansible.builtin.import_role" in task
        }
        assert actual == expected, name


def test_no_operational_entrypoint_added_to_normal_host_reconciliation():
    normal = (ANSIBLE / "playbook.yml").read_text()
    main = (ROLE / "tasks/main.yml").read_text()
    for name, task_names in PLAYBOOKS.items():
        assert name not in normal
        for task in task_names:
            assert f"import_tasks: {task}.yml" not in main


def test_private_assets_remain_outside_public_repository():
    protected = (
        "fleet-health.yml",
        "operational-access.yml",
        "omni-key-renewal.yml",
    )
    for name in protected:
        tasks = (ROLE / "tasks" / name).read_text()
        assert "hermes_private_operations_dir is defined" in tasks
        assert "hermes_private_operations_dir is match('^/')" in tasks
        assert "{{ hermes_private_operations_dir }}/" in tasks

    for path in (
        "files/fleet-health/SKILL.md",
        "files/homelab-operations/SKILL.md",
        "files/unslop/SKILL.md",
        "files/hermes-omni-key-renew",
        "vars/fleet-health.yml",
    ):
        assert not (ROLE / path).exists(), path


def test_omni_renewal_env_path_is_supplied_from_private_inputs():
    task = (ROLE / "tasks/omni-key-renewal.yml").read_text()
    service = (ROLE / "templates/hermes-omni-key-renewal.service.j2").read_text()
    assert "hermes_omni_credential_file is defined" in task
    assert "{{ hermes_omni_credential_file }}" in task
    assert "{{ hermes_omni_credential_file }}" in service
    assert "/home/hermes/.config/hermes/omni.env" not in service


def test_native_dispatch_and_key_renewal_remain_opt_in():
    dispatch = (ROLE / "tasks/renovate-nightly-dispatch.yml").read_text()
    renewal = (ROLE / "tasks/omni-key-renewal.yml").read_text()
    assert "talos_renovate_dispatch_reviewed" in dispatch
    assert "talos_renovate_dispatch_enabled" in dispatch
    assert "hermes_omni_key_renewal_reviewed" in renewal
    assert "hermes_omni_key_renewal_enable" in renewal
    assert "AgenticHomelab/talos-cluster" in (
        ROLE / "files/talos-renovate-dispatch.service"
    ).read_text()
