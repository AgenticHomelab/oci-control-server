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
            and "tasks_from" in task["ansible.builtin.import_role"]
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
    assert "omni.env" not in service


def test_sudoers_policy_is_private_and_validated_before_installation():
    tasks = (ROLE / "tasks/operational-access.yml").read_text()
    assert "sudoers/hermes-admin" in tasks
    assert "visudo -cf" in tasks
    assert "NOPASSWD" not in tasks


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

def test_hermes_release_update_is_isolated_and_not_automatic():
    upgrade = yaml.safe_load((ANSIBLE / "hermes-update.yml").read_text())
    assert len(upgrade) == 1
    assert upgrade[0]["hosts"] == "control"
    tasks = upgrade[0]["tasks"]
    assert len(tasks) == 1
    assert tasks[0]["ansible.builtin.import_role"] == {
        "name": "hermes",
        "tasks_from": "release-update",
    }
    normal = (ROLE / "tasks/main.yml").read_text()
    main = (ANSIBLE / "playbook.yml").read_text()
    assert "release-update" not in normal
    assert "release-update" not in main
    assert "release-verify.yml" in normal
    assert "hermes_install_commit" not in normal

    update_tasks = yaml.safe_load(
        (ROLE / "tasks/release-update.yml").read_text()
    )
    commands = [
        task["ansible.builtin.command"]["argv"]
        for task in update_tasks
        if "ansible.builtin.command" in task
    ]
    assert any("update" in argv and "--plan" in argv for argv in commands)
    assert any(
        "update" in argv and "--channel" in argv
        and "stable" in argv and "--backup" in argv
        for argv in commands
    )
    approval = next(
        task for task in update_tasks
        if task["name"].startswith("Require explicit approval")
    )
    assert "hermes_update_reviewed" in str(approval)
    mutation = next(
        task for task in update_tasks
        if task["name"].startswith("Run Hermes upstream stable updater")
    )
    assert "not ansible_check_mode" in mutation["when"]
    assert mutation["become_user"] == "hermes"
    assert mutation["async"] > 0

    verify = (ROLE / "tasks/release-verify.yml").read_text()
    assert "refs/tags/{{ hermes_release_version }}^{commit}" in verify
    assert "hermes_installed_revision.stdout" in verify

def test_hermes_runtime_comes_from_upstream_pm_lock():
    normal = (ROLE / "tasks/main.yml").read_text()
    upgrade = (ROLE / "tasks/release-update.yml").read_text()
    units = (ROLE / "tasks/runtime-units.yml").read_text()
    gateway = (ROLE / "templates/hermes-gateway.service.j2").read_text()
    vars_file = (ANSIBLE / "group_vars/control.yml").read_text()

    assert "import_tasks: runtime-units.yml" in normal
    assert "import_tasks: runtime-units.yml" in upgrade
    assert "/pm/lock.json" in units
    assert "hermes_pm_runtime.packages.node.version" in units
    assert "hermes_pm_runtime.packages.npm.version" in units
    assert "hermes_pm_runtime.packages.node.version" in gateway
    assert "hermes_pm_runtime.packages.npm.version" in gateway
    assert "hermes_node_version:" not in vars_file
    assert "hermes_npm_version:" not in vars_file


def test_matrix_e2ee_source_overlay_is_reviewed_and_kept_out_of_normal_updates():
    import ast
    import hashlib

    files = ROLE / "files/matrix"
    module = files / "direct_key_delivery.py"
    regressions = files / "test_matrix_direct_key_delivery.py"

    def blob_sha(path):
        source = path.read_bytes()
        return hashlib.sha1(
            b"blob " + str(len(source)).encode() + b"\x00" + source,
            usedforsecurity=False,
        ).hexdigest()

    import re
    # Keep reviewed hashes in the Ansible audit only, not a second test-owned list.
    audit_text = (ROLE / "tasks/matrix-overlay-verify.yml").read_text()
    reviewed = re.findall(r"'([0-9a-f]{40})'", audit_text)
    assert len(reviewed) == 3  # adapter, module, regression test
    assert [blob_sha(module), blob_sha(regressions)] == reviewed[1:]
    ast.parse(module.read_text())
    ast.parse(regressions.read_text())
    assert "test_late_device_receives_current_index_without_history" in regressions.read_text()

    patch = (files / "adapter-v0.23.4.patch").read_text()
    assert "from plugins.platforms.matrix.adapter_crypto import _CryptoStateStore" in patch
    assert "+                olm = DirectKeyDeliveryMachine" in patch
    assert "-            olm = OlmMachine" in patch

    normal = (ROLE / "tasks/main.yml").read_text()
    upgrade = (ROLE / "tasks/release-update.yml").read_text()
    overlay = (ROLE / "tasks/matrix-overlay.yml").read_text()
    audit = (ROLE / "tasks/matrix-overlay-verify.yml").read_text()
    assert "import_tasks: matrix-overlay-verify.yml" in normal
    assert "import_tasks: matrix-overlay.yml" in upgrade
    assert "--keep-stash" in upgrade
    assert "--no-gateway-restart" in upgrade
    assert "hermes_legacy_patch_blobs" in upgrade
    assert "a7d53d905f" in upgrade
    assert "ansible.builtin.copy" in overlay
    assert "ansible.builtin.command" in overlay
    assert "apply" in overlay
    assert "apply" in audit
    assert "ansible.builtin.copy" not in audit
