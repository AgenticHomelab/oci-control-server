"""Offline contract for explicit Renovate-managed host versions."""

import json
import re
import subprocess

import yaml
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# The other pins are intentionally operator-managed (checksums or runtime state).
EXPECTED = {
    "kubectl_version": ("github-tags", "kubernetes/kubernetes"),
    "talosctl_version": ("github-releases", "siderolabs/talos"),
    "flux_version": ("github-releases", "fluxcd/flux2"),
    "helm_version": ("github-releases", "helm/helm"),
    "omni_version": ("docker", "ghcr.io/siderolabs/omni"),
    "omni_dex_version": ("docker", "ghcr.io/dexidp/dex"),
}


def test_only_supported_host_pins_are_extracted():
    config = json.loads((ROOT / "renovate.json").read_text())
    assert config["automerge"] is False
    assert config["platformAutomerge"] is False
    assert config["enabledManagers"] == [
        "github-actions", "terraform", "custom.regex"
    ]
    assert len(config["customManagers"]) == 1

    # Python spells named groups differently than Renovate's JS/RE2 syntax.
    expression = config["customManagers"][0]["matchStrings"][0]
    expression = expression.replace("(?<", "(?P<")
    group_vars = (ROOT / "ansible/group_vars/all/versions.yml").read_text()
    matches = list(re.finditer(expression, group_vars))
    actual = {}
    for match in matches:
        groups = match.groupdict()
        key = groups["variable"]
        assert key not in actual
        assert groups["currentValue"]
        actual[key] = (groups["datasource"], groups["depName"])

    assert actual == EXPECTED


def test_opentofu_registry_is_not_silently_switched():
    config = json.loads((ROOT / "renovate.json").read_text())
    assert any(
        rule.get("matchDatasources") == [
            "terraform-provider", "terraform-module"
        ]
        and rule.get("registryUrls") == ["https://registry.opentofu.org"]
        for rule in config["packageRules"]
    )

def test_control_inventory_receives_reviewed_pins():
    expected = yaml.safe_load(
        (ROOT / "ansible/group_vars/all/versions.yml").read_text()
    )
    # Check actual host_group_vars loading without contacting control-01.
    result = subprocess.run(
        [
            "ansible-inventory", "-i", "inventory.ini.example",
            "--playbook-dir", ".", "--host", "control-01",
        ],
        cwd=ROOT / "ansible",
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    host = json.loads(result.stdout)
    assert len(expected) == len(EXPECTED)
    for variable, value in expected.items():
        assert host[variable] == value
