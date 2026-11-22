"""Synthetic GitHub App helper contracts for the exported OCI source tree."""

import io
import json
import os
import re
from pathlib import Path
import runpy
import subprocess
import sys
import types
from unittest.mock import patch

from jinja2 import Environment
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "ansible/roles/hermes/templates"
SELECTORS = {
    "hermes_github_app_id": 123,
    "hermes_github_app_organization_installation_id": 789,
    "hermes_github_app_organization_repositories": {"example/new": 222},
    "hermes_github_app_key_file": "/etc/synthetic-key/app-signing.pem",
    "hermes_github_app_metadata_file": "/etc/synthetic-key/selector.json",
}


def render(name):
    env = Environment(autoescape=False)
    env.filters["to_json"] = json.dumps
    return env.from_string((TEMPLATES / name).read_text()).render(**SELECTORS)


def test_token_minter_uses_private_selectors_and_rejects_other_repositories():
    source = render("hermes-github-app-token.j2")
    assert "antief/" not in source and "agentichomelab/" not in source
    token = types.ModuleType("synthetic_github_token")
    exec(compile(source, "synthetic_github_token", "exec"), token.__dict__)
    assert token.APP_ID == 123
    assert token.ORGANIZATION_INSTALLATION_ID == 789
    assert token.ORGANIZATION_REPOS == {"example/new": 222}
    assert token.KEY == SELECTORS["hermes_github_app_key_file"]
    assert "synthetic-key" in source
    with patch.object(token, "safe_key") as opening_key:
        for name in ("example/unauthorized", "example/legacy", "", None):
            with pytest.raises(token.TokenError):
                token.mint(name)
        opening_key.assert_not_called()


def test_credential_helper_allows_only_rendered_repositories(tmp_path):
    helper = tmp_path / "credential-helper"
    helper.write_text(render("hermes-github-git-credential.j2"))
    assert "antief/" not in helper.read_text()
    for repo, approved in [
        ("example/new.git", True), ("example/legacy.git", False),
        ("example/unauthorized.git", False),
    ]:
        output = io.StringIO()
        with (
            patch.object(sys, "argv", [str(helper), "get"]),
            patch.object(sys, "stdin", io.StringIO(
                f"protocol=https\nhost=github.com\npath={repo}\n\n"
            )),
            patch("subprocess.run", return_value=subprocess.CompletedProcess(
                [], 0, b"fixture-token-not-real\n"
            )) as minted,
            patch("sys.stdout", output),
        ):
            with pytest.raises(SystemExit) as ex:
                runpy.run_path(str(helper), run_name="__main__")
        assert ex.value.code == 0
        if approved:
            assert "username=x-access-token" in output.getvalue()
            assert "password=fixture-token-not-real" in output.getvalue()
            minted.assert_called_once()
        else:
            assert output.getvalue() == ""
            minted.assert_not_called()


def test_gh_wrapper_requires_explicit_repository():
    wrapper = ROOT / "ansible/roles/hermes/files/gh"
    result = subprocess.run(["/bin/sh", str(wrapper), "version"],
                            env={**os.environ, "GH_REPO": ""},
                            text=True, capture_output=True, check=False)
    assert result.returncode == 1
    assert "Set GH_REPO" in result.stderr
    assert result.stdout == ""


def test_scope_assertion_precedes_installation():
    tasks = yaml.safe_load(
        (ROOT / "ansible/roles/hermes/tasks/github-app.yml").read_text()
    )
    assert "ansible.builtin.assert" in tasks[0]
    assert "hermes_github_app_legacy_repositories" not in str(tasks[0])
    assert "hermes_github_app_organization_repositories is defined" in str(tasks[0])
    assert any(
        task.get("ansible.builtin.template", {}).get("src")
        == "hermes-github-app-token.j2"
        for task in tasks
    )
    assert any(
        task.get("ansible.builtin.template", {}).get("src")
        == "hermes-github-git-credential.j2"
        for task in tasks
    )


def test_key_retrieval_uses_only_rendered_private_paths():
    source = render("oci-hermes-github-app-key.j2")
    assert "synthetic-key" in source
    helper = types.ModuleType("synthetic_github_key")
    exec(compile(source, "synthetic_github_key", "exec"), helper.__dict__)
    assert helper.METADATA == Path(SELECTORS["hermes_github_app_metadata_file"])
    assert helper.DESTINATION == Path(SELECTORS["hermes_github_app_key_file"])


def test_ansible_tasks_require_private_key_paths():
    key_tasks = yaml.safe_load(
        (ROOT / "ansible/roles/hermes/tasks/github-app-key.yml").read_text()
    )
    scope_tasks = yaml.safe_load(
        (ROOT / "ansible/roles/hermes/tasks/github-app.yml").read_text()
    )
    for name, tasks in [("retrieval", key_tasks), ("contributor", scope_tasks)]:
        assert "hermes_github_app_key_file is defined" in str(tasks[0]), name
    assert "hermes_github_app_metadata_file is defined" in str(key_tasks[0])

    # Parse the exact Ansible regex literals used by the guarded stages.
    for tasks, selector in [
        (key_tasks, "hermes_github_app_key_file"),
        (key_tasks, "hermes_github_app_metadata_file"),
        (scope_tasks, "hermes_github_app_key_file"),
    ]:
        expressions = tasks[0]["ansible.builtin.assert"]["that"]
        matches = [x for x in expressions if x.startswith(selector + " is match(")]
        assert len(matches) == 1
        pattern = matches[0].split("is match('", 1)[1].rsplit("')", 1)[0]
        assert re.fullmatch(pattern, SELECTORS[selector])
        assert not re.fullmatch(pattern, "relative/" + selector)
        assert not re.fullmatch(pattern, "/tmp/" + selector)

    assert any(
        task.get("ansible.builtin.template", {}).get("src")
        == "oci-hermes-github-app-key.j2"
        for task in key_tasks
    )
    assert any(
        task.get("ansible.builtin.stat", {}).get("path")
        == "{{ hermes_github_app_key_file }}"
        for task in scope_tasks
    )
