"""Offline HCL source contracts. Never initialize, plan, or read state/credentials.

Install requirements-test.txt plus tests/requirements-eso-iam.txt, then run:
    pytest tests/test_talos_eso_iam.py
Provider schema/type validation is a separate `tofu validate` (no init/plan).
"""
from pathlib import Path
import json
import re

import hcl2
import pytest

ROOT = Path(__file__).resolve().parents[1]
TF = ROOT / "terraform"
ESO = TF / "talos_eso.tf"


def source():
    return hcl2.loads(ESO.read_text()) if ESO.exists() else {}


def blocks(kind):
    return {name: body for entry in source().get(kind, []) for name, body in entry.items()}


def resources():
    return {
        (kind, name): body
        for entry in source().get("resource", [])
        for kind, items in entry.items()
        for name, body in items.items()
    }


def compact(expression):
    # python-hcl2 reconstructs boolean literals inside expressions as Python case.
    return " ".join(expression.split()).replace("True", "true").replace("False", "false")


def test_opt_in_dedicated_domain_identity_has_only_api_key_capability():
    variables = blocks("variable")
    assert "talos_eso_enabled" in variables, "ESO IAM must be explicitly opt-in"
    assert variables["talos_eso_enabled"]["default"] is False
    assert variables["talos_eso_enabled"]["type"] == "bool"
    managed = resources()
    assert {
        ("oci_identity_domains_user", "talos_eso"),
        ("oci_identity_domains_group", "talos_eso"),
    } <= set(managed)
    for kind in ("oci_identity_domains_user", "oci_identity_domains_group"):
        resource = managed[(kind, "talos_eso")]
        assert resource["count"] == "${var.talos_eso_enabled ? 1 : 0}"
        assert resource["idcs_endpoint"] == "${var.hermes_truenas_s3_identity_domain_url}"
        assert resource["lifecycle"][0]["prevent_destroy"] is True
    user = managed[("oci_identity_domains_user", "talos_eso")]
    assert user["user_name"] == "talos-eso-vault-reader"
    capabilities = user["urnietfparamsscimschemasoracleidcsextensioncapabilities_user"][0]
    assert capabilities == {
        "can_use_api_keys": True,
        "can_use_auth_tokens": False,
        "can_use_console": False,
        "can_use_console_password": False,
        "can_use_customer_secret_keys": False,
        "can_use_db_credentials": False,
        "can_use_oauth2client_credentials": False,
        "can_use_smtp_credentials": False,
    }
    group = managed[("oci_identity_domains_group", "talos_eso")]
    assert group["display_name"] == "talos-eso-vault-reader"
    assert group["attribute_sets"] == ["all"]
    assert group["members"] == [{
        "type": "User", "value": "${oci_identity_domains_user.talos_eso[0].id}",
    }]


def test_operator_public_key_only_with_no_private_material_or_file_reads():
    managed = resources()
    assert ("oci_identity_domains_api_key", "talos_eso") in managed, "Only upload an independently created public signing key"
    key = managed[("oci_identity_domains_api_key", "talos_eso")]
    assert key["count"] == "${var.talos_eso_enabled ? 1 : 0}"
    assert key["idcs_endpoint"] == "${var.hermes_truenas_s3_identity_domain_url}"
    assert key["schemas"] == ["urn:ietf:params:scim:schemas:oracle:idcs:apikey"]
    assert key["key"] == "${var.talos_eso_api_signing_public_key_pem}"
    assert key["user"] == [{
        "ocid": "${oci_identity_domains_user.talos_eso[0].ocid}",
        "value": "${oci_identity_domains_user.talos_eso[0].id}",
    }]
    assert key["lifecycle"][0]["prevent_destroy"] is True
    variable = blocks("variable")["talos_eso_api_signing_public_key_pem"]
    assert variable["default"] is None
    assert variable["type"] == "string"
    validation = compact(variable["validation"][0]["condition"])
    assert 'var.talos_eso_api_signing_public_key_pem == null ? true :' in validation
    assert 'regex(' in validation
    assert '-----BEGIN PUBLIC KEY-----' in validation
    assert '-----END PUBLIC KEY-----$' in validation
    assert not source().get("data")
    text = ESO.read_text()
    for forbidden in ("tls_private_key", "private_key_pem", "secret_content", "oci_secrets_secretbundle", "oci_vault_secret", "local_file", "file(", "external\""):
        assert forbidden not in text.lower(), forbidden


def test_runtime_policy_is_exact_and_fail_closed_against_bootstrap_secrets():
    managed = resources()
    assert ("oci_identity_policy", "talos_eso") in managed, "ESO needs an exact runtime-only policy"
    assert set(managed) == {
        ("oci_identity_domains_user", "talos_eso"),
        ("oci_identity_domains_group", "talos_eso"),
        ("oci_identity_domains_api_key", "talos_eso"),
        ("oci_identity_policy", "talos_eso"),
    }
    assert all(item["count"] == "${var.talos_eso_enabled ? 1 : 0}" for item in managed.values())
    policy = managed[("oci_identity_policy", "talos_eso")]
    assert policy["compartment_id"] == "${var.compartment_ocid}"
    assert policy["name"] == "talos-eso-vault-reader"
    assert policy["lifecycle"][0]["prevent_destroy"] is True
    statements = compact(policy["statements"])
    assert 'for secret_id in sort(tolist(var.talos_eso_runtime_secret_ocids))' in statements
    assert 'to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = \'${secret_id}\'' in statements
    assert 'to {VAULT_READ} in compartment id ${var.compartment_ocid} where target.vault.id = \'${try(oci_kms_vault.control[0].id, "")}\'' in statements
    assert statements.count('Allow group id ${oci_identity_domains_group.talos_eso[0].ocid}') == 2
    for forbidden in ("manage ", "secret-family", "SECRET_READ", "SECRET_INSPECT", "KEY_", "any-user", "dynamic-group", "secrets in"):
        assert forbidden not in statements
    variables = blocks("variable")
    for name in ("talos_eso_runtime_secret_ocids", "talos_eso_bootstrap_secret_ocids"):
        assert variables[name]["type"] == "${set(string)}"
        assert variables[name]["default"] == []
        assert variables[name]["nullable"] is False
        assert "alltrue([for secret_id in var." + name in compact(variables[name]["validation"][0]["condition"])
    locals_ = blocks("locals")
    # All currently configured host bootstrap credential IDs are always denied,
    # including future additions to vault.tf, independently of the extra denylist.
    vault_variables = {
        name for entry in hcl2.loads((TF / "vault.tf").read_text())["variable"]
        for name in entry if name.endswith("_secret_ocid")
    }
    denied = compact(locals_["talos_eso_bootstrap_secret_ocids"])
    assert 'setunion(var.talos_eso_bootstrap_secret_ocids, toset(compact([' in denied
    assert {"var." + name for name in vault_variables} <= set(re.findall(r"var\.[A-Za-z0-9_]+", denied))
    lifecycle = managed[("oci_identity_domains_user", "talos_eso")]["lifecycle"][0]
    conditions = {compact(p["condition"]) for p in lifecycle["precondition"]}
    assert conditions == {
        "${var.control_vault_enabled}",
        "${var.talos_eso_api_signing_public_key_pem != null}",
        "${length(var.talos_eso_runtime_secret_ocids) > 0}",
        "${length(var.talos_eso_bootstrap_secret_ocids) > 0}",
        "${length(setintersection(var.talos_eso_runtime_secret_ocids, local.talos_eso_bootstrap_secret_ocids)) == 0}",
    }
    metadata = blocks("output")["talos_eso_iam_metadata"]["value"]
    assert compact(metadata).startswith('${var.talos_eso_enabled ? {')
    assert compact(metadata).endswith(': null}')
    assert '.fingerprint' in metadata
    assert '.ocid' in metadata
    assert 'oci_kms_vault.control[0].id' in metadata
    assert 'private' not in metadata.lower()


def test_plan_reader_only_adds_exact_eso_metadata_names_when_enabled():
    text = (TF / "hermes_oci_plan.tf").read_text()
    assert "talos-eso-vault-reader" in text, "Plan-reader metadata must recognize the dedicated ESO identity"
    assert text.count("talos-eso-vault-reader") == 3
    for kind in ("user", "group"):
        assert '${var.talos_eso_enabled ? ", target.' + kind + '.name = \'talos-eso-vault-reader\'" : ""}' in text
    assert ('where ${var.talos_eso_enabled ? "any {target.policy.name = \'oci-control-server-vault-reader\', '
            'target.policy.name = \'talos-eso-vault-reader\'}" : '
            '"target.policy.name = \'oci-control-server-vault-reader\'"}') in text
    # No secret reads, signing-key reads, or domain-administration expansion.
    assert "SECRET_BUNDLE_READ" not in text
    assert "read api-keys" not in text
    assert "manage domains" not in text


def source_regex(variable):
    """Exercise the literal regex in HCL, not a duplicated test-side pattern.

    These patterns use only the subset common to RE2 and Python re. This is
    lexical validation coverage, not an OCI/RSA or Terraform-plan simulation.
    """
    body = ESO.read_text().split(f'variable "{variable}" {{', 1)[1].split("\n}", 1)[0]
    match = re.search(r'regex\(\s*("(?:[^"\\]|\\.)*")', body)
    assert match is not None, f"Missing source validation regex for {variable}"
    return json.loads(match.group(1))


@pytest.mark.parametrize("value,accepted", [
    ("ocid1.vaultsecret.oc1.eu-stockholm-1.runtimeA", True),
    ("ocid1.vaultsecret.oc2.us-langley-1.runtimeA", True),
    ("ocid1.vaultsecret.oc1.eu-stockholm-1.*", False),
    ("ocid1.vaultsecret.oc1.eu-stockholm-1.runtimeA'", False),
    ("ocid1.vaultsecret.oc1.eu-stockholm-1.runtimeA, any-user", False),
    ("ocid1.vaultsecret.oc1.eu-stockholm-1.runtimeA\n", False),
    (" ocid1.vaultsecret.oc1.eu-stockholm-1.runtimeA", False),
    ("ocid1.vaultsecret.oc1..runtimeA", False),
    ("ocid1.vault.oc1.eu-stockholm-1.runtimeA", False),
    ("", False),
])
@pytest.mark.parametrize("variable", ["talos_eso_runtime_secret_ocids", "talos_eso_bootstrap_secret_ocids"])
def test_source_ocid_regex_rejects_wildcards_and_policy_injection(variable, value, accepted):
    assert bool(re.fullmatch(source_regex(variable), value)) is accepted


@pytest.mark.parametrize("value,accepted", [
    ("-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----", True),
    ("-----BEGIN PUBLIC KEY-----\r\nQUJD\r\n-----END PUBLIC KEY-----", True),
    ("-----BEGIN PRIVATE KEY-----\nNOT-A-KEY\n-----END PRIVATE KEY-----", False),
    ("-----BEGIN RSA PRIVATE KEY-----\nNOT-A-KEY\n-----END RSA PRIVATE KEY-----", False),
    ("/operator/public.pem", False),
    ("-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----", False),
    ("-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n-----BEGIN PRIVATE KEY-----\nNOT-A-KEY\n-----END PRIVATE KEY-----", False),
])
def test_source_public_key_regex_never_accepts_private_pem_or_bundles(value, accepted):
    assert bool(re.fullmatch(source_regex("talos_eso_api_signing_public_key_pem"), value)) is accepted


def test_disabled_metadata_templates_preserve_original_inspection_scope():
    text = (TF / "hermes_oci_plan.tf").read_text()
    pattern = r'\$\{var\.talos_eso_enabled \? "([^"]*)" : "([^"]*)"\}'
    disabled, count = re.subn(pattern, lambda m: m.group(2), text)
    assert count == 3
    enabled = re.sub(pattern, lambda m: m.group(1), text)
    assert "talos-eso-vault-reader" not in disabled
    assert enabled.count("talos-eso-vault-reader") == 3
    disabled_policy = next(entry["oci_identity_policy"]["hermes_oci_plan"] for entry in hcl2.loads(disabled)["resource"] if "hermes_oci_plan" in entry.get("oci_identity_policy", {}))
    enabled_policy = next(entry["oci_identity_policy"]["hermes_oci_plan"] for entry in hcl2.loads(enabled)["resource"] if "hermes_oci_plan" in entry.get("oci_identity_policy", {}))
    assert len(enabled_policy["statements"]) == len(disabled_policy["statements"])
    prefix = "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect "
    assert prefix + "users in tenancy where any {target.user.name = 'hermes-truenas-opentofu-s3', target.user.name = 'hermes-oci-opentofu-s3'}" in disabled_policy["statements"]
    assert prefix + "groups in tenancy where any {target.group.name = 'hermes-truenas-opentofu-s3', target.group.name = 'hermes-oci-opentofu-s3'}" in disabled_policy["statements"]
    assert prefix + "policies in compartment id ${var.compartment_ocid} where target.policy.name = 'oci-control-server-vault-reader'" in disabled_policy["statements"]


def test_iam_runbook_records_operator_gates_and_name_based_provider_contract():
    path = ROOT / "docs/talos-eso-iam.md"
    assert path.exists(), "Record the gated operator requirements separately from implementation"
    text = path.read_text()
    for required in (
        "talos_eso_enabled", "talos_eso_bootstrap_secret_ocids", "independently",
        "SECRET_BUNDLE_READ", "VAULT_READ", "GetSecretBundleByName",
        "remoteRef.key", "secret name", "GetVault", "separate approval",
        "no init", "no plan", "no apply", "prevent_destroy",
    ):
        assert required in text, required
