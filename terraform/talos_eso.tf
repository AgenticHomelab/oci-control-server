# Metadata only for the Talos External Secrets Operator runtime identity.
# Disabled by default. Private signing material stays outside OpenTofu.
variable "talos_eso_enabled" {
  description = "Opt in to the dedicated Talos ESO Identity Domains identity and exact Vault runtime reads; requires separate deployment approval."
  type        = bool
  default     = false
}

variable "talos_eso_api_signing_public_key_pem" {
  description = "Operator-created RSA API signing PUBLIC KEY PEM only; the independently held private key must never enter OpenTofu inputs or state."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.talos_eso_api_signing_public_key_pem == null ? true : can(regex(
      "^-----BEGIN PUBLIC KEY-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+\\r?\\n-----END PUBLIC KEY-----$",
      trimspace(var.talos_eso_api_signing_public_key_pem)
    ))
    error_message = "Provide only a PEM PUBLIC KEY (not a private key, path, certificate or credential bundle)."
  }
}

variable "talos_eso_runtime_secret_ocids" {
  description = "Exact operator-created runtime Vault secret OCID allowlist; never bootstrap credentials or secret contents."
  type        = set(string)
  default     = []
  nullable    = false

  validation {
    condition = alltrue([
      for secret_id in var.talos_eso_runtime_secret_ocids :
      can(regex("^ocid1\\.vaultsecret\\.[a-z0-9]+\\.[a-z0-9-]+\\.[A-Za-z0-9]+$", secret_id))
    ])
    error_message = "Every runtime entry must be an exact regional Vault secret OCID, without wildcards or IAM policy syntax."
  }
}

variable "talos_eso_bootstrap_secret_ocids" {
  description = "Explicit bootstrap secret OCIDs to deny ESO, including its separately managed signing-key bundle and any Git/SOPS bootstrap credentials; existing control host credential IDs are denied automatically too."
  type        = set(string)
  default     = []
  nullable    = false

  validation {
    condition = alltrue([
      for secret_id in var.talos_eso_bootstrap_secret_ocids :
      can(regex("^ocid1\\.vaultsecret\\.[a-z0-9]+\\.[a-z0-9-]+\\.[A-Za-z0-9]+$", secret_id))
    ])
    error_message = "Every bootstrap denylist entry must be an exact regional Vault secret OCID, never its contents."
  }
}

locals {
  # Host credentials remain outside the Kubernetes runtime allowlist.
  talos_eso_bootstrap_secret_ocids = setunion(var.talos_eso_bootstrap_secret_ocids, toset(compact([
    var.control_cloudflare_secret_ocid,
    var.control_hermes_dashboard_secret_ocid,
    var.control_omni_auth_secret_ocid,
    var.control_hermes_api_secret_ocid,
    var.control_hermes_github_app_key_secret_ocid,
    var.control_truenas_acme_secret_ocid,
    var.control_cloud_backup_secret_ocid,
  ])))
}

resource "oci_identity_domains_user" "talos_eso" {
  count         = var.talos_eso_enabled ? 1 : 0
  idcs_endpoint = var.hermes_truenas_s3_identity_domain_url
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User",
  ]
  user_name    = "talos-eso-vault-reader"
  display_name = "Talos External Secrets Operator Vault reader"
  active       = true

  name {
    given_name  = "Talos"
    family_name = "ESO Vault reader"
  }

  emails {
    type     = "recovery"
    value    = var.hermes_truenas_s3_iam_email
    primary  = false
    verified = true
  }

  emails {
    type     = "work"
    value    = var.hermes_truenas_s3_iam_email
    primary  = true
    verified = true
  }

  urnietfparamsscimschemasoracleidcsextensioncapabilities_user {
    can_use_api_keys                 = true
    can_use_auth_tokens              = false
    can_use_console                  = false
    can_use_console_password         = false
    can_use_customer_secret_keys     = false
    can_use_db_credentials           = false
    can_use_oauth2client_credentials = false
    can_use_smtp_credentials         = false
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.control_vault_enabled
      error_message = "ESO must use the existing managed control Vault; enable its existing metadata, never create a second ESO Vault."
    }

    precondition {
      condition     = var.talos_eso_api_signing_public_key_pem != null
      error_message = "Enabling ESO requires only an operator-created API signing PUBLIC KEY; retain its private key independently."
    }

    precondition {
      condition     = length(var.talos_eso_runtime_secret_ocids) > 0
      error_message = "Enabling ESO requires a nonempty exact runtime secret OCID allowlist."
    }

    precondition {
      condition     = length(var.talos_eso_bootstrap_secret_ocids) > 0
      error_message = "Explicitly identify the separately managed bootstrap secret OCIDs; ESO must not read its own bootstrap credentials."
    }

    precondition {
      condition     = length(setintersection(var.talos_eso_runtime_secret_ocids, local.talos_eso_bootstrap_secret_ocids)) == 0
      error_message = "ESO runtime secret OCIDs must be disjoint from every explicit bootstrap secret and all configured control host credential secrets."
    }
  }
}

resource "oci_identity_domains_api_key" "talos_eso" {
  count         = var.talos_eso_enabled ? 1 : 0
  idcs_endpoint = var.hermes_truenas_s3_identity_domain_url
  schemas       = ["urn:ietf:params:scim:schemas:oracle:idcs:apikey"]
  key           = var.talos_eso_api_signing_public_key_pem
  description   = "Operator-created Talos ESO API signing public key; private material is managed separately"

  user {
    ocid  = oci_identity_domains_user.talos_eso[0].ocid
    value = oci_identity_domains_user.talos_eso[0].id
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_domains_group" "talos_eso" {
  count          = var.talos_eso_enabled ? 1 : 0
  idcs_endpoint  = var.hermes_truenas_s3_identity_domain_url
  attribute_sets = ["all"]
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:Group",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group",
  ]
  display_name = "talos-eso-vault-reader"

  members {
    value = oci_identity_domains_user.talos_eso[0].id
    type  = "User"
  }

  urnietfparamsscimschemasoracleidcsextensiongroup_group {
    description = "Talos ESO runtime access to exact secret bundles and one existing Vault"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_policy" "talos_eso" {
  count          = var.talos_eso_enabled ? 1 : 0
  compartment_id = var.compartment_ocid
  name           = "talos-eso-vault-reader"
  description    = "Exact runtime secret bundle reads and validation of the existing control Vault only"
  statements = concat(
    [for secret_id in sort(tolist(var.talos_eso_runtime_secret_ocids)) :
      "Allow group id ${oci_identity_domains_group.talos_eso[0].ocid} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${secret_id}'"
    ],
    [
      # ESO validates its store with GetVault even for explicit secret names.
      # try keeps disabled Vault indexing safe; the user precondition fails closed.
      "Allow group id ${oci_identity_domains_group.talos_eso[0].ocid} to {VAULT_READ} in compartment id ${var.compartment_ocid} where target.vault.id = '${try(oci_kms_vault.control[0].id, "")}'",
    ],
  )
  freeform_tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

output "talos_eso_iam_metadata" {
  description = "Non-secret ESO wiring metadata only; no private signing key or runtime/bootstrap secret contents."
  value = var.talos_eso_enabled ? {
    tenancy_ocid         = var.tenancy_ocid
    user_ocid            = oci_identity_domains_user.talos_eso[0].ocid
    group_ocid           = oci_identity_domains_group.talos_eso[0].ocid
    api_key_fingerprint  = oci_identity_domains_api_key.talos_eso[0].fingerprint
    vault_ocid           = try(oci_kms_vault.control[0].id, null)
    runtime_secret_ocids = sort(tolist(var.talos_eso_runtime_secret_ocids))
  } : null
}
