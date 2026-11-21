# Metadata only. Populate the secret outside OpenTofu after separate approval.
variable "control_vault_enabled" {
  description = "Provision the standard Vault and software key; requires deployment approval"
  type        = bool
  default     = false
}

variable "control_cloudflare_secret_ocid" {
  description = "Manually populated secret in the control compartment; null leaves reader IAM unprovisioned"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.control_cloudflare_secret_ocid == null || can(regex("^ocid1\\.vaultsecret\\.[A-Za-z0-9.-]+$", var.control_cloudflare_secret_ocid))
    error_message = "Provide a Vault secret OCID, never a secret value."
  }
}

variable "control_hermes_dashboard_secret_ocid" {
  description = "Manually populated dashboard credential payload; null grants no dashboard access"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.control_hermes_dashboard_secret_ocid == null || can(regex("^ocid1\\.vaultsecret\\.[A-Za-z0-9.-]+$", var.control_hermes_dashboard_secret_ocid))
    error_message = "Provide a Vault secret OCID, never credential content."
  }
}

variable "control_omni_auth_secret_ocid" {
  description = "Manually populated Omni/Dex authentication bundle; null grants no Omni access"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.control_omni_auth_secret_ocid == null || can(regex("^ocid1\\.vaultsecret\\.[A-Za-z0-9.-]+$", var.control_omni_auth_secret_ocid))
    error_message = "Provide a Vault secret OCID, never credential content."
  }
}

variable "control_hermes_api_secret_ocid" {
  description = "Manually populated Hermes API credential; null grants no API credential access"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.control_hermes_api_secret_ocid == null || can(regex("^ocid1\\.vaultsecret\\.[A-Za-z0-9.-]+$", var.control_hermes_api_secret_ocid))
    error_message = "Provide a Vault secret OCID, never credential content."
  }
}

variable "control_hermes_github_app_key_secret_ocid" {
  description = "Operator-created GitHub App PEM Secret OCID; null adds no IAM grant"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.control_hermes_github_app_key_secret_ocid == null || can(regex("^ocid1\\.vaultsecret\\.[A-Za-z0-9.-]+$", var.control_hermes_github_app_key_secret_ocid))
    error_message = "Provide a Vault Secret OCID, not its contents."
  }
}

variable "control_truenas_acme_secret_ocid" {
  description = "Existing TrueNAS OpenTofu API key secret; null grants no host access"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.control_truenas_acme_secret_ocid == null || can(regex("^ocid1\\.vaultsecret\\.[A-Za-z0-9.-]+$", var.control_truenas_acme_secret_ocid))
    error_message = "Provide an existing Vault Secret OCID, not a credential value."
  }
}

variable "control_cloud_backup_secret_ocid" {
  description = "Existing Cloud Backup WebDAV application password secret; null grants no host access"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.control_cloud_backup_secret_ocid == null || can(regex("^ocid1\\.vaultsecret\\.[A-Za-z0-9.-]+$", var.control_cloud_backup_secret_ocid))
    error_message = "Provide the existing Vault Secret OCID, not the WebDAV password."
  }
}

resource "oci_kms_vault" "control" {
  count          = var.control_vault_enabled ? 1 : 0
  compartment_id = var.compartment_ocid
  display_name   = "control-01-secrets"
  vault_type     = "DEFAULT"
  freeform_tags  = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_kms_key" "control_secrets" {
  count               = var.control_vault_enabled ? 1 : 0
  compartment_id      = var.compartment_ocid
  display_name        = "control-01-secrets"
  management_endpoint = oci_kms_vault.control[0].management_endpoint
  protection_mode     = "SOFTWARE"
  freeform_tags       = local.common_tags

  key_shape {
    algorithm = "AES"
    length    = 32
  }

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  control_vault_reader_enabled = var.control_vault_enabled && (var.control_cloudflare_secret_ocid != null || var.control_hermes_dashboard_secret_ocid != null || var.control_omni_auth_secret_ocid != null || var.control_hermes_api_secret_ocid != null || var.control_hermes_github_app_key_secret_ocid != null || var.control_truenas_acme_secret_ocid != null || var.control_cloud_backup_secret_ocid != null)
}

resource "oci_identity_dynamic_group" "control_vault" {
  count          = local.control_vault_reader_enabled ? 1 : 0
  compartment_id = var.tenancy_ocid
  name           = "oci-control-server-vault-reader"
  description    = "Only control-01 may retrieve the designated secrets"
  matching_rule  = "instance.id = '${oci_core_instance.control.id}'"
  freeform_tags  = local.common_tags
}

resource "oci_identity_policy" "control_vault" {
  count          = local.control_vault_reader_enabled ? 1 : 0
  compartment_id = var.compartment_ocid
  name           = "oci-control-server-vault-reader"
  description    = "Read designated secret bundles; no listing, writing or key access"
  statements = concat(
    var.control_cloudflare_secret_ocid == null ? [] : [
      "Allow dynamic-group id ${oci_identity_dynamic_group.control_vault[0].id} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${var.control_cloudflare_secret_ocid}'",
    ],
    var.control_hermes_dashboard_secret_ocid == null ? [] : [
      "Allow dynamic-group id ${oci_identity_dynamic_group.control_vault[0].id} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${var.control_hermes_dashboard_secret_ocid}'",
    ],
    var.control_omni_auth_secret_ocid == null ? [] : [
      "Allow dynamic-group id ${oci_identity_dynamic_group.control_vault[0].id} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${var.control_omni_auth_secret_ocid}'",
    ],
    var.control_hermes_api_secret_ocid == null ? [] : [
      "Allow dynamic-group id ${oci_identity_dynamic_group.control_vault[0].id} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${var.control_hermes_api_secret_ocid}'",
    ],
    var.control_hermes_github_app_key_secret_ocid == null ? [] : [
      "Allow dynamic-group id ${oci_identity_dynamic_group.control_vault[0].id} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${var.control_hermes_github_app_key_secret_ocid}'",
    ],
    var.control_truenas_acme_secret_ocid == null ? [] : [
      "Allow dynamic-group id ${oci_identity_dynamic_group.control_vault[0].id} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${var.control_truenas_acme_secret_ocid}'",
    ],
    var.control_cloud_backup_secret_ocid == null ? [] : [
      "Allow dynamic-group id ${oci_identity_dynamic_group.control_vault[0].id} to {SECRET_BUNDLE_READ} in compartment id ${var.compartment_ocid} where target.secret.id = '${var.control_cloud_backup_secret_ocid}'",
    ],
  )
  freeform_tags = local.common_tags
}

output "control_vault_metadata" {
  description = "Non-secret bootstrap metadata; no secret resource or content is managed"
  value = var.control_vault_enabled ? {
    vault_id  = oci_kms_vault.control[0].id
    key_id    = oci_kms_key.control_secrets[0].id
    secret_id = var.control_cloudflare_secret_ocid
  } : null
}
