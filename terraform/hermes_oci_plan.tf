# Explicitly opt-in, standalone OCI plan identity and state access.
# Neither the operator's API signing key nor S3 Customer Secret Keys are
# created, copied or stored in OpenTofu state.
variable "hermes_oci_plan_enabled" {
  description = "Opt in to a dedicated Hermes OCI state reader and scoped Instance Principal provider reads."
  type        = bool
  default     = false
}

variable "hermes_oci_plan_state_key" {
  description = "The original OCI control-server state object key, from its existing initialized backend."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.hermes_oci_plan_state_key == null ? true : (
      can(regex("^[A-Za-z0-9._/-]+$", var.hermes_oci_plan_state_key)) &&
      !strcontains(var.hermes_oci_plan_state_key, "..")
    )
    error_message = "Provide only the original, distinct OCI state object key."
  }
}

resource "oci_identity_domains_user" "hermes_oci_plan_s3" {
  count         = var.hermes_oci_plan_enabled ? 1 : 0
  idcs_endpoint = var.hermes_truenas_s3_identity_domain_url
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User",
  ]
  user_name    = "hermes-oci-opentofu-s3"
  display_name = "Hermes OCI OpenTofu plan S3 backend"
  active       = true

  name {
    given_name  = "Hermes"
    family_name = "OCI OpenTofu S3"
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
    can_use_api_keys                 = false
    can_use_auth_tokens              = false
    can_use_console                  = false
    can_use_console_password         = false
    can_use_customer_secret_keys     = true
    can_use_db_credentials           = false
    can_use_oauth2client_credentials = false
    can_use_smtp_credentials         = false
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        var.hermes_oci_plan_state_key != null &&
        !contains(tolist(var.hermes_truenas_s3_state_keys), var.hermes_oci_plan_state_key) &&
        var.hermes_oci_plan_state_key != var.hermes_truenas_acme_state_key
      )
      error_message = "OCI planning requires a non-null original state key distinct from all three TrueNAS roots."
    }
  }
}

resource "oci_identity_domains_group" "hermes_oci_plan_s3" {
  count          = var.hermes_oci_plan_enabled ? 1 : 0
  idcs_endpoint  = var.hermes_truenas_s3_identity_domain_url
  attribute_sets = ["all"]
  # Unlike the existing TrueNAS group, OCI returned only these two schemas
  # for this newly created group. Preserve its actual SCIM representation.
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:Group",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group",
  ]
  display_name = "hermes-oci-opentofu-s3"

  members {
    value = oci_identity_domains_user.hermes_oci_plan_s3[0].id
    type  = "User"
  }

  urnietfparamsscimschemasoracleidcsextensiongroup_group {
    description = "Only the original OCI control-server OpenTofu state and native lock"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_policy" "hermes_oci_plan_s3" {
  count          = var.hermes_oci_plan_enabled ? 1 : 0
  compartment_id = var.tenancy_ocid
  name           = "hermes-oci-opentofu-s3"
  description    = "Read original OCI state; create/read/delete only its native lock"
  statements = [
    # Listing necessarily exposes the object names within this one bucket.
    "Allow group id ${oci_identity_domains_group.hermes_oci_plan_s3[0].ocid} to {OBJECT_INSPECT} in compartment id ${var.compartment_ocid} where target.bucket.name = '${var.hermes_truenas_s3_state_bucket}'",
    # Plans do not require state overwrite, creation or deletion.
    "Allow group id ${oci_identity_domains_group.hermes_oci_plan_s3[0].ocid} to {OBJECT_READ} in compartment id ${var.compartment_ocid} where all {target.bucket.name = '${var.hermes_truenas_s3_state_bucket}', target.object.name = '${var.hermes_oci_plan_state_key}'}",
    # Native S3 conditional-write locking has its own exact object key.
    "Allow group id ${oci_identity_domains_group.hermes_oci_plan_s3[0].ocid} to {OBJECT_READ, OBJECT_CREATE, OBJECT_DELETE} in compartment id ${var.compartment_ocid} where all {target.bucket.name = '${var.hermes_truenas_s3_state_bucket}', target.object.name = '${var.hermes_oci_plan_state_key}.tflock'}",
  ]
  freeform_tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

# The whole control-01 instance, not only the Hermes Unix process, can
# authenticate as an Instance Principal. This distinct dynamic group and policy
# make the extra read permissions independently reviewable and revocable.
resource "oci_identity_dynamic_group" "hermes_oci_plan" {
  count          = var.hermes_oci_plan_enabled ? 1 : 0
  compartment_id = var.tenancy_ocid
  name           = "oci-control-server-hermes-opentofu-plan"
  description    = "Only the existing control-01 instance, for native OCI OpenTofu provider reads"
  matching_rule  = "instance.id = '${oci_core_instance.control.id}'"
  freeform_tags  = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_identity_policy" "hermes_oci_plan" {
  count          = var.hermes_oci_plan_enabled ? 1 : 0
  compartment_id = var.tenancy_ocid
  name           = "hermes-oci-opentofu-plan-reader"
  description    = "Control-01 Instance Principal reads for the exact managed OCI OpenTofu root"
  statements = [
    # Tenancy metadata and exact existing managed IAM identities/policies.
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect compartments in tenancy",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect users in tenancy where any {target.user.name = 'hermes-truenas-opentofu-s3', target.user.name = 'hermes-oci-opentofu-s3'${var.talos_eso_enabled ? ", target.user.name = 'talos-eso-vault-reader'" : ""}}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect groups in tenancy where any {target.group.name = 'hermes-truenas-opentofu-s3', target.group.name = 'hermes-oci-opentofu-s3'${var.talos_eso_enabled ? ", target.group.name = 'talos-eso-vault-reader'" : ""}}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect dynamic-groups in tenancy where any {target.dynamic-group.name = 'oci-control-server-vault-reader', target.dynamic-group.name = 'oci-control-server-hermes-opentofu-plan'}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect policies in tenancy where any {target.policy.name = 'hermes-truenas-opentofu-s3', target.policy.name = 'hermes-oci-opentofu-s3', target.policy.name = 'hermes-oci-opentofu-plan-reader'}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect policies in compartment id ${var.compartment_ocid} where ${var.talos_eso_enabled ? "any {target.policy.name = 'oci-control-server-vault-reader', target.policy.name = 'talos-eso-vault-reader'}" : "target.policy.name = 'oci-control-server-vault-reader'"}",
    # These metadata reads do not grant domain administration.
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read domains in tenancy where target.domain.name = 'Default'",
    # The only OCI infrastructure compartment managed by this repository.
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read instance-family in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read virtual-network-family in compartment id ${var.compartment_ocid}",
    # The provider reads each NSG rule via ListNetworkSecurityGroupSecurityRules.
    # OCI excludes this operation from read virtual-network-family; grant only
    # the single required read operation, not use/manage network resources.
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to {NETWORK_SECURITY_GROUP_LIST_SECURITY_RULES} in compartment id ${var.compartment_ocid} where request.operation = 'ListNetworkSecurityGroupSecurityRules'",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read volume-family in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read alarms in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read metrics in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read ons-topics in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to inspect ons-subscriptions in compartment id ${var.compartment_ocid}",
    # GetSubscription uniquely requires a subscribe permission, despite being
    # a read API. Restrict it to precisely this API operation, not mutations.
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to {ONS_TOPIC_SUBSCRIBE} in compartment id ${var.compartment_ocid} where request.operation = 'GetSubscription'",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read vaults in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group id ${oci_identity_dynamic_group.hermes_oci_plan[0].id} to read keys in compartment id ${var.compartment_ocid}",
  ]
  freeform_tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}
