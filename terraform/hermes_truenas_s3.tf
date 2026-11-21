# Dedicated Customer Secret Key identity for the existing TrueNAS OpenTofu
# S3 states. The key itself is created and held outside OpenTofu: secret values
# must never enter Terraform state.
variable "hermes_truenas_s3_iam_email" {
  description = "Operator-controlled primary email for the distinct Hermes Identity Domains user; may reuse an existing operator email if the domain allows it"
  type        = string
  nullable    = false

  validation {
    condition = (
      can(regex("^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$", var.hermes_truenas_s3_iam_email)) &&
      var.hermes_truenas_s3_iam_email == trimspace(var.hermes_truenas_s3_iam_email)
    )
    error_message = "Provide a valid operator-controlled email address; OCI Identity Domains decides whether reuse is accepted."
  }
}

variable "hermes_truenas_s3_identity_domain_url" {
  description = "Existing OCI Default identity-domain endpoint from protected operator metadata"
  type        = string

  validation {
    condition     = can(regex("^https://[^[:space:]]+$", var.hermes_truenas_s3_identity_domain_url))
    error_message = "Provide the existing HTTPS identity-domain endpoint."
  }
}

variable "hermes_truenas_s3_state_bucket" {
  description = "Private bucket name shared by the existing TrueNAS identities and storage states"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.hermes_truenas_s3_state_bucket))
    error_message = "Provide the existing OCI Object Storage bucket name."
  }
}

variable "hermes_truenas_s3_state_keys" {
  description = "Private, original state object keys for identities and storage; native lock keys are derived"
  type        = set(string)

  validation {
    condition = (
      length(var.hermes_truenas_s3_state_keys) == 2 &&
      alltrue([for key in var.hermes_truenas_s3_state_keys : can(regex("^[A-Za-z0-9._/-]+$", key)) && !strcontains(key, "..")])
    )
    error_message = "Provide exactly the two distinct existing TrueNAS state keys using safe object-key characters."
  }
}

# Optional exact ACME state authorization in the same existing S3 bucket.
# Null retains the current two-root permission boundary.
variable "hermes_truenas_acme_state_key" {
  description = "Original ACME state object key in the existing TrueNAS S3 bucket; null disables Hermes ACME access."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.hermes_truenas_acme_state_key == null ? true : (
      can(regex("^[A-Za-z0-9._/-]+$", var.hermes_truenas_acme_state_key)) &&
      !strcontains(var.hermes_truenas_acme_state_key, "..") &&
      !contains(tolist(var.hermes_truenas_s3_state_keys), var.hermes_truenas_acme_state_key)
    )
    error_message = "ACME must use its original distinct, nonempty state object key without parent traversal."
  }
}

resource "oci_identity_domains_user" "hermes_truenas_s3" {
  idcs_endpoint = var.hermes_truenas_s3_identity_domain_url
  # These server-returned SCIM extensions are present on the adopted user.
  # Keep them in desired state so unrelated IAM plans do not strip them.
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User",
  ]
  user_name    = "hermes-truenas-opentofu-s3"
  display_name = "Hermes TrueNAS OpenTofu S3 backend"
  active       = true

  name {
    given_name  = "Hermes"
    family_name = "TrueNAS OpenTofu S3"
  }

  # OCI added a verified recovery address equal to the work address.
  # Preserve both existing entries; do not trigger a live recovery-mail reset.
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
  }
}

resource "oci_identity_domains_group" "hermes_truenas_s3" {
  idcs_endpoint = var.hermes_truenas_s3_identity_domain_url
  # Identity Domains marks members as returned=request. Request all attributes
  # so provider refreshes retain and detect changes to this security boundary.
  attribute_sets = ["all"]
  # OCI returns the dynamic Group schema even for this static-membership group.
  # Preserve it to avoid an unrelated PUT update during other IAM changes.
  schemas = [
    "urn:ietf:params:scim:schemas:core:2.0:Group",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:dynamic:Group",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group",
  ]
  display_name = "hermes-truenas-opentofu-s3"

  members {
    value = oci_identity_domains_user.hermes_truenas_s3.id
    type  = "User"
  }

  urnietfparamsscimschemasoracleidcsextensiongroup_group {
    description = "S3 backend access limited to the existing TrueNAS OpenTofu states"
  }

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  # Expand only the exact original ACME state and its native lock after
  # operator verification. Do not grant access to any other bucket objects.
  hermes_truenas_authorized_state_keys = setunion(
    var.hermes_truenas_s3_state_keys,
    var.hermes_truenas_acme_state_key == null ? toset([]) : toset([var.hermes_truenas_acme_state_key])
  )
  hermes_truenas_s3_state_key_conditions = join(", ", [
    for key in sort(tolist(local.hermes_truenas_authorized_state_keys)) : "target.object.name = '${key}'"
  ])
  hermes_truenas_s3_lock_key_conditions = join(", ", [
    for key in sort(tolist(local.hermes_truenas_authorized_state_keys)) : "target.object.name = '${key}.tflock'"
  ])
}

resource "oci_identity_policy" "hermes_truenas_s3" {
  compartment_id = var.tenancy_ocid
  name           = "hermes-truenas-opentofu-s3"
  description    = "Exact state and native lock object access; bucket-scoped listing required by OpenTofu"
  statements = [
    # OpenTofu's S3 backend uses ListObjects. OCI's OBJECT_INSPECT also allows
    # HeadObject, and ListObjects cannot be safely restricted by object name;
    # this intentionally reveals object names in this bucket only.
    "Allow group id ${oci_identity_domains_group.hermes_truenas_s3.ocid} to {OBJECT_INSPECT} in compartment id ${var.compartment_ocid} where target.bucket.name = '${var.hermes_truenas_s3_state_bucket}'",
    # Existing state objects are read and overwritten in place. State deletion
    # and creation are not granted.
    "Allow group id ${oci_identity_domains_group.hermes_truenas_s3.ocid} to {OBJECT_READ, OBJECT_OVERWRITE} in compartment id ${var.compartment_ocid} where all {target.bucket.name = '${var.hermes_truenas_s3_state_bucket}', any {${local.hermes_truenas_s3_state_key_conditions}}}",
    # Native lock acquisition creates a new .tflock object conditionally;
    # read permits lock inspection and delete releases it.
    "Allow group id ${oci_identity_domains_group.hermes_truenas_s3.ocid} to {OBJECT_READ, OBJECT_CREATE, OBJECT_DELETE} in compartment id ${var.compartment_ocid} where all {target.bucket.name = '${var.hermes_truenas_s3_state_bucket}', any {${local.hermes_truenas_s3_lock_key_conditions}}}",
  ]
  freeform_tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}
