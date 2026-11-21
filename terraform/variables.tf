# Opt-in provider authentication for control-01 without copying operator keys.
# Null preserves the provider's existing authentication selection.
variable "oci_auth_method" {
  description = "Optional OCI provider auth override; Hermes uses InstancePrincipal for read-only plans."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.oci_auth_method == null ? true : contains(["APIKey", "InstancePrincipal"], var.oci_auth_method)
    error_message = "Select APIKey or InstancePrincipal, or omit to keep the existing provider auth selection."
  }
}

variable "oci_profile" {
  description = "OCI CLI profile used for authentication"
  type        = string
  default     = "DEFAULT"
}

variable "tenancy_ocid" {
  description = "OCI tenancy OCID"
  type        = string
}

variable "compartment_ocid" {
  description = "OCI compartment OCID"
  type        = string
}

variable "region" {
  description = "OCI region"
  type        = string
  default     = "eu-stockholm-1"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key"
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "ubuntu_image_ocid" {
  description = "Pinned Ubuntu Server 26.04 ARM64 image for future clean creates; live source-image drift is ignored to preserve the upgraded singleton"
  type        = string
  default     = "ocid1.image.oc1.eu-stockholm-1.aaaaaaaazp54xqtal5jhxsjrzem2nxjcqf7rih3tmhubvc4w76eivc63zdla"
}

variable "bootstrap_ssh_cidr" {
  description = "Temporary CIDR allowed to SSH to control-01 during Tailscale bootstrap"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.bootstrap_ssh_cidr == null ||
      can(cidrhost(var.bootstrap_ssh_cidr, 0))
    )
    error_message = "bootstrap_ssh_cidr must be a valid CIDR, for example 203.0.113.10/32."
  }
}

# Expected in AgenticHomelab/homelab-secrets/config/oci-terraform.tfvars
variable "control_vcn_cidr" {
  description = "Private environment-specific OCI network input"
  type        = string
}

variable "control_subnet_cidr" {
  description = "Private environment-specific OCI network input"
  type        = string
}

variable "control_private_ip" {
  description = "Private environment-specific OCI network input"
  type        = string
}

variable "tailscale_direct_source_cidr" {
  description = "Private environment-specific OCI network input"
  type        = string
}

variable "omni_api_https_source_cidr" {
  description = "Private environment-specific OCI network input"
  type        = string
}

variable "omni_siderolink_wireguard_source_cidr" {
  description = "Private environment-specific OCI network input"
  type        = string
}
variable "tailscale_direct_udp_port" {
  description = "Private environment-specific OCI ingress port"
  type        = number
}

variable "omni_api_https_port" {
  description = "Private environment-specific OCI ingress port"
  type        = number
}

variable "omni_siderolink_wireguard_port" {
  description = "Private environment-specific OCI ingress port"
  type        = number
}

variable "bootstrap_ssh_port" {
  description = "Private environment-specific OCI ingress port"
  type        = number
}
