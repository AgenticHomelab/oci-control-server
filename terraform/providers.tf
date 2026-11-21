provider "oci" {
  # Instance Principal uses the VM identity, not an OCI CLI configuration file.
  # Preserve the original operator's configured API-key profile otherwise.
  auth                = var.oci_auth_method
  config_file_profile = var.oci_auth_method == "InstancePrincipal" ? null : var.oci_profile
  region              = var.region
}
