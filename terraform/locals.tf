locals {
  availability_domain = data.oci_identity_availability_domains.available.availability_domains[0].name

  common_tags = {
    managed-by = "opentofu"
    project    = "oci-control-server"
  }
}
