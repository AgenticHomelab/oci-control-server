data "oci_identity_availability_domains" "available" {
  compartment_id = var.tenancy_ocid
}
