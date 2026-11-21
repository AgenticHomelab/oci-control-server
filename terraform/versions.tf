terraform {
  required_version = "~> 1.12.0"

  required_providers {
    oci = {
      source  = "registry.opentofu.org/oracle/oci"
      version = "~> 8.29.0"
    }
  }
}
