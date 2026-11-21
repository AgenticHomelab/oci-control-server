resource "oci_core_vcn" "control" {
  compartment_id = var.compartment_ocid
  cidr_block     = var.control_vcn_cidr
  display_name   = "control-vcn"
  dns_label      = "control"

  freeform_tags = local.common_tags
}

resource "oci_core_internet_gateway" "control" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.control.id
  display_name   = "control-igw"
  enabled        = true

  freeform_tags = local.common_tags
}

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.control.id
  display_name   = "control-public-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.control.id
  }

  freeform_tags = local.common_tags
}

resource "oci_core_security_list" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.control.id
  display_name   = "control-public-sl"

  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
  }

  freeform_tags = local.common_tags
}

resource "oci_core_subnet" "public" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.control.id
  cidr_block                 = var.control_subnet_cidr
  display_name               = "control-public-subnet"
  dns_label                  = "public"
  prohibit_public_ip_on_vnic = false

  route_table_id    = oci_core_route_table.public.id
  security_list_ids = [oci_core_security_list.public.id]

  freeform_tags = local.common_tags
}

resource "oci_core_network_security_group" "control" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.control.id
  display_name   = "control-01-nsg"

  freeform_tags = local.common_tags
}

resource "oci_core_network_security_group_security_rule" "bootstrap_ssh" {
  count = var.bootstrap_ssh_cidr == null ? 0 : 1

  network_security_group_id = oci_core_network_security_group.control.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.bootstrap_ssh_cidr
  source_type               = "CIDR_BLOCK"
  description               = "Temporary SSH access for Tailscale bootstrap"

  tcp_options {
    destination_port_range {
      min = var.bootstrap_ssh_port
      max = var.bootstrap_ssh_port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "tailscale_direct" {
  network_security_group_id = oci_core_network_security_group.control.id
  direction                 = "INGRESS"
  protocol                  = "17"
  source                    = var.tailscale_direct_source_cidr
  source_type               = "CIDR_BLOCK"
  description               = "Allow Tailscale direct UDP connections"

  udp_options {
    destination_port_range {
      min = var.tailscale_direct_udp_port
      max = var.tailscale_direct_udp_port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "omni_api_https" {
  network_security_group_id = oci_core_network_security_group.control.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.omni_api_https_source_cidr
  source_type               = "CIDR_BLOCK"
  description               = "Allow Omni SideroLink API HTTPS"

  tcp_options {
    destination_port_range {
      min = var.omni_api_https_port
      max = var.omni_api_https_port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "omni_siderolink_wireguard" {
  network_security_group_id = oci_core_network_security_group.control.id
  direction                 = "INGRESS"
  protocol                  = "17"
  source                    = var.omni_siderolink_wireguard_source_cidr
  source_type               = "CIDR_BLOCK"
  description               = "Allow Omni SideroLink WireGuard"

  udp_options {
    destination_port_range {
      min = var.omni_siderolink_wireguard_port
      max = var.omni_siderolink_wireguard_port
    }
  }
}
