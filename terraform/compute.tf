resource "oci_core_instance" "control" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.availability_domain

  display_name = "control-01"
  shape        = "VM.Standard.A1.Flex"

  shape_config {
    ocpus         = 4
    memory_in_gbs = 24
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.public.id
    display_name     = "control-01-vnic"
    hostname_label   = "control-01"
    private_ip       = var.control_private_ip
    assign_public_ip = false
    nsg_ids          = [oci_core_network_security_group.control.id]
  }

  source_details {
    source_type             = "image"
    source_id               = var.ubuntu_image_ocid
    boot_volume_size_in_gbs = 200
  }

  metadata = {
    ssh_authorized_keys = trimspace(file(pathexpand(var.ssh_public_key_path)))
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  freeform_tags = local.common_tags

  lifecycle {
    prevent_destroy = true

    # Production was upgraded in place from 24.04. Keep the live singleton,
    # while allowing a future clean create to use the configured 26.04 image.
    ignore_changes = [source_details[0].source_id]
  }
}

data "oci_core_vnic_attachments" "control" {
  compartment_id = var.compartment_ocid
  instance_id    = oci_core_instance.control.id
}

data "oci_core_private_ips" "control" {
  vnic_id = data.oci_core_vnic_attachments.control.vnic_attachments[0].vnic_id
}

locals {
  control_primary_private_ip_id = one([
    for ip in data.oci_core_private_ips.control.private_ips : ip.id
    if ip.is_primary
  ])
}

resource "oci_core_public_ip" "control" {
  compartment_id = var.compartment_ocid
  display_name   = "control-01-public-ip"
  lifetime       = "RESERVED"

  private_ip_id = local.control_primary_private_ip_id

  freeform_tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}
