data "oci_core_boot_volume_attachments" "control" {
  availability_domain = local.availability_domain
  compartment_id      = var.compartment_ocid
  instance_id         = oci_core_instance.control.id
}

locals {
  control_boot_volume_id = one(
    data.oci_core_boot_volume_attachments.control.boot_volume_attachments
  ).boot_volume_id
}

resource "oci_core_volume_backup_policy" "control" {
  compartment_id = var.compartment_ocid
  display_name   = "control-01-daily"
  freeform_tags  = local.common_tags

  schedules {
    backup_type       = "INCREMENTAL"
    period            = "ONE_DAY"
    retention_seconds = 172800

    offset_type = "STRUCTURED"
    hour_of_day = 3
    time_zone   = "UTC"
  }
}

resource "oci_core_volume_backup_policy_assignment" "control" {
  asset_id  = local.control_boot_volume_id
  policy_id = oci_core_volume_backup_policy.control.id
}

output "control_boot_volume_id" {
  description = "OCID of the control-01 boot volume"
  value       = local.control_boot_volume_id
}

output "backup_policy_id" {
  description = "OCID of the control-01 rolling backup policy"
  value       = oci_core_volume_backup_policy.control.id
}
