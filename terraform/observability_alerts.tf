# Independent OCI Monitoring alarms. No custom runtime agents/relays.
# Inert until explicitly enabled with an approved email recipient.
variable "control_oci_alerts_enabled" {
  description = "Opt in to the reviewed control-01 OCI alarms, topic, and EMAIL subscription."
  type        = bool
  default     = false
}

variable "control_oci_alert_email" {
  description = "Explicitly approved EMAIL destination. Supply in ignored tfvars or TF_VAR; do not store a personal address in Git."
  type        = string
  default     = null
  nullable    = true
  # Redact the selected recipient in normal OpenTofu CLI plan/apply output.
  # This does NOT encrypt OpenTofu state or hide the endpoint from OCI.
  sensitive = true

  validation {
    condition = (
      var.control_oci_alert_email == null ||
      can(regex("^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$", var.control_oci_alert_email))
    )
    error_message = "Provide one valid email address or null."
  }
}

# Confirmed OCI Compute Agent CPU/memory streams, never unverified instance
# health metrics. All queries target the managed instance by resourceId.
locals {
  control_oci_alarm_definitions = {
    telemetry_missing = {
      display_name                 = "control-01: agent metrics missing"
      severity                     = "CRITICAL"
      pending_duration             = "PT5M"
      repeat_notification_duration = "PT2H"
      query                        = "CpuUtilization[10m]{resourceId = \"${oci_core_instance.control.id}\"}.groupBy(resourceId).absent(72h)"
      body                         = "No control-01 OCI Compute Agent CPU telemetry. Verify instance state and agent/telemetry path independently; loss of data does not prove VM outage. See docs/oci-monitoring-alerts.md."
    }
    memory_pressure = {
      display_name                 = "control-01: sustained high memory"
      severity                     = "WARNING"
      pending_duration             = "PT10M"
      repeat_notification_duration = "PT6H"
      query                        = "MemoryUtilization[5m]{resourceId = \"${oci_core_instance.control.id}\"}.mean() > 92"
      body                         = "Memory exceeds 92 percent over a sustained period. Diagnose host workload; do not restart production services automatically. See docs/oci-monitoring-alerts.md."
    }
    cpu_pressure = {
      display_name                 = "control-01: sustained CPU saturation"
      severity                     = "WARNING"
      pending_duration             = "PT10M"
      repeat_notification_duration = "PT6H"
      query                        = "CpuUtilization[5m]{resourceId = \"${oci_core_instance.control.id}\"}.mean() > 95"
      body                         = "CPU exceeds 95 percent over a sustained period. Diagnose host workload; do not restart production services automatically. See docs/oci-monitoring-alerts.md."
    }
  }
}

resource "oci_ons_notification_topic" "control_alerts" {
  count          = var.control_oci_alerts_enabled ? 1 : 0
  compartment_id = var.compartment_ocid
  name           = "control-01-independent-alerts"
  description    = "External OCI Monitoring alarms for control-01, independent of Grafana."
  freeform_tags  = local.common_tags

  lifecycle {
    precondition {
      condition     = try(length(trimspace(var.control_oci_alert_email)) > 0, false)
      error_message = "An approved control_oci_alert_email is required before enabling alerts."
    }
  }
}

resource "oci_ons_subscription" "control_alert_email" {
  count          = var.control_oci_alerts_enabled ? 1 : 0
  compartment_id = var.compartment_ocid
  topic_id       = oci_ons_notification_topic.control_alerts[0].id
  protocol       = "EMAIL"
  endpoint       = var.control_oci_alert_email
  # Remains PENDING until the actual recipient confirms the emailed link.
}

resource "oci_monitoring_alarm" "control" {
  for_each                                      = var.control_oci_alerts_enabled ? local.control_oci_alarm_definitions : {}
  compartment_id                                = var.compartment_ocid
  metric_compartment_id                         = var.compartment_ocid
  namespace                                     = "oci_computeagent"
  display_name                                  = each.value.display_name
  destinations                                  = [oci_ons_notification_topic.control_alerts[0].id]
  is_enabled                                    = true
  severity                                      = each.value.severity
  query                                         = each.value.query
  pending_duration                              = each.value.pending_duration
  body                                          = each.value.body
  resolution                                    = "1m"
  message_format                                = "ONS_OPTIMIZED"
  is_notifications_per_metric_dimension_enabled = false
  repeat_notification_duration                  = each.value.repeat_notification_duration
  freeform_tags                                 = local.common_tags
}

output "control_oci_alerts_metadata" {
  description = "Non-secret alert resource identifiers; null while feature is disabled."
  value = var.control_oci_alerts_enabled ? {
    topic_id        = oci_ons_notification_topic.control_alerts[0].id
    subscription_id = oci_ons_subscription.control_alert_email[0].id
    alarm_ids       = { for name, alarm in oci_monitoring_alarm.control : name => alarm.id }
  } : null
}
