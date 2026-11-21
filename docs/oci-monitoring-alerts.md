# OCI Monitoring alerts

This is the reusable, non-sensitive monitoring contract for the OCI management
server. It does **not** document live alert health, actual subscribers or
tested recovery. Detailed production evidence stays in the private operations
repository.

## Declared resources

`terraform/observability_alerts.tf` optionally declares one OCI Notifications
topic, one email subscription and three OCI Monitoring alarms for the managed
compute instance. All are disabled by default through
`control_oci_alerts_enabled = false`. An explicitly approved email address is
required before enabling the resources and must be provided from protected
runtime inputs, not Git. Sensitive OpenTofu marking reduces normal CLI
display but does not encrypt state or hide the recipient from OCI.

The rules cover missing Compute Agent CPU telemetry, sustained high memory
utilization and sustained high CPU utilization. Missing telemetry is not proof
that the VM is down. These alarms are deliberately separate from host-native
checks and do not introduce an agent, exporter or custom alerting service.

## Safe activation boundary

1. Verify the exact existing OCI resource addresses, operator permissions,
   original protected S3 backend and native state lock. Do not initialize
   against a new state or disable locking to bypass missing access.
2. Independently confirm the supported Compute Agent metric stream and
   alarm-query behavior for the selected instance and region.
3. Confirm subscription recipient approval, notification costs and operator
   recovery access. A newly created email subscription may remain PENDING
   until the recipient accepts it.
4. Obtain separate authorization for a refreshing, locked OpenTofu plan.
   Review the whole plan for unexpected IAM scope changes, replacements,
   deletions, recipient exposure and unrelated drift before any apply.
5. After separately authorized deployment, validate notification delivery
   and each relevant alarm signal by live, non-disruptive evidence.
   A source-only CI pass is never notification-delivery acceptance.

## Incident response and rollback

Investigate missing metrics and service health separately. Prefer supported
OCI Monitoring, Compute Agent and native host logs. Do not restart workloads
automatically in response to a metric alert. For any rollback, preserve the
original remote state and notification topic/subscriber identities; inspect a
fresh plan before modifying any infrastructure. Record actual live acceptance
only in its approved private operational location.
