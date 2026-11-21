# Oracle Identity Domains cannot delete this retired backup writer because
# IDCSApp's "Identity Domain Administrator" AppRole cannot be resolved.
# The last Customer Secret Key was revoked (operator-reported, 2026-11-18).
# Keep the user in OCI, but stop managing it through the original remote state.
removed {
  from = oci_identity_user.talos_etcd_backups

  lifecycle {
    destroy = false
  }
}
