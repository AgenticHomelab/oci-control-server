output "instance_id" {
  description = "OCID of control-01"
  value       = oci_core_instance.control.id
}

output "private_ip" {
  description = "Private IPv4 address of control-01"
  value       = oci_core_instance.control.private_ip
}

output "public_ip" {
  description = "Reserved public IPv4 address of control-01"
  value       = oci_core_public_ip.control.ip_address
}

output "ssh_command" {
  description = "SSH command over Tailscale"
  value       = "ssh ubuntu@control-01"
}

