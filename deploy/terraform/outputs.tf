output "nodes" {
  description = "etcd nodes: hostname -> {vm_id, fqdn, mac, ip}"
  value = {
    for k, v in var.nodes : k => {
      vm_id = v.vm_id
      fqdn  = "${k}.${var.search_domain}"
      mac   = lower(v.mac)
      ip    = v.ip
    }
  }
}

output "etcd_endpoints" {
  description = "Client endpoints for etcdctl --endpoints / ETCDCTL_ENDPOINTS"
  value       = join(",", [for k, v in var.nodes : "http://${v.ip}:2379"])
}

output "ssh_targets" {
  description = "Convenience SSH commands"
  value       = [for k, v in var.nodes : "ssh ${var.ci_user}@${k}.${var.search_domain}"]
}
