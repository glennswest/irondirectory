# Unit: irondirectory backing etcd cluster (D1) — dm1/dm2/dm3.g8.lo
#
# References the shared, versioned proxmox-fedora-vm module (pinned ?ref) — no
# copied .tf. Per-node etcd install is driven through the module's `user_data`
# hook with a rendered cloud-config; the nodes boot together and form a 3-node
# Raft cluster. fastetcd is a drop-in swap (same flags/env; change the install
# source in the template).

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::ssh://git@github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.1.0"
}

locals {
  etcd_version  = "v3.6.12"
  cluster_token = "irondir-etcd"
  data_dir      = "/var/lib/etcd"
  ssh_key       = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))

  # etcd nodes: fixed MAC -> reserved IP (outside the g8 DHCP pool .100-.200).
  nodes = {
    dm1 = { vm_id = 131, mac = "BC:24:11:08:00:11", ip = "192.168.8.41" }
    dm2 = { vm_id = 132, mac = "BC:24:11:08:00:12", ip = "192.168.8.42" }
    dm3 = { vm_id = 133, mac = "BC:24:11:08:00:13", ip = "192.168.8.43" }
  }

  # etcd static-bootstrap peer list: name=http://ip:2380,...
  initial_cluster = join(",", [for k, v in local.nodes : "${k}=http://${v.ip}:2380"])
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "etcd"]

  vms = {
    for k, v in local.nodes : k => {
      vm_id     = v.vm_id
      mac       = v.mac
      ip        = v.ip
      cores     = 2
      memory    = 2048
      disk_size = 30
      user_data = templatefile("${get_terragrunt_dir()}/templates/etcd-user-data.yaml.tftpl", {
        hostname        = k
        fqdn            = "${k}.g8.lo"
        ci_user         = "fedora"
        ssh_keys        = [local.ssh_key]
        node_ip         = v.ip
        initial_cluster = local.initial_cluster
        cluster_token   = local.cluster_token
        etcd_version    = local.etcd_version
        data_dir        = local.data_dir
      })
    }
  }
}
