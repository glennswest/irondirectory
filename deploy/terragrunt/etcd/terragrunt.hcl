# Unit: irondirectory backing fastetcd cluster (D1) — dm1/dm2/dm3.g8.lo
#
# References the shared, versioned proxmox-fedora-vm module (pinned ?ref) — no
# copied .tf. Per-node install is driven through the module's `user_data` hook
# with a rendered cloud-config that `dnf install`s the RELEASED fastetcd RPM
# (no hand-build, no container). Nodes boot together and form a 3-node Raft
# cluster. fastetcd is the backing store (D1) — never upstream etcd.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::ssh://git@github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.1.0"
}

locals {
  # Released fastetcd RPM (pinned). Published at:
  #   https://github.com/glennswest/fastetcd/releases/tag/v0.8.0
  # v0.8.0 carries the v0.7.0 fixes for fastetcd#4 (client writes on a
  # non-leader now forward correctly) and fastetcd#5 (HTTP GET /health on
  # the client port) — the live dm1/dm2/dm3 cluster was upgraded in place
  # (rolling dnf upgrade, followers then leader) and verified.
  fastetcd_version = "v0.8.0"
  fastetcd_rpm_url = "https://github.com/glennswest/fastetcd/releases/download/v0.8.0/fastetcd-0.8.0-1.x86_64.rpm"
  cluster_token    = "irondir-etcd"
  ssh_key          = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))

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
        hostname         = k
        fqdn             = "${k}.g8.lo"
        ci_user          = "fedora"
        ssh_keys         = [local.ssh_key]
        node_ip          = v.ip
        initial_cluster  = local.initial_cluster
        cluster_token    = local.cluster_token
        fastetcd_version = local.fastetcd_version
        fastetcd_rpm_url = local.fastetcd_rpm_url
      })
    }
  }
}
