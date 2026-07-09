# Unit: irondirectory LDAP redundancy — il1/il2/il3.g8.lo
#
# References the shared, versioned proxmox-fedora-vm module (pinned ?ref) — no
# copied .tf; same module dm1/dm2/dm3 (deploy/terragrunt/etcd) use. Per-node
# install is driven through the module's `user_data` hook with a rendered
# cloud-config that `dnf install`s the RELEASED iron-ldapd RPM (no hand-build,
# no container). Unlike the fastetcd cluster, these three nodes are NOT a
# cluster themselves — iron-ldap is stateless (D2/D8: all state lives in
# fastetcd's Raft), so each replica independently connects to the same
# fastetcd cluster. Redundancy is "N identical stateless replicas behind a
# health-checked LB" (see ../dns/ldap-lb.sh), the same pattern already used
# for etcd.g8.lo.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  # https (not the etcd unit's ssh://) so this applies cleanly from any
  # box with a git credential helper configured (e.g. `gh auth login`)
  # rather than needing a dedicated deploy key -- this unit is run from
  # dev.g8.lo (on the g8 LAN, stable path to the Proxmox API) rather than
  # a workstation with its own GitHub SSH key.
  source = "git::https://github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.2.0"
}

locals {
  # Released iron-ldapd RPM (pinned). Published at:
  #   https://github.com/glennswest/irondirectory/releases/tag/v0.5.0
  # v0.5.0 adds AD-shaped rootDSE naming contexts (defaultNamingContext,
  # rootDomainNamingContext, etc.) closing out #4's last gap -- the live
  # il1/il2/il3 nodes were upgraded in place (dnf install <rpm url>).
  iron_ldapd_version = "v0.5.0"
  iron_ldapd_rpm_url  = "https://github.com/glennswest/irondirectory/releases/download/v0.5.0/iron-ldapd-0.5.0-1.x86_64.rpm"

  # The shared fastetcd backend (D1) -- same cluster iron-store's tests
  # target, health-checked LB at etcd.g8.lo.
  fastetcd_endpoint = "http://etcd.g8.lo:2379"
  partition_id      = "g10"
  base_dn           = "dc=g10,dc=lo"

  ssh_key = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))

  # LDAP nodes: fixed MAC -> reserved IP (outside the g8 DHCP pool
  # .100-.200, and outside dm1/dm2/dm3's .41-.43).
  nodes = {
    il1 = { vm_id = 134, mac = "BC:24:11:08:00:14", ip = "192.168.8.44" }
    il2 = { vm_id = 135, mac = "BC:24:11:08:00:15", ip = "192.168.8.45" }
    il3 = { vm_id = 136, mac = "BC:24:11:08:00:16", ip = "192.168.8.46" }
  }
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "ldap"]

  vms = {
    for k, v in local.nodes : k => {
      vm_id     = v.vm_id
      mac       = v.mac
      ip        = v.ip
      cores     = 1
      memory    = 1024
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/ldap-user-data.yaml.tftpl", {
        hostname            = k
        fqdn                = "${k}.g8.lo"
        ci_user             = "fedora"
        ssh_keys            = [local.ssh_key]
        fastetcd_endpoint   = local.fastetcd_endpoint
        partition_id        = local.partition_id
        base_dn             = local.base_dn
        iron_ldapd_version  = local.iron_ldapd_version
        iron_ldapd_rpm_url  = local.iron_ldapd_rpm_url
      })
    }
  }
}
