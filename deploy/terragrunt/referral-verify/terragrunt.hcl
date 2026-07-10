# Unit: throwaway two-server referral generation+chasing verification (#10)
#
# Two disposable Fedora VMs, built/thrown away: each builds
# iron-ldapd + iron-config-ctl from source (no released RPM covers
# either #9's registry work or #10's registry-driven referrals yet) and
# runs iron-ldapd serving one real naming context:
#
#   - refparent: dc=g9demo,dc=lo (partition g9demo), also loads the
#     forest's persisted topology (IRON_LDAP_CONFIG_*) for
#     registry-driven referral generation.
#   - refchild:  dc=emea,dc=g9demo,dc=lo (partition g9demo-emea).
#
# iron-config-ctl provisioning (init-forest/create-child/set-ldap-url)
# is a manual step run once both nodes are up -- it needs a specific
# order across both VMs that cloud-init can't sequence. `terragrunt
# destroy` tears down both once the validation is done.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::https://github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.3.0"
}

locals {
  ssh_key = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))
  git_ref = "main"

  fastetcd_endpoint = "http://etcd.g8.lo:2379"
  config_partition_id = "g9demo-config"
  config_base_dn      = "cn=configuration,dc=g9demo,dc=lo"

  # Verified free via get-free-vmid.sh immediately before this unit was
  # written (2026-07-10).
  refparent = { vm_id = 2000, mac = "BC:24:11:08:20:01", ip = "192.168.8.61" }
  refchild  = { vm_id = 2001, mac = "BC:24:11:08:20:02", ip = "192.168.8.62" }
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "referral-verify", "throwaway"]
  vm_datastore       = "test-lvm-thin"
  snippet_datastore  = "terraform-snippets"

  vms = {
    refparent = {
      vm_id     = local.refparent.vm_id
      mac       = local.refparent.mac
      ip        = local.refparent.ip
      cores     = 1
      memory    = 1024
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/ldap-node-user-data.yaml.tftpl", {
        hostname            = "refparent"
        fqdn                = "refparent.g8.lo"
        ci_user             = "fedora"
        ssh_keys            = [local.ssh_key]
        git_ref             = local.git_ref
        fastetcd_endpoint   = local.fastetcd_endpoint
        partition_id        = "g9demo"
        base_dn             = "dc=g9demo,dc=lo"
        config_partition_id = local.config_partition_id
        config_base_dn      = local.config_base_dn
      })
    }
    refchild = {
      vm_id     = local.refchild.vm_id
      mac       = local.refchild.mac
      ip        = local.refchild.ip
      cores     = 1
      memory    = 1024
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/ldap-node-user-data.yaml.tftpl", {
        hostname            = "refchild"
        fqdn                = "refchild.g8.lo"
        ci_user             = "fedora"
        ssh_keys            = [local.ssh_key]
        git_ref             = local.git_ref
        fastetcd_endpoint   = local.fastetcd_endpoint
        partition_id        = "g9demo-emea"
        base_dn             = "dc=emea,dc=g9demo,dc=lo"
        config_partition_id = ""
        config_base_dn      = ""
      })
    }
  }
}
