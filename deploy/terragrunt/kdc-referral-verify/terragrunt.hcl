# Unit: throwaway two-realm Kerberos cross-realm referral verification (#11)
#
# Two disposable Fedora VMs, built/thrown away: each builds iron-kdcd
# from source (no released RPM covers #11's referral-routing work yet)
# and runs it serving one real Kerberos realm/partition:
#
#   - kdcparent: dc=g11ref,dc=lo (partition g11ref, realm G11REF.LO),
#     also loads the forest's persisted topology (IRON_KDC_CONFIG_*) so
#     TGS-REQ can find the one-hop trust with the child realm.
#   - kdcchild:  dc=emea,dc=g11ref,dc=lo (partition g11ref-emea, realm
#     EMEA.G11REF.LO), hosting a test service principal.
#
# Forest/config bootstrap (iron-config-ctl init-forest/create-child),
# principal provisioning (iron-kdc-ctl set-password/set-cross-realm-key)
# and the actual kinit/kvno referral-chase test are all run from
# dev.g8.lo directly against the shared fastetcd cluster and these two
# VMs' KDC ports -- no need for either VM to build iron-kdc-ctl/
# iron-config-ctl itself. `terragrunt destroy` tears down both once the
# validation is done.

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
  config_partition_id = "g11ref-config"
  config_base_dn      = "cn=configuration,dc=g11ref,dc=lo"

  parent_realm = "G11REF.LO"
  child_realm  = "EMEA.G11REF.LO"

  # Verified free via get-free-vmid.sh immediately before this unit was
  # written (2026-07-10).
  kdcparent = { vm_id = 2002, mac = "BC:24:11:08:20:05", ip = "192.168.8.65" }
  kdcchild  = { vm_id = 2003, mac = "BC:24:11:08:20:06", ip = "192.168.8.66" }
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "kdc-referral-verify", "throwaway"]
  vm_datastore       = "test-lvm-thin"
  snippet_datastore  = "terraform-snippets"

  vms = {
    kdcparent = {
      vm_id     = local.kdcparent.vm_id
      mac       = local.kdcparent.mac
      ip        = local.kdcparent.ip
      cores     = 1
      memory    = 1536
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/kdc-node-user-data.yaml.tftpl", {
        hostname            = "kdcparent"
        fqdn                = "kdcparent.g8.lo"
        ci_user             = "fedora"
        ssh_keys            = [local.ssh_key]
        git_ref             = local.git_ref
        fastetcd_endpoint   = local.fastetcd_endpoint
        partition_id        = "g11ref"
        base_dn             = "dc=g11ref,dc=lo"
        realm               = local.parent_realm
        config_partition_id = local.config_partition_id
        config_base_dn      = local.config_base_dn
        default_realm       = local.parent_realm
        parent_realm        = local.parent_realm
        child_realm         = local.child_realm
        parent_kdc_addr     = "${local.kdcparent.ip}:88"
        child_kdc_addr      = "${local.kdcchild.ip}:88"
      })
    }
    kdcchild = {
      vm_id     = local.kdcchild.vm_id
      mac       = local.kdcchild.mac
      ip        = local.kdcchild.ip
      cores     = 1
      memory    = 1536
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/kdc-node-user-data.yaml.tftpl", {
        hostname            = "kdcchild"
        fqdn                = "kdcchild.g8.lo"
        ci_user             = "fedora"
        ssh_keys            = [local.ssh_key]
        git_ref             = local.git_ref
        fastetcd_endpoint   = local.fastetcd_endpoint
        partition_id        = "g11ref-emea"
        base_dn             = "dc=emea,dc=g11ref,dc=lo"
        realm               = local.child_realm
        config_partition_id = ""
        config_base_dn      = ""
        default_realm       = local.child_realm
        parent_realm        = local.parent_realm
        child_realm         = local.child_realm
        parent_kdc_addr     = "${local.kdcparent.ip}:88"
        child_kdc_addr      = "${local.kdcchild.ip}:88"
      })
    }
  }
}
