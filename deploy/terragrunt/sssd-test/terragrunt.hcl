# Unit: throwaway SSSD end-to-end validation environment (#7)
#
# NOT a redundancy/production unit like ../ldap or ../etcd -- two
# disposable Fedora VMs used to validate that a real Linux client
# resolves users/groups via id_provider=ldap against iron-ldap and
# authenticates logins via auth_provider=krb5 against iron-kdc, without
# touching dev.g8.lo at all (that box stays a pure git-clone/build
# host, nothing from this test runs or lives there):
#
#   - ironrealm: builds iron-kdcd/iron-ldapd FROM SOURCE (no released
#     RPM covers the SASL/GSSAPI work yet, #7) and runs both directly.
#   - sssdtest: SSSD client (id_provider=ldap, auth_provider=krb5)
#     pointed at ironrealm.
#
# `terragrunt destroy` tears down both once the validation is done.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::https://github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.2.0"
}

locals {
  ssh_key = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))

  fastetcd_endpoint = "http://etcd.g8.lo:2379"
  partition_id      = "g8gssapi1"
  base_dn           = "dc=g8gssapi1,dc=lo"
  krb5_realm        = "G8GSSAPI.LO"
  domain            = "g8gssapi1.lo"
  test_user          = "dave"
  test_user_password = "gssapitestpassword"
  git_ref            = "main"

  # Next free vm_id/MAC/IP after il1/il2/il3 (134-136, .44-.46).
  ironrealm = { vm_id = 138, mac = "BC:24:11:08:00:18", ip = "192.168.8.48" }
  sssdtest  = { vm_id = 137, mac = "BC:24:11:08:00:17", ip = "192.168.8.47" }
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "sssd-test", "throwaway"]

  vms = {
    ironrealm = {
      vm_id     = local.ironrealm.vm_id
      mac       = local.ironrealm.mac
      ip        = local.ironrealm.ip
      cores     = 2
      memory    = 2048
      disk_size = 20
      user_data = templatefile("${get_terragrunt_dir()}/templates/ironrealm-user-data.yaml.tftpl", {
        hostname            = "ironrealm"
        fqdn                = "ironrealm.g8.lo"
        ci_user             = "fedora"
        ssh_keys            = [local.ssh_key]
        fastetcd_endpoint   = local.fastetcd_endpoint
        partition_id        = local.partition_id
        base_dn             = local.base_dn
        krb5_realm          = local.krb5_realm
        test_user           = local.test_user
        test_user_password  = local.test_user_password
        git_ref             = local.git_ref
      })
    }
    sssdtest = {
      vm_id     = local.sssdtest.vm_id
      mac       = local.sssdtest.mac
      ip        = local.sssdtest.ip
      cores     = 1
      memory    = 1024
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/sssd-test-user-data.yaml.tftpl", {
        hostname      = "sssdtest"
        fqdn          = "sssdtest.g8.lo"
        ci_user       = "fedora"
        ssh_keys      = [local.ssh_key]
        kdc_host_port = "ironrealm.g8.lo:88"
        ldap_uri      = "ldap://ironrealm.g8.lo:389"
        base_dn       = local.base_dn
        krb5_realm    = local.krb5_realm
        domain        = local.domain
      })
    }
  }
}
