# Unit: throwaway SSSD end-to-end validation host (#7)
#
# NOT a redundancy/production unit like ../ldap or ../etcd -- a single,
# disposable Fedora VM used to validate that a real Linux client
# resolves users/groups via id_provider=ldap against iron-ldap and
# authenticates logins via auth_provider=krb5 against iron-kdc. Intended
# to be `terragrunt destroy`ed once #7's SSSD e2e validation is done;
# iron-ldapd/iron-kdcd themselves keep running on dev.g8.lo (a throwaway
# g8gssapi1 partition/realm, not the redundant il1/il2/il3 deployment),
# not on this VM.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::https://github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.1.0"
}

locals {
  ssh_key = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))

  # Throwaway g8gssapi1 partition/realm already provisioned by hand on
  # dev.g8.lo for #7's GSSAPI bind live-testing (iron-kdcd :8891,
  # iron-ldapd :3895) -- this VM is only the SSSD client pointed at it.
  kdc_host_port = "dev.g8.lo:8891"
  ldap_uri      = "ldap://dev.g8.lo:3895"
  base_dn       = "dc=g8gssapi1,dc=lo"
  krb5_realm    = "G8GSSAPI.LO"
  domain        = "g8gssapi1.lo"

  # Next free vm_id/MAC/IP after il1/il2/il3 (134-136, .44-.46).
  vm_id = 137
  mac   = "BC:24:11:08:00:17"
  ip    = "192.168.8.47"
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "sssd-test", "throwaway"]

  vms = {
    sssdtest = {
      vm_id     = local.vm_id
      mac       = local.mac
      ip        = local.ip
      cores     = 1
      memory    = 1024
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/sssd-test-user-data.yaml.tftpl", {
        hostname      = "sssdtest"
        fqdn          = "sssdtest.g8.lo"
        ci_user       = "fedora"
        ssh_keys      = [local.ssh_key]
        kdc_host_port = local.kdc_host_port
        ldap_uri      = local.ldap_uri
        base_dn       = local.base_dn
        krb5_realm    = local.krb5_realm
        domain        = local.domain
      })
    }
  }
}
