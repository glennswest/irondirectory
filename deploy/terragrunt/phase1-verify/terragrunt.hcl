# Unit: throwaway RHEL enrollment / GSSAPI SSH SSO / rocketsmbd sec=krb5
# verification environment (#8)
#
# Two disposable Fedora VMs, built/thrown away -- nothing runs on
# dev.g8.lo itself (a pure git-clone/build host for the OTHER project,
# rocketsmbd, was already cloned there beforehand; this unit doesn't
# touch it):
#
#   - kdc: builds iron-kdcd/iron-ldapd FROM SOURCE (no released RPM
#     covers #7's SASL/GSSAPI work yet) and runs both. Also has
#     krb5-workstation + cifs-utils installed to act as the *client*
#     for the SSH/SMB tests against memberhost.
#   - memberhost: a "domain member" -- SSH server (GSSAPIAuthentication)
#     and rocketsmbd (built from source, --features kerberos) acting as
#     an SMB server for sec=krb5. Both authenticate against iron-kdc on
#     the kdc VM, a cross-project interop check (rocketsmbd's own #37
#     already verified sec=krb5 against MIT krb5/Samba; this is the
#     same test against iron-kdc instead).
#
# `terragrunt destroy` tears down both once the validation is done.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::https://github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.1.0"
}

locals {
  ssh_key = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))

  fastetcd_endpoint = "http://etcd.g8.lo:2379"
  partition_id      = "g8phase1verify"
  base_dn           = "dc=g8phase1verify,dc=lo"
  krb5_realm        = "G8PHASE1.LO"
  domain            = "g8phase1verify.lo"
  git_ref           = "main"
  rocketsmbd_git_ref = "main"

  # Next free vm_id/MAC/IP after il1/il2/il3 (134-136), sssd-test's
  # ironrealm/sssdtest (137-138) -- those are destroyed but keeping the
  # numbering free of collisions regardless.
  kdc        = { vm_id = 139, mac = "BC:24:11:08:00:19", ip = "192.168.8.49" }
  memberhost = { vm_id = 140, mac = "BC:24:11:08:00:1a", ip = "192.168.8.50" }
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "phase1-verify", "throwaway"]

  vms = {
    kdc = {
      vm_id     = local.kdc.vm_id
      mac       = local.kdc.mac
      ip        = local.kdc.ip
      cores     = 2
      memory    = 2048
      disk_size = 30
      user_data = templatefile("${get_terragrunt_dir()}/templates/kdc-user-data.yaml.tftpl", {
        hostname          = "kdc"
        fqdn              = "kdc.g8.lo"
        ci_user           = "fedora"
        ssh_keys          = [local.ssh_key]
        fastetcd_endpoint = local.fastetcd_endpoint
        partition_id      = local.partition_id
        base_dn           = local.base_dn
        krb5_realm        = local.krb5_realm
        domain            = local.domain
        git_ref           = local.git_ref
      })
    }
    memberhost = {
      vm_id     = local.memberhost.vm_id
      mac       = local.memberhost.mac
      ip        = local.memberhost.ip
      cores     = 2
      memory    = 2048
      disk_size = 30
      user_data = templatefile("${get_terragrunt_dir()}/templates/memberhost-user-data.yaml.tftpl", {
        hostname            = "memberhost"
        fqdn                = "memberhost.g8.lo"
        ci_user             = "fedora"
        ssh_keys            = [local.ssh_key]
        kdc_host            = "kdc.g8.lo"
        krb5_realm          = local.krb5_realm
        domain              = local.domain
        rocketsmbd_git_ref  = local.rocketsmbd_git_ref
      })
    }
  }
}
