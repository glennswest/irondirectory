# Unit: throwaway SPNEGO/mod_auth_gssapi verification (#16)
#
# One disposable Fedora VM: real iron-kdcd (binary copied in post-boot,
# not built via cloud-init) serving one realm/partition, plus real
# httpd + mod_auth_gssapi fronting a Kerberos-protected location --
# proving iron-kdc-issued tickets/keytabs interoperate with a THIRD
# independent GSSAPI acceptor (beyond iron-ldap's own, #7, and sshd's,
# #8), the piece OpenShift's RequestHeader+SPNEGO desktop-console SSO
# (D7) actually depends on. `terragrunt destroy` tears it down once the
# validation is done.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::https://github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.3.0"
}

locals {
  ssh_key = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))

  # Verified free via get-free-vmid.sh immediately before this unit was
  # written (2026-07-14).
  spnegotest = { vm_id = 2002, mac = "BC:24:11:08:20:07", ip = "192.168.8.65" }
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "spnego-verify", "throwaway"]
  vm_datastore       = "test-lvm-thin"
  snippet_datastore  = "terraform-snippets"

  vms = {
    spnegotest = {
      vm_id     = local.spnegotest.vm_id
      mac       = local.spnegotest.mac
      ip        = local.spnegotest.ip
      cores     = 1
      memory    = 1536
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/spnego-node-user-data.yaml.tftpl", {
        hostname = "spnegotest"
        fqdn     = "spnegotest.g8.lo"
        ci_user  = "fedora"
        ssh_keys = [local.ssh_key]
        realm    = "G16SPNEGO.LO"
      })
    }
  }
}
