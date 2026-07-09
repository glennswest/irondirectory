# Unit: throwaway iron-config-ctl verification host (#9)
#
# A single disposable Fedora VM, built/thrown away: clones + builds
# iron-config-ctl from source (no released RPM covers this new crate
# yet) and runs a handful of one-shot CLI invocations against the
# shared fastetcd cluster (etcd.g8.lo) -- init-forest, create-child,
# show. No long-lived service.
#
# vm_id verified free on the live node via
# ../get-free-vmid.sh (terraform-modules' canonical copy) before being
# written here -- never pattern-guessed. Uses test-lvm-thin (not
# local-lvm) per the post-incident storage-isolation practice: test VM
# disks stay off any storage that also hosts hand-created/production
# VMs.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "git::https://github.com/glennswest/terraform-modules.git//modules/proxmox-fedora-vm?ref=v0.3.0"
}

locals {
  ssh_key = trimspace(file(pathexpand("~/.ssh/id_rsa.pub")))
  git_ref = "main"

  # Verified free via get-free-vmid.sh immediately before this unit was
  # written (2026-07-09).
  vm = { vm_id = 2000, mac = "BC:24:11:08:20:00", ip = "192.168.8.60" }
}

inputs = {
  dns_zone_id        = "9bed60c8-1664-4183-88f9-a1a21b927edc" # g8.lo
  ci_ssh_public_keys = [local.ssh_key]
  tags               = ["terraform", "fedora", "irondirectory", "config-verify", "throwaway"]
  vm_datastore       = "test-lvm-thin"

  vms = {
    configverify = {
      vm_id     = local.vm.vm_id
      mac       = local.vm.mac
      ip        = local.vm.ip
      cores     = 1
      memory    = 1024
      disk_size = 15
      user_data = templatefile("${get_terragrunt_dir()}/templates/config-verify-user-data.yaml.tftpl", {
        hostname = "configverify"
        fqdn     = "configverify.g8.lo"
        ci_user  = "fedora"
        ssh_keys = [local.ssh_key]
        git_ref  = local.git_ref
      })
    }
  }
}
