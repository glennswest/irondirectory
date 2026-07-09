# Root Terragrunt config for irondirectory infrastructure.
# Included by every unit:  include "root" { path = find_in_parent_folders("root.hcl") }
#
# Project boilerplate (provider + token wiring) lives here ONCE. Units only
# declare their module `source` and `inputs`. We never copy module .tf files —
# units reference the shared, versioned module at
# github.com/glennswest/terraform-modules (always pin ?ref=<tag>).

locals {
  proxmox_endpoint = "https://pve.g8.lo:8006/"
  ssh_private_key  = pathexpand("~/.ssh/id_rsa")
}

# Provider generated into every unit. Token comes from the environment so it
# never lands in code or state:  export PROXMOX_API_TOKEN='terraform-svc@pve!irondirectory=...'
# -- source it from .env at the repo root (gitignored, chmod 600), don't
# mint a fresh one; Proxmox never re-displays a token secret after
# creation. Must be the dedicated, pool-scoped terraform-svc@pve service
# token -- root@pam tokens are BANNED for this project (see README.md
# and terraform-modules CLAUDE.md, "Incident: 2026-07-08").
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<-EOF
    provider "proxmox" {
      endpoint  = "${local.proxmox_endpoint}"
      api_token = var.proxmox_api_token
      insecure  = true
      ssh {
        agent       = false
        username    = "root"
        private_key = file("${local.ssh_private_key}")
      }
    }

    variable "proxmox_api_token" {
      type      = string
      sensitive = true
    }
  EOF
}

inputs = {
  proxmox_api_token = get_env("PROXMOX_API_TOKEN")
}
