# irondirectory infrastructure — Terragrunt

Provisions irondirectory's infrastructure using the **shared, versioned**
module at [`github.com/glennswest/terraform-modules`](https://github.com/glennswest/terraform-modules)
(`modules/proxmox-fedora-vm`). We never copy `.tf` files — units reference the
module by a pinned `?ref=` tag.

```
deploy/terragrunt/
  root.hcl            # provider + token wiring (PROXMOX_API_TOKEN from env), once
  etcd/               # unit: dm1/dm2/dm3.g8.lo — the dedicated etcd backend (D1)
    terragrunt.hcl
    templates/etcd-user-data.yaml.tftpl
```

## One-time setup

```sh
brew install hashicorp/tap/terraform terragrunt
# Proxmox node must trust your ~/.ssh/id_rsa.pub (root@pve.g8.lo).
# The token lives in .env at the repo root (gitignored, chmod 600) — source
# it, don't mint a fresh one:
source .env   # from the repo root; adjust the path from a unit subdir

# If it's genuinely lost: Proxmox never re-displays a token secret after
# creation, so you'll need a new one. DO NOT run
# `pveum user token add root@pam <name>` as a shortcut — that's how we ended
# up with five different unrestricted root tokens (terraform, irondir,
# terraform-cli, -cli-2, -cli-3) and one of them destroyed a hand-created VM
# with no ACL to stop it. Instead:
#   pveum user token add terraform-svc@pve <name>
#   pveum acl modify /pool/terraform-managed --tokens 'terraform-svc@pve!<name>' --roles TerraformOperator
#   pveum acl modify /storage/local-lvm      --tokens 'terraform-svc@pve!<name>' --roles TerraformOperator
#   pveum acl modify /storage/local          --tokens 'terraform-svc@pve!<name>' --roles TerraformOperator
# Full context: terraform-modules CLAUDE.md, "Incident: 2026-07-08".
```

## etcd cluster

```sh
cd etcd
terragrunt init
terragrunt apply
export ETCDCTL_ENDPOINTS=http://192.168.8.41:2379,http://192.168.8.42:2379,http://192.168.8.43:2379
etcdctl member list -w table     # brew install etcd for a native macOS etcdctl
```

`terragrunt destroy` removes the VMs, their DHCP reservations, and DNS records.

- **dm1/dm2/dm3.g8.lo** → VMID 131/132/133 → 192.168.8.41/.42/.43 (reserved,
  outside the .100-.200 DHCP pool). etcd `v3.6.12`; **fastetcd is a drop-in swap**.
- Per-node etcd install rides the module's `user_data` hook (rendered
  cloud-config). `/var/lib/etcd` is on the root disk today — a dedicated data
  disk is filed as an enhancement on `terraform-modules`.

> The bash `../proxmox/ironetcd.sh` was the bootstrap that proved these steps;
> Terragrunt is the going-forward tool.
