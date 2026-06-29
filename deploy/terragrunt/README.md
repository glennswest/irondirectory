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
# Mint an API token on the node, then export it (never commit it):
ssh root@pve.g8.lo 'pveum user token add root@pam irondir --privsep 0'
export PROXMOX_API_TOKEN='root@pam!irondir=<the-value>'
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
